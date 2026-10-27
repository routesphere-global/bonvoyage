#include "bonvoyage/runtime/runtime_log.hh"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <initializer_list>
#include <iostream>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace {

// A queue record contains 2048 bytes. Exception-message allocations are smaller.
// Restrict the probe to the constructing thread and the guarded constructor call.
thread_local bool reject_queue_allocation = false;
thread_local std::size_t queue_allocation_attempts = 0U;

}  // namespace

/** Test-only allocation replacement that detects premature queue allocation. */
// Preserve the probe boundary: GCC otherwise folds replacement delete's free
// into callers and diagnoses the intentionally malloc-backed new as mismatched.
[[gnu::noinline]] void* operator new(std::size_t size) {
  if (reject_queue_allocation && size >= 2048U) {
    ++queue_allocation_attempts;
    throw std::bad_alloc();
  }
  if (void* memory = std::malloc(size == 0U ? 1U : size)) {
    return memory;
  }
  throw std::bad_alloc();
}

/** Match the test-only allocation replacement, including sanitizer builds. */
[[gnu::noinline]] void operator delete(void* memory) noexcept { std::free(memory); }
/** Match sized scalar deallocation. */
[[gnu::noinline]] void operator delete(void* memory, std::size_t) noexcept { std::free(memory); }
/** Apply the same test-only allocation probe to arrays. */
[[gnu::noinline]] void* operator new[](std::size_t size) { return ::operator new(size); }
/** Match array deallocation. */
[[gnu::noinline]] void operator delete[](void* memory) noexcept { std::free(memory); }
/** Match sized array deallocation. */
[[gnu::noinline]] void operator delete[](void* memory, std::size_t) noexcept { std::free(memory); }

namespace {

using bonvoyage::runtime::RuntimeLogOptions;
using bonvoyage::runtime::RuntimeLogSendResult;
using bonvoyage::runtime::RuntimeLogSeverity;
using bonvoyage::runtime::RuntimeLogSink;
using bonvoyage::runtime::RuntimeLogStats;
using bonvoyage::runtime::UnixRuntimeLogTransport;
using bonvoyage::runtime::PipeRuntimeLogTransport;
using Result = RuntimeLogSendResult;
using Severity = RuntimeLogSeverity;
using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

std::atomic<std::uint64_t> assertions{0U};

void require(bool condition, const char* message) {
  assertions.fetch_add(1U, std::memory_order_relaxed);
  if (!condition) {
    throw std::runtime_error(message);
  }
}

void check_accounting(const RuntimeLogSink& sink) {
  const auto& s = sink.stats();
  require(s.records_attempted == s.records_sent + s.records_dropped + s.queue_depth,
          "attempted != sent + dropped + depth");
  require(s.records_dropped == s.queue_overflows + s.oversized_records +
              s.invalid_severities + s.send_failure_drops + s.shutdown_drops +
              s.stopped_drops,
          "record loss reasons do not sum to dropped");
  require(s.records_enqueued == s.records_sent + s.queue_depth +
              s.send_failure_drops + s.shutdown_drops,
          "admitted records were duplicated or lost without accounting");
  require(s.records_attempted == s.records_enqueued + s.queue_overflows +
              s.oversized_records + s.invalid_severities + s.stopped_drops,
          "enqueue admissions/rejections do not partition attempted records");
  require(s.send_attempts == s.records_sent + s.send_failure_drops +
              s.would_block_events + s.unavailable_events,
          "transport outcomes do not partition send attempts");
  require(s.queue_depth <= s.queue_capacity, "queue escaped its capacity");
  require(s.queue_depth <= s.queue_high_water, "high-water mark is below depth");
  require(s.queue_high_water <= s.queue_capacity, "high-water mark exceeds capacity");
  require(s.active <= 1U && s.sink_healthy <= 1U, "status is not boolean");
  require(s.active != 0U || s.queue_depth == 0U, "stopped sink retained records");
}

std::array<std::uint64_t, 19U> counters(const RuntimeLogStats& s) {
  return {s.records_attempted, s.records_enqueued, s.records_sent,
          s.records_dropped, s.queue_overflows, s.oversized_records,
          s.invalid_severities, s.send_failure_drops, s.shutdown_drops,
          s.stopped_drops, s.send_attempts, s.would_block_events,
          s.unavailable_events, s.bytes_sent, s.queue_depth, s.queue_high_water,
          s.queue_capacity, s.sink_healthy, s.active};
}

std::string frame(unsigned priority, std::string_view escaped_body) {
  return "<" + std::to_string(priority) + ">bonvoyage[" +
         std::to_string(::getpid()) + "]: " + std::string(escaped_body);
}

void enqueue(RuntimeLogSink& sink, Severity severity, std::string_view message,
             bool accepted = true) {
  require(sink.enqueue(severity, message) == accepted,
          "enqueue admission did not match the expected outcome");
  check_accounting(sink);
}

struct ScriptedSender final {
  struct Attempt final {
    std::array<char, 2048U> bytes{};
    std::size_t size{};
  };

  explicit ScriptedSender(std::initializer_list<Result> script = {},
                          Result default_result = Result::sent)
      : results(script), fallback(default_result), attempts(512U) {}

  static Result send(void* context, std::string_view record) noexcept {
    auto& self = *static_cast<ScriptedSender*>(context);
    const auto index = self.calls++;
    if (index >= self.attempts.size() || record.size() > 2048U) {
      self.capture_failed = true;
      return Result::failed;
    }
    auto& attempt = self.attempts[index];
    // Copy into storage allocated before drain; the callback cannot throw or
    // retain the borrowed view, even when an attempted record is retried.
    std::memcpy(attempt.bytes.data(), record.data(), record.size());
    attempt.size = record.size();
    if (self.stopping_sink != nullptr && self.stopping_sink->stats().active != 0U) {
      self.saw_active_during_stop = true;
    }
    return index < self.results.size() ? self.results[index] : self.fallback;
  }

  std::string_view at(std::size_t index) const {
    require(!capture_failed && index < calls && index < attempts.size(),
            "fake sender capture is missing or exceeded its fixed bound");
    return {attempts[index].bytes.data(), attempts[index].size};
  }

  std::vector<Result> results;
  Result fallback;
  std::vector<Attempt> attempts;
  std::size_t calls{};
  bool capture_failed{};
  const RuntimeLogSink* stopping_sink{};
  bool saw_active_during_stop{};
};

void drain(RuntimeLogSink& sink, ScriptedSender& sender) {
  sink.drain(&ScriptedSender::send, &sender);
  require(!sender.capture_failed, "fake sender exhausted its capture storage");
  check_accounting(sink);
}

void stop_empty(RuntimeLogSink& sink) {
  require(sink.stats().queue_depth == 0U, "test left pending records before explicit stop");
  sink.stop(nullptr, nullptr);
  check_accounting(sink);
  require(sink.stats().shutdown_drops == 0U, "empty shutdown unexpectedly lost a record");
}

struct AllocationGuard final {
  AllocationGuard() {
    queue_allocation_attempts = 0U;
    reject_queue_allocation = true;
  }
  ~AllocationGuard() { reject_queue_allocation = false; }
  AllocationGuard(const AllocationGuard&) = delete;
  AllocationGuard& operator=(const AllocationGuard&) = delete;
};

void expect_invalid_options(RuntimeLogOptions options) {
  bool validation_rejected = false;
  try {
    bonvoyage::runtime::validate_runtime_log_options(options);
  } catch (const std::invalid_argument&) {
    validation_rejected = true;
  }
  require(validation_rejected, "option validator accepted an invalid bound");

  bool constructor_rejected = false;
  {
    AllocationGuard guard;
    try {
      RuntimeLogSink sink(options);
    } catch (const std::invalid_argument&) {
      constructor_rejected = true;
    }
  }
  require(constructor_rejected, "constructor did not reject invalid options");
  require(queue_allocation_attempts == 0U,
          "invalid options reached queue allocation before validation");
}

void test_options_before_allocation() {
  for (const auto capacity : {0U, 4097U}) {
    expect_invalid_options({capacity, 128U, 1U});
  }
  for (const auto bytes : {0U, 127U, 2049U}) {
    expect_invalid_options({1U, bytes, 1U});
  }
  for (const auto batch : {0U, 257U}) {
    expect_invalid_options({1U, 128U, batch});
  }
  const auto huge = std::numeric_limits<std::size_t>::max();
  expect_invalid_options({huge, 128U, 1U});
  expect_invalid_options({1U, huge, 1U});
  expect_invalid_options({1U, 128U, huge});

  bool probe_detected_valid_allocation = false;
  {
    AllocationGuard guard;
    try {
      RuntimeLogSink sink({1U, 128U, 1U});
    } catch (const std::bad_alloc&) {
      probe_detected_valid_allocation = true;
    }
  }
  require(probe_detected_valid_allocation && queue_allocation_attempts == 1U,
          "allocation probe failed its positive control");

  const std::array<RuntimeLogOptions, 3U> valid{
      RuntimeLogOptions{}, RuntimeLogOptions{1U, 128U, 1U},
      RuntimeLogOptions{4096U, 2048U, 256U}};
  for (const auto& options : valid) {
    bonvoyage::runtime::validate_runtime_log_options(options);
    RuntimeLogSink sink(options);
    check_accounting(sink);
    require(sink.stats().queue_capacity == options.queue_capacity,
            "valid capacity was not captured");
    require(sink.stats().active == 1U && sink.stats().sink_healthy == 0U,
            "initial accepting/unknown-health state changed");
    auto initial = counters(sink.stats());
    initial[16U] = 0U;
    initial[18U] = 0U;
    require(initial == std::array<std::uint64_t, 19U>{},
            "initial counters were not zero");
    stop_empty(sink);
  }
}

void test_typed_priorities_and_escaping() {
  RuntimeLogSink sink({8U, 2048U, 8U});
  ScriptedSender sender;
  const std::array<Severity, 4U> severities{
      Severity::error, Severity::warning, Severity::info, Severity::debug};
  const std::array<unsigned, 4U> priorities{11U, 12U, 14U, 15U};
  for (const auto severity : severities) {
    enqueue(sink, severity, "diagnostic");
  }
  require(sender.calls == 0U && sink.stats().send_attempts == 0U,
          "enqueue performed transport work");
  drain(sink, sender);
  for (std::size_t i = 0U; i < severities.size(); ++i) {
    require(sender.at(i) == frame(priorities[i], "diagnostic"),
            "typed severity produced the wrong exact syslog frame");
  }

  std::string controls;
  for (unsigned byte = 0U; byte < 32U; ++byte) {
    controls.push_back(static_cast<char>(byte));
  }
  controls.push_back('\x7f');
  controls += " plain\\x00\"<>";
  constexpr std::string_view escaped =
      "\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07"
      "\\x08\\x09\\x0a\\x0b\\x0c\\x0d\\x0e\\x0f"
      "\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17"
      "\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f"
      "\\x7f plain\\x5cx00\"<>";
  enqueue(sink, Severity::info, controls);
  drain(sink, sender);
  require(sender.at(4U) == frame(14U, escaped),
          "control escaping or printable-byte preservation is incorrect");
  require(sender.at(4U).find('\0') == std::string_view::npos &&
              sender.at(4U).find('\n') == std::string_view::npos &&
              sender.at(4U).find('\x1b') == std::string_view::npos,
          "a raw control byte escaped into the wire datagram");
  enqueue(sink, Severity::info, "\\x0a");
  enqueue(sink, Severity::info, "\n");
  drain(sink, sender);
  require(sender.at(5U) == frame(14U, "\\x5cx0a") && sender.at(6U) == frame(14U, "\\x0a") &&
              sender.at(5U) != sender.at(6U),
          "literal escape-looking text is indistinguishable from a real control byte");

  for (unsigned value = 0U; value <= 255U; ++value) {
    if (value != 3U && value != 4U && value != 6U && value != 7U) {
      enqueue(sink, static_cast<Severity>(value), "invalid", false);
    }
  }
  require(sink.stats().invalid_severities == 252U,
          "not every unsupported underlying severity value was rejected");
  drain(sink, sender);
  require(sender.calls == 7U, "invalid severities reached the sender");
  stop_empty(sink);
}

void test_copied_message_lifetime() {
  RuntimeLogSink sink({4U, 2048U, 4U});
  ScriptedSender sender({Result::would_block});
  {
    std::array<char, 5U> stack{'a', '\0', 'b', '\n', 'c'};
    enqueue(sink, Severity::warning, {stack.data(), stack.size()});
    stack.fill('z');
    std::string heap(400U, 'h');
    enqueue(sink, Severity::error, std::string_view(heap).substr(17U, 250U));
    heap.assign(400U, 'z');
    enqueue(sink, Severity::debug, std::string(130U, 't'));
  }
  drain(sink, sender);
  require(sink.stats().queue_depth == 3U, "blocked send lost copied records");
  drain(sink, sender);
  require(sender.at(0U) == frame(12U, "a\\x00b\\x0ac") &&
              sender.at(1U) == sender.at(0U),
          "stack/embedded-NUL record or its retry outlived its copied bytes");
  require(sender.at(2U) == frame(11U, std::string(250U, 'h')),
          "heap substring was not copied before mutation/destruction");
  require(sender.at(3U) == frame(15U, std::string(130U, 't')),
          "temporary message bytes were not copied");
  require(sink.stats().records_sent == 3U && sink.stats().records_dropped == 0U,
          "lifetime test lost or duplicated a record");
  stop_empty(sink);
}

void test_whole_record_size_limits() {
  for (const std::size_t limit : {128U, 2048U}) {
    RuntimeLogSink sink({8U, limit, 8U});
    ScriptedSender sender;
    const auto budget = limit - frame(14U, "").size();
    std::vector<std::string> expected;

    const std::string exact(budget, 'a');
    enqueue(sink, Severity::info, exact);
    expected.push_back(frame(14U, exact));
    enqueue(sink, Severity::info, std::string(budget + 1U, 'a'), false);
    enqueue(sink, Severity::info, std::string(limit + 1U, 'r'), false);

    enqueue(sink, Severity::info, std::string(budget - 4U, 'e') + '\n');
    expected.push_back(frame(14U, std::string(budget - 4U, 'e') + "\\x0a"));
    enqueue(sink, Severity::info, std::string(budget - 3U, 'e') + '\n', false);
    enqueue(sink, Severity::info, std::string(budget - 4U, 'b') + '\\');
    expected.push_back(frame(14U, std::string(budget - 4U, 'b') + "\\x5c"));
    enqueue(sink, Severity::info, std::string(budget - 3U, 'b') + '\\', false);

    // Exercise complete 2-, 3-, and 4-byte UTF-8 at the exact datagram limit.
    for (const std::string_view utf8 : {"\xc3\xa9", "\xe2\x82\xac", "\xf0\x9f\x8c\x8d"}) {
      const auto body = std::string(budget - utf8.size(), 'u') + std::string(utf8);
      enqueue(sink, Severity::info, body);
      expected.push_back(frame(14U, body));
      enqueue(sink, Severity::info, "u" + body, false);
    }
    enqueue(sink, Severity::info, std::string_view{});
    expected.push_back(frame(14U, ""));
    require(sink.stats().oversized_records == 7U && sink.stats().queue_depth == 7U,
            "raw/framed/escaped/UTF-8 oversize accounting is incorrect");
    drain(sink, sender);
    require(sender.calls == expected.size(), "oversize records leaked partial datagrams");
    std::uint64_t bytes = 0U;
    for (std::size_t i = 0U; i < expected.size(); ++i) {
      require(sender.at(i) == expected[i], "record was truncated or UTF-8 was split");
      require(i + 1U == expected.size() || sender.at(i).size() == limit,
              "exact-fit datagram did not use the complete configured limit");
      bytes += expected[i].size();
    }
    require(sink.stats().bytes_sent == bytes, "byte accounting includes rejected records");
    stop_empty(sink);
  }
}

void test_bounded_fifo_wraparound() {
  RuntimeLogSink sink({3U, 128U, 2U});
  ScriptedSender sender;
  for (const auto* body : {"a", "b", "c"}) {
    enqueue(sink, Severity::info, body);
  }
  enqueue(sink, Severity::info, "drop-newest-1", false);
  drain(sink, sender);
  require(sender.calls == 2U && sink.stats().queue_depth == 1U,
          "finite drain did not leave the oldest pending record");
  enqueue(sink, Severity::info, "d");
  enqueue(sink, Severity::info, "e");
  enqueue(sink, Severity::info, "drop-newest-2", false);
  drain(sink, sender);
  enqueue(sink, Severity::info, "f");
  enqueue(sink, Severity::info, "g");
  drain(sink, sender);
  drain(sink, sender);
  for (std::size_t i = 0U; i < 7U; ++i) {
    require(sender.at(i) == frame(14U, std::string(1U, static_cast<char>('a' + i))),
            "drop-newest or ring wraparound changed FIFO contents");
  }
  require(sink.stats().queue_overflows == 2U && sink.stats().queue_high_water == 3U &&
              sink.stats().records_sent == 7U && sink.stats().queue_depth == 0U,
          "wrapped queue statistics are incorrect");

  RuntimeLogSink single({1U, 128U, 1U});
  ScriptedSender one;
  for (unsigned i = 0U; i < 32U; ++i) {
    const auto body = std::to_string(i);
    enqueue(single, Severity::debug, body);
    enqueue(single, Severity::debug, "overflow", false);
    drain(single, one);
    require(one.at(i) == frame(15U, body), "capacity-one ring did not wrap safely");
  }
  require(single.stats().queue_capacity == 1U && single.stats().queue_high_water == 1U,
          "capacity-one ring grew during repeated wraparound");
  stop_empty(single);
  stop_empty(sink);
}

void test_scripted_send_results() {
  RuntimeLogSink sink({3U, 128U, 2U});
  ScriptedSender sender({Result::would_block, Result::unavailable, Result::sent,
                         Result::failed, Result::sent});
  for (const auto* body : {"a", "b", "c"}) {
    enqueue(sink, Severity::info, body);
  }
  const auto before_null = counters(sink.stats());
  sink.drain(nullptr, &sender);
  check_accounting(sink);
  require(counters(sink.stats()) == before_null, "null sender changed the queue/counters");
  drain(sink, sender);
  require(sender.calls == 1U && sink.stats().queue_depth == 3U &&
              sink.stats().would_block_events == 1U && sink.stats().sink_healthy == 0U,
          "would_block did not immediately retain the head");
  drain(sink, sender);
  require(sender.calls == 2U && sink.stats().queue_depth == 3U &&
              sink.stats().unavailable_events == 1U,
          "unavailable retried inside the same drain or discarded the head");
  drain(sink, sender);
  require(sender.calls == 4U && sink.stats().queue_depth == 1U &&
              sink.stats().records_sent == 1U && sink.stats().send_failure_drops == 1U &&
              sink.stats().sink_healthy == 0U,
          "permanent failure did not consume one head and one batch attempt");
  drain(sink, sender);
  require(sender.calls == 5U && sink.stats().records_sent == 2U &&
              sink.stats().queue_depth == 0U && sink.stats().sink_healthy == 1U,
          "sender did not recover after a permanent failure");
  for (std::size_t i = 0U; i < 3U; ++i) {
    require(sender.at(i) == frame(14U, "a"), "retry did not keep the identical FIFO head");
  }
  require(sender.at(3U) == frame(14U, "b") && sender.at(4U) == frame(14U, "c"),
          "permanent failure did not advance to the next record");
  require(sink.stats().bytes_sent == frame(14U, "a").size() + frame(14U, "c").size(),
          "failed or retried sends were counted as accepted bytes");
  const auto empty = counters(sink.stats());
  drain(sink, sender);
  require(counters(sink.stats()) == empty && sender.calls == 5U,
          "empty drain performed work or changed health");
  stop_empty(sink);
}

void test_finite_drain_batches() {
  for (const std::size_t batch : {1U, 2U, 256U}) {
    for (const auto result : {Result::sent, Result::failed}) {
      RuntimeLogSink sink({batch + 1U, 128U, batch});
      ScriptedSender sender({}, result);
      for (std::size_t i = 0U; i <= batch; ++i) {
        enqueue(sink, Severity::info, std::to_string(i));
      }
      drain(sink, sender);
      require(sender.calls == batch && sink.stats().queue_depth == 1U,
              "drain exceeded or underused its fixed attempt budget");
      drain(sink, sender);
      require(sender.calls == batch + 1U && sink.stats().queue_depth == 0U,
              "next bounded drain did not consume the remaining head");
      require(sender.at(batch) == frame(14U, std::to_string(batch)),
              "batch boundary lost FIFO order");
      require(result == Result::sent ? sink.stats().records_sent == batch + 1U
                                    : sink.stats().send_failure_drops == batch + 1U,
              "finite batch outcome counts are incorrect");
      stop_empty(sink);
    }
  }
}

void test_stop_and_accounting() {
  for (unsigned mode = 0U; mode < 5U; ++mode) {
    const std::array<Result, 5U> results{Result::sent, Result::would_block,
                                       Result::unavailable, Result::failed, Result::sent};
    RuntimeLogSink sink({5U, 128U, 2U});
    ScriptedSender sender({}, results[mode]);
    sender.stopping_sink = &sink;
    for (unsigned i = 0U; i < 5U; ++i) {
      enqueue(sink, Severity::info, std::to_string(i));
    }
    sink.stop(mode == 4U ? nullptr : &ScriptedSender::send, &sender);
    check_accounting(sink);
    const std::size_t expected_attempts = mode == 4U ? 0U : (mode == 0U || mode == 3U ? 2U : 1U);
    const std::uint64_t consumed = mode == 0U || mode == 3U ? 2U : 0U;
    require(sender.calls == expected_attempts && !sender.capture_failed,
            "stop was not bounded by the drain batch/first retryable result");
    require(!sender.saw_active_during_stop && sink.stats().active == 0U,
            "stop did not mark the sink inactive before the final callback");
    require(sink.stats().shutdown_drops == 5U - consumed && sink.stats().queue_depth == 0U,
            "stop did not account for every pending record");
    require(sink.stats().records_sent == (mode == 0U ? 2U : 0U) &&
                sink.stats().send_failure_drops == (mode == 3U ? 2U : 0U),
            "shutdown conflated permanent failure with pending loss");
    const auto stopped = counters(sink.stats());
    sink.stop(&ScriptedSender::send, &sender);
    sink.stop(nullptr, nullptr);
    drain(sink, sender);
    require(counters(sink.stats()) == stopped && sender.calls == expected_attempts,
            "stop was not idempotent or drain sent after stop");
    enqueue(sink, Severity::info, "late", false);
    enqueue(sink, static_cast<Severity>(0U), "late invalid", false);
    enqueue(sink, Severity::error, std::string(2049U, 'x'), false);
    require(sink.stats().stopped_drops == 3U && sink.stats().invalid_severities == 0U &&
                sink.stats().oversized_records == 0U && sink.stats().queue_overflows == 0U,
            "late enqueue was not classified exclusively as stopped loss");
  }

  RuntimeLogSink mixed({2U, 128U, 1U});
  ScriptedSender sender({Result::failed, Result::would_block, Result::unavailable, Result::sent});
  enqueue(mixed, Severity::info, std::string(129U, 'x'), false);
  enqueue(mixed, static_cast<Severity>(255U), "bad", false);
  enqueue(mixed, Severity::info, "a");
  enqueue(mixed, Severity::info, "b");
  enqueue(mixed, Severity::info, "overflow", false);
  drain(mixed, sender);
  enqueue(mixed, Severity::info, "c");
  drain(mixed, sender);
  drain(mixed, sender);
  mixed.stop(&ScriptedSender::send, &sender);
  check_accounting(mixed);
  enqueue(mixed, Severity::info, "late", false);
  const auto& s = mixed.stats();
  require(s.records_attempted == 7U && s.records_enqueued == 3U &&
              s.records_sent == 1U && s.records_dropped == 6U && s.send_attempts == 4U,
          "mixed lifecycle totals do not match the actual operations");
  require(s.queue_overflows == 1U && s.oversized_records == 1U &&
              s.invalid_severities == 1U && s.send_failure_drops == 1U &&
              s.shutdown_drops == 1U && s.stopped_drops == 1U,
          "mixed lifecycle did not account separately for all six loss reasons");
}

struct ReentrantSender final {
  explicit ReentrantSender(RuntimeLogSink& owner, Result first_result)
      : sink(owner), capture({first_result}) {}

  static Result nested_send(void* context, std::string_view) noexcept {
    ++static_cast<ReentrantSender*>(context)->nested_calls;
    return Result::sent;
  }

  static Result send(void* context, std::string_view record) noexcept {
    auto& self = *static_cast<ReentrantSender*>(context);
    const auto result = ScriptedSender::send(&self.capture, record);
    const auto before = counters(self.sink.stats());
    self.sink.drain(&nested_send, &self);
    self.unchanged = self.unchanged && counters(self.sink.stats()) == before;
    self.sink.stop(&nested_send, &self);
    self.unchanged = self.unchanged && counters(self.sink.stats()) == before;
    self.sink.stop(nullptr, nullptr);
    self.unchanged = self.unchanged && counters(self.sink.stats()) == before;
    return result;
  }

  RuntimeLogSink& sink;
  ScriptedSender capture;
  std::size_t nested_calls{};
  bool unchanged{true};
};

void test_callback_reentry() {
  for (const bool stopping : {false, true}) {
    for (const auto result : {Result::sent, Result::would_block, Result::unavailable, Result::failed}) {
      RuntimeLogSink sink({3U, 128U, 2U});
      ReentrantSender sender(sink, result);
      for (const auto* body : {"a", "b", "c"}) {
        enqueue(sink, Severity::info, body);
      }
      if (stopping) {
        sink.stop(&ReentrantSender::send, &sender);
      } else {
        sink.drain(&ReentrantSender::send, &sender);
      }
      check_accounting(sink);
      require(sender.unchanged && sender.nested_calls == 0U,
              "callback drain/stop reentry changed state or invoked a nested sender");
      const bool retryable = result == Result::would_block || result == Result::unavailable;
      require(sender.capture.calls == (retryable ? 1U : 2U),
              "callback reentry changed the outer operation's finite batch");
      require(sender.capture.at(0U) == frame(14U, "a"), "reentry changed the original head");
      if (!retryable) {
        require(sender.capture.at(1U) == frame(14U, "b"), "reentry corrupted the next FIFO head");
      }
      if (stopping) {
        require(sink.stats().active == 0U &&
                    sink.stats().shutdown_drops == (retryable ? 3U : 1U),
                "nested stop interfered with outer shutdown accounting");
        const auto stopped = counters(sink.stats());
        sink.stop(&ReentrantSender::send, &sender);
        check_accounting(sink);
        require(counters(sink.stats()) == stopped, "reentrant shutdown was not idempotent");
      } else {
        require(sink.stats().active == 1U && sink.stats().queue_depth == (retryable ? 3U : 1U),
                "nested stop deactivated an ordinary drain or discarded its records");
        const auto sent_before = sink.stats().records_sent;
        // A subsequent public drain must run after every early-return outcome.
        sink.drain(&ReentrantSender::send, &sender);
        check_accounting(sink);
        require(sink.stats().records_sent - sent_before == (retryable ? 2U : 1U),
                "drain reentry guard remained set after the outer callback returned");
        require(sender.unchanged && sender.nested_calls == 0U,
                "repeated drain no longer rejected nested operations");
        sink.stop(&ReentrantSender::send, &sender);
        check_accounting(sink);
        require(sink.stats().shutdown_drops == 0U && sink.stats().queue_depth == 0U &&
                    sender.unchanged && sender.nested_calls == 0U,
                "explicit stop after reentry did not finish the original queue");
      }
    }
  }
}

class PrivateSocket final {
 public:
  PrivateSocket() {
    char pattern[] = "/tmp/bonvoyage-runtime-log-XXXXXX";
    const auto* created = ::mkdtemp(pattern);
    require(created != nullptr, "mkdtemp failed for private runtime-log sockets");
    directory_ = created;
    path_ = directory_ + "/receiver.sock";
  }
  ~PrivateSocket() {
    if (receiver_ >= 0) {
      ::close(receiver_);
    }
    ::unlink(path_.c_str());
    ::rmdir(directory_.c_str());
  }
  PrivateSocket(const PrivateSocket&) = delete;
  PrivateSocket& operator=(const PrivateSocket&) = delete;

  const std::string& path() const noexcept { return path_; }
  const std::string& directory() const noexcept { return directory_; }

  void bind_receiver(int type = SOCK_DGRAM) {
    require(receiver_ < 0, "private receiver was already open");
    receiver_ = ::socket(AF_UNIX, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    require(receiver_ >= 0, "private receiver socket creation failed");
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    require(path_.size() < sizeof(address.sun_path), "private socket path is too long");
    std::memcpy(address.sun_path, path_.c_str(), path_.size() + 1U);
    const auto size = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + path_.size() + 1U);
    require(::bind(receiver_, reinterpret_cast<const sockaddr*>(&address), size) == 0,
            "private receiver bind failed");
  }

  void close_receiver() {
    require(receiver_ >= 0, "private receiver was not open");
    const auto result = ::close(receiver_);
    receiver_ = -1;
    require(result == 0, "private receiver close failed");
  }

  void unlink_receiver() {
    require(::unlink(path_.c_str()) == 0, "private receiver unlink failed");
  }

  std::string receive() const {
    pollfd descriptor{receiver_, POLLIN, 0};
    int ready = -1;
    for (unsigned attempt = 0U; attempt < 4U; ++attempt) {
      ready = ::poll(&descriptor, 1U, 250);
      if (ready >= 0 || errno != EINTR) {
        break;
      }
    }
    require(ready == 1 && (descriptor.revents & POLLIN) != 0,
            "private receive timed out or receiver failed");
    std::array<char, 2048U> bytes{};
    const auto received = ::recv(receiver_, bytes.data(), bytes.size(), MSG_DONTWAIT | MSG_TRUNC);
    require(received >= 0 && static_cast<std::size_t>(received) <= bytes.size(),
            "private receive failed or a datagram was truncated");
    return {bytes.data(), static_cast<std::size_t>(received)};
  }

  void require_empty() const {
    char byte{};
    const auto result = ::recv(receiver_, &byte, 1U, MSG_DONTWAIT);
    const auto error = errno;
    require(result == -1 && (error == EAGAIN || error == EWOULDBLOCK),
            "unexpected extra/duplicate datagram on the private receiver");
  }

 private:
  std::string directory_;
  std::string path_;
  int receiver_{-1};
};

void check_descriptor_flags(int fd) {
  require(fd >= 0, "sender did not lazily acquire a descriptor");
  const auto status_flags = ::fcntl(fd, F_GETFL);
  require(status_flags >= 0 && (status_flags & O_NONBLOCK) != 0,
          "sender descriptor does not have O_NONBLOCK");
  const auto descriptor_flags = ::fcntl(fd, F_GETFD);
  require(descriptor_flags >= 0 && (descriptor_flags & FD_CLOEXEC) != 0,
          "sender descriptor does not have FD_CLOEXEC");
}

void test_pipe_transport() {
  int ends[2]{-1, -1};
  require(::pipe2(ends, O_CLOEXEC) == 0, "private pipe creation failed");
  const int reader = ends[0];
  const int writer = ends[1];
  int owned = -1;
  require(::fcntl(reader, F_SETFL, ::fcntl(reader, F_GETFL) | O_NONBLOCK) == 0,
          "private reader nonblocking setup failed");
  try {
    errno = EDOM;
    {
      PipeRuntimeLogTransport transport(writer);
      require(errno == EDOM, "pipe constructor changed ambient errno");
      owned = transport.native_handle();
      require(owned >= 0 && owned != writer, "pipe descriptor was not duplicated");
      check_descriptor_flags(owned);
      require((::fcntl(writer, F_GETFL) & O_NONBLOCK) != 0,
              "shared pipe description was not made nonblocking");
      require(PipeRuntimeLogTransport::send(nullptr, "x") == Result::failed,
              "null pipe adapter was accepted");
      require(transport.try_send({}) == Result::failed && transport.last_error() == EMSGSIZE,
              "empty pipe record was accepted");
      require(transport.try_send(std::string(2049U, 'x')) == Result::failed &&
                  transport.last_error() == EMSGSIZE, "oversized pipe record was accepted");
      const std::string maximum(2048U, 'z');
      require(transport.try_send(maximum) == Result::sent && transport.last_error() == 0,
              "maximum pipe record was not accepted");
      std::array<char, 2049U> received{};
      require(::read(reader, received.data(), received.size()) == 2049 &&
                  std::string_view(received.data(), 2048U) == maximum &&
                  received[2048U] == '\n',
              "maximum pipe record was not complete with one LF");
      require(transport.try_send("already\n\n") == Result::sent,
              "newline-terminated pipe record was rejected");
      require(::read(reader, received.data(), received.size()) == 8 &&
                  std::string_view(received.data(), 8U) == "already\n",
              "pipe transport duplicated an input trailing newline");
      require(::read(reader, received.data(), received.size()) == -1 && errno == EAGAIN,
              "pipe transport emitted extra bytes after complete records");

      std::array<char, 2048U> filler{};
      while (::write(writer, filler.data(), filler.size()) > 0) {}
      require(errno == EAGAIN, "private pipe did not reach backpressure");
      const int writer_flags = ::fcntl(writer, F_GETFL);
      require(writer_flags >= 0 && (writer_flags & O_NONBLOCK) != 0,
              "original pipe writer did not share nonblocking status");
      require(::fcntl(writer, F_SETFL, writer_flags & ~O_NONBLOCK) == 0,
              "could not clear shared nonblocking status");
      errno = EDOM;
      require(transport.try_send("must not block") == Result::failed &&
                  transport.last_error() == EOPNOTSUPP && errno == EDOM,
              "cleared nonblocking status was not rejected immediately");
      require(::fcntl(writer, F_SETFL, writer_flags) == 0,
              "could not restore shared nonblocking status");
      check_descriptor_flags(owned);
      errno = EDOM;
      require(transport.try_send(maximum) == Result::would_block &&
                  transport.last_error() == EAGAIN && errno == EDOM,
              "full pipe partially accepted a maximum-sized record");
      RuntimeLogSink sink({2U, 2048U, 2U});
      enqueue(sink, Severity::info, "pipe queued");
      errno = EDOM;
      sink.drain(&PipeRuntimeLogTransport::send, &transport);
      require(errno == EDOM && transport.last_error() == EAGAIN,
              "full pipe send changed errno or error classification");
      require(sink.stats().would_block_events == 1U && sink.stats().queue_depth == 1U,
              "backpressure lost a queued sink record");
      check_accounting(sink);
      require(sink.stats().records_sent == 0U && sink.stats().bytes_sent == 0U,
              "backpressure partially accepted a sink record");
      ssize_t drained = 0;
      while ((drained = ::read(reader, received.data(), received.size())) > 0) {
        require(std::all_of(received.begin(), received.begin() + drained,
                            [](char byte) { return byte == '\0'; }),
                "backpressure leaked a partial record into the full pipe");
      }
      require(errno == EAGAIN, "private pipe drain did not finish");
      sink.drain(&PipeRuntimeLogTransport::send, &transport);
      require(sink.stats().records_sent == 1U && sink.stats().queue_depth == 0U &&
                  sink.stats().sink_healthy == 1U, "pipe recovery did not update sink accounting");
      const auto queued_frame = frame(14U, "pipe queued");
      require(sink.stats().bytes_sent == queued_frame.size(),
              "sink bytes_sent included pipe LF rather than queued payload only");
      require(::read(reader, received.data(), received.size()) ==
                  static_cast<ssize_t>(queued_frame.size() + 1U) &&
                  std::string_view(received.data(), queued_frame.size()) == queued_frame &&
                  received[queued_frame.size()] == '\n',
              "recovered sink record was not complete with one LF");
      require(::read(reader, received.data(), received.size()) == -1 && errno == EAGAIN,
              "backpressure recovery duplicated or partially wrote a record");
      check_accounting(sink);
      sink.stop(&PipeRuntimeLogTransport::send, &transport);
      check_accounting(sink);

      require(::close(writer) == 0, "original pipe writer close failed");
      require(transport.try_send("owned") == Result::sent,
              "owned pipe duplicate did not survive original close");
      require(::close(reader) == 0, "private pipe reader close failed");
      errno = EDOM;
      require(transport.try_send("closed") == Result::unavailable &&
                  transport.last_error() == EPIPE && errno == EDOM,
              "closed reader did not yield EPIPE without changing errno");
    }
    require(errno == EDOM && ::fcntl(owned, F_GETFD) == -1 && errno == EBADF,
            "pipe destructor did not preserve errno or close its duplicate");
  } catch (...) {
    ::close(reader);
    ::close(writer);
    throw;
  }

  for (const int invalid : {-1, 999999}) {
    bool rejected = false;
    try { PipeRuntimeLogTransport transport(invalid); }
    catch (const std::system_error&) { rejected = true; }
    require(rejected, "invalid pipe descriptor was accepted");
  }
  int file = ::open("/dev/null", O_WRONLY | O_CLOEXEC);
  require(file >= 0, "test file open failed");
  bool rejected = false;
  try { PipeRuntimeLogTransport transport(file); }
  catch (const std::invalid_argument&) { rejected = true; }
  require(rejected, "regular/character file descriptor was accepted");
  require(::close(file) == 0, "test file close failed");
  FILE* regular = ::tmpfile();
  require(regular != nullptr, "temporary regular file creation failed");
  rejected = false;
  try { PipeRuntimeLogTransport transport(::fileno(regular)); }
  catch (const std::invalid_argument&) { rejected = true; }
  require(rejected, "regular file was accepted as pipe");
  require(::fclose(regular) == 0, "temporary regular file close failed");
  int tty = ::posix_openpt(O_RDWR | O_CLOEXEC);
  require(tty >= 0, "private pseudo-terminal creation failed");
  rejected = false;
  try { PipeRuntimeLogTransport transport(tty); }
  catch (const std::invalid_argument&) { rejected = true; }
  require(rejected, "TTY descriptor was accepted as pipe");
  require(::close(tty) == 0, "private pseudo-terminal close failed");
  int read_only[2]{};
  require(::pipe(read_only) == 0, "read-only pipe creation failed");
  rejected = false;
  try { PipeRuntimeLogTransport transport(read_only[0]); }
  catch (const std::invalid_argument&) { rejected = true; }
  require(rejected, "read-only pipe endpoint was accepted");
  ::close(read_only[0]);
  ::close(read_only[1]);
  int sockets[2]{};
  require(::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0, "test socketpair failed");
  rejected = false;
  try { PipeRuntimeLogTransport transport(sockets[0]); }
  catch (const std::invalid_argument&) { rejected = true; }
  require(rejected, "socket descriptor was accepted as pipe");
  ::close(sockets[0]);
  ::close(sockets[1]);
}

void test_unix_path_and_record_validation() {
  PrivateSocket socket;
  struct stat directory_stat {};
  require(::stat(socket.directory().c_str(), &directory_stat) == 0 &&
              (directory_stat.st_mode & 0777U) == 0700U,
          "socket test directory is not private mode 0700");
  const sockaddr_un address{};
  std::vector<std::string> invalid{"", "relative.sock", std::string("\0abstract", 9U),
                                    std::string(sizeof(address.sun_path), '/')};
  for (unsigned byte = 0U; byte < 32U; ++byte) {
    invalid.push_back(socket.path() + static_cast<char>(byte));
  }
  invalid.push_back(socket.path() + '\x7f');
  for (const auto& path : invalid) {
    bool rejected = false;
    try {
      UnixRuntimeLogTransport transport(path);
    } catch (const std::invalid_argument&) {
      rejected = true;
    }
    require(rejected, "invalid Unix socket destination was accepted");
  }
  const auto longest = socket.directory() + "/" +
      std::string(sizeof(address.sun_path) - socket.directory().size() - 2U, 'x');
  UnixRuntimeLogTransport boundary(longest);
  require(boundary.native_handle() == -1, "valid path boundary eagerly opened a socket");

  UnixRuntimeLogTransport transport(socket.path());
  require(transport.native_handle() == -1 && transport.last_error() == 0,
          "new transport was not lazy and error-free");
  require(transport.try_send({}) == Result::failed && transport.last_error() == EMSGSIZE,
          "empty transport datagram did not fail with EMSGSIZE");
  require(transport.try_send(std::string(2049U, 'x')) == Result::failed &&
              transport.last_error() == EMSGSIZE && transport.native_handle() == -1,
          "invalid record opened a descriptor or exceeded the transport limit");
  require(UnixRuntimeLogTransport::send(nullptr, "data") == Result::failed,
          "null transport adapter context did not fail safely");
  socket.bind_receiver();
  require(UnixRuntimeLogTransport::send(&transport, "x") == Result::sent &&
              transport.last_error() == 0,
          "valid one-byte datagram did not clear the prior error");
  require(socket.receive() == "x", "one-byte datagram changed in transport");
  const auto fd = transport.native_handle();
  const std::string maximum(2048U, '\0');
  require(transport.try_send(maximum) == Result::sent, "maximum binary datagram was rejected");
  require(socket.receive() == maximum, "transport truncated or modified binary bytes");
  require(transport.try_send({}) == Result::failed && transport.native_handle() == fd,
          "invalid record replaced an already-open sender descriptor");
  socket.require_empty();
  check_descriptor_flags(fd);

  PrivateSocket wrong_type;
  wrong_type.bind_receiver(SOCK_STREAM);
  UnixRuntimeLogTransport permanent(wrong_type.path());
  require(permanent.try_send("wrong socket type") == Result::failed &&
              permanent.last_error() == EPROTOTYPE,
          "incompatible socket type was not classified as a permanent failure");
}

void test_unix_receiver_recovery_and_fd_lifecycle() {
  PrivateSocket socket;
  int closed_fd = -1;
  {
    UnixRuntimeLogTransport transport(socket.path());
    RuntimeLogSink sink({3U, 128U, 2U});
    enqueue(sink, Severity::warning, "absent-a");
    enqueue(sink, Severity::warning, "absent-b");
    sink.drain(&UnixRuntimeLogTransport::send, &transport);
    check_accounting(sink);
    require(transport.last_error() == ENOENT && sink.stats().unavailable_events == 1U &&
                sink.stats().send_attempts == 1U && sink.stats().queue_depth == 2U &&
                sink.stats().records_dropped == 0U,
            "absent receiver did not preserve the bounded queue");
    closed_fd = transport.native_handle();
    check_descriptor_flags(closed_fd);
    socket.bind_receiver();
    sink.drain(&UnixRuntimeLogTransport::send, &transport);
    check_accounting(sink);
    require(socket.receive() == frame(12U, "absent-a") &&
                socket.receive() == frame(12U, "absent-b"),
            "receiver creation did not recover the original FIFO records");
    require(transport.last_error() == 0 && sink.stats().sink_healthy == 1U,
            "successful receiver recovery did not clear the unhealthy state");

    socket.close_receiver();
    enqueue(sink, Severity::info, "replacement");
    sink.drain(&UnixRuntimeLogTransport::send, &transport);
    check_accounting(sink);
    require(transport.last_error() == ECONNREFUSED && sink.stats().queue_depth == 1U &&
                sink.stats().sink_healthy == 0U,
            "stale pathname did not retain the record as unavailable");
    socket.unlink_receiver();
    sink.drain(&UnixRuntimeLogTransport::send, &transport);
    check_accounting(sink);
    require(transport.last_error() == ENOENT && sink.stats().queue_depth == 1U,
            "unlinked replacement path did not retain the head");
    socket.bind_receiver();
    sink.drain(&UnixRuntimeLogTransport::send, &transport);
    check_accounting(sink);
    require(socket.receive() == frame(14U, "replacement"),
            "same-path receiver replacement did not recover without reconnecting");
    require(transport.native_handle() == closed_fd && transport.last_error() == 0,
            "recovery replaced the sender fd or retained an obsolete error");
    require(sink.stats().records_sent == 3U && sink.stats().records_dropped == 0U &&
                sink.stats().unavailable_events == 3U && sink.stats().send_attempts == 6U,
            "receiver lifecycle introduced loss, duplication, or incorrect retries");
    socket.require_empty();
    sink.stop(&UnixRuntimeLogTransport::send, &transport);
    check_accounting(sink);
  }
  // Do not open any descriptor between destruction and this ownership check.
  errno = 0;
  const auto result = ::fcntl(closed_fd, F_GETFD);
  const auto error = errno;
  require(result == -1 && error == EBADF, "transport destructor leaked its descriptor");
}

void test_unix_backpressure_lossless_recovery() {
  PrivateSocket socket;
  socket.bind_receiver();
  UnixRuntimeLogTransport prefill(socket.path());
  std::size_t prefilled = 0U;
  Result result = Result::sent;
  const auto deadline = Clock::now() + 2s;
  for (std::size_t i = 0U; i < 65536U && Clock::now() < deadline; ++i) {
    result = prefill.try_send("prefill");
    if (result != Result::sent) {
      break;
    }
    ++prefilled;
  }
  require(prefilled > 0U && result == Result::would_block &&
              (prefill.last_error() == EAGAIN || prefill.last_error() == EWOULDBLOCK),
          "private receiver queue did not reach EAGAIN within the finite prefill bound");
  const auto blocked_start = Clock::now();
  require(prefill.try_send("must-not-arrive") == Result::would_block,
          "full private queue unexpectedly accepted another datagram");
  require(Clock::now() - blocked_start < 1s, "full-queue send did not return promptly");
  check_descriptor_flags(prefill.native_handle());

  UnixRuntimeLogTransport transport(socket.path());
  RuntimeLogSink sink({4U, 128U, 2U});
  for (const auto* body : {"a", "b", "c", "d"}) {
    enqueue(sink, Severity::info, body);
  }
  for (unsigned i = 0U; i < 3U; ++i) {
    const auto start = Clock::now();
    sink.drain(&UnixRuntimeLogTransport::send, &transport);
    require(Clock::now() - start < 1s, "backpressured sink drain blocked");
    check_accounting(sink);
    require(sink.stats().send_attempts == i + 1U && sink.stats().queue_depth == 4U &&
                sink.stats().would_block_events == i + 1U && sink.stats().records_dropped == 0U,
            "backpressure busy-retried, lost records, or escaped the queue bound");
  }
  check_descriptor_flags(transport.native_handle());

  require(socket.receive() == "prefill", "private prefill datagram changed");
  sink.drain(&UnixRuntimeLogTransport::send, &transport);
  check_accounting(sink);
  require(sink.stats().records_sent == 1U && sink.stats().queue_depth == 3U &&
              sink.stats().send_attempts == 5U && sink.stats().would_block_events == 4U,
          "one freed receiver slot did not yield sent-then-would_block within one batch");
  for (std::size_t i = 1U; i < prefilled; ++i) {
    require(socket.receive() == "prefill", "recovery interleaved ahead of older prefill data");
  }
  require(socket.receive() == frame(14U, "a"), "first recovered record changed or was lost");
  socket.require_empty();

  for (unsigned round = 0U; round < 2U; ++round) {
    const auto before = sink.stats().send_attempts;
    sink.drain(&UnixRuntimeLogTransport::send, &transport);
    check_accounting(sink);
    require(sink.stats().send_attempts - before == (round == 0U ? 2U : 1U),
            "recovery did not obey the configured finite batch");
    if (round == 0U) {
      require(socket.receive() == frame(14U, "b") && socket.receive() == frame(14U, "c"),
              "bounded recovery changed middle-record FIFO order");
    } else {
      require(socket.receive() == frame(14U, "d"), "bounded recovery lost its final record");
    }
  }
  require(sink.stats().records_sent == 4U && sink.stats().records_dropped == 0U &&
              sink.stats().queue_depth == 0U && sink.stats().queue_high_water == 4U &&
              sink.stats().bytes_sent == 4U * frame(14U, "a").size() &&
              sink.stats().sink_healthy == 1U && transport.last_error() == 0,
          "backpressure recovery was not lossless, bounded, and fully accounted");
  socket.require_empty();
  sink.stop(&UnixRuntimeLogTransport::send, &transport);
  check_accounting(sink);
}

void expect_preserved_errno(UnixRuntimeLogTransport& transport, std::string_view record,
                            Result expected, int operation_error) {
  for (const int ambient : {0, EDOM, EINTR, ERANGE}) {
    errno = ambient;
    const auto result = transport.try_send(record);
    const auto after = errno;
    require(after == ambient, "transport send overwrote the caller's ambient errno");
    require(result == expected && transport.last_error() == operation_error,
            "preserving ambient errno lost the actual transport outcome/error");
  }
}

void test_errno_preservation() {
  PrivateSocket socket;
  int fd = -1;
  {
    UnixRuntimeLogTransport transport(socket.path());
    expect_preserved_errno(transport, {}, Result::failed, EMSGSIZE);
    const std::string oversized(2049U, 'x');
    expect_preserved_errno(transport, oversized, Result::failed, EMSGSIZE);
    require(transport.native_handle() == -1, "invalid datagrams allocated a sender socket");
    expect_preserved_errno(transport, "absent", Result::unavailable, ENOENT);
    fd = transport.native_handle();
    socket.bind_receiver();
    expect_preserved_errno(transport, "accepted", Result::sent, 0);
    for (unsigned i = 0U; i < 4U; ++i) {
      require(socket.receive() == "accepted", "errno test did not receive every accepted datagram");
    }

    Result result = Result::sent;
    std::size_t accepted = 0U;
    const auto deadline = Clock::now() + 2s;
    for (std::size_t i = 0U; i < 65536U && Clock::now() < deadline; ++i) {
      errno = EDOM;
      result = transport.try_send("pressure");
      const auto after = errno;
      require(after == EDOM, "pressure transition overwrote ambient errno");
      if (result != Result::sent) {
        break;
      }
      ++accepted;
    }
    require(accepted > 0U && result == Result::would_block &&
                (transport.last_error() == EAGAIN || transport.last_error() == EWOULDBLOCK),
            "errno pressure scenario did not reach a bounded EAGAIN state");
    const auto blocked_error = transport.last_error();
    expect_preserved_errno(transport, "blocked", Result::would_block, blocked_error);
    for (std::size_t i = 0U; i < accepted; ++i) {
      require(socket.receive() == "pressure", "errno pressure prefill was lost or duplicated");
    }
    errno = E2BIG;
    const auto recovered = UnixRuntimeLogTransport::send(&transport, "recovered");
    const auto recovered_errno = errno;
    require(recovered == Result::sent && recovered_errno == E2BIG && transport.last_error() == 0,
            "adapter recovery failed to preserve errno and clear last_error");
    require(socket.receive() == "recovered", "adapter recovery datagram was lost");
    socket.close_receiver();
    expect_preserved_errno(transport, "stale", Result::unavailable, ECONNREFUSED);
    // Nothing between setting the sentinel and destruction may touch errno.
    errno = ERANGE;
  }
  const auto after_close = errno;
  require(after_close == ERANGE, "transport destructor overwrote ambient errno");
  errno = 0;
  const auto descriptor = ::fcntl(fd, F_GETFD);
  const auto descriptor_error = errno;
  require(descriptor == -1 && descriptor_error == EBADF,
          "preserving errno prevented the destructor from closing its descriptor");
  {
    UnixRuntimeLogTransport unopened(socket.path());
    errno = EDOM;
  }
  const auto after_unopened = errno;
  require(after_unopened == EDOM, "unopened transport destruction overwrote ambient errno");

  PrivateSocket wrong_type;
  wrong_type.bind_receiver(SOCK_STREAM);
  UnixRuntimeLogTransport permanent(wrong_type.path());
  expect_preserved_errno(permanent, "wrong type", Result::failed, EPROTOTYPE);
  errno = ERANGE;
  const auto null_result = UnixRuntimeLogTransport::send(nullptr, "invalid adapter");
  const auto null_errno = errno;
  require(null_result == Result::failed && null_errno == ERANGE,
          "null adapter changed ambient errno");
}

void wait_for_flag(const std::atomic<bool>& flag) {
  const auto deadline = Clock::now() + 5s;
  while (!flag.load(std::memory_order_acquire) && Clock::now() < deadline) {
    std::this_thread::sleep_for(1ms);
  }
  require(flag.load(std::memory_order_acquire), "independent owner-thread handshake timed out");
}

void test_independent_owner_threads() {
  std::atomic<bool> blocked_ready{false};
  std::atomic<bool> healthy_finished{false};
  std::array<std::exception_ptr, 2U> failures{};
  std::jthread blocked([&] {
    try {
      RuntimeLogSink sink({2U, 128U, 1U});
      ScriptedSender sender({}, Result::would_block);
      enqueue(sink, Severity::warning, "blocked-a");
      enqueue(sink, Severity::warning, "blocked-b");
      drain(sink, sender);
      blocked_ready.store(true, std::memory_order_release);
      wait_for_flag(healthy_finished);
      require(sink.stats().records_sent == 0U && sink.stats().queue_depth == 2U &&
                  sink.stats().send_attempts == 1U,
              "another owner's work mutated a blocked sink");
      sink.stop(&ScriptedSender::send, &sender);
      check_accounting(sink);
      require(sink.stats().shutdown_drops == 2U && sink.stats().would_block_events == 2U,
              "blocked owner did not account for its own shutdown independently");
    } catch (...) {
      failures[0U] = std::current_exception();
      blocked_ready.store(true, std::memory_order_release);
    }
  });
  std::jthread healthy([&] {
    try {
      wait_for_flag(blocked_ready);
      PrivateSocket socket;
      socket.bind_receiver();
      UnixRuntimeLogTransport transport(socket.path());
      RuntimeLogSink sink({1U, 128U, 1U});
      for (unsigned i = 0U; i < 16U; ++i) {
        const auto body = "healthy-" + std::to_string(i);
        enqueue(sink, Severity::debug, body);
        sink.drain(&UnixRuntimeLogTransport::send, &transport);
        check_accounting(sink);
        require(socket.receive() == frame(15U, body),
                "healthy owner did not deliver while a different sink was blocked");
      }
      require(sink.stats().records_sent == 16U && sink.stats().records_dropped == 0U &&
                  sink.stats().would_block_events == 0U && sink.stats().queue_high_water == 1U,
              "owner-thread counters or transport state leaked between sinks");
      sink.stop(&UnixRuntimeLogTransport::send, &transport);
      check_accounting(sink);
      socket.require_empty();
    } catch (...) {
      failures[1U] = std::current_exception();
    }
    healthy_finished.store(true, std::memory_order_release);
  });
  blocked.join();
  healthy.join();
  for (const auto& failure : failures) {
    if (failure != nullptr) {
      std::rethrow_exception(failure);
    }
  }
}

struct TestGroup final {
  const char* name;
  void (*run)();
};

constexpr std::array<TestGroup, 15U> groups{{
    {"options_before_allocation", &test_options_before_allocation},
    {"typed_priorities_and_escaping", &test_typed_priorities_and_escaping},
    {"copied_message_lifetime", &test_copied_message_lifetime},
    {"whole_record_size_limits", &test_whole_record_size_limits},
    {"bounded_fifo_wraparound", &test_bounded_fifo_wraparound},
    {"scripted_send_results", &test_scripted_send_results},
    {"finite_drain_batches", &test_finite_drain_batches},
    {"stop_and_accounting", &test_stop_and_accounting},
    {"unix_path_and_record_validation", &test_unix_path_and_record_validation},
    {"unix_receiver_recovery_and_fd_lifecycle", &test_unix_receiver_recovery_and_fd_lifecycle},
    {"unix_backpressure_lossless_recovery", &test_unix_backpressure_lossless_recovery},
    {"independent_owner_threads", &test_independent_owner_threads},
    {"callback_reentry", &test_callback_reentry},
    {"errno_preservation", &test_errno_preservation},
    {"pipe_transport", &test_pipe_transport},
}};

void timeout_failure(int) {
  constexpr char message[] = "FAIL runtime_log_test: 60-second watchdog expired\n";
  const auto ignored = ::write(STDERR_FILENO, message, sizeof(message) - 1U);
  (void)ignored;
  ::_exit(124);
}

void print_summary(const char* status, std::size_t completed) {
  std::cout << "{\"status\":\"" << status << "\",\"groups\":[";
  for (std::size_t i = 0U; i < completed; ++i) {
    if (i != 0U) {
      std::cout << ',';
    }
    std::cout << '"' << groups[i].name << '"';
  }
  std::cout << "],\"assertions\":" << assertions.load(std::memory_order_relaxed) << "}\n";
}

}  // namespace

int main() {
  std::size_t completed = 0U;
  try {
    require(std::signal(SIGALRM, &timeout_failure) != SIG_ERR, "could not install finite test watchdog");
    ::alarm(60U);
    for (const auto& group : groups) {
      const auto before = assertions.load(std::memory_order_relaxed);
      group.run();
      const auto count = assertions.load(std::memory_order_relaxed) - before;
      require(count > 0U, "test group executed no assertions");
      ++completed;
      std::cout << "PASS " << group.name << " assertions=" << count << std::endl;
    }
    ::alarm(0U);
    print_summary("passed", completed);
    return 0;
  } catch (const std::exception& error) {
    ::alarm(0U);
    std::cerr << "FAIL " << (completed < groups.size() ? groups[completed].name : "runner")
              << ": " << error.what() << '\n';
  } catch (...) {
    ::alarm(0U);
    std::cerr << "FAIL runtime_log_test: unknown exception\n";
  }
  print_summary("failed", completed);
  return 1;
}
