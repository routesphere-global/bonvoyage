#include "bonvoyage/runtime/runtime_log_binding.hh"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <initializer_list>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <streambuf>
#include <string>
#include <string_view>
#include <thread>

#include <linux/magic.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/vfs.h>
#include <unistd.h>

namespace {
std::atomic<std::uint64_t> assertions{0U};
std::atomic<std::uint64_t> syslog_calls{0U};
std::atomic<std::uint64_t> rejected_sink_calls{0U};
}

// Interpose both libc entry points, including fortified Seastar builds. Never
// forward: even a regressed logger must not contact the host's /dev/log.
extern "C" void syslog(int, const char*, ...) {
  syslog_calls.fetch_add(1U, std::memory_order_relaxed);
}
extern "C" void __syslog_chk(int, int, const char*, ...) {
  syslog_calls.fetch_add(1U, std::memory_order_relaxed);
}

struct FormatProbe final {
  unsigned& calls;
  seastar::logger* recursive{};
  bool fail{};
  std::size_t padding{};
};

template <>
struct fmt::formatter<FormatProbe> {
  constexpr auto parse(fmt::format_parse_context& context) { return context.begin(); }
  template <typename Context>
  auto format(const FormatProbe& probe, Context& context) const -> decltype(context.out()) {
    ++probe.calls;
    errno = EILSEQ;
    auto out = context.out();
    for (std::size_t i = 0U; i < probe.padding; ++i) { *out++ = 'P'; }
    if (probe.fail) { out = fmt::format_to(out, "partial-must-not-arrive"); }
    if (probe.recursive != nullptr) {
      probe.recursive->error("nested-must-not-arrive");
    }
    if (probe.fail) {
      throw std::runtime_error("intentional formatter failure");
    }
    return fmt::format_to(out, "custom-ok");
  }
};

namespace {
using namespace bonvoyage::runtime;
using Level = seastar::log_level;
using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;
constexpr std::string_view logger_context = " binding-test - ";

// Deliberately not assert(): checks and their operands remain active in NDEBUG.
void require(bool condition, const char* message) {
  assertions.fetch_add(1U, std::memory_order_relaxed);
  if (!condition) {
    throw std::runtime_error(message);
  }
}

template <typename Function>
void require_logic_error(Function function) {
  bool rejected = false;
  try { function(); } catch (const std::logic_error&) { rejected = true; }
  require(rejected, "invalid binding construction was not rejected");
}

template <typename Function>
void require_errno(Function function) {
  errno = EDOM;
  function();
  const int after = errno;
  require(after == EDOM, "logger/transport changed ambient errno");
}

struct CountingBuffer final : std::streambuf {
  std::atomic<std::uint64_t> writes{0U}, bytes{0U}, flushes{0U};
  std::streamsize xsputn(const char*, std::streamsize count) override {
    writes.fetch_add(1U, std::memory_order_relaxed);
    if (count > 0) { bytes.fetch_add(static_cast<std::uint64_t>(count), std::memory_order_relaxed); }
    return count;
  }
  int_type overflow(int_type character) override {
    writes.fetch_add(1U, std::memory_order_relaxed);
    if (!traits_type::eq_int_type(character, traits_type::eof())) {
      bytes.fetch_add(1U, std::memory_order_relaxed);
    }
    return traits_type::not_eof(character);
  }
  int sync() override { flushes.fetch_add(1U, std::memory_order_relaxed); return 0; }
};

CountingBuffer legacy_buffer;
std::array<std::uint64_t, 4U> legacy_baseline{};

auto legacy_counts() {
  return std::array<std::uint64_t, 4U>{syslog_calls.load(), legacy_buffer.writes.load(),
                                    legacy_buffer.bytes.load(), legacy_buffer.flushes.load()};
}

void legacy_flags(bool stream, bool syslog) {
  seastar::logger::set_ostream_enabled(stream);
  seastar::logger::set_syslog_enabled(syslog);
}

struct LegacyGuard final {
  std::ostream stream{&legacy_buffer};
  LegacyGuard() { seastar::logger::set_ostream(stream); }
  ~LegacyGuard() { legacy_flags(false, false); seastar::logger::set_ostream(std::cerr); }
};

void check_binding(const RuntimeLogBinding& binding, std::uint64_t received,
                   std::uint64_t overflow = 0U, std::uint64_t errors = 0U) {
  const auto& stats = binding.stats();
  require(stats.received == received, "owner callback count differs");
  require(stats.format_overflow_drops == overflow, "owner format overflow count differs");
  require(stats.format_error_drops == errors, "owner formatter error count differs");
  require(stats.invalid_severity_drops == 0U, "valid logger severity was rejected");
}

void check_accounting(const RuntimeLogSink& sink) {
  const auto& s = sink.stats();
  require(s.records_attempted == s.records_sent + s.records_dropped + s.queue_depth,
          "attempted != sent + dropped + depth");
  require(s.records_dropped == s.queue_overflows + s.oversized_records + s.invalid_severities +
              s.send_failure_drops + s.shutdown_drops + s.stopped_drops,
          "record loss reasons do not partition drops");
  require(s.records_enqueued == s.records_sent + s.queue_depth + s.send_failure_drops + s.shutdown_drops,
          "enqueued records were lost or duplicated");
  require(s.send_attempts == s.records_sent + s.send_failure_drops + s.would_block_events + s.unavailable_events,
          "transport outcomes do not partition attempts");
  require(s.queue_depth <= s.queue_high_water && s.queue_high_water <= s.queue_capacity,
          "queue escaped its fixed capacity");
}

class PrivateSocket final {
 public:
  PrivateSocket() {
    char pattern[] = "/dev/shm/bv-binding-XXXXXX";
    char* created = ::mkdtemp(pattern);
    require(created != nullptr, "cannot create private tmpfs socket directory");
    try {
      directory_ = created;
      path_ = directory_ + "/log";
      struct statfs filesystem {};
      struct stat directory {};
      require(::statfs(created, &filesystem) == 0 && filesystem.f_type == TMPFS_MAGIC,
              "private socket directory must be on tmpfs");
      require(::stat(created, &directory) == 0 && (directory.st_mode & 0777U) == 0700U,
              "socket namespace is not private");
    } catch (...) { (void)::rmdir(created); throw; }
  }
  ~PrivateSocket() {
    const int saved = errno;
    close_receiver();
    (void)::unlink(path_.c_str());
    (void)::rmdir(directory_.c_str());
    errno = saved;
  }
  PrivateSocket(const PrivateSocket&) = delete;
  PrivateSocket& operator=(const PrivateSocket&) = delete;
  const std::string& path() const noexcept { return path_; }
  void bind_receiver() {
    require(fd_ == -1, "receiver was already bound");
    fd_ = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    require(fd_ >= 0, "cannot create private nonblocking receiver");
    const int receive_bytes = 2048;
    require(::setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &receive_bytes, sizeof(receive_bytes)) == 0,
            "cannot bound receiver buffer");
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    require(path_.size() < sizeof(address.sun_path), "private socket pathname too long");
    std::memcpy(address.sun_path, path_.c_str(), path_.size() + 1U);
    const auto size = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + path_.size() + 1U);
    require(::bind(fd_, reinterpret_cast<const sockaddr*>(&address), size) == 0, "receiver bind failed");
  }
  void close_receiver() noexcept { if (fd_ >= 0) { (void)::close(fd_); fd_ = -1; } }
  void unlink_receiver() { require(::unlink(path_.c_str()) == 0, "private socket unlink failed"); }
  std::string receive() {
    std::array<char, 2048U> bytes{};
    const auto size = ::recv(fd_, bytes.data(), bytes.size(), MSG_DONTWAIT | MSG_TRUNC);
    require(size >= 0, "expected datagram missing from private receiver");
    require(static_cast<std::size_t>(size) <= bytes.size(), "datagram exceeded complete-record bound");
    return {bytes.data(), static_cast<std::size_t>(size)};
  }
  void require_empty() {
    char byte{};
    const auto result = ::recv(fd_, &byte, 1U, MSG_DONTWAIT | MSG_TRUNC);
    const int error = errno;
    require(result == -1 && (error == EAGAIN || error == EWOULDBLOCK), "unexpected extra datagram");
  }
 private:
  std::string directory_, path_;
  int fd_{-1};
};

std::string frame(unsigned priority, std::string_view body) {
  return "<" + std::to_string(priority) + ">bonvoyage[" + std::to_string(::getpid()) + "]: " +
         std::string(logger_context) + std::string(body);
}

struct Fixture final {
  PrivateSocket socket;
  RuntimeLogSink sink;
  UnixRuntimeLogTransport transport;
  explicit Fixture(RuntimeLogOptions options = {8U, 2048U, 1U}, bool bind = true)
      : sink(options), transport(socket.path()) { if (bind) { socket.bind_receiver(); } }
  ~Fixture() { sink.stop(nullptr, nullptr); }
  void drain() { sink.drain(&UnixRuntimeLogTransport::send, &transport); check_accounting(sink); }
  void expect(unsigned priority, std::string_view body) {
    drain();
    require(socket.receive() == frame(priority, body), "complete datagram/context/priority differs");
    socket.require_empty();
  }
};

void rejected_consume(void*, Level, std::string_view, seastar::log_record_status) noexcept {
  rejected_sink_calls.fetch_add(1U, std::memory_order_relaxed);
}

void test_install_validation(seastar::logger& log) {
  static const seastar::custom_log_sink missing{nullptr, nullptr, 1U};
  static const seastar::custom_log_sink zero{&rejected_consume, nullptr, 0U};
  static const seastar::custom_log_sink huge{&rejected_consume, nullptr, 8193U};
  static const seastar::custom_log_sink different{&rejected_consume, nullptr, kRuntimeLogFormatLimit};
  require(!seastar::logger::install_custom_sink(nullptr), "null sink accepted before install");
  require(!seastar::logger::install_custom_sink(&missing), "missing callback accepted before install");
  require(!seastar::logger::install_custom_sink(&zero), "zero-sized sink accepted before install");
  require(!seastar::logger::install_custom_sink(&huge), "sink larger than 8192 accepted before install");
  const auto initial = legacy_counts();
  legacy_flags(false, true);
  log.info("syslog-positive-control");
  const auto syslog_control = legacy_counts();
  require(syslog_control[0U] == initial[0U] + 1U && syslog_control[1U] == initial[1U],
          "C syslog interposition failed its real-logger positive control");
  legacy_flags(true, false);
  log.info("ostream-positive-control");
  legacy_baseline = legacy_counts();
  require(legacy_baseline[0U] == syslog_control[0U] && legacy_baseline[1U] > syslog_control[1U] &&
              legacy_baseline[2U] > syslog_control[2U] && legacy_baseline[3U] > syslog_control[3U],
          "bounded counting stream failed its real-logger positive control");
  require(rejected_sink_calls.load() == 0U, "invalid configuration consumed a record");
  require(install_runtime_log_dispatcher(), "real dispatcher installation failed");
  require(install_runtime_log_dispatcher(), "same static dispatcher install is not idempotent");
  require(!seastar::logger::install_custom_sink(&different), "different static sink replaced dispatcher");
  require(!seastar::logger::install_custom_sink(nullptr), "null reset accepted after installation");
  legacy_flags(false, false);
  const auto before = runtime_log_unbound_drops();
  log.info("installed-without-owner");
  require(runtime_log_unbound_drops() == before + 1U, "installed dispatcher did not own disabled-sink logs");
}

void test_log_buf_bounds(seastar::logger&) {
  // Tests buffer storage, not arbitrary custom-formatter CPU or allocations.
  for (const std::size_t capacity : std::array<std::size_t, 5U>{0U, 1U, 8U, 1792U, 8192U}) {
    std::array<char, 8194U> storage{};
    storage.fill('!');
    seastar::internal::log_buf buffer(storage.data() + 1U, capacity, true);
    auto out = buffer.back_insert_begin();
    for (std::size_t i = 0U; i < capacity; ++i) { *out++ = 'x'; }
    require(!buffer.overflowed() && buffer.size() == capacity, "exact bounded capacity overflowed");
    for (unsigned i = 0U; i < 128U; ++i) { *out++ = 'z'; }
    require(buffer.overflowed() && buffer.size() == capacity && buffer.capacity() == capacity,
            "bounded log_buf grew or did not mark overflow");
    require(buffer.data() == storage.data() + 1U && buffer.view() == std::string(capacity, 'x') &&
                storage[0U] == '!' && storage[capacity + 1U] == '!', "bounded buffer escaped storage");
    buffer.clear();
    require(buffer.size() == 0U && !buffer.overflowed() && buffer.capacity() == capacity,
            "clear did not reset bounded size/status while preserving capacity");
    if (capacity != 0U) {
      *buffer.back_insert_begin() = 'r';
      require(buffer.view() == "r" && !buffer.overflowed(), "bounded buffer did not recover after clear");
    }
  }
  std::array<char, 2U> initial{};
  seastar::internal::log_buf legacy(initial.data(), initial.size());
  const std::string larger(128U, 'l');
  std::copy(larger.begin(), larger.end(), legacy.back_insert_begin());
  require(legacy.view() == larger && legacy.capacity() >= larger.size() && !legacy.overflowed() &&
              legacy.data() != initial.data(), "legacy external buffer no longer grows");
  const auto capacity = legacy.capacity();
  legacy.clear();
  require(legacy.size() == 0U && legacy.capacity() == capacity && !legacy.overflowed(), "legacy clear changed capacity");
}

void test_severity_mapping(seastar::logger& log) {
  Fixture f;
  RuntimeLogBinding binding(f.sink);
  constexpr std::array<Level, 5U> levels{Level::error, Level::warn, Level::info, Level::debug, Level::trace};
  constexpr std::array<unsigned, 5U> priorities{11U, 12U, 14U, 15U, 15U};
  require(static_cast<int>(Level::error) == 0, "test requires Seastar error ordinal zero");
  for (std::size_t i = 0U; i < levels.size(); ++i) { log.log(levels[i], "level-{}", i); }
  check_binding(binding, 5U);
  require(f.sink.stats().records_attempted == 5U && f.sink.stats().queue_depth == 5U, "severity records missing");
  for (std::size_t i = 0U; i < levels.size(); ++i) { f.expect(priorities[i], "level-" + std::to_string(i)); }
}

void test_filtering(seastar::logger& log) {
  Fixture f;
  RuntimeLogBinding binding(f.sink);
  unsigned calls = 0U;
  log.set_level(Level::warn);
  log.info("{}", FormatProbe{calls, nullptr, true});
  log.debug("{}", FormatProbe{calls, nullptr, true});
  log.trace("{}", FormatProbe{calls, nullptr, true});
  check_binding(binding, 0U);
  require(calls == 0U && f.sink.stats().records_attempted == 0U, "filtered record reached formatter or sink");
  log.error("error-visible");
  log.warn("warn-visible");
  check_binding(binding, 2U);
  f.expect(11U, "error-visible");
  f.expect(12U, "warn-visible");
  log.set_level(Level::trace);
  log.trace("{}", FormatProbe{calls});
  require(calls == 1U, "enabled formatter positive control did not execute");
  check_binding(binding, 3U);
  f.expect(15U, "custom-ok");
  seastar::logger::rate_limit limit(std::chrono::minutes(1));
  log.log(Level::info, limit, "{}", FormatProbe{calls});
  log.log(Level::info, limit, "{}", FormatProbe{calls, nullptr, true});
  require(calls == 2U, "rate-limited record reached the formatter");
  check_binding(binding, 4U);
  require(f.sink.stats().records_attempted == 4U, "rate-limited record reached the queue");
  f.expect(14U, "custom-ok");
}

void test_borrowed_lifetime(seastar::logger& log) {
  Fixture f;
  RuntimeLogBinding binding(f.sink);
  {
    std::string borrowed(256U, 'a');
    log.info("{}", std::string_view(borrowed));
    std::fill(borrowed.begin(), borrowed.end(), 'z');
    log.info("overwrite-thread-local-formatter-buffer");
  }
  log.info("{}", std::string("temporary-destroyed-before-drain"));
  log.info("last-buffer-reuse");
  check_binding(binding, 4U);
  require(f.transport.native_handle() == -1 && f.sink.stats().send_attempts == 0U, "callback performed transport I/O");
  f.socket.require_empty();
  f.expect(14U, std::string(256U, 'a'));
  f.expect(14U, "overwrite-thread-local-formatter-buffer");
  f.expect(14U, "temporary-destroyed-before-drain");
  f.expect(14U, "last-buffer-reuse");
}

void test_whole_record_overflow(seastar::logger& log) {
  {
    Fixture f;
    RuntimeLogBinding binding(f.sink);
    require(kRuntimeLogFormatLimit > logger_context.size() + 2U, "format budget cannot hold context");
    std::string exact(kRuntimeLogFormatLimit - logger_context.size() - 2U, 'x');
    exact += "\xc3\xa9";
    log.info("{}", exact);
    log.info("{}", exact + "x");
    log.info("{}", std::string(kRuntimeLogFormatLimit * 3U, 'L'));
    check_binding(binding, 3U, 2U);
    unsigned calls = 0U;
    require_errno([&] { log.info("{}", FormatProbe{calls, nullptr, true, kRuntimeLogFormatLimit * 2U}); });
    check_binding(binding, 4U, 2U, 1U);
    require(calls == 1U, "overflow-then-exception formatter was retried");
    log.info("{}", std::string(600U, '\n'));
    check_binding(binding, 5U, 2U, 1U);
    require(f.sink.stats().records_attempted == 2U && f.sink.stats().oversized_records == 1U,
            "escaping-only overflow was not classified exclusively by the sink");
    log.info("after-overflow");
    check_binding(binding, 6U, 2U, 1U);
    require(f.sink.stats().records_attempted == 3U && f.sink.stats().oversized_records == 1U &&
                f.sink.stats().queue_depth == 2U, "format/escaped-frame overflow did not drop whole records");
    f.expect(14U, exact);
    f.expect(14U, "after-overflow");
  }
  Fixture f({4U, 128U, 1U});
  RuntimeLogBinding binding(f.sink);
  require(frame(14U, "").size() < 128U, "framing exhausted small-record test budget");
  const std::string exact(128U - frame(14U, "").size(), 'b');
  log.info("{}", exact);
  log.info("{}", exact + "b");
  check_binding(binding, 2U);
  require(f.sink.stats().oversized_records == 1U && f.sink.stats().queue_depth == 1U,
          "syslog framing was not included in complete-record byte limit");
  f.expect(14U, exact);
}

void test_escaping(seastar::logger& log) {
  Fixture f;
  RuntimeLogBinding binding(f.sink);
  std::string body = "controls:";
  for (const char byte : std::array<char, 7U>{'\0', '\n', '\r', '\t', '\x1b', '\x7f', '\\'}) { body += byte; }
  body += "%\xc3\xa9";
  log.info("{}", body);
  log.info("{}", "\\x0a");
  check_binding(binding, 2U);
  f.expect(14U, "controls:\\x00\\x0a\\x0d\\x09\\x1b\\x7f\\x5c%\xc3\xa9");
  f.expect(14U, "\\x5cx0a");
}

void test_formatter_errors_and_recursion(seastar::logger& log) {
  for (const bool enabled : {false, true}) {
    legacy_flags(enabled, enabled);
    Fixture f;
    RuntimeLogBinding binding(f.sink);
    unsigned calls = 0U;
    const auto unbound = runtime_log_unbound_drops();
    require_errno([&] { log.info("{}", FormatProbe{calls, nullptr, true}); });
    check_binding(binding, 1U, 0U, 1U);
    require(f.sink.stats().records_attempted == 0U, "throwing formatter emitted partial/fallback record");
    require_errno([&] { log.info("{}", FormatProbe{calls, &log, false}); });
    check_binding(binding, 2U, 0U, 1U);
    require_errno([&] { log.info("{}", FormatProbe{calls, &log, true}); });
    check_binding(binding, 3U, 0U, 2U);
    log.info("after-formatter");
    check_binding(binding, 4U, 0U, 2U);
    require(calls == 3U && f.sink.stats().records_attempted == 2U && log.is_enabled(Level::info),
            "formatter retried, recursion dispatched, or silencer failed to reset");
    require(runtime_log_unbound_drops() == unbound, "recursive formatting escaped owner binding");
    f.expect(14U, "custom-ok");
    f.expect(14U, "after-formatter");
    require(legacy_counts() == legacy_baseline, "formatter failure fell back to a legacy sink");
  }
}

void test_binding_lifecycle(seastar::logger& log) {
  Fixture first, replacement;
  const auto unbound = runtime_log_unbound_drops();
  std::optional<RuntimeLogBinding> stale;
  stale.emplace(first.sink);
  bool wrong_thread_result = true;
  std::exception_ptr foreign_failure;
  std::jthread foreign([&] {
    try {
      Fixture own;
      RuntimeLogBinding binding(own.sink);
      wrong_thread_result = stale->detach();
      log.info("foreign-owner-survives-rejection");
      check_binding(binding, 1U);
      own.expect(14U, "foreign-owner-survives-rejection");
    } catch (...) { foreign_failure = std::current_exception(); }
  });
  foreign.join();
  if (foreign_failure != nullptr) { std::rethrow_exception(foreign_failure); }
  require(!wrong_thread_result, "foreign-thread explicit detach was not rejected");
  log.info("owner-survives-foreign-detach");
  check_binding(*stale, 1U);
  require_logic_error([&] { RuntimeLogBinding nested(first.sink); });
  require_logic_error([&] { RuntimeLogBinding nested(replacement.sink); });
  log.info("owner-survives-nested-rejection");
  check_binding(*stale, 2U);
  require(stale->detach() && stale->detach(), "owner-thread detach is not idempotent");
  log.info("detached-unbound");
  {
    RuntimeLogBinding current(replacement.sink);
    require(stale->detach(), "stale owner-thread detach should succeed as a no-op");
    log.info("replacement-survives-stale-detach");
    stale.reset();
    log.info("replacement-survives-stale-destruction");
    check_binding(current, 2U);
  }
  log.info("destructor-unbound");
  struct Unwind final {};
  try {
    RuntimeLogBinding reattached(first.sink);
    check_binding(reattached, 0U);
    log.info("reattached-before-unwind");
    check_binding(reattached, 1U);
    throw Unwind{};
  } catch (const Unwind&) {}
  log.info("unwound-unbound");
  require(runtime_log_unbound_drops() == unbound + 3U, "RAII/detach/unwind left an owner attached");
  require(first.sink.stats().active == 1U && first.sink.stats().queue_depth == 3U &&
              replacement.sink.stats().active == 1U && replacement.sink.stats().queue_depth == 2U &&
              first.sink.stats().send_attempts == 0U && replacement.sink.stats().send_attempts == 0U,
          "binding detach/destruction stopped or flushed an external sink");
  first.expect(14U, "owner-survives-foreign-detach");
  first.expect(14U, "owner-survives-nested-rejection");
  first.expect(14U, "reattached-before-unwind");
  replacement.expect(14U, "replacement-survives-stale-detach");
  replacement.expect(14U, "replacement-survives-stale-destruction");
  first.sink.stop(nullptr, nullptr);
  require_logic_error([&] { RuntimeLogBinding stopped(first.sink); });
  RuntimeLogBinding after_rejection(replacement.sink);
  log.info("active-after-stopped-rejection");
  check_binding(after_rejection, 1U);
  replacement.expect(14U, "active-after-stopped-rejection");
  check_accounting(first.sink);
}

void test_errno_preservation(seastar::logger& log) {
  Fixture f({1U, 2048U, 1U});
  RuntimeLogBinding binding(f.sink);
  unsigned calls = 0U;
  const std::string huge(kRuntimeLogFormatLimit + 1U, 'x');
  const std::string escaping(600U, '\n');
  require_errno([&] { log.info("{}", FormatProbe{calls}); });
  require_errno([&] { log.info("queue-overflow"); });
  require_errno([&] { log.info("{}", FormatProbe{calls, nullptr, true}); });
  require_errno([&] { log.info("{}", huge); });
  log.set_level(Level::error);
  require_errno([&] { log.info("{}", FormatProbe{calls, nullptr, true}); });
  log.set_level(Level::trace);
  require(calls == 2U && f.sink.stats().queue_overflows == 1U, "errno scenario did not cover intended paths");
  require_errno([&] { f.sink.drain(&UnixRuntimeLogTransport::send, &f.transport); });
  require(f.socket.receive() == frame(14U, "custom-ok"), "errno success record changed");
  require_errno([&] { log.info("{}", escaping); });
  f.socket.close_receiver();
  f.socket.unlink_receiver();
  require_errno([&] { log.info("errno-absent"); });
  require_errno([&] { f.sink.drain(&UnixRuntimeLogTransport::send, &f.transport); });
  require(f.transport.last_error() == ENOENT && f.sink.stats().queue_depth == 1U, "missing-receiver errno lost");
  f.socket.bind_receiver();
  f.expect(14U, "errno-absent");
  check_binding(binding, 6U, 1U, 1U);
  require(f.sink.stats().oversized_records == 1U, "errno scenario missed escaped overflow");
  require_errno([&] { (void)binding.detach(); });
  const auto unbound = runtime_log_unbound_drops();
  require_errno([&] { log.info("{}", FormatProbe{calls, &log, true}); });
  require(runtime_log_unbound_drops() == unbound + 1U, "errno unbound failure was not counted");
}

void test_unbound_dispatch(seastar::logger& log) {
  const auto unbound = runtime_log_unbound_drops();
  {
    Fixture f;
    log.info("before-attach");
    {
      RuntimeLogBinding binding(f.sink);
      log.info("owner-only");
      std::jthread foreign([&] { log.error("foreign-error"); log.trace("foreign-trace"); });
      foreign.join();
      check_binding(binding, 1U);
      require(f.sink.stats().records_attempted == 1U, "foreign thread reached another owner's queue");
      f.expect(14U, "owner-only");
    }
    log.info("after-attach");
    f.socket.require_empty();
  }
  log.info("after-sink-destruction");
  require(runtime_log_unbound_drops() == unbound + 5U, "before/after/foreign/destroyed-sink unbound drops differ");
}

std::size_t fill_receiver(PrivateSocket& socket) {
  UnixRuntimeLogTransport filler(socket.path());
  const auto deadline = Clock::now() + 1s;
  std::size_t accepted = 0U;
  auto result = RuntimeLogSendResult::sent;
  while (accepted < 65536U && Clock::now() < deadline) {
    result = filler.try_send("prefill");
    if (result != RuntimeLogSendResult::sent) { break; }
    ++accepted;
  }
  require(accepted > 0U && result == RuntimeLogSendResult::would_block &&
              (filler.last_error() == EAGAIN || filler.last_error() == EWOULDBLOCK),
          "private receiver did not reach EAGAIN within finite prefill bound");
  return accepted;
}

void wait_for(const std::atomic<bool>& flag) {
  const auto deadline = Clock::now() + 2s;
  while (!flag.load(std::memory_order_acquire) && Clock::now() < deadline) { std::this_thread::yield(); }
  require(flag.load(std::memory_order_acquire), "parallel owner handshake timed out");
}

void test_parallel_owners(seastar::logger& log) {
  std::atomic<bool> blocked_ready{false}, healthy_done{false};
  std::array<std::exception_ptr, 2U> failures{};
  const auto unbound = runtime_log_unbound_drops();
  std::jthread blocked([&] {
    try {
      Fixture f({2U, 2048U, 1U});
      const auto prefilled = fill_receiver(f.socket);
      RuntimeLogBinding binding(f.sink);
      unsigned calls = 0U;
      log.info("blocked-a"); log.info("blocked-b");
      log.info("{}", FormatProbe{calls, nullptr, true});
      f.drain();
      require(f.sink.stats().would_block_events == 1U, "blocked owner did not encounter real socket pressure");
      blocked_ready.store(true, std::memory_order_release);
      wait_for(healthy_done);
      check_binding(binding, 3U, 0U, 1U);
      require(f.sink.stats().queue_depth == 2U && f.sink.stats().send_attempts == 1U && calls == 1U,
              "healthy owner mutated blocked owner's records/errors/transport");
      for (std::size_t i = 0U; i < prefilled; ++i) { require(f.socket.receive() == "prefill", "prefill changed"); }
      f.expect(14U, "blocked-a"); f.expect(14U, "blocked-b");
    } catch (...) { failures[0U] = std::current_exception(); blocked_ready.store(true, std::memory_order_release); }
  });
  std::jthread healthy([&] {
    try {
      wait_for(blocked_ready);
      Fixture f({1U, 2048U, 1U});
      RuntimeLogBinding binding(f.sink);
      for (unsigned i = 0U; i < 16U; ++i) {
        log.info("healthy-{}", i);
        f.expect(14U, "healthy-" + std::to_string(i));
      }
      check_binding(binding, 16U);
      require(f.sink.stats().records_sent == 16U && f.sink.stats().records_dropped == 0U &&
                  f.sink.stats().would_block_events == 0U, "healthy owner inherited blocked state");
    } catch (...) { failures[1U] = std::current_exception(); }
    healthy_done.store(true, std::memory_order_release);
  });
  blocked.join(); healthy.join();
  for (const auto& failure : failures) { if (failure != nullptr) { std::rethrow_exception(failure); } }
  require(runtime_log_unbound_drops() == unbound, "parallel owners lost their thread-local bindings");
}

void test_pressure_and_recovery(seastar::logger& log) {
  Fixture f({4U, 2048U, 1U}, false);
  RuntimeLogBinding binding(f.sink);
  log.info("absent");
  f.drain();
  require(f.transport.last_error() == ENOENT && f.sink.stats().queue_depth == 1U, "absence did not retain head");
  const int sender = f.transport.native_handle();
  f.socket.bind_receiver();
  f.expect(14U, "absent");
  f.socket.close_receiver();
  log.info("replacement");
  f.drain();
  require(f.transport.last_error() == ECONNREFUSED, "stale receiver path did not report unavailable");
  f.socket.unlink_receiver();
  f.drain();
  require(f.transport.last_error() == ENOENT, "unlinked receiver path did not report unavailable");
  f.socket.bind_receiver();
  f.expect(14U, "replacement");
  const auto prefilled = fill_receiver(f.socket);
  for (unsigned i = 0U; i < 4U; ++i) { log.info("pressure-{}", i); }
  log.info("drop-newest-must-not-arrive");
  require(f.sink.stats().queue_depth == 4U && f.sink.stats().queue_overflows == 1U, "pressure queue was not bounded");
  for (std::uint64_t i = 1U; i <= 3U; ++i) {
    const auto before = f.sink.stats().send_attempts;
    const auto start = Clock::now();
    require_errno([&] { f.sink.drain(&UnixRuntimeLogTransport::send, &f.transport); });
    require(Clock::now() - start < 1s, "backpressured drain blocked");
    require(f.sink.stats().send_attempts == before + 1U && f.sink.stats().queue_depth == 4U &&
                f.sink.stats().would_block_events == i, "backpressure retried or discarded queued records");
    check_accounting(f.sink);
  }
  for (std::size_t i = 0U; i < prefilled; ++i) { require(f.socket.receive() == "prefill", "prefill FIFO changed"); }
  for (unsigned i = 0U; i < 4U; ++i) { f.expect(14U, "pressure-" + std::to_string(i)); }
  log.info("after-pressure");
  f.expect(14U, "after-pressure");
  check_binding(binding, 8U);
  require(f.sink.stats().records_sent == 7U && f.sink.stats().records_dropped == 1U &&
              f.sink.stats().unavailable_events == 3U && f.sink.stats().send_attempts == 13U &&
              f.sink.stats().queue_high_water == 4U && f.sink.stats().sink_healthy == 1U &&
              f.transport.last_error() == 0 && f.transport.native_handle() == sender,
          "receiver replacement/pressure recovery lost records or required sender recreation");
}

void test_legacy_sink_isolation(seastar::logger& log) {
  for (const bool stream : {false, true}) {
    for (const bool syslog : {false, true}) {
      legacy_flags(stream, syslog);
      Fixture f;
      const auto unbound = runtime_log_unbound_drops();
      {
        RuntimeLogBinding binding(f.sink);
        unsigned calls = 0U;
        log.info("custom-exclusive");
        log.error("{}", FormatProbe{calls, &log, true});
        check_binding(binding, 2U, 0U, 1U);
        require(calls == 1U && f.sink.stats().records_attempted == 1U, "legacy flags changed custom dispatch");
        f.expect(14U, "custom-exclusive");
      }
      log.info("custom-unbound-exclusive");
      require(runtime_log_unbound_drops() == unbound + 1U, "legacy flags intercepted unbound dispatch");
      require(legacy_counts() == legacy_baseline, "legacy sink received post-install output/flush");
    }
  }
}

struct TestGroup final { const char* name; void (*run)(seastar::logger&); };
constexpr std::array<TestGroup, 14U> groups{{
    {"install_validation", &test_install_validation},
    {"log_buf_bounds", &test_log_buf_bounds},
    {"severity_mapping", &test_severity_mapping},
    {"filtering", &test_filtering},
    {"borrowed_lifetime", &test_borrowed_lifetime},
    {"whole_record_overflow", &test_whole_record_overflow},
    {"escaping", &test_escaping},
    {"formatter_errors_and_recursion", &test_formatter_errors_and_recursion},
    {"binding_lifecycle", &test_binding_lifecycle},
    {"errno_preservation", &test_errno_preservation},
    {"unbound_dispatch", &test_unbound_dispatch},
    {"parallel_owners", &test_parallel_owners},
    {"pressure_and_recovery", &test_pressure_and_recovery},
    {"legacy_sink_isolation", &test_legacy_sink_isolation},
}};

void watchdog(int) {
  constexpr char message[] = "FAIL runtime_log_binding_test: 18-second watchdog expired\n";
  const auto written = ::write(STDERR_FILENO, message, sizeof(message) - 1U);
  (void)written;
  ::_exit(124);
}

void summary(const char* status, std::size_t completed) {
  std::cout << "{\"status\":\"" << status << "\",\"groups\":[";
  for (std::size_t i = 0U; i < completed; ++i) {
    if (i != 0U) { std::cout << ','; }
    std::cout << '"' << groups[i].name << '"';
  }
  std::cout << "],\"assertions\":" << assertions.load(std::memory_order_relaxed) << "}\n";
}
}  // namespace

int main() {
  std::size_t completed = 0U;
  try {
    require(std::signal(SIGALRM, &watchdog) != SIG_ERR, "cannot install finite test watchdog");
    (void)::alarm(18U);
    LegacyGuard legacy;
    seastar::logger log("binding-test");
    for (const auto& group : groups) {
      log.set_level(Level::trace);
      const auto before = assertions.load(std::memory_order_relaxed);
      group.run(log);
      require(assertions.load(std::memory_order_relaxed) > before, "group executed no assertions");
      require(legacy_counts() == legacy_baseline, "post-install legacy dispatch detected");
      require(rejected_sink_calls.load() == 0U, "rejected static sink received callback");
      ++completed;
    }
    summary("passed", completed);
    (void)::alarm(0U);
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "FAIL " << (completed < groups.size() ? groups[completed].name : "runner")
              << ": " << error.what() << '\n';
  } catch (...) { std::cerr << "FAIL runtime_log_binding_test: unknown exception\n"; }
  summary("failed", completed);
  (void)::alarm(0U);
  return 1;
}
