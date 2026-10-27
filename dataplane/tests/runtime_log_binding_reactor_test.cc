#include "bonvoyage/runtime/runtime_log_binding.hh"

#include <array>
#include <atomic>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>

#include <seastar/core/app-template.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/smp.hh>

namespace {
using namespace bonvoyage::runtime;
std::atomic<unsigned> assertions{};
std::array<bool, 2U> completed{};
seastar::logger reactor_log{"binding-reactor-test"};

void require(bool condition, const char* message) {
  assertions.fetch_add(1U, std::memory_order_relaxed);
  if (!condition) { throw std::runtime_error(message); }
}

// This harness validates reactor ownership using a fixed capture sender.
// The companion non-reactor suite separately exercises real Unix sockets.
struct Capture final {
  std::array<char, 2048U> bytes{};
  std::size_t size{};
  unsigned calls{};
  static RuntimeLogSendResult send(void* context, std::string_view message) noexcept {
    auto& capture = *static_cast<Capture*>(context);
    if (message.size() > capture.bytes.size()) { return RuntimeLogSendResult::failed; }
    std::memcpy(capture.bytes.data(), message.data(), message.size());
    capture.size = message.size();
    ++capture.calls;
    return RuntimeLogSendResult::sent;
  }
  std::string_view view() const { return {bytes.data(), size}; }
};

struct InjectedFailure {};

void check_owner(unsigned shard) {
  require(seastar::this_shard_id() == shard, "test did not run on its requested shard");
  RuntimeLogSink sink({2U, 2048U, 2U});
  Capture capture;
  {
    RuntimeLogBinding binding(sink);
    reactor_log.error("owner-{}", shard);
    require(binding.stats().received == 1U && sink.stats().records_enqueued == 1U,
            "reactor logger did not reach its owner queue");
    sink.drain(&Capture::send, &capture);
    require(capture.view().starts_with("<11>bonvoyage["), "reactor severity was not syslog error");
    require(capture.view().find("[shard " + std::to_string(shard) + ":") != std::string_view::npos,
            "logger lost reactor shard/scheduling context");
    require(capture.view().ends_with(" binding-reactor-test - owner-" + std::to_string(shard)),
            "reactor record body or logger name changed");
  }
  const auto detached = runtime_log_unbound_drops();
  reactor_log.warn("detached-owner-{}", shard);
  require(runtime_log_unbound_drops() >= detached + 1U && sink.stats().records_attempted == 1U,
          "detached reactor log mutated its retired queue");
  try {
    RuntimeLogBinding binding(sink);
    reactor_log.error("before-unwind-{}", shard);
    throw InjectedFailure{};
  } catch (const InjectedFailure&) {
    const auto before = runtime_log_unbound_drops();
    reactor_log.error("after-unwind-{}", shard);
    require(runtime_log_unbound_drops() >= before + 1U, "exception unwinding left an owner attached");
  }
  sink.stop(&Capture::send, &capture);
  require(capture.calls == 2U && capture.view().ends_with("before-unwind-" + std::to_string(shard)),
          "bounded final drain lost the diagnostic captured before unwinding");
  require(sink.stats().records_attempted == 2U && sink.stats().records_sent == 2U &&
              sink.stats().records_dropped == 0U && sink.stats().queue_depth == 0U && sink.stats().active == 0U,
          "reactor final accounting did not survive binding destruction");
  completed[shard] = true;
}

seastar::future<> run() {
  require(seastar::smp::count == 2U, "exactly two reactor shards are required");
  // Submit sequentially so global unbound observations cannot be confused with
  // another test shard's deliberate loss. Both distinct owner threads execute.
  co_await seastar::smp::submit_to(0U, [] { check_owner(0U); });
  co_await seastar::smp::submit_to(1U, [] { check_owner(1U); });
}
}  // namespace

int main(int argc, char** argv) {
  try {
    require(install_runtime_log_dispatcher(), "cannot install candidate dispatcher");
    const auto before = runtime_log_unbound_drops();
    reactor_log.error("pre-reactor");
    require(runtime_log_unbound_drops() == before + 1U, "pre-reactor policy was not counted dropping");
    int status;
    {
      seastar::app_template app;
      status = app.run(argc, argv, &run);
    }
    require(status == 0 && completed[0U] && completed[1U], "reactor fixture did not complete both owners");
    const auto after = runtime_log_unbound_drops();
    reactor_log.error("post-reactor");
    require(runtime_log_unbound_drops() == after + 1U, "post-reactor dispatch did not survive owner teardown");
    std::cout << "{\"status\":\"passed\",\"groups\":[\"pre_reactor\",\"two_shards\",\"unwind\",\"post_reactor\"],"
              << "\"shards\":[0,1],\"assertions\":" << assertions.load() << "}\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
