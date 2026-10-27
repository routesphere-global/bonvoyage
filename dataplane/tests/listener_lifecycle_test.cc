#include <chrono>
#include <coroutine>
#include <exception>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <seastar/core/app-template.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/gate.hh>
#include <seastar/core/sleep.hh>
#include <seastar/http/httpd.hh>
#include <seastar/net/api.hh>

namespace {

using namespace std::chrono_literals;

void require(bool condition, std::string_view message) {
  if (!condition) {
    throw std::runtime_error(std::string(message));
  }
}

seastar::future<> check_gate_lifecycle() {
  // Exercise consumer-side holder code alongside the library's accept-loop code.
  seastar::gate gate;
  auto holder = gate.hold();
  auto moved = std::move(holder);
  holder.release();
  require(gate.get_count() == 1U,
          "moving a gate holder changed the outstanding hold count");

  seastar::promise<> completed;
  auto work = seastar::with_gate(gate, [&completed] {
    return completed.get_future();
  });
  require(gate.get_count() == 2U,
          "pending gate work did not retain its holder");
  moved.release();
  auto closed = gate.close();
  require(!closed.available(), "gate closed before pending work completed");
  completed.set_value();
  co_await std::move(work);
  co_await std::move(closed);
  require(gate.get_count() == 0U, "gate retained a holder after close");
}

seastar::future<> run_checks() {
  for (unsigned cycle = 0U; cycle < 2U; ++cycle) {
    seastar::httpd::http_server_control server;
    co_await server.start("bonvoyage-listener-lifecycle");
    std::exception_ptr failure;
    try {
      co_await check_gate_lifecycle();
      // Let the kernel choose a free port, bound only on loopback.
      co_await server.listen(seastar::socket_address(
          seastar::ipv4_addr("127.0.0.1", 0)));
      co_await seastar::sleep(1ms);
      co_await check_gate_lifecycle();
    } catch (...) {
      failure = std::current_exception();
    }
    co_await server.stop();
    if (failure) {
      std::rethrow_exception(failure);
    }
  }
}

}  // namespace

int main(int argc, char** argv) {
  seastar::app_template app;
  return app.run(argc, argv, [] { return run_checks(); });
}
