#include "bonvoyage/runtime/runtime_log_binding.hh"
#include "bonvoyage/runtime/runtime_log_service.hh"

#include <iostream>
#include <stdexcept>
#include <string>

#include <seastar/core/app-template.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/future.hh>
#include <seastar/core/reactor.hh>
#include <unistd.h>

namespace {

seastar::logger service_log{"runtime-log-service-test"};
unsigned assertions{};

void require(bool condition, const char* message) {
  ++assertions;
  if (!condition) {
    throw std::runtime_error(message);
  }
}

seastar::future<> run() {
  using bonvoyage::runtime::RuntimeLogService;

  require(seastar::smp::count == 1U, "service fixture requires one reactor shard");
  const auto missing_path =
      "/tmp/bonvoyage-runtime-log-missing-" + std::to_string(::getpid()) + ".sock";
  ::unlink(missing_path.c_str());

  RuntimeLogService service;
  service.start("unix", missing_path);
  service_log.info("shutdown-accounting-a");
  service_log.warn("shutdown-accounting-b");
  co_await service.stop();

  const auto& stats = service.final_stats();
  require(stats.records_attempted == 2U && stats.records_enqueued == 2U,
          "service did not retain both typed records before stop");
  require(stats.records_sent == 0U && stats.unavailable_events == 1U,
          "missing receiver was not classified as one bounded unavailable attempt");
  require(stats.shutdown_drops == 2U && stats.records_dropped == 2U,
          "service did not account every queued record as a shutdown drop");
  require(stats.queue_depth == 0U && stats.active == 0U,
          "service retained records or remained active after stop");
  require(!service.final_report_sent(),
          "service claimed its final report was delivered to a missing receiver");

  const auto unbound_before = bonvoyage::runtime::runtime_log_unbound_drops();
  service_log.error("after-service-stop");
  require(bonvoyage::runtime::runtime_log_unbound_drops() == unbound_before + 1U,
          "stopped service remained attached to the logger callback");

  std::cout << "{\"status\":\"passed\",\"groups\":[\"missing_receiver_stop\","
               "\"shutdown_accounting\",\"final_report_truth\"],\"assertions\":"
            << assertions << "}\n";
}

}  // namespace

int main(int argc, char** argv) {
  try {
    require(bonvoyage::runtime::install_runtime_log_dispatcher(),
            "cannot install runtime log dispatcher");
    seastar::app_template app;
    return app.run(argc, argv, &run);
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
