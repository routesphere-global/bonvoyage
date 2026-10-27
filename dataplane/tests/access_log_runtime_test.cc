#include "bonvoyage/runtime/access_log.hh"

#include <chrono>
#include <coroutine>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <unistd.h>

#include <seastar/core/app-template.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/sleep.hh>

namespace {

using namespace std::chrono_literals;
using bonvoyage::runtime::AccessLogAction;
using bonvoyage::runtime::AccessLogCompletion;
using bonvoyage::runtime::AccessLogMethod;
using bonvoyage::runtime::AccessLogOptions;
using bonvoyage::runtime::AccessLogRecord;
using bonvoyage::runtime::AccessLogSink;

void require(bool condition, std::string_view message) {
  if (!condition) {
    throw std::runtime_error(std::string(message));
  }
}

AccessLogRecord record(std::string_view listener, std::string_view route,
                       std::string_view cluster) {
  AccessLogRecord value;
  value.timestamp_unix_microseconds = 1720000000000000U;
  value.snapshot_generation = 51U;
  value.duration_microseconds = 125U;
  value.shard = 0U;
  value.status = 200U;
  value.listener = listener;
  value.route = route;
  value.cluster = cluster;
  value.method = AccessLogMethod::get;
  value.action = AccessLogAction::proxy;
  value.completion = AccessLogCompletion::complete;
  return value;
}

std::size_t count_json_lines(const std::filesystem::path& directory) {
  std::size_t lines = 0U;
  for (const auto& entry : std::filesystem::directory_iterator(directory)) {
    if (!entry.is_regular_file() || entry.path().extension() != ".jsonl") {
      continue;
    }
    std::ifstream input(entry.path());
    std::string line;
    while (std::getline(input, line)) {
      require(line.starts_with("{\"schema\":\"bonvoyage.access.v1\""),
              "runtime sink wrote an unexpected record schema");
      ++lines;
    }
  }
  return lines;
}

seastar::future<> run_runtime_checks(
    const std::filesystem::path& recovery_directory,
    const std::filesystem::path& capacity_directory) {
  const std::string listener = "runtime-listener";
  const std::string route = "runtime-route";
  const std::string cluster = "runtime-cluster";

  AccessLogOptions recovery_options;
  recovery_options.directory = recovery_directory.string();
  recovery_options.queue_capacity = 2U;
  recovery_options.flush_interval_ms = 10U;
  AccessLogSink recovery(std::move(recovery_options));
  co_await recovery.start("runtime-recovery", 51U);
  recovery.enqueue(record(listener, route, cluster));
  recovery.enqueue(record(listener, route, cluster));
  recovery.enqueue(record(listener, route, cluster));
  co_await seastar::sleep(25ms);
  std::filesystem::create_directories(recovery_directory);
  co_await seastar::sleep(50ms);
  co_await recovery.stop();

  const auto& recovery_stats = recovery.stats();
  require(recovery_stats.records_enqueued == 2U,
          "runtime recovery admitted an unexpected record count");
  require(recovery_stats.queue_overflows == 1U &&
              recovery_stats.records_dropped == 1U,
          "runtime recovery did not enforce drop-newest overflow");
  require(recovery_stats.write_failures >= 1U,
          "runtime recovery did not observe the missing directory");
  require(recovery_stats.records_written == 2U &&
              recovery_stats.sink_healthy == 1U,
          "runtime sink did not recover without restart");

  AccessLogOptions capacity_options;
  capacity_options.directory = capacity_directory.string();
  capacity_options.queue_capacity = 8192U;
  capacity_options.max_file_bytes = 1024U * 1024U;
  capacity_options.flush_interval_ms = 10U;
  AccessLogSink capacity(std::move(capacity_options));
  co_await capacity.start("runtime-capacity", 52U);
  const std::string maximum_name(128U, 'a');
  for (std::size_t index = 0U; index < 5000U; ++index) {
    capacity.enqueue(record(maximum_name, maximum_name, maximum_name));
  }
  co_await seastar::sleep(250ms);
  co_await capacity.stop();

  const auto& capacity_stats = capacity.stats();
  require(capacity_stats.capacity_exhaustions == 1U,
          "runtime sink did not enforce its byte ceiling");
  require(capacity_stats.records_dropped > 0U &&
              capacity_stats.records_written > 0U,
          "runtime byte ceiling did not preserve bounded evidence");
  require(capacity_stats.bytes_written <= 1024U * 1024U,
          "runtime sink exceeded its logical byte ceiling");
}

}  // namespace

int main(int argc, char** argv) {
  const auto root = std::filesystem::path("/tmp") /
                    ("bonvoyage-access-log-runtime-" +
                     std::to_string(static_cast<std::uint64_t>(::getpid())));
  const auto recovery_directory = root / "recovery";
  const auto capacity_directory = root / "capacity";
  std::filesystem::remove_all(root);
  std::filesystem::create_directories(capacity_directory);

  seastar::app_template app;
  const auto status = app.run(argc, argv, [&] {
    return run_runtime_checks(recovery_directory, capacity_directory);
  });

  if (status == 0) {
    require(count_json_lines(recovery_directory) == 2U,
            "runtime recovery evidence did not contain two records");
    const auto capacity_lines = count_json_lines(capacity_directory);
    require(capacity_lines > 0U && capacity_lines < 5000U,
            "runtime capacity evidence escaped its bounded range");
  }
  std::filesystem::remove_all(root);
  return status;
}
