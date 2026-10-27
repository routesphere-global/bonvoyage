#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <string>
#include <sys/resource.h>
#include <unistd.h>

#include <boost/program_options.hpp>
#include <seastar/util/log-cli.hh>
#include <seastar/util/log.hh>

namespace {
std::int64_t cpu_us() {
  rusage usage{};
  if (getrusage(RUSAGE_SELF, &usage) != 0) {
    throw std::runtime_error("getrusage failed");
  }
  return (usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) * 1000000LL +
         usage.ru_utime.tv_usec + usage.ru_stime.tv_usec;
}
}  // namespace

// A synchronous logger call occupies its calling thread. This probe deliberately
// has no reactor or gateway: it measures that boundary, not HTTP performance.
int main(int argc, char** argv) {
  namespace bpo = boost::program_options;
  auto options = seastar::log_cli::get_options_description();
  options.add_options()
      ("count", bpo::value<unsigned>()->required(), "Bounded attempted calls")
      ("payload-bytes", bpo::value<unsigned>()->required(), "Synthetic payload")
      ("disabled", bpo::bool_switch(), "Filter info calls at the logger")
      ("progress", bpo::bool_switch(), "Report completed calls outside cost mode");
  bpo::variables_map values;
  bpo::store(bpo::parse_command_line(argc, argv, options), values);
  bpo::notify(values);
  const auto count = values["count"].as<unsigned>();
  const auto bytes = values["payload-bytes"].as<unsigned>();
  if (count == 0 || count > 4096 || bytes == 0 || bytes > 1024) {
    std::cerr << "probe bounds exceeded\n";
    return 2;
  }
  seastar::apply_logging_settings(seastar::log_cli::extract_settings(values));
  seastar::logger log{"bonvoyage-pressure"};
  log.set_level(values["disabled"].as<bool>() ? seastar::log_level::error
                                           : seastar::log_level::info);
  const std::string payload(bytes, 'x');
  const bool progress = values["progress"].as<bool>();
  std::cerr << "{\"event\":\"begin\",\"pid\":" << getpid() << "}\n";
  const auto cpu_start = cpu_us();
  const auto start = std::chrono::steady_clock::now();
  std::int64_t max_call_ns = 0;
  for (unsigned i = 0; i < count; ++i) {
    const auto before = std::chrono::steady_clock::now();
    log.info("BVLOG_PRESSURE seq={} payload={}", i, payload);
    const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                             std::chrono::steady_clock::now() - before).count();
    max_call_ns = std::max(max_call_ns, static_cast<std::int64_t>(elapsed));
    if (progress) {
      std::cerr << "{\"event\":\"progress\",\"returned\":" << i + 1 << "}\n";
    }
  }
  const auto wall_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                           std::chrono::steady_clock::now() - start).count();
  const auto cpu_elapsed = cpu_us() - cpu_start;
  std::cerr << "{\"event\":\"complete\",\"pid\":" << getpid()
            << ",\"calls_returned\":" << count << ",\"wall_ns\":" << wall_ns
            << ",\"cpu_us\":" << cpu_elapsed
            << ",\"max_call_ns\":" << max_call_ns << "}\n";
}
