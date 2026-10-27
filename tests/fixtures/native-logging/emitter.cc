#include <cstdio>
#include <string>

#include <boost/program_options.hpp>
#include <seastar/util/log-cli.hh>
#include <seastar/util/log.hh>

// Use the real pinned Seastar formatter and syslog sink, without a reactor or
// gateway workload. The receiver lives only in the disposable test container.
int main(int argc, char** argv) {
  namespace bpo = boost::program_options;
  bpo::variables_map options;
  bpo::store(bpo::parse_command_line(
                 argc, argv, seastar::log_cli::get_options_description()),
             options);
  bpo::notify(options);
  seastar::apply_logging_settings(seastar::log_cli::extract_settings(options));
  seastar::logger log{"bonvoyage-fixture"};
  log.set_level(seastar::log_level::trace);
  log.trace("BVLOG-trace");
  log.debug("BVLOG-debug");
  log.info("BVLOG-info");
  log.warn("BVLOG-warn\n<0>untrusted-priority\x1b[31m literal %s");
  log.error("BVLOG-error");
  std::puts("<0>BVLOG-raw-stdout");
  std::fputs("<0>BVLOG-raw-stderr\n", stderr);
}
