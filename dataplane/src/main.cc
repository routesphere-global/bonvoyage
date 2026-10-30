#include <boost/program_options/value_semantic.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <memory>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

#include <seastar/core/app-template.hh>
#include <seastar/core/abort_source.hh>
#include <seastar/core/condition-variable.hh>
#include <seastar/coroutine/as_future.hh>
#include <seastar/core/distributed.hh>
#include <seastar/core/file.hh>
#include <seastar/core/fstream.hh>
#include <seastar/core/future.hh>
#include <seastar/core/gate.hh>
#include <seastar/core/prometheus.hh>
#include <seastar/core/semaphore.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/smp.hh>
#include <seastar/core/thread.hh>
#include <seastar/http/function_handlers.hh>
#include <seastar/http/httpd.hh>
#include <seastar/http/routes.hh>
#include <seastar/net/inet_address.hh>
#include <seastar/util/log.hh>
#include <seastar/util/short_streams.hh>

#include "bonvoyage/runtime/discovery_client.hh"
#include "bonvoyage/runtime/gateway.hh"
#include "bonvoyage/runtime/live_snapshot_coordinator.hh"
#include "bonvoyage/runtime/runtime_snapshot.hh"
#include "bonvoyage/runtime/runtime_log_service.hh"
#include "bonvoyage/runtime/shutdown_sequence.hh"
#include "bonvoyage/runtime/snapshot_preparation.hh"
#include "bonvoyage/runtime/stop_signal.hh"
#include "bonvoyage/runtime/upstream_http1_client.hh"
#include "bonvoyage/version.hh"

namespace {

namespace bpo = boost::program_options;

seastar::logger runtime_log{"bonvoyage"};
constexpr std::string_view kReleaseVersion{BONVOYAGE_RELEASE_VERSION};
static_assert(!kReleaseVersion.empty());
constexpr std::uint64_t kMaximumSnapshotBytes = 16U * 1024U * 1024U;
constexpr auto kRetiredSnapshotReapInterval =
    std::chrono::milliseconds(100);

[[nodiscard]] std::string make_process_instance_id() {
  std::array<std::uint8_t, 16U> bytes{};
  std::random_device random;
  for (auto& byte : bytes) {
    byte = static_cast<std::uint8_t>(random());
  }
  // Set the UUID variant/version bits so logs and audits can use standard
  // UUID tooling without making the value an external identity authority.
  bytes[6] = static_cast<std::uint8_t>((bytes[6] & 0x0fU) | 0x40U);
  bytes[8] = static_cast<std::uint8_t>((bytes[8] & 0x3fU) | 0x80U);
  constexpr std::string_view hex{"0123456789abcdef"};
  std::string result;
  result.reserve(36U);
  for (std::size_t index = 0U; index < bytes.size(); ++index) {
    if (index == 4U || index == 6U || index == 8U || index == 10U) {
      result.push_back('-');
    }
    result.push_back(hex[bytes[index] >> 4U]);
    result.push_back(hex[bytes[index] & 0x0fU]);
  }
  return result;
}

seastar::future<std::string> read_snapshot(const std::string& path) {
  auto file = co_await seastar::open_file_dma(path, seastar::open_flags::ro);
  const auto size = co_await file.size();
  if (size == 0U || size > kMaximumSnapshotBytes) {
    co_await file.close();
    throw std::runtime_error(
        "snapshot size must be between 1 byte and 16 MiB");
  }
  auto input = seastar::make_file_input_stream(file, 0U, size);
  auto read = co_await seastar::coroutine::as_future(
      seastar::util::read_entire_stream_contiguous(input));
  co_await input.close().handle_exception([](const std::exception_ptr&) {});
  co_await file.close().handle_exception([](const std::exception_ptr&) {});
  if (read.failed()) {
    std::rethrow_exception(read.get_exception());
  }
  const auto bytes = read.get();
  co_return std::string(bytes.data(), bytes.size());
}

class LiveDiscoveryCoordinator final {
 public:
  LiveDiscoveryCoordinator(
      bonvoyage::runtime::DiscoveryNodeIdentity identity,
      seastar::sharded<bonvoyage::runtime::SnapshotPreparationShard>& lifecycle,
      seastar::sharded<bonvoyage::runtime::GatewayShard>& gateway)
      : identity_(std::move(identity)),
        lifecycle_(lifecycle),
        gateway_(gateway) {}

  LiveDiscoveryCoordinator(const LiveDiscoveryCoordinator&) = delete;
  LiveDiscoveryCoordinator& operator=(const LiveDiscoveryCoordinator&) =
      delete;

  ~LiveDiscoveryCoordinator() {
    if (running_) {
      std::terminate();
    }
  }

  seastar::future<> start() {
    if (seastar::this_shard_id() != 0U || running_) {
      throw std::logic_error(
          "live discovery coordinator must start once on shard zero");
    }
    running_ = true;
    (void)seastar::with_gate(retirement_gate_, [this] {
      return retirement_loop();
    }).handle_exception([](const std::exception_ptr& failure) {
      runtime_log.error(
          "event=snapshot_retirement_supervisor_failed error={}", failure);
      std::terminate();
    });
    co_return;
  }

  seastar::future<> stop() noexcept {
    if (!running_) {
      co_return;
    }
    stopping_ = true;
    stop_abort_.request_abort();
    retirement_ready_.broadcast();
    try {
      co_await retirement_gate_.close();
    } catch (...) {
    }
    running_ = false;
  }

  [[nodiscard]] bonvoyage::runtime::DiscoveryCommandHandler handler() {
    return [this](bonvoyage::runtime::SnapshotLifecycleCommand command,
                  seastar::abort_source& abort) {
      return handle(std::move(command), abort);
    };
  }

 private:
  seastar::future<bonvoyage::v1::NodeRolloutReport> handle(
      bonvoyage::runtime::SnapshotLifecycleCommand command,
      seastar::abort_source& abort) {
    auto operation = co_await seastar::get_units(operation_mutex_, 1U);
    if (abort.abort_requested()) {
      throw seastar::abort_requested_exception{};
    }
    co_await reap_pending_once();
    if (auto* prepare =
            std::get_if<bonvoyage::runtime::SnapshotPrepareCommand>(
                &command)) {
      auto report = co_await
          bonvoyage::runtime::prepare_live_snapshot_on_all_shards(
              lifecycle_, gateway_, std::move(*prepare));
      co_return bonvoyage::runtime::build_node_rollout_report(
          identity_, report, std::chrono::system_clock::now());
    }
    if (auto* activate =
            std::get_if<bonvoyage::runtime::SnapshotActivateCommand>(
                &command)) {
      const auto retired_snapshot = activate->expected_active_snapshot;
      auto report = co_await
          bonvoyage::runtime::activate_live_snapshot_on_all_shards(
              lifecycle_, gateway_, std::move(*activate));
      if (report.acknowledged && report.retirement_pending_shards != 0U) {
        schedule_retirement(retired_snapshot);
      }
      co_return bonvoyage::runtime::build_node_rollout_report(
          identity_, report, std::chrono::system_clock::now());
    }
    if (auto* cancel =
            std::get_if<bonvoyage::runtime::SnapshotCancelCommand>(
                &command)) {
      auto report = co_await
          bonvoyage::runtime::cancel_live_snapshot_on_all_shards(
              lifecycle_, gateway_, std::move(*cancel));
      co_return bonvoyage::runtime::build_node_rollout_report(
          identity_, report, std::chrono::system_clock::now());
    }
    throw std::logic_error("discovery command variant is empty");
  }

  void schedule_retirement(
      const bonvoyage::runtime::SnapshotReference& snapshot) {
    if (pending_retirement_.has_value() &&
        *pending_retirement_ != snapshot) {
      throw std::logic_error(
          "a different retired snapshot is already being drained");
    }
    pending_retirement_ = snapshot;
    retirement_ready_.broadcast();
  }

  seastar::future<> reap_pending_once() {
    if (!pending_retirement_.has_value()) {
      co_return;
    }
    const auto snapshot = *pending_retirement_;
    auto report = co_await
        bonvoyage::runtime::reap_live_retired_snapshot_on_all_shards(
            lifecycle_, gateway_, snapshot);
    if (report.issue.has_value()) {
      throw std::logic_error("retired snapshot cleanup failed: " +
                             report.issue->code);
    }
    if (report.complete) {
      pending_retirement_.reset();
      runtime_log.info(
          "event=snapshot_retirement_complete snapshot_id={} pinned_leases=0",
          snapshot.snapshot_id);
    }
  }

  seastar::future<> retirement_loop() {
    while (!stopping_) {
      co_await retirement_ready_.wait([this] {
        return stopping_ || pending_retirement_.has_value();
      });
      if (stopping_) {
        break;
      }
      {
        auto operation = co_await seastar::get_units(operation_mutex_, 1U);
        co_await reap_pending_once();
      }
      if (!pending_retirement_.has_value()) {
        continue;
      }
      try {
        co_await seastar::sleep_abortable(kRetiredSnapshotReapInterval,
                                          stop_abort_);
      } catch (const seastar::abort_requested_exception&) {
        break;
      }
    }
  }

  bonvoyage::runtime::DiscoveryNodeIdentity identity_;
  seastar::sharded<bonvoyage::runtime::SnapshotPreparationShard>& lifecycle_;
  seastar::sharded<bonvoyage::runtime::GatewayShard>& gateway_;
  seastar::semaphore operation_mutex_{1U};
  seastar::condition_variable retirement_ready_;
  seastar::abort_source stop_abort_;
  seastar::gate retirement_gate_;
  std::optional<bonvoyage::runtime::SnapshotReference> pending_retirement_;
  bool running_{false};
  bool stopping_{false};
};

void set_admin_routes(
    seastar::httpd::routes& routes,
    seastar::sharded<bonvoyage::runtime::GatewayShard>& gateway) {
  auto health = [](seastar::httpd::const_req, seastar::http::reply&) {
    return seastar::sstring{"{\"status\":\"ok\"}\n"};
  };
  auto active_snapshot = [&gateway](seastar::httpd::const_req,
                                    seastar::http::reply&) {
        return seastar::format(
            "{{\"snapshot_id\":\"{}\",\"generation\":{}}}\n",
            gateway.local().snapshot_id(),
            gateway.local().snapshot_generation());
      };
  routes.add(seastar::httpd::operation_type::GET,
             seastar::httpd::url("/health/live"),
             new seastar::httpd::function_handler(health, "json"));
  routes.add(seastar::httpd::operation_type::GET,
             seastar::httpd::url("/health/ready"),
             new seastar::httpd::function_handler(health, "json"));
  routes.add(seastar::httpd::operation_type::GET,
             seastar::httpd::url("/config/active"),
             new seastar::httpd::function_handler(active_snapshot, "json"));
}

}  // namespace

int main(int argc, char** argv) {
  if (!bonvoyage::runtime::install_runtime_log_dispatcher()) {
    std::fprintf(stderr, "bonvoyage: cannot install typed runtime logger\n");
    return 1;
  }
  seastar::app_template::config app_config;
  app_config.name = bonvoyage::kDataplaneName;
  app_config.description =
      "Independent C++/Seastar dataplane for RouteSphere BonVoyage.";
  app_config.auto_handle_sigint_sigterm = false;

  seastar::app_template app{app_config};
  app.add_options()
      ("version", bpo::bool_switch()->default_value(false),
       "Print the BonVoyage dataplane version and exit")
      ("snapshot", bpo::value<std::string>()->default_value(
                       "/etc/bonvoyage/snapshot.pb"),
       "Path to the compiled static v1 snapshot")
      ("secrets-directory",
       bpo::value<std::string>()->default_value("/etc/bonvoyage/secrets"),
       "Directory containing listener certificate and trust secrets")
      ("admin-address", bpo::value<std::string>()->default_value("127.0.0.1"),
       "Admin health listener address")
      ("admin-port", bpo::value<std::uint16_t>()->default_value(9901U),
       "Admin health listener port; zero disables it")
      ("metrics-address",
       bpo::value<std::string>()->default_value("127.0.0.1"),
       "Prometheus listener address")
      ("metrics-port", bpo::value<std::uint16_t>()->default_value(9090U),
       "Prometheus listener port; zero disables it")
      ("response-path-diagnostics",
       bpo::bool_switch()->default_value(false),
       "Enable bounded shard-local HTTP/1 response-path diagnostics")
      ("trust-upstream-http1-connection-reuse",
       bpo::bool_switch()->default_value(false),
       "Reuse persistent HTTP/1 connections only when every upstream and OTLP collector in this process is trusted")
      ("runtime-log-transport",
       bpo::value<std::string>()->default_value("unix"),
       "Runtime diagnostic transport: unix or stderr-pipe")
      ("runtime-log-socket",
       bpo::value<std::string>()->default_value("/dev/log"),
       "Absolute local syslog socket path for unix transport")
      ("access-log-directory",
       bpo::value<std::string>()->default_value(""),
       "Existing writable directory for shard-local JSONL access logs; empty disables them")
      ("access-log-queue-capacity",
       bpo::value<std::size_t>()->default_value(8192U),
       "Maximum in-memory access records retained per shard")
      ("access-log-max-file-bytes",
       bpo::value<std::uint64_t>()->default_value(1024ULL * 1024ULL * 1024ULL),
       "Maximum logical access-log bytes emitted per shard and process")
      ("access-log-flush-interval-ms",
       bpo::value<std::uint32_t>()->default_value(1000U),
       "Maximum access-log durability interval in milliseconds")
      ("access-log-sample-every",
       bpo::value<std::uint32_t>()->default_value(1U),
       "Deterministically retain one completed request out of this many")
      ("otlp-traces-endpoint", bpo::value<std::string>()->default_value(""),
       "Full OTLP/HTTP protobuf trace endpoint; empty disables tracing")
      ("otlp-traces-tls-ca-file",
       bpo::value<std::string>()->default_value(
           "/etc/ssl/certs/ca-certificates.crt"),
       "PEM trust bundle used to authenticate an HTTPS OTLP collector")
      ("otlp-traces-allow-insecure",
       bpo::bool_switch()->default_value(false),
       "Allow cleartext OTLP export to a non-loopback collector")
      ("otlp-traces-queue-capacity",
       bpo::value<std::size_t>()->default_value(8192U),
       "Maximum completed trace spans retained per shard")
      ("otlp-traces-max-batch-spans",
       bpo::value<std::size_t>()->default_value(256U),
       "Maximum spans encoded in one OTLP request")
      ("otlp-traces-max-batch-bytes",
       bpo::value<std::size_t>()->default_value(1024U * 1024U),
       "Maximum serialized bytes in one OTLP request")
      ("otlp-traces-flush-interval-ms",
       bpo::value<std::uint32_t>()->default_value(1000U),
       "Maximum delay before a nonempty trace queue is exported")
      ("otlp-traces-request-timeout-ms",
       bpo::value<std::uint32_t>()->default_value(10000U),
       "Bounded timeout for each OTLP export attempt")
      ("otlp-traces-sample-every",
       bpo::value<std::uint32_t>()->default_value(100U),
       "Locally retain one request trace out of this many")
      ("otlp-traces-max-retries",
       bpo::value<std::uint32_t>()->default_value(3U),
       "Maximum retry attempts after the first OTLP request")
      ("otlp-traces-retry-initial-backoff-ms",
       bpo::value<std::uint32_t>()->default_value(100U),
       "Initial OTLP transient-failure retry delay")
      ("otlp-traces-retry-max-backoff-ms",
       bpo::value<std::uint32_t>()->default_value(5000U),
       "Maximum OTLP transient-failure retry delay")
      ("discovery-address", bpo::value<std::string>()->default_value(""),
       "Control-plane discovery address; empty preserves standalone static mode")
      ("discovery-port", bpo::value<std::uint16_t>()->default_value(9443U),
       "Control-plane discovery TLS port")
      ("discovery-authority", bpo::value<std::string>()->default_value(""),
       "Discovery HTTP/2 authority; defaults to server-name and port")
      ("discovery-server-name",
       bpo::value<std::string>()->default_value(""),
       "Discovery TLS certificate name and SNI; required when enabled")
      ("discovery-trust-bundle",
       bpo::value<std::string>()->default_value(
           "/etc/bonvoyage/discovery/ca.pem"),
       "PEM trust bundle for the discovery server")
      ("discovery-client-certificate",
       bpo::value<std::string>()->default_value(
           "/etc/bonvoyage/discovery/node.pem"),
       "PEM node certificate chain for discovery mTLS")
      ("discovery-client-private-key",
       bpo::value<std::string>()->default_value(
           "/etc/bonvoyage/discovery/node-key.pem"),
       "PEM node private key for discovery mTLS")
      ("discovery-credential-generation-file",
       bpo::value<std::string>()->default_value(""),
       "Atomic node credential generation marker; empty keeps static TLS "
       "credentials")
      ("discovery-node-id", bpo::value<std::string>()->default_value(""),
       "Stable node identity bound to the discovery client certificate")
      ("discovery-heartbeat-interval-ms",
       bpo::value<std::uint32_t>()->default_value(5000U),
       "Discovery heartbeat interval")
      ("discovery-connect-timeout-ms",
       bpo::value<std::uint32_t>()->default_value(5000U),
       "Bound for discovery DNS, TCP, and TLS establishment")
      ("discovery-request-timeout-ms",
       bpo::value<std::uint32_t>()->default_value(5000U),
       "Bound for flushing the initial discovery NodeHello")
      ("discovery-reconnect-initial-backoff-ms",
       bpo::value<std::uint32_t>()->default_value(100U),
       "Initial bounded discovery reconnect delay")
      ("discovery-reconnect-max-backoff-ms",
       bpo::value<std::uint32_t>()->default_value(10000U),
       "Maximum bounded discovery reconnect delay");

  const int status = app.run(argc, argv, [&app] {
    if (app.configuration()["version"].as<bool>()) {
      const auto client = bonvoyage::runtime::kSelectedUpstreamHttp1Client;
      std::fprintf(stdout,
                   "%s dataplane %s release=%.*s upstream-http1-client=%.*s\n",
                   bonvoyage::kProductName, bonvoyage::kDataplaneVersion,
                   static_cast<int>(kReleaseVersion.size()),
                   kReleaseVersion.data(),
                   static_cast<int>(client.size()), client.data());
      return seastar::make_ready_future<>();
    }

    return seastar::async([&app] {
      bonvoyage::runtime::StopSignal stop_signal;
      seastar::sharded<bonvoyage::runtime::GatewayShard> gateway;
      seastar::sharded<bonvoyage::runtime::SnapshotPreparationShard>
          snapshot_lifecycle;
      std::unique_ptr<LiveDiscoveryCoordinator> live_discovery_coordinator;
      std::unique_ptr<bonvoyage::runtime::DiscoveryClient> discovery_client;
      seastar::httpd::http_server_control admin_server;
      seastar::httpd::http_server_control metrics_server;
      seastar::sharded<bonvoyage::runtime::RuntimeLogService> logging;
      bool gateway_started = false;
      bool snapshot_lifecycle_started = false;
      bool live_discovery_coordinator_started = false;
      bool discovery_started = false;
      bool maintenance_started = false;
      bool admin_started = false;
      bool metrics_started = false;
      bool logging_started = false;
      bool logging_bound = false;
      std::exception_ptr outer_failure;

      const auto& config = app.configuration();
      const auto log_transport =
          config["runtime-log-transport"].as<std::string>();
      const auto log_socket = config["runtime-log-socket"].as<std::string>();
      try {
        logging.start().get();
        logging_started = true;
        logging.invoke_on_all([log_transport, log_socket](
                                  bonvoyage::runtime::RuntimeLogService& owner) {
          owner.start(log_transport, log_socket);
        }).get();
        logging_bound = true;
        const auto prebind_drops =
            bonvoyage::runtime::runtime_log_unbound_drops();
        if (prebind_drops != 0U) {
          runtime_log.warn("event=runtime_log_prebind_drops count={}",
                           prebind_drops);
        }
        const auto snapshot_path = config["snapshot"].as<std::string>();
        const auto secrets_directory =
            config["secrets-directory"].as<std::string>();
        auto access_log_options = bonvoyage::runtime::AccessLogOptions{
            .directory = config["access-log-directory"].as<std::string>(),
            .queue_capacity =
                config["access-log-queue-capacity"].as<std::size_t>(),
            .max_file_bytes =
                config["access-log-max-file-bytes"].as<std::uint64_t>(),
            .flush_interval_ms =
                config["access-log-flush-interval-ms"].as<std::uint32_t>(),
            .sample_every =
                config["access-log-sample-every"].as<std::uint32_t>(),
        };
        bonvoyage::runtime::validate_access_log_options(access_log_options);
        auto trace_options = bonvoyage::runtime::OtlpTraceOptions{
            .endpoint = config["otlp-traces-endpoint"].as<std::string>(),
            .tls_ca_file =
                config["otlp-traces-tls-ca-file"].as<std::string>(),
            .allow_insecure =
                config["otlp-traces-allow-insecure"].as<bool>(),
            .trust_upstream_http1_connection_reuse =
                config["trust-upstream-http1-connection-reuse"].as<bool>(),
            .queue_capacity =
                config["otlp-traces-queue-capacity"].as<std::size_t>(),
            .max_batch_spans =
                config["otlp-traces-max-batch-spans"].as<std::size_t>(),
            .max_batch_bytes =
                config["otlp-traces-max-batch-bytes"].as<std::size_t>(),
            .flush_interval_ms =
                config["otlp-traces-flush-interval-ms"].as<std::uint32_t>(),
            .request_timeout_ms =
                config["otlp-traces-request-timeout-ms"].as<std::uint32_t>(),
            .sample_every =
                config["otlp-traces-sample-every"].as<std::uint32_t>(),
            .max_retries =
                config["otlp-traces-max-retries"].as<std::uint32_t>(),
            .retry_initial_backoff_ms =
                config["otlp-traces-retry-initial-backoff-ms"]
                    .as<std::uint32_t>(),
            .retry_max_backoff_ms =
                config["otlp-traces-retry-max-backoff-ms"]
                    .as<std::uint32_t>(),
        };
        bonvoyage::runtime::validate_otlp_trace_options(trace_options);
        const auto response_path_diagnostics =
            bonvoyage::runtime::ResponsePathDiagnosticOptions{
                .enabled =
                    config["response-path-diagnostics"].as<bool>(),
            };
        const auto upstream_http1_options =
            bonvoyage::runtime::UpstreamHttp1ConnectionOptions{
                .trust_connection_reuse =
                    config["trust-upstream-http1-connection-reuse"].as<bool>(),
            };
        std::exception_ptr failure;
        try {
          const auto snapshot = read_snapshot(snapshot_path).get();
          auto bootstrap =
              bonvoyage::runtime::RuntimeSnapshot::decode(snapshot);
          const auto bootstrap_reference =
              bonvoyage::runtime::SnapshotReference{
                  bootstrap.snapshot_id(),
                  bonvoyage::runtime::snapshot_sha256(snapshot)};
          snapshot_lifecycle.start().get();
          snapshot_lifecycle_started = true;
          snapshot_lifecycle
              .invoke_on_all([bootstrap_reference](
                                 bonvoyage::runtime::SnapshotPreparationShard&
                                     lifecycle) {
                lifecycle.initialize(bootstrap_reference);
              })
              .get();
          gateway.start().get();
          gateway_started = true;
          gateway
              .invoke_on_all([&snapshot_lifecycle, snapshot,
                              secrets_directory, access_log_options,
                              trace_options, response_path_diagnostics,
                              upstream_http1_options](
                                 bonvoyage::runtime::GatewayShard& shard) {
                shard.bind_snapshot_lifecycle(snapshot_lifecycle.local());
                return shard.start(snapshot, secrets_directory,
                                   access_log_options, trace_options,
                                   response_path_diagnostics,
                                   upstream_http1_options);
              })
              .get();
          gateway.local()
              .start_maintenance(
                  [&gateway](std::size_t cluster_index,
                             std::size_t endpoint_index, bool active_healthy) {
                    return gateway.invoke_on_all(
                        [cluster_index, endpoint_index, active_healthy](
                            bonvoyage::runtime::GatewayShard& shard) {
                          shard.apply_active_health(cluster_index, endpoint_index,
                                                    active_healthy);
                        });
                  },
                  [&gateway](std::size_t cluster_index,
                             std::size_t endpoint_index,
                             std::string resolved_address) {
                    return gateway.invoke_on_all(
                        [cluster_index, endpoint_index,
                         resolved_address = std::move(resolved_address)](
                            bonvoyage::runtime::GatewayShard& shard) {
                          shard.apply_resolved_address(
                              cluster_index, endpoint_index, resolved_address);
                        });
                  })
              .get();
          maintenance_started = true;

          const auto active_snapshot_id = gateway.local().snapshot_id();
          const auto active_snapshot_generation =
              gateway.local().snapshot_generation();

          const auto admin_port = config["admin-port"].as<std::uint16_t>();
          if (admin_port != 0U) {
            admin_server.start("bonvoyage-admin").get();
            admin_started = true;
            admin_server
                .set_routes([&gateway](seastar::httpd::routes& routes) {
                  set_admin_routes(routes, gateway);
                })
                .get();
            admin_server
                .listen(seastar::socket_address{
                    seastar::net::inet_address(
                        config["admin-address"].as<std::string>()),
                    admin_port})
                .get();
          }

          const auto metrics_port = config["metrics-port"].as<std::uint16_t>();
          if (metrics_port != 0U) {
            metrics_server.start("bonvoyage-metrics").get();
            metrics_started = true;
            seastar::prometheus::config prometheus;
            prometheus.prefix = "bonvoyage";
            prometheus.metric_help = "BonVoyage shard-local gateway metrics";
            seastar::prometheus::start(metrics_server, prometheus).get();
            metrics_server
                .listen(seastar::socket_address{
                    seastar::net::inet_address(
                        config["metrics-address"].as<std::string>()),
                    metrics_port})
                .get();
          }

          const auto discovery_address =
              config["discovery-address"].as<std::string>();
          if (!discovery_address.empty()) {
            const auto discovery_port =
                config["discovery-port"].as<std::uint16_t>();
            const auto discovery_server_name =
                config["discovery-server-name"].as<std::string>();
            auto discovery_authority =
                config["discovery-authority"].as<std::string>();
            if (discovery_authority.empty()) {
              discovery_authority = discovery_server_name + ":" +
                                    std::to_string(discovery_port);
            }
            auto identity = bonvoyage::runtime::DiscoveryNodeIdentity{
                .node_id =
                    config["discovery-node-id"].as<std::string>(),
                .process_instance_id = make_process_instance_id(),
                .dataplane_version = bonvoyage::kDataplaneVersion,
            };
            auto discovery_config =
                bonvoyage::runtime::DiscoveryClientConfig{
                    .endpoint_address = discovery_address,
                    .endpoint_port = discovery_port,
                    .authority = std::move(discovery_authority),
                    .server_name = discovery_server_name,
                    .trust_bundle_file =
                        config["discovery-trust-bundle"].as<std::string>(),
                    .client_certificate_file =
                        config["discovery-client-certificate"]
                            .as<std::string>(),
                    .client_private_key_file =
                        config["discovery-client-private-key"]
                            .as<std::string>(),
                    .credential_generation_file =
                        config["discovery-credential-generation-file"]
                            .as<std::string>(),
                    .heartbeat_interval = std::chrono::milliseconds(
                        config["discovery-heartbeat-interval-ms"]
                            .as<std::uint32_t>()),
                    .connect_timeout = std::chrono::milliseconds(
                        config["discovery-connect-timeout-ms"]
                            .as<std::uint32_t>()),
                    .request_timeout = std::chrono::milliseconds(
                        config["discovery-request-timeout-ms"]
                            .as<std::uint32_t>()),
                    .reconnect_initial_backoff = std::chrono::milliseconds(
                        config["discovery-reconnect-initial-backoff-ms"]
                            .as<std::uint32_t>()),
                    .reconnect_max_backoff = std::chrono::milliseconds(
                        config["discovery-reconnect-max-backoff-ms"]
                            .as<std::uint32_t>()),
                };
            live_discovery_coordinator =
                std::make_unique<LiveDiscoveryCoordinator>(
                    identity, snapshot_lifecycle, gateway);
            live_discovery_coordinator->start().get();
            live_discovery_coordinator_started = true;
            discovery_client =
                std::make_unique<bonvoyage::runtime::DiscoveryClient>(
                    std::move(discovery_config), identity,
                    static_cast<std::uint32_t>(seastar::smp::count),
                    [&snapshot_lifecycle] {
                      return snapshot_lifecycle.local().state();
                    },
                    live_discovery_coordinator->handler());
            discovery_client->start().get();
            discovery_started = true;
          }

          runtime_log.info(
              "event=dataplane_ready product=\"{}\" version=\"{}\" release=\"{}\" shards={} snapshot_id={} snapshot_generation={} discovery_enabled={}",
              bonvoyage::kProductName, bonvoyage::kDataplaneVersion,
              kReleaseVersion, seastar::smp::count, active_snapshot_id,
              active_snapshot_generation, discovery_started);
          stop_signal.wait().get();
        } catch (...) {
          failure = std::current_exception();
        }

        bonvoyage::runtime::ShutdownSequence shutdown{std::move(failure)};
        if (discovery_started && discovery_client != nullptr) {
          shutdown.attempt([&] { discovery_client->stop().get(); });
          discovery_started = false;
        }
        discovery_client.reset();
        if (live_discovery_coordinator_started &&
            live_discovery_coordinator != nullptr) {
          shutdown.attempt(
              [&] { live_discovery_coordinator->stop().get(); });
          live_discovery_coordinator_started = false;
        }
        live_discovery_coordinator.reset();
        if (admin_started) {
          shutdown.attempt([&] { admin_server.stop().get(); });
        }
        if (metrics_started) {
          shutdown.attempt([&] { metrics_server.stop().get(); });
        }
        if (maintenance_started) {
          shutdown.attempt([&] {
            gateway.local().stop_maintenance().get();
          });
        }
        if (gateway_started) {
          shutdown.attempt([&] { gateway.stop().get(); });
        }
        if (snapshot_lifecycle_started) {
          shutdown.attempt([&] { snapshot_lifecycle.stop().get(); });
        }
        shutdown.rethrow_if_failed();
        runtime_log.info(
            "event=dataplane_stopped product=\"{}\" version=\"{}\" release=\"{}\" outcome=clean",
            bonvoyage::kProductName, bonvoyage::kDataplaneVersion,
            kReleaseVersion);
      } catch (...) {
        outer_failure = std::current_exception();
      }
      bonvoyage::runtime::ShutdownSequence completion{
          std::move(outer_failure)};
      if (logging_started) {
        if (logging_bound && completion.failed()) {
          completion.attempt([&] {
            try {
              std::rethrow_exception(completion.failure());
            } catch (const std::exception& error) {
              const auto text = error.what();
              const std::string_view bounded{text, ::strnlen(text, 512U)};
              runtime_log.error("event=dataplane_failed error={}", bounded);
            } catch (...) {
              runtime_log.error("event=dataplane_failed error=unknown");
            }
          });
        }
        completion.attempt([&] { logging.stop().get(); });
      }
      completion.rethrow_if_failed();
    });
  });
  if (status != 0) {
    std::fprintf(stderr,
                 "bonvoyage: dataplane exited with an error; unbound log callbacks=%llu\n",
                 static_cast<unsigned long long>(
                     bonvoyage::runtime::runtime_log_unbound_drops()));
  }
  return status;
}
