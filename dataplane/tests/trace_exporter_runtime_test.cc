#include "bonvoyage/runtime/trace_exporter.hh"

#include <chrono>
#include <coroutine>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

#include <seastar/core/app-template.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/sleep.hh>

#include "opentelemetry/proto/collector/trace/v1/trace_service.pb.h"

namespace {

using namespace std::chrono_literals;
namespace otlp = opentelemetry::proto::collector::trace::v1;
using bonvoyage::runtime::AccessLogAction;
using bonvoyage::runtime::AccessLogCompletion;
using bonvoyage::runtime::AccessLogMethod;
using bonvoyage::runtime::OtlpHttpResult;
using bonvoyage::runtime::OtlpTraceExporter;
using bonvoyage::runtime::OtlpTraceOptions;
using bonvoyage::runtime::TraceSpanRecord;

void require(bool condition, std::string_view message) {
  if (!condition) {
    throw std::runtime_error(std::string(message));
  }
}

TraceSpanRecord complete(OtlpTraceExporter& exporter,
                         std::string_view traceparent = {}) {
  auto record = exporter.begin_request(traceparent);
  record.end_unix_nanoseconds = record.start_unix_nanoseconds + 125000U;
  record.snapshot_generation = 61U;
  record.shard = 0U;
  record.status = 200U;
  record.listener = "runtime-listener";
  record.route = "runtime-route";
  record.cluster = "runtime-cluster";
  record.method = AccessLogMethod::get;
  record.action = AccessLogAction::proxy;
  record.completion = AccessLogCompletion::complete;
  return record;
}

seastar::future<> run_checks() {
  OtlpTraceOptions options;
  options.endpoint = "http://localhost:4318/v1/traces";
  options.queue_capacity = 2U;
  options.max_batch_spans = 2U;
  options.flush_interval_ms = 10U;
  options.request_timeout_ms = 100U;
  options.sample_every = 1U;
  options.max_retries = 1U;
  options.retry_initial_backoff_ms = 10U;
  options.retry_max_backoff_ms = 10U;

  std::uint32_t attempts = 0U;
  std::uint64_t decoded_spans = 0U;
  OtlpTraceExporter exporter(
      options, [&attempts, &decoded_spans](const std::string& payload) {
        otlp::ExportTraceServiceRequest request;
        require(request.ParseFromString(payload),
                "runtime exporter emitted malformed OTLP Protobuf");
        require(request.resource_spans_size() == 1,
                "runtime exporter emitted an unexpected resource count");
        const auto& resource_spans = request.resource_spans(0);
        require(resource_spans.scope_spans_size() == 1,
                "runtime exporter emitted an unexpected scope count");
        decoded_spans += static_cast<std::uint64_t>(
            resource_spans.scope_spans(0).spans_size());
        ++attempts;
        if (attempts <= 2U) {
          return seastar::make_ready_future<OtlpHttpResult>(
              OtlpHttpResult{
                  .status = 503U,
                  .retry_after_ms = 10U,
                  .response_body = {},
              });
        }
        return seastar::make_ready_future<OtlpHttpResult>(
            OtlpHttpResult{
                .status = 200U,
                .retry_after_ms = 0U,
                .response_body = {},
            });
      });
  co_await exporter.start("runtime-snapshot", 61U, "0.2.0-test");

  constexpr std::string_view parent =
      "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-03";
  auto remote = complete(exporter, parent);
  require(remote.has_parent,
          "valid remote traceparent did not become a parent");
  require(bonvoyage::runtime::format_traceparent(
              remote.trace_id, remote.span_id, remote.trace_flags)
              .starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-"),
          "outbound context did not preserve the remote trace ID");
  exporter.enqueue(remote);
  exporter.enqueue(complete(exporter, "malformed-sentinel"));
  exporter.enqueue(complete(exporter));
  require(exporter.stats().queue_overflows == 1U,
          "trace queue did not enforce drop-newest overflow");

  co_await seastar::sleep(60ms);
  require(exporter.stats().retry_exhaustions == 1U &&
              exporter.stats().spans_dropped >= 3U &&
              exporter.stats().exporter_healthy == 0U,
          "transient collector failure did not remain bounded and observable");

  exporter.enqueue(complete(exporter));
  exporter.enqueue(complete(exporter));
  co_await seastar::sleep(40ms);
  co_await exporter.stop();

  const auto& stats = exporter.stats();
  require(stats.invalid_traceparents == 1U,
          "invalid traceparent was not observed");
  require(stats.remote_parents == 1U,
          "remote parent count was incorrect");
  require(stats.spans_exported == 2U && stats.batches_exported == 1U,
          "collector recovery did not export the second batch");
  require(stats.exporter_recoveries == 1U &&
              stats.exporter_healthy == 1U,
          "collector recovery required a restart or stayed unhealthy");
  require(decoded_spans >= 6U,
          "runtime callback did not decode every attempted batch");
}

}  // namespace

int main(int argc, char** argv) {
  seastar::app_template app;
  return app.run(argc, argv, [] { return run_checks(); });
}
