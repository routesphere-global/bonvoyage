#include "bonvoyage/runtime/trace_exporter.hh"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <seastar/core/abort_source.hh>
#include <seastar/core/condition-variable.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/coroutine/as_future.hh>
#include <seastar/core/iostream.hh>
#include <seastar/core/loop.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/shared_ptr.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/sstring.hh>
#include <seastar/core/timer.hh>
#include <seastar/http/client.hh>
#include <seastar/http/reply.hh>
#include <seastar/http/request.hh>
#include <seastar/net/api.hh>
#include <seastar/net/dns.hh>
#include <seastar/net/inet_address.hh>
#include <seastar/net/tls.hh>
#include <seastar/util/log.hh>
#include <seastar/util/optimized_optional.hh>

#include "opentelemetry/proto/collector/trace/v1/trace_service.pb.h"
#include "opentelemetry/proto/common/v1/common.pb.h"
#include "opentelemetry/proto/trace/v1/trace.pb.h"

#include "bonvoyage/runtime/upstream_http1_client.hh"

namespace bonvoyage::runtime {
namespace {

using namespace std::chrono_literals;
namespace otlp_collector = opentelemetry::proto::collector::trace::v1;
namespace otlp_common = opentelemetry::proto::common::v1;
namespace otlp_trace = opentelemetry::proto::trace::v1;

constexpr std::size_t kMaximumEndpointBytes = 2048U;
constexpr std::size_t kMaximumPathBytes = 1024U;
constexpr std::size_t kMaximumTlsPathBytes = 4096U;
constexpr std::size_t kMaximumQueueCapacity = 65536U;
constexpr std::size_t kMaximumBatchSpans = 1024U;
constexpr std::size_t kMinimumBatchBytes = 64U * 1024U;
constexpr std::size_t kMaximumBatchBytes = 8U * 1024U * 1024U;
constexpr std::size_t kMaximumResponseBytes = 4U * 1024U * 1024U;
constexpr std::uint32_t kMaximumSampleEvery = 1000000U;
constexpr std::uint32_t kMaximumRetries = 8U;
constexpr std::uint32_t kMaximumRetryDelayMs = 60000U;
constexpr std::uint32_t kRemoteParentFlags = 0x00000300U;
constexpr std::string_view kHttp11Alpn = "http/1.1";
constexpr std::string_view kTlsPriority =
    "NORMAL:-VERS-ALL:+VERS-TLS1.3:+VERS-TLS1.2";

seastar::logger trace_log{"bonvoyage-otlp-traces"};

class PermanentExportFailure final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

bool contains_control(std::string_view value) noexcept {
  return std::any_of(value.begin(), value.end(), [](char character) {
    const auto byte = static_cast<unsigned char>(character);
    return byte < 0x20U || byte == 0x7fU;
  });
}

bool loopback_host(std::string_view host) noexcept {
  return host == "localhost" || host == "127.0.0.1" ||
         host.starts_with("127.");
}

struct ParsedEndpoint final {
  std::string scheme;
  std::string host;
  std::string authority;
  std::string path;
  std::uint16_t port{};
  bool tls{false};
};

std::uint16_t parse_port(std::string_view value) {
  std::uint32_t port = 0U;
  const auto [end, error] =
      std::from_chars(value.data(), value.data() + value.size(), port);
  if (value.empty() || error != std::errc{} ||
      end != value.data() + value.size() || port == 0U || port > 65535U) {
    throw std::invalid_argument("OTLP endpoint port must be between 1 and 65535");
  }
  return static_cast<std::uint16_t>(port);
}

ParsedEndpoint parse_endpoint(std::string_view endpoint) {
  if (endpoint.empty() || endpoint.size() > kMaximumEndpointBytes ||
      contains_control(endpoint)) {
    throw std::invalid_argument(
        "OTLP endpoint must contain 1 through 2048 bytes without controls");
  }
  const auto scheme_end = endpoint.find("://");
  if (scheme_end == std::string_view::npos) {
    throw std::invalid_argument("OTLP endpoint requires an http or https scheme");
  }
  ParsedEndpoint result;
  result.scheme = std::string(endpoint.substr(0U, scheme_end));
  result.tls = result.scheme == "https";
  if (result.scheme != "http" && !result.tls) {
    throw std::invalid_argument("OTLP endpoint scheme must be http or https");
  }
  auto remainder = endpoint.substr(scheme_end + 3U);
  const auto path_offset = remainder.find('/');
  const auto authority = remainder.substr(0U, path_offset);
  const auto path = path_offset == std::string_view::npos
                        ? std::string_view{"/v1/traces"}
                        : remainder.substr(path_offset);
  if (authority.empty() || authority.find('@') != std::string_view::npos ||
      authority.find('[') != std::string_view::npos ||
      authority.find(']') != std::string_view::npos ||
      path.empty() || path.front() != '/' || path.size() > kMaximumPathBytes ||
      path.find('?') != std::string_view::npos ||
      path.find('#') != std::string_view::npos) {
    throw std::invalid_argument(
        "OTLP endpoint requires a bounded IPv4/DNS authority and absolute path without credentials, query, or fragment");
  }
  const auto colon = authority.rfind(':');
  if (colon == std::string_view::npos) {
    result.host = std::string(authority);
    result.port = result.tls ? 443U : 4318U;
  } else {
    result.host = std::string(authority.substr(0U, colon));
    result.port = parse_port(authority.substr(colon + 1U));
  }
  if (result.host.empty() || contains_control(result.host) ||
      result.host.find(':') != std::string::npos) {
    throw std::invalid_argument("OTLP endpoint host is invalid");
  }
  result.authority = std::string(authority);
  result.path = std::string(path);
  return result;
}

std::uint64_t unix_nanoseconds_now() noexcept {
  const auto value = std::chrono::duration_cast<std::chrono::nanoseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
  return value > 0 ? static_cast<std::uint64_t>(value) : 0U;
}

std::string_view method_name(AccessLogMethod method) noexcept {
  switch (method) {
    case AccessLogMethod::get:
      return "GET";
    case AccessLogMethod::head:
      return "HEAD";
    case AccessLogMethod::post:
      return "POST";
    case AccessLogMethod::put:
      return "PUT";
    case AccessLogMethod::patch:
      return "PATCH";
    case AccessLogMethod::delete_:
      return "DELETE";
    case AccessLogMethod::options:
      return "OPTIONS";
    case AccessLogMethod::connect:
      return "CONNECT";
    case AccessLogMethod::other:
      return "OTHER";
  }
  return "OTHER";
}

std::string_view protocol_version(AccessLogProtocol protocol) noexcept {
  return protocol == AccessLogProtocol::http1 ||
                 protocol == AccessLogProtocol::websocket
             ? "1.1"
             : "2";
}

std::string_view action_name(AccessLogAction action) noexcept {
  switch (action) {
    case AccessLogAction::unresolved:
      return "unresolved";
    case AccessLogAction::route_miss:
      return "route_miss";
    case AccessLogAction::proxy:
      return "proxy";
    case AccessLogAction::fixed_response:
      return "fixed_response";
    case AccessLogAction::redirect:
      return "redirect";
    case AccessLogAction::cors_preflight:
      return "cors_preflight";
    case AccessLogAction::websocket:
      return "websocket";
  }
  return "unresolved";
}

std::string_view completion_name(AccessLogCompletion completion) noexcept {
  switch (completion) {
    case AccessLogCompletion::complete:
      return "complete";
    case AccessLogCompletion::partial:
      return "partial";
    case AccessLogCompletion::aborted:
      return "aborted";
  }
  return "aborted";
}

std::int64_t bounded_integer(std::uint64_t value) noexcept {
  constexpr auto maximum =
      static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
  return static_cast<std::int64_t>(std::min(value, maximum));
}

template <typename Owner>
void add_string_attribute(Owner& owner, std::string_view key,
                          std::string_view value) {
  auto* attribute = owner.add_attributes();
  attribute->set_key(key.data(), key.size());
  attribute->mutable_value()->set_string_value(value.data(), value.size());
}

template <typename Owner>
void add_integer_attribute(Owner& owner, std::string_view key,
                           std::uint64_t value) {
  auto* attribute = owner.add_attributes();
  attribute->set_key(key.data(), key.size());
  attribute->mutable_value()->set_int_value(bounded_integer(value));
}

std::string serialize_batch(std::span<const TraceSpanRecord> records,
                            std::string_view snapshot_id,
                            std::uint64_t snapshot_generation,
                            std::string_view service_version) {
  otlp_collector::ExportTraceServiceRequest request;
  auto* resource_spans = request.add_resource_spans();
  auto* resource = resource_spans->mutable_resource();
  add_string_attribute(*resource, "service.name", "routesphere-bonvoyage");
  add_string_attribute(*resource, "service.namespace", "routesphere");
  add_string_attribute(*resource, "service.version", service_version);
  add_string_attribute(*resource, "bonvoyage.snapshot.id", snapshot_id);
  add_integer_attribute(*resource, "bonvoyage.snapshot.generation",
                        snapshot_generation);
  if (!records.empty()) {
    add_integer_attribute(*resource, "bonvoyage.shard", records.front().shard);
  }

  auto* scope_spans = resource_spans->add_scope_spans();
  scope_spans->mutable_scope()->set_name("io.routesphere.bonvoyage.gateway");
  scope_spans->mutable_scope()->set_version(service_version.data(),
                                            service_version.size());

  for (const auto& record : records) {
    auto* span = scope_spans->add_spans();
    span->set_trace_id(record.trace_id.data(), record.trace_id.size());
    span->set_span_id(record.span_id.data(), record.span_id.size());
    if (record.has_parent) {
      span->set_parent_span_id(record.parent_span_id.data(),
                               record.parent_span_id.size());
    }
    auto name = std::string(method_name(record.method));
    name.push_back(' ');
    name.append(record.route.empty() ? action_name(record.action)
                                     : record.route);
    span->set_name(std::move(name));
    span->set_kind(otlp_trace::Span::SPAN_KIND_SERVER);
    span->set_start_time_unix_nano(record.start_unix_nanoseconds);
    span->set_end_time_unix_nano(
        std::max(record.start_unix_nanoseconds, record.end_unix_nanoseconds));
    auto flags = static_cast<std::uint32_t>(record.trace_flags);
    if (record.has_parent) {
      flags |= kRemoteParentFlags;
    }
    span->set_flags(flags);

    add_string_attribute(*span, "http.request.method", method_name(record.method));
    add_integer_attribute(*span, "http.response.status_code", record.status);
    add_string_attribute(*span, "network.protocol.name", "http");
    add_string_attribute(*span, "network.protocol.version",
                         protocol_version(record.protocol));
    if (record.protocol == AccessLogProtocol::grpc) {
      add_string_attribute(*span, "rpc.system", "grpc");
    }
    add_string_attribute(*span, "bonvoyage.listener", record.listener);
    if (!record.route.empty()) {
      add_string_attribute(*span, "bonvoyage.route", record.route);
    }
    if (!record.cluster.empty()) {
      add_string_attribute(*span, "bonvoyage.cluster", record.cluster);
    }
    add_string_attribute(*span, "bonvoyage.action", action_name(record.action));
    add_string_attribute(*span, "bonvoyage.completion",
                         completion_name(record.completion));
    add_integer_attribute(*span, "http.request.body.size",
                          record.request_body_bytes);
    add_integer_attribute(*span, "http.response.body.size",
                          record.response_body_bytes);
    add_integer_attribute(*span, "bonvoyage.snapshot.generation",
                          record.snapshot_generation);
    add_integer_attribute(*span, "bonvoyage.shard", record.shard);
    if (record.status >= 500U ||
        record.completion != AccessLogCompletion::complete) {
      span->mutable_status()->set_code(otlp_trace::Status::STATUS_CODE_ERROR);
    }
  }

  std::string result;
  if (!request.SerializeToString(&result)) {
    throw std::runtime_error("OTLP trace request serialization failed");
  }
  return result;
}

class TraceConnectionFactory final
    : public seastar::http::experimental::connection_factory {
 public:
  TraceConnectionFactory(
      seastar::socket_address address, std::chrono::milliseconds timeout,
      seastar::shared_ptr<seastar::tls::certificate_credentials>
          tls_credentials,
      seastar::sstring tls_server_name)
      : address_(address),
        timeout_(timeout),
        tls_credentials_(std::move(tls_credentials)),
        tls_server_name_(std::move(tls_server_name)) {}

  seastar::future<seastar::connected_socket> make(
      seastar::abort_source* abort) override {
    const auto address = address_;
    return seastar::do_with(
        seastar::engine().net().socket(),
        std::optional<seastar::connected_socket>{}, seastar::timer<>{}, false,
        [this, abort, address](seastar::socket& socket,
                              std::optional<seastar::connected_socket>& connection,
                              seastar::timer<>& timer, bool& timed_out) {
          const auto shutdown = [this, &socket, &connection]() noexcept {
            if (connection.has_value()) {
              if (tls_credentials_ != nullptr) {
                try {
                  seastar::tls::abort(*connection);
                  return;
                } catch (...) {
                }
              }
              connection->shutdown_input();
              connection->shutdown_output();
            } else {
              socket.shutdown();
            }
          };
          timer.set_callback([&timed_out, shutdown] {
            timed_out = true;
            shutdown();
          });
          seastar::optimized_optional<seastar::abort_source::subscription>
              subscription;
          if (abort != nullptr) {
            if (abort->abort_requested()) {
              return seastar::make_exception_future<seastar::connected_socket>(
                  seastar::abort_requested_exception{});
            }
            subscription = abort->subscribe(shutdown);
          }
          timer.arm(seastar::timer<>::clock::now() + timeout_);
          auto connecting = socket.connect(address);
          return seastar::do_with(
              std::move(subscription),
              [this, &connection, &timer, &timed_out,
               connecting = std::move(connecting)](auto&) mutable {
                return std::move(connecting).then_wrapped(
                    [this, &connection, &timer, &timed_out](
                        seastar::future<seastar::connected_socket> result) {
                      if (result.failed()) {
                        timer.cancel();
                        if (timed_out) {
                          result.ignore_ready_future();
                          return seastar::make_exception_future<
                              seastar::connected_socket>(
                              std::runtime_error("OTLP collector connect timed out"));
                        }
                        return result;
                      }
                      connection.emplace(result.get());
                      if (tls_credentials_ == nullptr) {
                        timer.cancel();
                        return seastar::make_ready_future<
                            seastar::connected_socket>(std::move(*connection));
                      }
                      seastar::tls::tls_options options;
                      options.server_name = tls_server_name_;
                      options.verify_certificate = true;
                      options.alpn_protocols.emplace_back(kHttp11Alpn);
                      auto transport = std::move(*connection);
                      connection.reset();
                      return seastar::tls::wrap_client(
                                 tls_credentials_, std::move(transport),
                                 std::move(options))
                          .then([&connection](seastar::connected_socket secured) {
                            connection.emplace(std::move(secured));
                            return seastar::tls::get_negotiated_alpn(*connection);
                          })
                          .then_wrapped(
                              [&connection, &timer, &timed_out](auto negotiated) {
                                timer.cancel();
                                if (timed_out) {
                                  negotiated.ignore_ready_future();
                                  return seastar::make_exception_future<
                                      seastar::connected_socket>(
                                      std::runtime_error(
                                          "OTLP collector TLS handshake timed out"));
                                }
                                if (negotiated.failed()) {
                                  return seastar::make_exception_future<
                                      seastar::connected_socket>(
                                      negotiated.get_exception());
                                }
                                const auto alpn = negotiated.get();
                                if (alpn.has_value() && *alpn != kHttp11Alpn) {
                                  return seastar::make_exception_future<
                                      seastar::connected_socket>(
                                      std::runtime_error(
                                          "OTLP collector negotiated an unsupported ALPN protocol"));
                                }
                                return seastar::make_ready_future<
                                    seastar::connected_socket>(
                                    std::move(*connection));
                              });
                    });
              });
        });
  }

 private:
  seastar::socket_address address_;
  std::chrono::milliseconds timeout_;
  seastar::shared_ptr<seastar::tls::certificate_credentials> tls_credentials_;
  seastar::sstring tls_server_name_;
};

std::uint32_t parse_retry_after(std::string_view value) noexcept {
  std::uint32_t seconds = 0U;
  const auto [end, error] =
      std::from_chars(value.data(), value.data() + value.size(), seconds);
  if (value.empty() || error != std::errc{} ||
      end != value.data() + value.size()) {
    return 0U;
  }
  const auto milliseconds = static_cast<std::uint64_t>(seconds) * 1000U;
  return static_cast<std::uint32_t>(
      std::min<std::uint64_t>(milliseconds, kMaximumRetryDelayMs));
}

class TraceHttpTransport final {
 public:
  TraceHttpTransport(OtlpTraceOptions options, ParsedEndpoint endpoint)
      : options_(std::move(options)), endpoint_(std::move(endpoint)) {}

  seastar::future<> start() {
    seastar::net::dns_resolver::options resolver_options;
    resolver_options.timeout =
        std::chrono::milliseconds(options_.request_timeout_ms);
    resolver_ =
        std::make_unique<seastar::net::dns_resolver>(resolver_options);
    if (endpoint_.tls) {
      tls_credentials_ =
          seastar::make_shared<seastar::tls::certificate_credentials>();
      tls_credentials_->set_priority_string(seastar::sstring(kTlsPriority));
      co_await tls_credentials_->set_x509_trust_file(
          seastar::sstring(options_.tls_ca_file),
          seastar::tls::x509_crt_format::PEM);
    }
  }

  seastar::future<OtlpHttpResult> send(std::string payload) {
    auto prepared = co_await seastar::coroutine::as_future(ensure_client());
    if (prepared.failed()) {
      const auto failure = prepared.get_exception();
      co_await reset_client();
      std::rethrow_exception(failure);
    }

    OtlpHttpResult response;
    auto request = seastar::http::request::make(
        "POST", endpoint_.authority, endpoint_.path);
    request._version = "1.1";
    request._headers["Content-Type"] = "application/x-protobuf";
    request._headers["Accept"] = "application/x-protobuf";
    request._headers["Connection"] = "keep-alive";
    request.content_length = payload.size();
    request.body_writer =
        [body = std::move(payload)](
            seastar::output_stream<char>&& output) mutable {
          return seastar::do_with(
              std::move(output), std::move(body),
              [](auto& destination, auto& bytes) {
                return destination.write(bytes.data(), bytes.size())
                    .finally([&destination] { return destination.close(); });
              });
        };

    seastar::abort_source abort;
    bool timed_out = false;
    seastar::timer<> timer([&abort, &timed_out] {
      timed_out = true;
      abort.request_abort();
    });
    timer.arm(seastar::timer<>::clock::now() +
              std::chrono::milliseconds(options_.request_timeout_ms));
    auto handler = [&response](const seastar::http::reply& reply,
                               seastar::input_stream<char>&& body) {
      response.status = static_cast<std::uint16_t>(reply._status);
      response.retry_after_ms =
          parse_retry_after(reply.get_header("Retry-After"));
      return seastar::do_with(std::move(body), [&response](auto& input) {
        return seastar::repeat([&response, &input] {
                 return input.read().then(
                     [&response](seastar::temporary_buffer<char> chunk) {
                       if (chunk.empty()) {
                         return seastar::stop_iteration::yes;
                       }
                       if (response.response_body.size() + chunk.size() >
                           kMaximumResponseBytes) {
                         throw PermanentExportFailure(
                             "OTLP collector response exceeded 4 MiB");
                       }
                       response.response_body.append(chunk.get(), chunk.size());
                       return seastar::stop_iteration::no;
                     });
               })
            .finally([&input] { return input.close(); });
      });
    };
    auto result = co_await seastar::coroutine::as_future(
        client_->make_request(std::move(request), std::move(handler), &abort));
    timer.cancel();
    if (timed_out || result.failed()) {
      std::exception_ptr failure;
      if (timed_out) {
        if (result.failed()) {
          result.ignore_ready_future();
        }
        failure = std::make_exception_ptr(
            std::runtime_error("OTLP export request timed out"));
      } else {
        failure = result.get_exception();
      }
      co_await reset_client();
      std::rethrow_exception(failure);
    }
    co_return response;
  }

  seastar::future<> close() noexcept {
    co_await reset_client();
    resolver_.reset();
    tls_credentials_ = nullptr;
  }

 private:
  seastar::future<> ensure_client() {
    if (client_ != nullptr) {
      co_return;
    }
    const auto address = co_await resolver_->resolve_name(
        seastar::sstring(endpoint_.host),
        seastar::net::inet_address::family::INET);
    auto factory = std::make_unique<TraceConnectionFactory>(
        seastar::socket_address{address, endpoint_.port},
        std::chrono::milliseconds(options_.request_timeout_ms),
        tls_credentials_, seastar::sstring(endpoint_.host));
    client_ = std::make_unique<SeastarReferenceHttp1Client>(
        std::move(factory), 1U, 16U * 1024U, 16U * 1024U,
        Http1PoolWaitObserver{},
        options_.trust_upstream_http1_connection_reuse);
  }

  seastar::future<> reset_client() noexcept {
    if (client_ != nullptr) {
      co_await client_->close().handle_exception(
          [](const std::exception_ptr&) {});
      client_.reset();
    }
  }

  OtlpTraceOptions options_;
  ParsedEndpoint endpoint_;
  std::unique_ptr<seastar::net::dns_resolver> resolver_;
  seastar::shared_ptr<seastar::tls::certificate_credentials> tls_credentials_;
  std::unique_ptr<SeastarReferenceHttp1Client> client_;
};

bool retryable_status(std::uint16_t status) noexcept {
  return status == 429U || status == 502U || status == 503U ||
         status == 504U;
}

}  // namespace

void validate_otlp_trace_options(const OtlpTraceOptions& options) {
  if (options.queue_capacity == 0U ||
      options.queue_capacity > kMaximumQueueCapacity) {
    throw std::invalid_argument(
        "OTLP trace queue capacity must be between 1 and 65536 spans");
  }
  if (options.max_batch_spans == 0U ||
      options.max_batch_spans > kMaximumBatchSpans ||
      options.max_batch_spans > options.queue_capacity) {
    throw std::invalid_argument(
        "OTLP trace batch must contain 1 through 1024 spans and not exceed the queue");
  }
  if (options.max_batch_bytes < kMinimumBatchBytes ||
      options.max_batch_bytes > kMaximumBatchBytes) {
    throw std::invalid_argument(
        "OTLP trace batch bytes must be between 64 KiB and 8 MiB");
  }
  if (options.flush_interval_ms < 10U ||
      options.flush_interval_ms > 60000U) {
    throw std::invalid_argument(
        "OTLP trace flush interval must be between 10 and 60000 milliseconds");
  }
  if (options.request_timeout_ms < 100U ||
      options.request_timeout_ms > 60000U) {
    throw std::invalid_argument(
        "OTLP trace request timeout must be between 100 and 60000 milliseconds");
  }
  if (options.sample_every == 0U ||
      options.sample_every > kMaximumSampleEvery) {
    throw std::invalid_argument(
        "OTLP trace sample interval must be between 1 and 1000000 requests");
  }
  if (options.max_retries > kMaximumRetries ||
      options.retry_initial_backoff_ms < 10U ||
      options.retry_initial_backoff_ms > kMaximumRetryDelayMs ||
      options.retry_max_backoff_ms < options.retry_initial_backoff_ms ||
      options.retry_max_backoff_ms > kMaximumRetryDelayMs) {
    throw std::invalid_argument(
        "OTLP trace retries require 0 through 8 retries and a bounded 10 through 60000 millisecond backoff");
  }
  if (options.tls_ca_file.size() > kMaximumTlsPathBytes ||
      contains_control(options.tls_ca_file)) {
    throw std::invalid_argument(
        "OTLP trace TLS CA path must be at most 4096 bytes without controls");
  }
  if (!options.enabled()) {
    return;
  }
  const auto endpoint = parse_endpoint(options.endpoint);
  if (!endpoint.tls && !loopback_host(endpoint.host) &&
      !options.allow_insecure) {
    throw std::invalid_argument(
        "cleartext OTLP export to a non-loopback collector requires --otlp-traces-allow-insecure");
  }
  if (endpoint.tls && options.tls_ca_file.empty()) {
    throw std::invalid_argument("HTTPS OTLP export requires a TLS CA bundle");
  }
}

BoundedTraceQueue::BoundedTraceQueue(std::size_t capacity)
    : entries_(capacity) {
  if (capacity == 0U) {
    throw std::invalid_argument("bounded trace queue requires positive capacity");
  }
}

bool BoundedTraceQueue::push(TraceSpanRecord record) noexcept {
  if (size_ == entries_.size()) {
    return false;
  }
  const auto tail = (head_ + size_) % entries_.size();
  entries_[tail] = record;
  ++size_;
  return true;
}

TraceSpanRecord BoundedTraceQueue::pop() noexcept {
  const auto result = entries_[head_];
  head_ = (head_ + 1U) % entries_.size();
  --size_;
  return result;
}

std::size_t BoundedTraceQueue::clear() noexcept {
  const auto discarded = size_;
  head_ = 0U;
  size_ = 0U;
  return discarded;
}

class OtlpTraceExporter::Impl final {
 public:
  Impl(OtlpTraceOptions options, ExportFunction export_function)
      : options_(std::move(options)),
        queue_(options_.queue_capacity),
        export_function_(std::move(export_function)) {
    validate_otlp_trace_options(options_);
    stats_.enabled = options_.enabled() ? 1U : 0U;
    stats_.exporter_healthy = options_.enabled() ? 0U : 1U;
    stats_.queue_capacity = options_.enabled() ? options_.queue_capacity : 0U;
    if (options_.enabled()) {
      generator_.emplace();
      const auto jitter_seed = generator_->next_span_id();
      std::memcpy(&retry_jitter_, jitter_seed.data(), sizeof(retry_jitter_));
    }
  }

  seastar::future<> start(std::string snapshot_id,
                          std::uint64_t snapshot_generation,
                          std::string service_version) {
    if (started_) {
      throw std::logic_error("OTLP trace exporter was already started");
    }
    started_ = true;
    snapshot_id_ = std::move(snapshot_id);
    snapshot_generation_ = snapshot_generation;
    service_version_ = std::move(service_version);
    if (!options_.enabled()) {
      co_return;
    }
    if (!export_function_) {
      transport_ = std::make_unique<TraceHttpTransport>(
          options_, parse_endpoint(options_.endpoint));
      co_await transport_->start();
      export_function_ = [this](std::string payload) {
        return transport_->send(std::move(payload));
      };
    }
    flush_timer_.set_callback([this] {
      flush_due_ = true;
      wake_.broadcast();
    });
    flush_timer_.arm_periodic(
        std::chrono::milliseconds(options_.flush_interval_ms));
    worker_ = run();
  }

  seastar::future<> stop() {
    if (!started_ || stopped_) {
      co_return;
    }
    stopped_ = true;
    flush_timer_.cancel();
    wake_.broadcast();
    if (options_.enabled()) {
      co_await std::move(worker_);
    }
    if (transport_ != nullptr) {
      co_await transport_->close();
      transport_.reset();
    }
  }

  TraceSpanRecord begin_request(std::string_view incoming_traceparent) {
    if (!options_.enabled() || !started_ || stopped_ ||
        !generator_.has_value()) {
      throw std::logic_error(
          "trace context creation requires a running configured exporter");
    }
    TraceSpanRecord record;
    ++stats_.spans_started;
    ++sample_cursor_;
    record.sampled = (sample_cursor_ - 1U) % options_.sample_every == 0U;
    record.trace_flags = record.sampled ? 0x01U : 0U;
    if (record.sampled) {
      ++stats_.spans_sampled;
    } else {
      ++stats_.spans_sampled_out;
    }

    if (!incoming_traceparent.empty()) {
      const auto parsed = parse_traceparent(incoming_traceparent);
      if (parsed.has_value()) {
        record.trace_id = parsed->trace_id;
        record.parent_span_id = parsed->parent_id;
        record.has_parent = true;
        record.trace_flags = static_cast<std::uint8_t>(
            (parsed->flags & 0x02U) | (record.sampled ? 0x01U : 0U));
        ++stats_.remote_parents;
      } else {
        ++stats_.invalid_traceparents;
      }
    }
    if (!record.has_parent) {
      record.trace_id = generator_->next_trace_id();
    }
    record.span_id = generator_->next_span_id();
    record.start_unix_nanoseconds = unix_nanoseconds_now();
    return record;
  }

  void enqueue(TraceSpanRecord record) noexcept {
    if (!record.sampled || !started_ || stopped_ || !options_.enabled()) {
      return;
    }
    if (!queue_.push(record)) {
      ++stats_.spans_dropped;
      ++stats_.queue_overflows;
      return;
    }
    ++stats_.spans_enqueued;
    stats_.queue_depth = queue_.size();
    if (queue_.size() >= options_.max_batch_spans) {
      wake_.signal();
    }
  }

  [[nodiscard]] bool enabled() const noexcept { return options_.enabled(); }
  [[nodiscard]] const OtlpTraceOptions& options() const noexcept {
    return options_;
  }
  [[nodiscard]] const OtlpTraceStats& stats() const noexcept { return stats_; }
  [[nodiscard]] OtlpTraceStats& stats() noexcept { return stats_; }

 private:
  std::uint32_t retry_delay(std::uint32_t attempt,
                            std::uint32_t retry_after_ms) noexcept {
    if (retry_after_ms != 0U) {
      return std::min(retry_after_ms, options_.retry_max_backoff_ms);
    }
    auto delay = static_cast<std::uint64_t>(options_.retry_initial_backoff_ms);
    delay <<= std::min<std::uint32_t>(attempt, 16U);
    delay = std::min<std::uint64_t>(delay, options_.retry_max_backoff_ms);
    retry_jitter_ = retry_jitter_ * 6364136223846793005ULL + 1U;
    const auto jitter = delay == 0U ? 0U : (retry_jitter_ >> 32U) %
                                                   (delay / 4U + 1U);
    return static_cast<std::uint32_t>(
        std::min<std::uint64_t>(delay + jitter,
                                options_.retry_max_backoff_ms));
  }

  void mark_failure() noexcept {
    ++stats_.export_failures;
    stats_.exporter_healthy = 0U;
  }

  void mark_success() noexcept {
    if (stats_.exporter_healthy == 0U && stats_.export_requests > 1U) {
      ++stats_.exporter_recoveries;
      trace_log.info(
          "event=otlp_trace_exporter_recovered shard={} snapshot_generation={}",
          seastar::this_shard_id(), snapshot_generation_);
    }
    stats_.exporter_healthy = 1U;
  }

  seastar::future<bool> export_batch(
      std::span<const TraceSpanRecord> batch, std::string payload) noexcept {
    for (std::uint32_t attempt = 0U;; ++attempt) {
      ++stats_.export_requests;
      auto exported = co_await seastar::coroutine::as_future(
          export_function_(payload));
      std::uint32_t retry_after_ms = 0U;
      if (!exported.failed()) {
        auto response = exported.get();
        if (response.status == 200U) {
          otlp_collector::ExportTraceServiceResponse decoded;
          if (!decoded.ParseFromString(response.response_body)) {
            mark_failure();
            co_return false;
          }
          std::uint64_t rejected = 0U;
          if (decoded.has_partial_success() &&
              (decoded.partial_success().rejected_spans() != 0 ||
               !decoded.partial_success().error_message().empty())) {
            ++stats_.partial_success_responses;
            if (decoded.partial_success().rejected_spans() > 0) {
              rejected = std::min<std::uint64_t>(
                  static_cast<std::uint64_t>(
                      decoded.partial_success().rejected_spans()),
                  batch.size());
            }
          }
          mark_success();
          ++stats_.batches_exported;
          stats_.spans_exported += batch.size() - rejected;
          stats_.spans_dropped += rejected;
          stats_.bytes_exported += payload.size();
          co_return true;
        }
        if (!retryable_status(response.status)) {
          mark_failure();
          co_return false;
        }
        retry_after_ms = response.retry_after_ms;
        mark_failure();
      } else {
        bool permanent = false;
        try {
          std::rethrow_exception(exported.get_exception());
        } catch (const PermanentExportFailure&) {
          permanent = true;
        } catch (...) {
        }
        mark_failure();
        if (permanent) {
          co_return false;
        }
      }
      if (attempt >= options_.max_retries) {
        ++stats_.retry_exhaustions;
        co_return false;
      }
      ++stats_.export_retries;
      co_await seastar::sleep(std::chrono::milliseconds(
          retry_delay(attempt, retry_after_ms)));
    }
  }

  seastar::future<> drain_once() {
    std::vector<TraceSpanRecord> records;
    records.reserve(options_.max_batch_spans);
    while (!queue_.empty() && records.size() < options_.max_batch_spans) {
      records.push_back(queue_.pop());
    }
    stats_.queue_depth = queue_.size();

    std::size_t offset = 0U;
    while (offset < records.size()) {
      auto count = records.size() - offset;
      std::string payload;
      while (true) {
        payload = serialize_batch(
            std::span<const TraceSpanRecord>(records).subspan(offset, count),
            snapshot_id_, snapshot_generation_, service_version_);
        if (payload.size() <= options_.max_batch_bytes || count == 1U) {
          break;
        }
        count = std::max<std::size_t>(1U, count / 2U);
      }
      if (payload.size() > options_.max_batch_bytes) {
        ++stats_.spans_dropped;
        ++offset;
        continue;
      }
      const auto exported = co_await export_batch(
          std::span<const TraceSpanRecord>(records).subspan(offset, count),
          std::move(payload));
      if (!exported) {
        stats_.spans_dropped += count;
        trace_log.warn(
            "event=otlp_trace_export_failed shard={} spans={} snapshot_generation={}",
            seastar::this_shard_id(), count, snapshot_generation_);
      }
      offset += count;
    }
  }

  seastar::future<> run() noexcept {
    bool worker_failed = false;
    try {
      while (true) {
        if (!stopped_ && !flush_due_ &&
            queue_.size() < options_.max_batch_spans) {
          co_await wake_.wait([this] {
            return stopped_ || flush_due_ ||
                   queue_.size() >= options_.max_batch_spans;
          });
        }
        flush_due_ = false;
        while (!queue_.empty()) {
          co_await drain_once();
        }
        if (stopped_) {
          break;
        }
      }
    } catch (...) {
      worker_failed = true;
    }
    if (worker_failed) {
      mark_failure();
      trace_log.error(
          "event=otlp_trace_worker_failed shard={} snapshot_generation={}",
          seastar::this_shard_id(), snapshot_generation_);
    }
    stats_.spans_dropped += queue_.clear();
    stats_.queue_depth = 0U;
    trace_log.info(
        "event=otlp_trace_exporter_stopped shard={} exported={} dropped={} snapshot_generation={}",
        seastar::this_shard_id(), stats_.spans_exported,
        stats_.spans_dropped, snapshot_generation_);
  }

  OtlpTraceOptions options_;
  BoundedTraceQueue queue_;
  ExportFunction export_function_;
  std::unique_ptr<TraceHttpTransport> transport_;
  std::optional<TraceIdGenerator> generator_;
  OtlpTraceStats stats_;
  std::string snapshot_id_;
  std::string service_version_;
  std::uint64_t snapshot_generation_{};
  std::uint64_t sample_cursor_{};
  std::uint64_t retry_jitter_{};
  seastar::condition_variable wake_;
  seastar::timer<> flush_timer_;
  seastar::future<> worker_{seastar::make_ready_future<>()};
  bool flush_due_{false};
  bool started_{false};
  bool stopped_{false};
};

OtlpTraceExporter::OtlpTraceExporter(OtlpTraceOptions options,
                                     ExportFunction export_function)
    : impl_(std::make_unique<Impl>(std::move(options),
                                   std::move(export_function))) {}

OtlpTraceExporter::~OtlpTraceExporter() = default;

seastar::future<> OtlpTraceExporter::start(std::string snapshot_id,
                                           std::uint64_t snapshot_generation,
                                           std::string service_version) {
  return impl_->start(std::move(snapshot_id), snapshot_generation,
                      std::move(service_version));
}

seastar::future<> OtlpTraceExporter::stop() { return impl_->stop(); }

TraceSpanRecord OtlpTraceExporter::begin_request(
    std::string_view incoming_traceparent) {
  return impl_->begin_request(incoming_traceparent);
}

void OtlpTraceExporter::enqueue(TraceSpanRecord record) noexcept {
  impl_->enqueue(record);
}

bool OtlpTraceExporter::enabled() const noexcept { return impl_->enabled(); }

const OtlpTraceOptions& OtlpTraceExporter::options() const noexcept {
  return impl_->options();
}

const OtlpTraceStats& OtlpTraceExporter::stats() const noexcept {
  return impl_->stats();
}

OtlpTraceStats& OtlpTraceExporter::stats() noexcept { return impl_->stats(); }

}  // namespace bonvoyage::runtime
