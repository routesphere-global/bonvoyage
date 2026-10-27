#include "bonvoyage/runtime/discovery_client.hh"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <exception>
#include <limits>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include <seastar/core/condition-variable.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/coroutine/as_future.hh>
#include <seastar/core/file.hh>
#include <seastar/core/fstream.hh>
#include <seastar/core/gate.hh>
#include <seastar/core/iostream.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/sstring.hh>
#include <seastar/core/timer.hh>
#include <seastar/http/client.hh>
#include <seastar/http/reply.hh>
#include <seastar/http/request.hh>
#include <seastar/net/api.hh>
#include <seastar/net/dns.hh>
#include <seastar/net/tls.hh>
#include <seastar/util/log.hh>
#include <seastar/util/optimized_optional.hh>
#include <seastar/util/short_streams.hh>

#include "bonvoyage/http/grpc_protocol.hh"
#include "bonvoyage/runtime/upstream_http2_client.hh"

namespace bonvoyage::runtime {
namespace {

using namespace std::chrono_literals;

constexpr std::string_view kDiscoveryMethod =
    "/bonvoyage.v1.SnapshotDiscoveryService/StreamSnapshots";
constexpr std::string_view kHttp2Alpn = "h2";
constexpr std::string_view kTls13Priority =
    "NORMAL:-VERS-ALL:+VERS-TLS1.3";
constexpr std::size_t kMaximumEndpointBytes = 253U;
constexpr std::size_t kMaximumAuthorityBytes = 512U;
constexpr std::size_t kMaximumTlsPathBytes = 4096U;
constexpr std::size_t kMaximumResponseHeaderBytes = 16U * 1024U;
constexpr std::size_t kMaximumIdentityBytes = 128U;
constexpr std::size_t kMaximumSchemaVersions = 32U;
constexpr std::size_t kMaximumCapabilities = 16U;
constexpr std::uint32_t kSupportedSchemaVersion = 1U;
constexpr std::uint32_t kSupportedCapabilityVersion = 1U;
constexpr auto kMinimumHeartbeatInterval = 100ms;
constexpr auto kMaximumHeartbeatInterval = std::chrono::minutes(5);
constexpr auto kMinimumTimeout = 100ms;
constexpr auto kMaximumTimeout = std::chrono::minutes(2);
constexpr auto kMinimumReconnectBackoff = 10ms;
constexpr auto kMaximumReconnectBackoff = std::chrono::minutes(5);
constexpr auto kMinimumCredentialReloadTolerance = 100ms;
constexpr auto kMaximumCredentialReloadTolerance = std::chrono::seconds(30);
constexpr std::size_t kMaximumCredentialFailureLogBytes = 256U;
constexpr std::size_t kMaximumCredentialGenerationBytes = 64U * 1024U;

[[nodiscard]] seastar::logger& discovery_logger() {
  static seastar::logger logger{"bonvoyage-discovery-client"};
  return logger;
}

[[nodiscard]] bool contains_control(std::string_view value) noexcept {
  return std::any_of(value.begin(), value.end(), [](char character) {
    const auto byte = static_cast<unsigned char>(character);
    return byte < 0x20U || byte == 0x7fU;
  });
}

[[nodiscard]] bool valid_utf8(std::string_view value) noexcept {
  std::size_t offset = 0U;
  while (offset < value.size()) {
    const auto first = static_cast<std::uint8_t>(value[offset]);
    if (first <= 0x7fU) {
      ++offset;
      continue;
    }

    std::size_t continuation_count = 0U;
    std::uint8_t second_minimum = 0x80U;
    std::uint8_t second_maximum = 0xbfU;
    if (first >= 0xc2U && first <= 0xdfU) {
      continuation_count = 1U;
    } else if (first >= 0xe0U && first <= 0xefU) {
      continuation_count = 2U;
      if (first == 0xe0U) {
        second_minimum = 0xa0U;
      } else if (first == 0xedU) {
        second_maximum = 0x9fU;
      }
    } else if (first >= 0xf0U && first <= 0xf4U) {
      continuation_count = 3U;
      if (first == 0xf0U) {
        second_minimum = 0x90U;
      } else if (first == 0xf4U) {
        second_maximum = 0x8fU;
      }
    } else {
      return false;
    }

    if (offset + continuation_count >= value.size()) {
      return false;
    }
    const auto second = static_cast<std::uint8_t>(value[offset + 1U]);
    if (second < second_minimum || second > second_maximum) {
      return false;
    }
    for (std::size_t index = 2U; index <= continuation_count; ++index) {
      const auto byte = static_cast<std::uint8_t>(value[offset + index]);
      if (byte < 0x80U || byte > 0xbfU) {
        return false;
      }
    }
    offset += continuation_count + 1U;
  }
  return true;
}

[[nodiscard]] bool identity_character(char character) noexcept {
  return (character >= 'a' && character <= 'z') ||
         (character >= 'A' && character <= 'Z') ||
         (character >= '0' && character <= '9') || character == '.' ||
         character == '_' || character == '-' || character == ':';
}

void validate_identity_identifier(std::string_view value,
                                  std::string_view field_name) {
  if (value.empty() || value.size() > kMaximumIdentityBytes ||
      !std::all_of(value.begin(), value.end(), identity_character)) {
    throw std::invalid_argument(std::string(field_name) +
                                " must contain 1-128 supported ASCII bytes");
  }
  const auto first = value.front();
  if (first == '.' || first == ':' || first == '-') {
    throw std::invalid_argument(std::string(field_name) +
                                " has an unsupported leading character");
  }
}

[[nodiscard]] bool known_identity_capability(
    bonvoyage::v1::NodeCapabilityType capability) noexcept {
  switch (capability) {
    case bonvoyage::v1::NODE_CAPABILITY_TYPE_TWO_PHASE_ROLLOUT:
    case bonvoyage::v1::NODE_CAPABILITY_TYPE_EXACT_ARTIFACT_ROLLBACK:
    case bonvoyage::v1::NODE_CAPABILITY_TYPE_HEARTBEAT_STATE_REPORT:
      return true;
    case bonvoyage::v1::NODE_CAPABILITY_TYPE_UNSPECIFIED:
    default:
      return false;
  }
}

void validate_endpoint_component(std::string_view value, std::size_t maximum,
                                 std::string_view forbidden,
                                 std::string_view name) {
  if (value.empty() || value.size() > maximum || contains_control(value) ||
      value.find_first_of(forbidden) != std::string_view::npos) {
    throw std::invalid_argument(std::string(name) + " is invalid");
  }
}

void validate_tls_path(std::string_view value, std::string_view name) {
  if (value.empty() || value.size() > kMaximumTlsPathBytes ||
      contains_control(value)) {
    throw std::invalid_argument(std::string(name) +
                                " must name a bounded PEM file");
  }
}

[[nodiscard]] bool ascii_case_equal(std::string_view left,
                                    std::string_view right) noexcept {
  return left.size() == right.size() &&
         std::equal(left.begin(), left.end(), right.begin(),
                    [](char lhs, char rhs) {
                      const auto left_byte = static_cast<unsigned char>(lhs);
                      const auto right_byte = static_cast<unsigned char>(rhs);
                      if (left_byte >= 'A' && left_byte <= 'Z') {
                        return static_cast<unsigned char>(left_byte +
                                                          ('a' - 'A')) ==
                               right_byte;
                      }
                      if (right_byte >= 'A' && right_byte <= 'Z') {
                        return left_byte ==
                               static_cast<unsigned char>(right_byte +
                                                          ('a' - 'A'));
                      }
                      return left_byte == right_byte;
                    });
}

void validate_authority_binding(const DiscoveryClientConfig& config) {
  auto host = std::string_view(config.authority);
  const auto colon = host.rfind(':');
  if (colon != std::string_view::npos) {
    if (host.find(':') != colon || colon == 0U || colon + 1U == host.size()) {
      throw std::invalid_argument("discovery authority port is invalid");
    }
    std::uint32_t port = 0U;
    const auto port_text = host.substr(colon + 1U);
    const auto [end, error] = std::from_chars(
        port_text.data(), port_text.data() + port_text.size(), port);
    if (error != std::errc{} || end != port_text.data() + port_text.size() ||
        port == 0U || port > 65535U) {
      throw std::invalid_argument("discovery authority port is invalid");
    }
    host = host.substr(0U, colon);
  }
  if (!ascii_case_equal(host, config.server_name)) {
    throw std::invalid_argument(
        "discovery authority host must match the verified TLS server name");
  }
}

[[nodiscard]] std::string exception_message(
    const std::exception_ptr& failure) noexcept {
  try {
    if (failure != nullptr) {
      std::rethrow_exception(failure);
    }
  } catch (const std::exception& error) {
    return error.what();
  } catch (...) {
    return "unknown discovery failure";
  }
  return "discovery operation ended without an error";
}

[[nodiscard]] std::string bounded_failure_message(
    const std::exception_ptr& failure) {
  auto message = exception_message(failure);
  for (auto& character : message) {
    const auto byte = static_cast<unsigned char>(character);
    if (byte < 0x20U || byte == 0x7fU) {
      character = '?';
    }
  }
  if (message.size() > kMaximumCredentialFailureLogBytes) {
    message.resize(kMaximumCredentialFailureLogBytes);
  }
  return message;
}

void saturating_increment(std::uint64_t& value) noexcept {
  if (value != std::numeric_limits<std::uint64_t>::max()) {
    ++value;
  }
}

[[nodiscard]] std::string serialize_request(
    const bonvoyage::v1::StreamSnapshotsRequest& request,
    std::size_t maximum_message_bytes) {
  std::string protobuf;
  if (!request.SerializeToString(&protobuf)) {
    throw std::runtime_error("discovery request protobuf serialization failed");
  }
  return frame_grpc_message(protobuf, maximum_message_bytes);
}

seastar::future<std::string> read_credential_generation(
    const std::string& path) {
  auto file = co_await seastar::open_file_dma(
      seastar::sstring(path), seastar::open_flags::ro);
  const auto size = co_await file.size();
  if (size == 0U || size > kMaximumCredentialGenerationBytes) {
    co_await file.close().handle_exception([](const std::exception_ptr&) {});
    throw std::runtime_error(
        "discovery credential generation marker is empty or unbounded");
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

seastar::future<seastar::shared_ptr<seastar::tls::certificate_credentials>>
build_discovery_credentials(const DiscoveryClientConfig& config) {
  seastar::tls::credentials_builder builder;
  // Seastar exposes GnuTLS priorities rather than a min/max-version setter.
  // Rejecting failure here prevents an accidental downgrade below TLS 1.3.
  builder.set_priority_string(seastar::sstring(kTls13Priority));
  co_await builder.set_x509_trust_file(
      seastar::sstring(config.trust_bundle_file),
      seastar::tls::x509_crt_format::PEM);
  co_await builder.set_x509_key_file(
      seastar::sstring(config.client_certificate_file),
      seastar::sstring(config.client_private_key_file),
      seastar::tls::x509_crt_format::PEM);
  co_return builder.build_certificate_credentials();
}

[[nodiscard]] std::string hello_frame(
    const DiscoveryNodeIdentity& identity,
    const SnapshotPreparationState& state, std::uint32_t shard_count,
    std::size_t maximum_message_bytes) {
  bonvoyage::v1::StreamSnapshotsRequest request;
  *request.mutable_hello() = build_node_hello(identity, state, shard_count);
  return serialize_request(request, maximum_message_bytes);
}

[[nodiscard]] std::string heartbeat_frame(
    const DiscoveryNodeIdentity& identity,
    const SnapshotPreparationState& state, std::uint32_t shard_count,
    std::size_t maximum_message_bytes) {
  bonvoyage::v1::StreamSnapshotsRequest request;
  *request.mutable_heartbeat() = build_node_heartbeat(
      identity, state, shard_count, std::chrono::system_clock::now());
  return serialize_request(request, maximum_message_bytes);
}

[[nodiscard]] std::uint64_t command_sequence(
    const SnapshotLifecycleCommand& command) noexcept {
  return std::visit(
      [](const auto& value) { return value.rollout_sequence; }, command);
}

[[nodiscard]] bonvoyage::v1::RolloutOperation command_operation(
    const SnapshotLifecycleCommand& command) noexcept {
  return std::visit(
      [](const auto& value) {
        using Command = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<Command, SnapshotPrepareCommand>) {
          return bonvoyage::v1::ROLLOUT_OPERATION_PREPARE;
        } else if constexpr (std::is_same_v<Command,
                                            SnapshotActivateCommand>) {
          return bonvoyage::v1::ROLLOUT_OPERATION_ACTIVATE;
        } else {
          return bonvoyage::v1::ROLLOUT_OPERATION_CANCEL;
        }
      },
      command);
}

void validate_report(const bonvoyage::v1::NodeRolloutReport& report,
                     const DiscoveryNodeIdentity& identity,
                     std::uint64_t expected_sequence,
                     bonvoyage::v1::RolloutOperation expected_operation) {
  if (report.node_id() != identity.node_id ||
      report.process_instance_id() != identity.process_instance_id ||
      report.rollout_sequence() != expected_sequence ||
      report.operation() != expected_operation ||
      (report.result() != bonvoyage::v1::ACKNOWLEDGEMENT_RESULT_ACK &&
       report.result() != bonvoyage::v1::ACKNOWLEDGEMENT_RESULT_NACK)) {
    throw std::invalid_argument(
        "discovery command handler returned a mismatched rollout report");
  }
}

[[nodiscard]] std::string report_frame(
    const bonvoyage::v1::NodeRolloutReport& report,
    std::size_t maximum_message_bytes) {
  bonvoyage::v1::StreamSnapshotsRequest request;
  *request.mutable_rollout_report() = report;
  return serialize_request(request, maximum_message_bytes);
}

[[nodiscard]] std::string_view as_view(const seastar::sstring& value) {
  return {value.data(), value.size()};
}

class DiscoveryAttempt final {
 public:
  DiscoveryAttempt(const DiscoveryClientConfig& config,
                   const DiscoveryNodeIdentity& identity,
                   std::uint32_t shard_count,
                   DiscoveryStateProvider state_provider,
                   DiscoveryCommandHandler command_handler)
      : config_(config),
        identity_(identity),
        shard_count_(shard_count),
        state_provider_(std::move(state_provider)),
        command_handler_(std::move(command_handler)),
        request_timer_([this] {
          request_timed_out_ = true;
          request_stop();
        }),
        heartbeat_timer_([this] {
          heartbeat_due_ = true;
          outbound_ready_.broadcast();
        }) {
    abort_subscription_ = abort_.subscribe([this]() noexcept {
      outbound_ready_.broadcast();
      report_space_.broadcast();
      report_complete_.broadcast();
    });
  }

  ~DiscoveryAttempt() {
    request_timer_.cancel();
    heartbeat_timer_.cancel();
  }

  DiscoveryAttempt(const DiscoveryAttempt&) = delete;
  DiscoveryAttempt& operator=(const DiscoveryAttempt&) = delete;

  void transport_ready() {
    if (transport_ready_) {
      throw std::logic_error("discovery transport became ready twice");
    }
    transport_ready_ = true;
    request_timer_.arm(seastar::timer<>::clock::now() +
                       config_.request_timeout);
  }

  void request_stop() noexcept {
    request_timer_.cancel();
    heartbeat_timer_.cancel();
    abort_.request_abort();
    outbound_ready_.broadcast();
    report_space_.broadcast();
    report_complete_.broadcast();
  }

  [[nodiscard]] bool request_timed_out() const noexcept {
    return request_timed_out_;
  }

  [[nodiscard]] bool stable() const noexcept { return stable_; }

  [[nodiscard]] seastar::abort_source& abort() noexcept { return abort_; }

  seastar::future<> write_request(seastar::output_stream<char>&& output) {
    std::exception_ptr failure;
    try {
      const auto hello = hello_frame(identity_, state_provider_(), shard_count_,
                                     config_.max_message_bytes);
      co_await output.write(hello.data(), hello.size());
      co_await output.flush();
      request_timer_.cancel();
      heartbeat_timer_.arm_periodic(config_.heartbeat_interval);

      while (!abort_.abort_requested()) {
        co_await outbound_ready_.wait([this] {
          return abort_.abort_requested() || pending_report_.has_value() ||
                 heartbeat_due_;
        });
        if (abort_.abort_requested()) {
          throw seastar::abort_requested_exception{};
        }

        std::string frame;
        std::uint64_t report_epoch = 0U;
        if (pending_report_.has_value()) {
          report_epoch = pending_report_->first;
          frame = std::move(pending_report_->second);
          pending_report_.reset();
          report_space_.broadcast();
        } else {
          heartbeat_due_ = false;
          frame = heartbeat_frame(identity_, state_provider_(), shard_count_,
                                  config_.max_message_bytes);
        }

        co_await output.write(frame.data(), frame.size());
        co_await output.flush();
        if (report_epoch != 0U) {
          delivered_report_epoch_ = report_epoch;
          report_complete_.broadcast();
        } else {
          stable_ = true;
        }
      }
    } catch (...) {
      failure = std::current_exception();
      request_stop();
    }

    co_await output.close().handle_exception(
        [](const std::exception_ptr&) {});
    if (failure != nullptr) {
      std::rethrow_exception(failure);
    }
  }

  seastar::future<> read_response(const seastar::http::reply& reply,
                                  seastar::input_stream<char>&& input) {
    std::exception_ptr failure;
    try {
      validate_response_head(reply);
      GrpcMessageDeframer decoder(config_.max_message_bytes);
      while (true) {
        auto chunk = co_await input.read();
        if (chunk.empty()) {
          break;
        }
        const auto bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(chunk.get()), chunk.size());
        std::size_t offset = 0U;
        while (offset < bytes.size()) {
          auto decoded = decoder.consume(bytes.subspan(offset));
          if (decoded.consumed == 0U) {
            throw std::runtime_error(
                "discovery gRPC decoder made no input progress");
          }
          offset += decoded.consumed;
          if (decoded.message.has_value()) {
            co_await handle_command(std::move(*decoded.message));
          }
        }
      }
      decoder.finish();
      validate_response_trailers(reply);
      throw std::runtime_error("discovery stream ended unexpectedly");
    } catch (...) {
      failure = std::current_exception();
      request_stop();
    }

    co_await input.close().handle_exception(
        [](const std::exception_ptr&) {});
    if (failure != nullptr) {
      std::rethrow_exception(failure);
    }
  }

 private:
  void validate_response_head(const seastar::http::reply& reply) const {
    if (static_cast<std::uint16_t>(reply._status) != 200U) {
      throw std::runtime_error(
          "discovery RPC returned a non-200 HTTP status");
    }
    const auto content_type = reply.get_header("Content-Type");
    if (!bonvoyage::http::is_grpc_content_type(as_view(content_type))) {
      throw std::runtime_error(
          "discovery RPC response is not application/grpc");
    }
    const auto grpc_encoding = reply.get_header("Grpc-Encoding");
    if (!grpc_encoding.empty() && as_view(grpc_encoding) != "identity") {
      throw std::runtime_error(
          "discovery RPC negotiated unsupported compression");
    }
    if (!reply.get_header("Content-Encoding").empty() ||
        !reply.get_header("Grpc-Status").empty()) {
      throw std::runtime_error(
          "discovery RPC returned forbidden response metadata");
    }
  }

  static void validate_response_trailers(
      const seastar::http::reply& reply) {
    std::vector<bonvoyage::http::Http2Header> trailers;
    trailers.reserve(reply.trailing_headers.size());
    for (const auto& [name, value] : reply.trailing_headers) {
      trailers.push_back(
          {std::string(name), std::string(value), false});
    }
    const auto info =
        bonvoyage::http::validate_grpc_response_trailers(trailers);
    if (info.status != 0U) {
      throw std::runtime_error(
          "discovery RPC ended with a non-zero grpc-status");
    }
  }

  seastar::future<> handle_command(std::string protobuf) {
    auto command = decode_discovery_response(protobuf);
    const auto sequence = command_sequence(command);
    const auto operation = command_operation(command);
    auto report = co_await command_handler_(std::move(command), abort_);
    validate_report(report, identity_, sequence, operation);
    co_await enqueue_report(
        report_frame(report, config_.max_message_bytes));
  }

  seastar::future<> enqueue_report(std::string frame) {
    co_await report_space_.wait([this] {
      return abort_.abort_requested() || !pending_report_.has_value();
    });
    if (abort_.abort_requested()) {
      throw seastar::abort_requested_exception{};
    }
    if (next_report_epoch_ == std::numeric_limits<std::uint64_t>::max()) {
      throw std::overflow_error("discovery report epoch exhausted");
    }
    const auto epoch = ++next_report_epoch_;
    pending_report_.emplace(epoch, std::move(frame));
    outbound_ready_.broadcast();
    co_await report_complete_.wait([this, epoch] {
      return abort_.abort_requested() || delivered_report_epoch_ >= epoch;
    });
    if (abort_.abort_requested() && delivered_report_epoch_ < epoch) {
      throw seastar::abort_requested_exception{};
    }
  }

  const DiscoveryClientConfig& config_;
  const DiscoveryNodeIdentity& identity_;
  std::uint32_t shard_count_;
  DiscoveryStateProvider state_provider_;
  DiscoveryCommandHandler command_handler_;
  seastar::abort_source abort_;
  seastar::optimized_optional<seastar::abort_source::subscription>
      abort_subscription_;
  seastar::condition_variable outbound_ready_;
  seastar::condition_variable report_space_;
  seastar::condition_variable report_complete_;
  seastar::timer<> request_timer_;
  seastar::timer<> heartbeat_timer_;
  std::optional<std::pair<std::uint64_t, std::string>> pending_report_;
  std::uint64_t next_report_epoch_{};
  std::uint64_t delivered_report_epoch_{};
  bool transport_ready_{false};
  bool heartbeat_due_{false};
  bool request_timed_out_{false};
  bool stable_{false};
};

class DiscoveryConnectionFactory final
    : public seastar::http::experimental::connection_factory {
 public:
  DiscoveryConnectionFactory(
      seastar::socket_address address, std::chrono::milliseconds timeout,
      seastar::shared_ptr<seastar::tls::certificate_credentials> credentials,
      seastar::sstring server_name, std::shared_ptr<DiscoveryAttempt> attempt)
      : address_(address),
        timeout_(timeout),
        credentials_(std::move(credentials)),
        server_name_(std::move(server_name)),
        attempt_(std::move(attempt)) {}

  seastar::future<seastar::connected_socket> make(
      seastar::abort_source* abort) override {
    const auto address = address_;
    return seastar::do_with(
        seastar::engine().net().socket(),
        std::optional<seastar::connected_socket>{}, seastar::timer<>{}, false,
        [this, abort, address](seastar::socket& socket,
                              std::optional<seastar::connected_socket>& connection,
                              seastar::timer<>& timer, bool& timed_out) {
          const auto shutdown = [&socket, &connection]() noexcept {
            if (connection.has_value()) {
              try {
                seastar::tls::abort(*connection);
                return;
              } catch (...) {
                connection->shutdown_input();
                connection->shutdown_output();
              }
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
              return seastar::make_exception_future<
                  seastar::connected_socket>(
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
                              seastar::connected_socket>(std::runtime_error(
                              "discovery TCP connect timed out"));
                        }
                        return result;
                      }
                      connection.emplace(result.get());
                      seastar::tls::tls_options options;
                      options.server_name = server_name_;
                      options.verify_certificate = true;
                      options.alpn_protocols.emplace_back(kHttp2Alpn);
                      auto transport = std::move(*connection);
                      connection.reset();
                      return seastar::tls::wrap_client(
                                 credentials_, std::move(transport),
                                 std::move(options))
                          .then([&connection](
                                    seastar::connected_socket secured) {
                            connection.emplace(std::move(secured));
                            return seastar::tls::get_negotiated_alpn(
                                *connection);
                          })
                          .then_wrapped(
                              [this, &connection, &timer,
                               &timed_out](auto negotiated) {
                                timer.cancel();
                                if (timed_out) {
                                  negotiated.ignore_ready_future();
                                  return seastar::make_exception_future<
                                      seastar::connected_socket>(
                                      std::runtime_error(
                                          "discovery TLS handshake timed out"));
                                }
                                if (negotiated.failed()) {
                                  return seastar::make_exception_future<
                                      seastar::connected_socket>(
                                      negotiated.get_exception());
                                }
                                const auto alpn = negotiated.get();
                                if (!alpn.has_value() || *alpn != kHttp2Alpn) {
                                  try {
                                    seastar::tls::abort(*connection);
                                  } catch (...) {
                                  }
                                  return seastar::make_exception_future<
                                      seastar::connected_socket>(
                                      std::runtime_error(
                                          "discovery TLS did not negotiate h2"));
                                }
                                attempt_->transport_ready();
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
  seastar::shared_ptr<seastar::tls::certificate_credentials> credentials_;
  seastar::sstring server_name_;
  std::shared_ptr<DiscoveryAttempt> attempt_;
};

class DiscoveryCredentialReloadController final {
 public:
  void record_initial_generation() noexcept {
    state_.record_initial_generation();
  }

  void handle_reload(const std::exception_ptr& failure) noexcept {
    if (stopping_) {
      return;
    }
    if (failure != nullptr) {
      state_.record_reload_failure();
      try {
        const auto status = state_.status();
        discovery_logger().warn(
            "discovery credential reload rejected; retaining generation {}: {}",
            status.generation_count, bounded_failure_message(failure));
      } catch (...) {
        discovery_logger().warn(
            "discovery credential reload rejected; retaining active generation");
      }
      return;
    }

    state_.record_reload_success();
    const auto status = state_.status();
    discovery_logger().info(
        "discovery credential generation {} loaded; controlled reconnect requested",
        status.generation_count);
    abort_bound_work();
  }

  void handle_material_unavailable() noexcept {
    if (stopping_) {
      return;
    }
    state_.record_reload_failure();
    try {
      const auto status = state_.status();
      discovery_logger().warn(
          "discovery credential material unavailable after reload tolerance; retaining generation {}",
          status.generation_count);
    } catch (...) {
    }
  }

  void bind_attempt(const std::shared_ptr<DiscoveryAttempt>& attempt) noexcept {
    active_attempt_ = attempt;
    if (stopping_ || state_.status().reconnect_pending) {
      attempt->request_stop();
    }
  }

  void clear_attempt(
      const std::shared_ptr<DiscoveryAttempt>& attempt) noexcept {
    if (const auto active = active_attempt_.lock();
        active != nullptr && active.get() == attempt.get()) {
      active_attempt_.reset();
    }
  }

  void bind_reconnect_wait(
      const std::shared_ptr<seastar::abort_source>& wait_abort) noexcept {
    reconnect_wait_abort_ = wait_abort;
    if (stopping_ || state_.status().reconnect_pending) {
      wait_abort->request_abort();
    }
  }

  void clear_reconnect_wait(
      const std::shared_ptr<seastar::abort_source>& wait_abort) noexcept {
    if (const auto active = reconnect_wait_abort_.lock();
        active != nullptr && active.get() == wait_abort.get()) {
      reconnect_wait_abort_.reset();
    }
  }

  [[nodiscard]] bool consume_reconnect_request() noexcept {
    return state_.consume_reconnect_request();
  }

  [[nodiscard]] DiscoveryCredentialStatus status() const noexcept {
    return state_.status();
  }

  void begin_stop() noexcept {
    stopping_ = true;
    abort_bound_work();
    active_attempt_.reset();
    reconnect_wait_abort_.reset();
  }

 private:
  void abort_bound_work() noexcept {
    if (const auto attempt = active_attempt_.lock(); attempt != nullptr) {
      attempt->request_stop();
    }
    if (const auto wait_abort = reconnect_wait_abort_.lock();
        wait_abort != nullptr && !wait_abort->abort_requested()) {
      wait_abort->request_abort();
    }
  }

  DiscoveryCredentialReloadState state_;
  std::weak_ptr<DiscoveryAttempt> active_attempt_;
  std::weak_ptr<seastar::abort_source> reconnect_wait_abort_;
  bool stopping_{};
};

}  // namespace

void validate_discovery_client_config(const DiscoveryClientConfig& config) {
  validate_endpoint_component(config.endpoint_address, kMaximumEndpointBytes,
                              "/[]:@?# ", "discovery endpoint address");
  if (config.endpoint_port == 0U) {
    throw std::invalid_argument("discovery endpoint port must be non-zero");
  }
  validate_endpoint_component(config.authority, kMaximumAuthorityBytes,
                              "/[]@?# ", "discovery authority");
  validate_endpoint_component(config.server_name, kMaximumEndpointBytes,
                              "/[]:@?# ", "discovery TLS server name");
  validate_authority_binding(config);
  validate_tls_path(config.trust_bundle_file, "discovery trust bundle");
  validate_tls_path(config.client_certificate_file,
                    "discovery client certificate");
  validate_tls_path(config.client_private_key_file,
                    "discovery client private key");
  if (!config.credential_generation_file.empty()) {
    validate_tls_path(config.credential_generation_file,
                      "discovery credential generation marker");
  }
  if (config.heartbeat_interval < kMinimumHeartbeatInterval ||
      config.heartbeat_interval > kMaximumHeartbeatInterval) {
    throw std::invalid_argument(
        "discovery heartbeat interval must be between 100 ms and 5 minutes");
  }
  if (config.connect_timeout < kMinimumTimeout ||
      config.connect_timeout > kMaximumTimeout ||
      config.request_timeout < kMinimumTimeout ||
      config.request_timeout > kMaximumTimeout) {
    throw std::invalid_argument(
        "discovery connect and request timeouts must be between 100 ms and 2 minutes");
  }
  if (config.reconnect_initial_backoff < kMinimumReconnectBackoff ||
      config.reconnect_initial_backoff > kMaximumReconnectBackoff ||
      config.reconnect_max_backoff < config.reconnect_initial_backoff ||
      config.reconnect_max_backoff > kMaximumReconnectBackoff) {
    throw std::invalid_argument(
        "discovery reconnect backoff bounds are invalid");
  }
  if (config.max_message_bytes == 0U ||
      config.max_message_bytes > kMaximumDiscoveryMessageBytes) {
    throw std::invalid_argument(
        "discovery message limit must be between 1 byte and the protocol maximum");
  }
  if (config.credential_reload_tolerance <
          kMinimumCredentialReloadTolerance ||
      config.credential_reload_tolerance >
          kMaximumCredentialReloadTolerance) {
    throw std::invalid_argument(
        "discovery credential reload tolerance must be between 100 ms and 30 seconds");
  }
}

void validate_discovery_node_identity(const DiscoveryNodeIdentity& identity) {
  validate_identity_identifier(identity.node_id, "discovery node_id");
  validate_identity_identifier(identity.process_instance_id,
                               "discovery process_instance_id");
  if (identity.dataplane_version.size() > kMaximumIdentityBytes ||
      !valid_utf8(identity.dataplane_version) ||
      contains_control(identity.dataplane_version) ||
      std::none_of(identity.dataplane_version.begin(),
                   identity.dataplane_version.end(), [](char character) {
                     return static_cast<unsigned char>(character) > 0x20U;
                   })) {
    throw std::invalid_argument(
        "discovery dataplane_version is missing, malformed, or unbounded");
  }

  if (identity.supported_schema_versions.empty() ||
      identity.supported_schema_versions.size() > kMaximumSchemaVersions) {
    throw std::invalid_argument(
        "discovery schema version count must be between 1 and 32");
  }
  auto schemas = identity.supported_schema_versions;
  std::sort(schemas.begin(), schemas.end());
  if (schemas.front() == 0U ||
      std::adjacent_find(schemas.begin(), schemas.end()) != schemas.end() ||
      !std::binary_search(schemas.begin(), schemas.end(),
                          kSupportedSchemaVersion)) {
    throw std::invalid_argument(
        "discovery schema versions must be non-zero, unique, and include version 1");
  }

  if (identity.capabilities.empty() ||
      identity.capabilities.size() > kMaximumCapabilities) {
    throw std::invalid_argument(
        "discovery capability count must be between 1 and 16");
  }
  auto capabilities = identity.capabilities;
  std::sort(capabilities.begin(), capabilities.end(),
            [](const SnapshotCapability& left,
               const SnapshotCapability& right) {
              return left.capability < right.capability;
            });
  for (std::size_t index = 0U; index < capabilities.size(); ++index) {
    const auto& capability = capabilities[index];
    if (!known_identity_capability(capability.capability) ||
        capability.version != kSupportedCapabilityVersion) {
      throw std::invalid_argument(
          "discovery capability type or version is unsupported");
    }
    if (index != 0U &&
        capabilities[index - 1U].capability == capability.capability) {
      throw std::invalid_argument("discovery capability type is duplicated");
    }
  }
  const std::vector<SnapshotCapability> required{
      {bonvoyage::v1::NODE_CAPABILITY_TYPE_TWO_PHASE_ROLLOUT, 1U},
      {bonvoyage::v1::NODE_CAPABILITY_TYPE_EXACT_ARTIFACT_ROLLBACK, 1U},
      {bonvoyage::v1::NODE_CAPABILITY_TYPE_HEARTBEAT_STATE_REPORT, 1U},
  };
  if (capabilities != required) {
    throw std::invalid_argument(
        "discovery identity requires the complete Phase 4 capability set");
  }
}

DiscoveryReconnectBackoff::DiscoveryReconnectBackoff(
    std::chrono::milliseconds initial, std::chrono::milliseconds maximum,
    DiscoveryJitterSource jitter)
    : initial_(initial), maximum_(maximum), jitter_(std::move(jitter)) {
  if (initial_ <= 0ms || maximum_ < initial_) {
    throw std::invalid_argument("reconnect backoff bounds are invalid");
  }
}

std::chrono::milliseconds DiscoveryReconnectBackoff::next_delay() {
  auto base = static_cast<std::uint64_t>(initial_.count());
  const auto ceiling = static_cast<std::uint64_t>(maximum_.count());
  for (std::uint32_t exponent = 0U;
       exponent < attempts_ && base < ceiling; ++exponent) {
    base = base > ceiling / 2U ? ceiling : base * 2U;
  }
  base = std::min(base, ceiling);
  if (attempts_ != std::numeric_limits<std::uint32_t>::max()) {
    ++attempts_;
  }
  if (!jitter_) {
    return std::chrono::milliseconds(base);
  }
  const auto floor = base - (base / 4U);
  const auto width = base - floor;
  const auto sample = jitter_(width + 1U) % (width + 1U);
  return std::chrono::milliseconds(floor + sample);
}

void DiscoveryReconnectBackoff::reset() noexcept { attempts_ = 0U; }

std::uint32_t DiscoveryReconnectBackoff::attempts() const noexcept {
  return attempts_;
}

void DiscoveryCredentialReloadState::record_initial_generation() noexcept {
  if (generation_count_ == 0U) {
    generation_count_ = 1U;
    last_outcome_ = "initial_load_succeeded";
  }
}

void DiscoveryCredentialReloadState::record_reload_success() noexcept {
  saturating_increment(generation_count_);
  saturating_increment(successful_reload_count_);
  last_outcome_ = "reload_succeeded";
  reconnect_pending_ = true;
}

void DiscoveryCredentialReloadState::record_reload_failure() noexcept {
  saturating_increment(failed_reload_count_);
  last_outcome_ = "reload_failed";
}

bool DiscoveryCredentialReloadState::consume_reconnect_request() noexcept {
  const auto pending = reconnect_pending_;
  reconnect_pending_ = false;
  return pending;
}

DiscoveryCredentialStatus DiscoveryCredentialReloadState::status()
    const noexcept {
  return DiscoveryCredentialStatus{
      .generation_count = generation_count_,
      .successful_reload_count = successful_reload_count_,
      .failed_reload_count = failed_reload_count_,
      .last_outcome = last_outcome_,
      .reconnect_pending = reconnect_pending_,
  };
}

class DiscoveryClient::Impl final {
 public:
  Impl(DiscoveryClientConfig config, DiscoveryNodeIdentity identity,
       std::uint32_t shard_count, DiscoveryStateProvider state_provider,
       DiscoveryCommandHandler command_handler, DiscoveryJitterSource jitter)
      : config_(std::move(config)),
        identity_(std::move(identity)),
        shard_count_(shard_count),
        state_provider_(std::move(state_provider)),
        command_handler_(std::move(command_handler)),
        random_(std::random_device{}()),
        backoff_(
            config_.reconnect_initial_backoff, config_.reconnect_max_backoff,
            jitter ? std::move(jitter)
                   : DiscoveryJitterSource([this](std::uint64_t upper_bound) {
                       if (upper_bound <= 1U) {
                         return std::uint64_t{0U};
                       }
                       std::uniform_int_distribution<std::uint64_t>
                           distribution(0U, upper_bound - 1U);
                       return distribution(random_);
                     })) {
    validate_discovery_client_config(config_);
    validate_discovery_node_identity(identity_);
    if (shard_count_ == 0U || !state_provider_ || !command_handler_) {
      throw std::invalid_argument(
          "discovery client requires shards, state provider, and command handler");
    }
  }

  ~Impl() {
    if (running_) {
      discovery_logger().error(
          "discovery client destroyed before asynchronous stop completed");
    }
  }

  seastar::future<> start() {
    if (seastar::this_shard_id() != 0U) {
      throw std::logic_error("discovery client must start on shard zero");
    }
    if (running_) {
      throw std::logic_error("discovery client is already running");
    }
    if (started_once_) {
      throw std::logic_error("discovery client cannot restart after stop");
    }

    auto reload_controller =
        std::make_shared<DiscoveryCredentialReloadController>();
    std::exception_ptr setup_failure;
    try {
      seastar::net::dns_resolver::options resolver_options;
      resolver_options.timeout = config_.connect_timeout;
      resolver_ = std::make_unique<seastar::net::dns_resolver>(
          resolver_options);
      std::optional<std::string> generation;
      if (!config_.credential_generation_file.empty()) {
        generation = co_await read_credential_generation(
            config_.credential_generation_file);
      }
      credentials_ = co_await build_discovery_credentials(config_);
      if (generation.has_value()) {
        const auto confirmed = co_await read_credential_generation(
            config_.credential_generation_file);
        if (confirmed != *generation) {
          throw std::runtime_error(
              "discovery credential generation changed during startup");
        }
        active_credential_generation_ = std::move(*generation);
      }
      reload_controller->record_initial_generation();
    } catch (...) {
      setup_failure = std::current_exception();
    }
    if (setup_failure != nullptr) {
      reload_controller->begin_stop();
      if (resolver_ != nullptr) {
        co_await resolver_->close().handle_exception(
            [](const std::exception_ptr&) {});
        resolver_.reset();
      }
      credentials_ = nullptr;
      discovery_logger().error("discovery credential setup failed: {}",
                               bounded_failure_message(setup_failure));
      std::rethrow_exception(setup_failure);
    }

    reload_controller_ = std::move(reload_controller);
    started_once_ = true;
    running_ = true;
    stopping_ = false;
    (void)seastar::with_gate(supervisor_gate_, [this] {
      return supervise();
    }).handle_exception([this](const std::exception_ptr& failure) {
      if (!stopping_) {
        discovery_logger().error("discovery supervisor stopped: {}",
                                 exception_message(failure));
      }
    });
    if (!config_.credential_generation_file.empty()) {
      (void)seastar::with_gate(supervisor_gate_, [this] {
        return monitor_credential_generation();
      }).handle_exception([this](const std::exception_ptr& failure) {
        if (!stopping_) {
          discovery_logger().error(
              "discovery credential generation monitor stopped: {}",
              bounded_failure_message(failure));
        }
      });
    }
  }

  seastar::future<> stop() noexcept {
    if (!running_) {
      co_return;
    }
    stopping_ = true;
    if (reload_controller_ != nullptr) {
      reload_controller_->begin_stop();
    }
    stop_abort_.request_abort();
    try {
      co_await supervisor_gate_.close();
    } catch (...) {
    }
    if (resolver_ != nullptr) {
      try {
        co_await resolver_->close();
      } catch (...) {
      }
      resolver_.reset();
    }
    credentials_ = nullptr;
    running_ = false;
  }

  [[nodiscard]] bool running() const noexcept { return running_; }

  [[nodiscard]] DiscoveryCredentialStatus credential_status() const noexcept {
    return reload_controller_ != nullptr ? reload_controller_->status()
                                         : DiscoveryCredentialStatus{};
  }

 private:
  seastar::future<> monitor_credential_generation() {
    std::optional<std::string> candidate_generation;
    bool candidate_failure_reported = false;
    bool unavailable_reported = false;
    while (!stopping_) {
      try {
        co_await seastar::sleep_abortable(
            config_.credential_reload_tolerance, stop_abort_);
      } catch (const seastar::abort_requested_exception&) {
        break;
      }
      if (stopping_) {
        break;
      }

      std::optional<std::string> observed;
      try {
        observed = co_await read_credential_generation(
            config_.credential_generation_file);
      } catch (...) {
        if (!unavailable_reported && reload_controller_ != nullptr) {
          reload_controller_->handle_material_unavailable();
          unavailable_reported = true;
        }
        continue;
      }
      unavailable_reported = false;
      if (observed == active_credential_generation_) {
        candidate_generation.reset();
        candidate_failure_reported = false;
        continue;
      }
      if (candidate_generation != observed) {
        candidate_generation = observed;
        candidate_failure_reported = false;
      }

      try {
        auto candidate = co_await build_discovery_credentials(config_);
        const auto confirmed = co_await read_credential_generation(
            config_.credential_generation_file);
        if (confirmed != *observed) {
          candidate_generation.reset();
          candidate_failure_reported = false;
          continue;
        }
        credentials_ = std::move(candidate);
        active_credential_generation_ = std::move(*observed);
        candidate_generation.reset();
        candidate_failure_reported = false;
        if (reload_controller_ != nullptr) {
          reload_controller_->handle_reload(nullptr);
        }
      } catch (...) {
        if (!candidate_failure_reported && reload_controller_ != nullptr) {
          reload_controller_->handle_reload(std::current_exception());
          candidate_failure_reported = true;
        }
      }
    }
  }

  seastar::future<> supervise() {
    while (!stopping_) {
      last_attempt_stable_ = false;
      try {
        co_await run_attempt();
      } catch (const seastar::abort_requested_exception&) {
        if (stopping_) {
          break;
        }
        if (reload_controller_ != nullptr &&
            reload_controller_->status().reconnect_pending) {
          discovery_logger().info(
              "discovery stream drained for credential generation change");
        } else {
          discovery_logger().warn(
              "discovery stream was aborted; reconnecting");
        }
      } catch (...) {
        if (stopping_) {
          break;
        }
        discovery_logger().warn(
            "discovery stream failed: {}; reconnecting",
            exception_message(std::current_exception()));
      }
      if (stopping_) {
        break;
      }
      if (reload_controller_ != nullptr &&
          reload_controller_->consume_reconnect_request()) {
        backoff_.reset();
        continue;
      }
      if (last_attempt_stable_) {
        backoff_.reset();
      }
      const auto delay = backoff_.next_delay();
      auto wait_abort = std::make_shared<seastar::abort_source>();
      if (reload_controller_ != nullptr) {
        reload_controller_->bind_reconnect_wait(wait_abort);
        if (reload_controller_->consume_reconnect_request()) {
          reload_controller_->clear_reconnect_wait(wait_abort);
          backoff_.reset();
          continue;
        }
      }
      try {
        co_await seastar::sleep_abortable(delay, *wait_abort);
      } catch (const seastar::abort_requested_exception&) {
        if (reload_controller_ != nullptr) {
          reload_controller_->clear_reconnect_wait(wait_abort);
        }
        if (stopping_) {
          break;
        }
        if (reload_controller_ != nullptr &&
            reload_controller_->consume_reconnect_request()) {
          backoff_.reset();
          continue;
        }
        continue;
      }
      if (reload_controller_ != nullptr) {
        reload_controller_->clear_reconnect_wait(wait_abort);
      }
    }
  }

  seastar::future<> run_attempt() {
    if (stopping_ || stop_abort_.abort_requested()) {
      throw seastar::abort_requested_exception{};
    }
    auto attempt = std::make_shared<DiscoveryAttempt>(
        config_, identity_, shard_count_, state_provider_, command_handler_);
    if (reload_controller_ != nullptr) {
      reload_controller_->bind_attempt(attempt);
    }
    seastar::optimized_optional<seastar::abort_source::subscription>
        stop_subscription;
    if (stop_abort_.abort_requested()) {
      attempt->request_stop();
    } else {
      stop_subscription = stop_abort_.subscribe(
          [attempt]() noexcept { attempt->request_stop(); });
    }
    const auto address = co_await resolver_->resolve_name(
        seastar::sstring(config_.endpoint_address),
        seastar::net::inet_address::family::INET);
    if (stopping_ || stop_abort_.abort_requested() ||
        attempt->abort().abort_requested()) {
      throw seastar::abort_requested_exception{};
    }
    auto factory = std::make_unique<DiscoveryConnectionFactory>(
        seastar::socket_address{address, config_.endpoint_port},
        config_.connect_timeout, credentials_,
        seastar::sstring(config_.server_name), attempt);
    ShardLocalUpstreamHttp2Client client(
        std::move(factory), 1U, 1U, kMaximumResponseHeaderBytes, {});

    auto request = seastar::http::request::make(
        "POST", config_.authority, std::string(kDiscoveryMethod));
    request._version = "2";
    request._headers["Content-Type"] = "application/grpc";
    request._headers["TE"] = "trailers";
    request._headers["Grpc-Accept-Encoding"] = "identity";
    request.body_writer =
        [attempt](seastar::output_stream<char>&& output) {
          return attempt->write_request(std::move(output));
        };
    auto handler =
        [attempt](const seastar::http::reply& reply,
                  seastar::input_stream<char>&& input) {
          return attempt->read_response(reply, std::move(input));
        };

    std::exception_ptr failure;
    try {
      co_await client.make_request(std::move(request), std::move(handler),
                                   &attempt->abort());
      failure = std::make_exception_ptr(
          std::runtime_error("discovery stream completed unexpectedly"));
    } catch (...) {
      failure = std::current_exception();
    }
    last_attempt_stable_ = attempt->stable();
    const auto request_timed_out = attempt->request_timed_out();
    attempt->request_stop();
    co_await client.close().handle_exception(
        [](const std::exception_ptr&) {});
    if (reload_controller_ != nullptr) {
      reload_controller_->clear_attempt(attempt);
    }
    if (stopping_) {
      throw seastar::abort_requested_exception{};
    }
    if (request_timed_out) {
      throw std::runtime_error(
          "discovery request did not flush NodeHello before its deadline");
    }
    std::rethrow_exception(failure);
  }

  DiscoveryClientConfig config_;
  DiscoveryNodeIdentity identity_;
  std::uint32_t shard_count_;
  DiscoveryStateProvider state_provider_;
  DiscoveryCommandHandler command_handler_;
  std::mt19937_64 random_;
  DiscoveryReconnectBackoff backoff_;
  seastar::abort_source stop_abort_;
  seastar::gate supervisor_gate_;
  std::unique_ptr<seastar::net::dns_resolver> resolver_;
  seastar::shared_ptr<seastar::tls::certificate_credentials> credentials_;
  std::optional<std::string> active_credential_generation_;
  std::shared_ptr<DiscoveryCredentialReloadController> reload_controller_;
  bool started_once_{false};
  bool running_{false};
  bool stopping_{false};
  bool last_attempt_stable_{false};
};

DiscoveryClient::DiscoveryClient(DiscoveryClientConfig config,
                                 DiscoveryNodeIdentity identity,
                                 std::uint32_t shard_count,
                                 DiscoveryStateProvider state_provider,
                                 DiscoveryCommandHandler command_handler,
                                 DiscoveryJitterSource jitter)
    : impl_(std::make_unique<Impl>(
          std::move(config), std::move(identity), shard_count,
          std::move(state_provider), std::move(command_handler),
          std::move(jitter))) {}

DiscoveryClient::~DiscoveryClient() = default;

seastar::future<> DiscoveryClient::start() { return impl_->start(); }

seastar::future<> DiscoveryClient::stop() noexcept { return impl_->stop(); }

bool DiscoveryClient::running() const noexcept { return impl_->running(); }

DiscoveryCredentialStatus DiscoveryClient::credential_status() const noexcept {
  return impl_->credential_status();
}

}  // namespace bonvoyage::runtime
