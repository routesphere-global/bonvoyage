#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string_view>

#include "bonvoyage/http/grpc_protocol.hh"

namespace {

using bonvoyage::http::GrpcUnaryMessageValidator;
using bonvoyage::http::Http2Header;

void require(bool condition, const char* message) {
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

template <typename Callback>
void require_invalid(Callback callback, const char* message) {
  try {
    callback();
  } catch (const std::invalid_argument&) {
    return;
  }
  require(false, message);
}

void test_content_type_and_path() {
  using bonvoyage::http::is_grpc_content_type;
  using bonvoyage::http::is_grpc_method_path;
  require(is_grpc_content_type("application/grpc"),
          "base gRPC content type was rejected");
  require(is_grpc_content_type("Application/GRPC+proto"),
          "typed gRPC content type was rejected");
  require(!is_grpc_content_type("application/grpc-web"),
          "gRPC-Web was accepted as native gRPC");
  require(is_grpc_method_path("/echo.v1.Echo/Unary"),
          "valid gRPC method path was rejected");
  require(!is_grpc_method_path("/missing-method"),
          "invalid gRPC method path was accepted");
  require(!is_grpc_method_path("/echo/Unary?query=1"),
          "gRPC method path with query was accepted");
}

void test_timeout_round_trip() {
  using bonvoyage::http::format_grpc_timeout;
  using bonvoyage::http::parse_grpc_timeout;
  require(parse_grpc_timeout("10m") == std::chrono::milliseconds(10),
          "millisecond grpc-timeout changed");
  require(parse_grpc_timeout("2S") == std::chrono::seconds(2),
          "second grpc-timeout changed");
  require(format_grpc_timeout(std::chrono::nanoseconds(99'999'999)) ==
              "99999999n",
          "bounded nanosecond timeout encoding changed");
  require(format_grpc_timeout(std::chrono::nanoseconds(100'000'001)) ==
              "100001u",
          "timeout encoding did not round up");
  require_invalid([] { (void)parse_grpc_timeout("0m"); },
                  "zero grpc-timeout was accepted");
  require_invalid([] { (void)parse_grpc_timeout("123456789m"); },
                  "nine-digit grpc-timeout was accepted");
  require_invalid([] { (void)parse_grpc_timeout("10x"); },
                  "unknown grpc-timeout unit was accepted");
}

void test_metadata_and_trailers() {
  using bonvoyage::http::validate_grpc_metadata;
  using bonvoyage::http::validate_grpc_response_trailers;
  validate_grpc_metadata("x-trace-id", "trace-1");
  validate_grpc_metadata("trace-bin", "AQID,BAU=");
  require_invalid(
      [] { validate_grpc_metadata("grpc-private", "value"); },
      "reserved grpc- metadata was accepted");
  require_invalid([] { validate_grpc_metadata("trace-bin", "a"); },
                  "malformed binary metadata was accepted");

  const std::array<Http2Header, 4U> trailers{{
      {"grpc-status", "3", false},
      {"grpc-message", "invalid%20request", false},
      {"grpc-status-details-bin", "AQID", true},
      {"x-trace-id", "trace-1", false},
  }};
  const auto info = validate_grpc_response_trailers(trailers);
  require(info.status == 3U && info.custom_metadata_fields == 1U,
          "valid gRPC trailers changed");
  const std::array<Http2Header, 1U> missing{{
      {"x-trace-id", "trace-1", false},
  }};
  require_invalid(
      [&missing] { (void)validate_grpc_response_trailers(missing); },
      "trailer block without grpc-status was accepted");
  const std::array<Http2Header, 1U> invalid_status{{
      {"grpc-status", "17", false},
  }};
  require_invalid(
      [&invalid_status] {
        (void)validate_grpc_response_trailers(invalid_status);
      },
      "noncanonical grpc-status was accepted");
}

void test_unary_message_envelope() {
  const std::array<std::uint8_t, 8U> message{
      0U, 0U, 0U, 0U, 3U, 'a', 'b', 'c'};
  GrpcUnaryMessageValidator validator(false);
  validator.consume(std::span<const std::uint8_t>(message).first(2U));
  validator.consume(std::span<const std::uint8_t>(message).subspan(2U));
  validator.finish(true);
  require(validator.has_message(), "complete unary message was not observed");

  GrpcUnaryMessageValidator multiple(false);
  require_invalid(
      [&multiple, &message] {
        multiple.consume(message);
        multiple.consume(message);
      },
      "multiple unary messages were accepted");

  GrpcUnaryMessageValidator truncated(false);
  truncated.consume(std::span<const std::uint8_t>(message).first(7U));
  require_invalid([&truncated] { truncated.finish(true); },
                  "truncated unary message was accepted");

  const std::array<std::uint8_t, 5U> compressed{1U, 0U, 0U, 0U, 0U};
  GrpcUnaryMessageValidator no_encoding(false);
  require_invalid([&no_encoding, &compressed] {
    no_encoding.consume(compressed);
  }, "compressed message without grpc-encoding was accepted");
  GrpcUnaryMessageValidator with_encoding(true);
  with_encoding.consume(compressed);
  with_encoding.finish(true);
}

}  // namespace

int main() {
  test_content_type_and_path();
  test_timeout_round_trip();
  test_metadata_and_trailers();
  test_unary_message_envelope();
  std::cout << "gRPC protocol tests passed\n";
  return 0;
}
