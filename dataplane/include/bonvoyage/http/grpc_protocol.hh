#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include "bonvoyage/http/http2_session.hh"

namespace bonvoyage::http {

/** Parsed and validated gRPC response-trailer metadata. */
struct GrpcTrailerInfo final {
  /** Canonical gRPC status code carried by the trailer block. */
  std::uint32_t status{};
  /** Application-defined trailing metadata fields. */
  std::size_t custom_metadata_fields{};
};

/** Returns whether a media type selects native gRPC over HTTP/2. */
[[nodiscard]] bool is_grpc_content_type(std::string_view value) noexcept;

/** Returns whether a request target has the conventional /service/method form. */
[[nodiscard]] bool is_grpc_method_path(std::string_view value) noexcept;

/** Parses the bounded gRPC timeout grammar into a saturating duration. */
[[nodiscard]] std::chrono::nanoseconds parse_grpc_timeout(
    std::string_view value);

/** Encodes a positive timeout using at most eight decimal digits. */
[[nodiscard]] std::string format_grpc_timeout(
    std::chrono::nanoseconds value);

/** Validates one application-defined ASCII or binary metadata field. */
void validate_grpc_metadata(std::string_view name, std::string_view value);

/** Validates a complete response trailer block and returns its status. */
[[nodiscard]] GrpcTrailerInfo validate_grpc_response_trailers(
    std::span<const Http2Header> trailers);

/** Percent-encodes a bounded diagnostic for the grpc-message field. */
[[nodiscard]] std::string encode_grpc_message(std::string_view value);

/**
 * Incrementally validates the one-message envelope used by a unary RPC.
 *
 * The validator observes bytes without retaining message payloads. It rejects
 * malformed compression flags, truncated prefixes or payloads, and a second
 * length-prefixed message.
 */
class GrpcUnaryMessageValidator final {
 public:
  /** Creates a validator for the declared request or response encoding. */
  explicit GrpcUnaryMessageValidator(bool compression_allowed) noexcept;

  /** Observes one body fragment and throws on an invalid unary envelope. */
  void consume(std::span<const std::uint8_t> data);

  /** Verifies terminal framing; a request must contain exactly one message. */
  void finish(bool require_message) const;

  /** Returns whether one complete message was observed. */
  [[nodiscard]] bool has_message() const noexcept;

 private:
  std::uint32_t payload_remaining_{};
  std::uint32_t declared_length_{};
  std::uint8_t prefix_[5]{};
  std::size_t prefix_bytes_{};
  bool compression_allowed_{false};
  bool message_started_{false};
  bool message_complete_{false};
};

}  // namespace bonvoyage::http
