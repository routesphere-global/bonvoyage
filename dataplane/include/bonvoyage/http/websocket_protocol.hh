#pragma once

#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "bonvoyage/http/header_view.hh"

namespace bonvoyage::http {

/** A bounded HTTP error produced while validating a WebSocket handshake. */
class WebSocketHandshakeError final : public std::runtime_error {
 public:
  /** Constructs a stable client-facing handshake rejection. */
  WebSocketHandshakeError(std::uint16_t status_code, std::string code,
                          const std::string& message,
                          bool advertise_version = false);

  /** Returns the HTTP status that should reject the handshake. */
  [[nodiscard]] std::uint16_t status_code() const noexcept {
    return status_code_;
  }

  /** Returns the stable machine-readable rejection code. */
  [[nodiscard]] const std::string& code() const noexcept { return code_; }

  /** Returns whether the response must advertise WebSocket version 13. */
  [[nodiscard]] bool advertise_version() const noexcept {
    return advertise_version_;
  }

 private:
  std::uint16_t status_code_;
  std::string code_;
  bool advertise_version_;
};

/** Prepared request metadata retained through the upstream handshake. */
struct WebSocketRequestHandshake final {
  /** Canonical client nonce copied without surrounding HTTP whitespace. */
  std::string client_key;

  /** RFC 6455 accept value that the selected upstream must return. */
  std::string expected_accept;

  /** Bounded set of client-offered subprotocol tokens. */
  std::vector<std::string> offered_subprotocols;

  /** Bounded extension names offered by the client. */
  std::vector<std::string> offered_extensions;
};

/** Returns whether the HTTP fields indicate any WebSocket handshake attempt. */
[[nodiscard]] bool websocket_handshake_attempt(
    std::string_view connection, std::string_view upgrade,
    std::string_view version, std::string_view key,
    std::string_view subprotocols, std::string_view extensions) noexcept;

/** Strictly validates an RFC 6455 client handshake and prepares its proof. */
[[nodiscard]] WebSocketRequestHandshake validate_websocket_request(
    std::string_view method, std::string_view http_version,
    std::string_view connection, std::string_view upgrade,
    std::string_view version, std::string_view key,
    std::string_view subprotocols, std::string_view extensions,
    bool has_request_body);

/**
 * Strictly validates the selected upstream's switching-protocols response.
 *
 * Header views are borrowed only for this call. Duplicate security-sensitive
 * fields, framing fields, unsolicited extensions, and unoffered subprotocols
 * are rejected before any `101` bytes are sent downstream.
 */
void validate_websocket_response(
    std::uint16_t status, std::uint8_t http_major,
    std::uint8_t http_minor, std::span<const HeaderView> headers,
    const WebSocketRequestHandshake& request);

}  // namespace bonvoyage::http
