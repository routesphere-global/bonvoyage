#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include "bonvoyage/http/header_view.hh"
#include "bonvoyage/http/websocket_protocol.hh"

namespace {

void require(bool condition, std::string_view message) {
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(EXIT_FAILURE);
  }
}

template <typename Function>
void require_status(Function&& function, std::uint16_t status) {
  try {
    function();
  } catch (const bonvoyage::http::WebSocketHandshakeError& error) {
    require(error.status_code() == status, "unexpected rejection status");
    return;
  }
  require(false, "expected WebSocket handshake rejection");
}

}  // namespace

int main() {
  using bonvoyage::http::HeaderView;
  using bonvoyage::http::validate_websocket_request;
  using bonvoyage::http::validate_websocket_response;

  const auto request = validate_websocket_request(
      "GET", "1.1", "keep-alive, Upgrade", "WebSocket", "13",
      "dGhlIHNhbXBsZSBub25jZQ==", "chat, superchat",
      "permessage-deflate; client_max_window_bits", false);
  require(request.expected_accept == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
          "RFC 6455 accept proof did not match the published vector");
  require(request.offered_subprotocols.size() == 2U,
          "subprotocol offers were not retained");
  require(request.offered_extensions ==
              std::vector<std::string>{"permessage-deflate"},
          "extension offers were not retained");

  const std::vector<HeaderView> valid_response{
      {"Connection", "Upgrade"},
      {"Upgrade", "websocket"},
      {"Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="},
      {"Sec-WebSocket-Protocol", "chat"},
      {"Sec-WebSocket-Extensions", "permessage-deflate"}};
  validate_websocket_response(101U, 1U, 1U, valid_response, request);

  require_status(
      [] {
        (void)validate_websocket_request(
            "POST", "1.1", "Upgrade", "websocket", "13",
            "dGhlIHNhbXBsZSBub25jZQ==", "", "", false);
      },
      400U);
  require_status(
      [] {
        (void)validate_websocket_request(
            "GET", "1.1", "Upgrade", "websocket", "12",
            "dGhlIHNhbXBsZSBub25jZQ==", "", "", false);
      },
      426U);
  require_status(
      [] {
        (void)validate_websocket_request(
            "GET", "1.1", "Upgrade", "websocket", "13", "not-base64",
            "", "", false);
      },
      400U);
  require_status(
      [] {
        (void)validate_websocket_request(
            "GET", "1.1", "Upgrade", "websocket", "13",
            "dGhlIHNhbXBsZSBub25jZQ==", "", "", true);
      },
      400U);

  auto unextended = request;
  unextended.offered_extensions.clear();
  require_status(
      [&] {
        validate_websocket_response(101U, 1U, 1U, valid_response,
                                    unextended);
      },
      502U);
  const std::vector<HeaderView> unoffered_extension{
      {"Connection", "Upgrade"},
      {"Upgrade", "websocket"},
      {"Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="},
      {"Sec-WebSocket-Extensions", "x-unoffered"}};
  require_status(
      [&] {
        validate_websocket_response(101U, 1U, 1U, unoffered_extension,
                                    request);
      },
      502U);
  require_status(
      [] {
        (void)validate_websocket_request(
            "GET", "1.1", "Upgrade", "websocket", "13",
            "dGhlIHNhbXBsZSBub25jZQ==", "", "permessage-deflate; =bad",
            false);
      },
      400U);
  const std::vector<HeaderView> bad_accept{
      {"Connection", "Upgrade"}, {"Upgrade", "websocket"},
      {"Sec-WebSocket-Accept", "invalid"}};
  require_status(
      [&] {
        validate_websocket_response(101U, 1U, 1U, bad_accept, request);
      },
      502U);
  const std::vector<HeaderView> unoffered_protocol{
      {"Connection", "Upgrade"},
      {"Upgrade", "websocket"},
      {"Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="},
      {"Sec-WebSocket-Protocol", "admin"}};
  require_status(
      [&] {
        validate_websocket_response(101U, 1U, 1U, unoffered_protocol,
                                    request);
      },
      502U);
  const std::vector<HeaderView> framed_upgrade{
      {"Connection", "Upgrade"},
      {"Upgrade", "websocket"},
      {"Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="},
      {"Content-Length", "0"}};
  require_status(
      [&] {
        validate_websocket_response(101U, 1U, 1U, framed_upgrade, request);
      },
      502U);

  std::cout << "WebSocket handshake protocol tests passed\n";
  return EXIT_SUCCESS;
}
