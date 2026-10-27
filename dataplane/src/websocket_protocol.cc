#include "bonvoyage/http/websocket_protocol.hh"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

namespace bonvoyage::http {

namespace {

constexpr std::string_view kWebSocketGuid =
    "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
constexpr std::size_t kMaximumSubprotocols = 32U;
constexpr std::size_t kMaximumSubprotocolBytes = 128U;
constexpr std::size_t kMaximumExtensions = 32U;
constexpr std::size_t kMaximumExtensionBytes = 4096U;

std::string_view trim_ows(std::string_view value) noexcept {
  while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
    value.remove_prefix(1U);
  }
  while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
    value.remove_suffix(1U);
  }
  return value;
}

bool ascii_case_equal(std::string_view left,
                      std::string_view right) noexcept {
  if (left.size() != right.size()) {
    return false;
  }
  for (std::size_t index = 0U; index < left.size(); ++index) {
    auto left_byte = static_cast<unsigned char>(left[index]);
    auto right_byte = static_cast<unsigned char>(right[index]);
    if (left_byte >= 'A' && left_byte <= 'Z') {
      left_byte = static_cast<unsigned char>(left_byte + ('a' - 'A'));
    }
    if (right_byte >= 'A' && right_byte <= 'Z') {
      right_byte = static_cast<unsigned char>(right_byte + ('a' - 'A'));
    }
    if (left_byte != right_byte) {
      return false;
    }
  }
  return true;
}

bool token_character(unsigned char character) noexcept {
  if ((character >= '0' && character <= '9') ||
      (character >= 'A' && character <= 'Z') ||
      (character >= 'a' && character <= 'z')) {
    return true;
  }
  constexpr std::string_view punctuation{"!#$%&'*+-.^_`|~"};
  return punctuation.find(static_cast<char>(character)) !=
         std::string_view::npos;
}

bool valid_token(std::string_view value) noexcept {
  return !value.empty() &&
         std::all_of(value.begin(), value.end(), [](char character) {
           return token_character(static_cast<unsigned char>(character));
         });
}

bool safe_visible_field(std::string_view value) noexcept {
  return !value.empty() &&
         std::none_of(value.begin(), value.end(), [](char character) {
           const auto byte = static_cast<unsigned char>(character);
           return (byte < 0x20U && byte != '\t') || byte == 0x7fU;
         });
}

std::vector<std::string> parse_token_list(std::string_view value,
                                          std::string_view field) {
  std::vector<std::string> result;
  std::unordered_set<std::string> seen;
  std::size_t offset = 0U;
  while (offset <= value.size()) {
    const auto comma = value.find(',', offset);
    const auto end = comma == std::string_view::npos ? value.size() : comma;
    const auto token = trim_ows(value.substr(offset, end - offset));
    if (!valid_token(token) || token.size() > kMaximumSubprotocolBytes) {
      throw WebSocketHandshakeError(
          400U, "invalid_websocket_handshake",
          std::string(field) + " must contain bounded HTTP tokens");
    }
    if (result.size() == kMaximumSubprotocols) {
      throw WebSocketHandshakeError(
          400U, "invalid_websocket_handshake",
          std::string(field) + " contains too many values");
    }
    auto owned = std::string(token);
    if (!seen.emplace(owned).second) {
      throw WebSocketHandshakeError(
          400U, "invalid_websocket_handshake",
          std::string(field) + " contains a duplicate value");
    }
    result.push_back(std::move(owned));
    if (comma == std::string_view::npos) {
      break;
    }
    offset = comma + 1U;
  }
  return result;
}

[[noreturn]] void reject_extension(std::uint16_t status,
                                   std::string_view code,
                                   std::string_view field) {
  throw WebSocketHandshakeError(
      status, std::string(code),
      std::string(field) + " must contain bounded RFC 6455 extensions");
}

std::string parse_extension_item(std::string_view item,
                                 std::uint16_t status,
                                 std::string_view code,
                                 std::string_view field) {
  item = trim_ows(item);
  std::size_t offset = 0U;
  const auto consume_token = [&item, &offset]() -> std::string_view {
    const auto start = offset;
    while (offset < item.size() &&
           token_character(static_cast<unsigned char>(item[offset]))) {
      ++offset;
    }
    return item.substr(start, offset - start);
  };
  const auto skip_ows = [&item, &offset] {
    while (offset < item.size() &&
           (item[offset] == ' ' || item[offset] == '\t')) {
      ++offset;
    }
  };

  const auto extension = consume_token();
  if (extension.empty() || extension.size() > kMaximumSubprotocolBytes) {
    reject_extension(status, code, field);
  }
  skip_ows();
  while (offset < item.size()) {
    if (item[offset++] != ';') {
      reject_extension(status, code, field);
    }
    skip_ows();
    const auto parameter = consume_token();
    if (parameter.empty() || parameter.size() > kMaximumSubprotocolBytes) {
      reject_extension(status, code, field);
    }
    skip_ows();
    if (offset < item.size() && item[offset] == '=') {
      ++offset;
      skip_ows();
      if (offset == item.size()) {
        reject_extension(status, code, field);
      }
      if (item[offset] == '"') {
        ++offset;
        bool closed = false;
        while (offset < item.size()) {
          const auto character = item[offset++];
          if (character == '\\') {
            if (offset == item.size()) {
              reject_extension(status, code, field);
            }
            ++offset;
          } else if (character == '"') {
            closed = true;
            break;
          }
        }
        if (!closed) {
          reject_extension(status, code, field);
        }
      } else if (consume_token().empty()) {
        reject_extension(status, code, field);
      }
      skip_ows();
    }
  }
  return std::string(extension);
}

std::vector<std::string> parse_extension_names(
    std::string_view value, std::uint16_t status, std::string_view code,
    std::string_view field) {
  if (value.empty() || value.size() > kMaximumExtensionBytes ||
      !safe_visible_field(value)) {
    reject_extension(status, code, field);
  }
  std::vector<std::string> result;
  std::unordered_set<std::string> seen;
  std::size_t item_start = 0U;
  bool quoted = false;
  bool escaped = false;
  for (std::size_t offset = 0U; offset <= value.size(); ++offset) {
    if (offset == value.size() || (!quoted && value[offset] == ',')) {
      auto name = parse_extension_item(
          value.substr(item_start, offset - item_start), status, code, field);
      if (result.size() == kMaximumExtensions ||
          !seen.emplace(name).second) {
        reject_extension(status, code, field);
      }
      result.push_back(std::move(name));
      item_start = offset + 1U;
      continue;
    }
    const auto character = value[offset];
    if (quoted && escaped) {
      escaped = false;
    } else if (quoted && character == '\\') {
      escaped = true;
    } else if (character == '"') {
      quoted = !quoted;
    }
  }
  if (quoted || escaped) {
    reject_extension(status, code, field);
  }
  return result;
}

bool token_list_contains(std::string_view list,
                         std::string_view expected) noexcept {
  std::size_t offset = 0U;
  while (offset <= list.size()) {
    const auto comma = list.find(',', offset);
    const auto end = comma == std::string_view::npos ? list.size() : comma;
    if (ascii_case_equal(trim_ows(list.substr(offset, end - offset)),
                         expected)) {
      return true;
    }
    if (comma == std::string_view::npos) {
      break;
    }
    offset = comma + 1U;
  }
  return false;
}

bool response_connection_is_upgrade(std::string_view list) noexcept {
  bool found = false;
  std::size_t offset = 0U;
  while (offset <= list.size()) {
    const auto comma = list.find(',', offset);
    const auto end = comma == std::string_view::npos ? list.size() : comma;
    const auto token = trim_ows(list.substr(offset, end - offset));
    if (!ascii_case_equal(token, "upgrade") || found) {
      return false;
    }
    found = true;
    if (comma == std::string_view::npos) {
      break;
    }
    offset = comma + 1U;
  }
  return found;
}

int base64_value(char character) noexcept {
  if (character >= 'A' && character <= 'Z') {
    return character - 'A';
  }
  if (character >= 'a' && character <= 'z') {
    return 26 + character - 'a';
  }
  if (character >= '0' && character <= '9') {
    return 52 + character - '0';
  }
  if (character == '+') {
    return 62;
  }
  if (character == '/') {
    return 63;
  }
  return -1;
}

bool valid_websocket_key(std::string_view value) noexcept {
  if (value.size() != 24U || !value.ends_with("==")) {
    return false;
  }
  std::size_t decoded = 0U;
  for (std::size_t offset = 0U; offset < value.size(); offset += 4U) {
    const auto first = base64_value(value[offset]);
    const auto second = base64_value(value[offset + 1U]);
    if (first < 0 || second < 0) {
      return false;
    }
    const bool final = offset + 4U == value.size();
    if (!final) {
      if (base64_value(value[offset + 2U]) < 0 ||
          base64_value(value[offset + 3U]) < 0) {
        return false;
      }
      decoded += 3U;
      continue;
    }
    if (value[offset + 2U] != '=' || value[offset + 3U] != '=' ||
        (second & 0x0f) != 0) {
      return false;
    }
    ++decoded;
  }
  return decoded == 16U;
}

std::string base64_encode(std::span<const unsigned char> input) {
  constexpr std::string_view alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string result;
  result.reserve(((input.size() + 2U) / 3U) * 4U);
  std::size_t offset = 0U;
  while (offset + 3U <= input.size()) {
    const auto value =
        (static_cast<std::uint32_t>(input[offset]) << 16U) |
        (static_cast<std::uint32_t>(input[offset + 1U]) << 8U) |
        static_cast<std::uint32_t>(input[offset + 2U]);
    result.push_back(alphabet[(value >> 18U) & 0x3fU]);
    result.push_back(alphabet[(value >> 12U) & 0x3fU]);
    result.push_back(alphabet[(value >> 6U) & 0x3fU]);
    result.push_back(alphabet[value & 0x3fU]);
    offset += 3U;
  }
  const auto remaining = input.size() - offset;
  if (remaining == 1U) {
    const auto value = static_cast<std::uint32_t>(input[offset]) << 16U;
    result.push_back(alphabet[(value >> 18U) & 0x3fU]);
    result.push_back(alphabet[(value >> 12U) & 0x3fU]);
    result.append("==");
  } else if (remaining == 2U) {
    const auto value =
        (static_cast<std::uint32_t>(input[offset]) << 16U) |
        (static_cast<std::uint32_t>(input[offset + 1U]) << 8U);
    result.push_back(alphabet[(value >> 18U) & 0x3fU]);
    result.push_back(alphabet[(value >> 12U) & 0x3fU]);
    result.push_back(alphabet[(value >> 6U) & 0x3fU]);
    result.push_back('=');
  }
  return result;
}

std::string expected_accept(std::string_view key) {
  std::string proof;
  proof.reserve(key.size() + kWebSocketGuid.size());
  proof.append(key);
  proof.append(kWebSocketGuid);
  std::array<unsigned char, 20U> digest{};
  const auto status = gnutls_hash_fast(
      GNUTLS_DIG_SHA1, proof.data(), proof.size(), digest.data());
  if (status < 0) {
    throw std::runtime_error(std::string("WebSocket SHA-1 failed: ") +
                             gnutls_strerror(status));
  }
  return base64_encode(digest);
}

struct HeaderSelection final {
  std::optional<std::string_view> connection;
  std::optional<std::string_view> upgrade;
  std::optional<std::string_view> accept;
  std::optional<std::string_view> subprotocol;
  std::optional<std::string_view> extensions;
  bool content_length{false};
  bool transfer_encoding{false};
};

void assign_once(std::optional<std::string_view>& destination,
                 std::string_view value, std::string_view field) {
  if (destination.has_value()) {
    throw WebSocketHandshakeError(
        502U, "invalid_upstream_websocket_handshake",
        "The upstream WebSocket response contains duplicate " +
            std::string(field));
  }
  destination = value;
}

HeaderSelection select_headers(std::span<const HeaderView> headers) {
  HeaderSelection result;
  for (const auto& header : headers) {
    if (ascii_case_equal(header.name, "connection")) {
      assign_once(result.connection, header.value, "Connection");
    } else if (ascii_case_equal(header.name, "upgrade")) {
      assign_once(result.upgrade, header.value, "Upgrade");
    } else if (ascii_case_equal(header.name, "sec-websocket-accept")) {
      assign_once(result.accept, header.value, "Sec-WebSocket-Accept");
    } else if (ascii_case_equal(header.name, "sec-websocket-protocol")) {
      assign_once(result.subprotocol, header.value,
                  "Sec-WebSocket-Protocol");
    } else if (ascii_case_equal(header.name, "sec-websocket-extensions")) {
      assign_once(result.extensions, header.value,
                  "Sec-WebSocket-Extensions");
    } else if (ascii_case_equal(header.name, "content-length")) {
      if (result.content_length) {
        throw WebSocketHandshakeError(
            502U, "invalid_upstream_websocket_handshake",
            "The upstream WebSocket response contains duplicate Content-Length");
      }
      result.content_length = true;
    } else if (ascii_case_equal(header.name, "transfer-encoding")) {
      if (result.transfer_encoding) {
        throw WebSocketHandshakeError(
            502U, "invalid_upstream_websocket_handshake",
            "The upstream WebSocket response contains duplicate Transfer-Encoding");
      }
      result.transfer_encoding = true;
    }
  }
  return result;
}

}  // namespace

WebSocketHandshakeError::WebSocketHandshakeError(
    std::uint16_t status_code, std::string code,
    const std::string& message, bool advertise_version)
    : std::runtime_error(message),
      status_code_(status_code),
      code_(std::move(code)),
      advertise_version_(advertise_version) {}

bool websocket_handshake_attempt(
    std::string_view connection, std::string_view upgrade,
    std::string_view version, std::string_view key,
    std::string_view subprotocols, std::string_view extensions) noexcept {
  return !upgrade.empty() || !version.empty() || !key.empty() ||
         !subprotocols.empty() || !extensions.empty() ||
         token_list_contains(connection, "upgrade");
}

WebSocketRequestHandshake validate_websocket_request(
    std::string_view method, std::string_view http_version,
    std::string_view connection, std::string_view upgrade,
    std::string_view version, std::string_view key,
    std::string_view subprotocols, std::string_view extensions,
    bool has_request_body) {
  if (method != "GET" || http_version != "1.1") {
    throw WebSocketHandshakeError(
        400U, "invalid_websocket_handshake",
        "WebSocket handshakes require GET over HTTP/1.1");
  }
  if (!token_list_contains(connection, "upgrade") ||
      !ascii_case_equal(trim_ows(upgrade), "websocket")) {
    throw WebSocketHandshakeError(
        400U, "invalid_websocket_handshake",
        "WebSocket handshakes require Connection: Upgrade and Upgrade: websocket");
  }
  if (trim_ows(version) != "13") {
    throw WebSocketHandshakeError(
        426U, "unsupported_websocket_version",
        "Only WebSocket version 13 is supported", true);
  }
  key = trim_ows(key);
  if (!valid_websocket_key(key)) {
    throw WebSocketHandshakeError(
        400U, "invalid_websocket_handshake",
        "Sec-WebSocket-Key must be canonical base64 for exactly 16 bytes");
  }
  if (has_request_body) {
    throw WebSocketHandshakeError(
        400U, "invalid_websocket_handshake",
        "WebSocket handshakes must not contain a request body");
  }
  WebSocketRequestHandshake result;
  result.client_key = std::string(key);
  result.expected_accept = expected_accept(key);
  if (!subprotocols.empty()) {
    result.offered_subprotocols =
        parse_token_list(subprotocols, "Sec-WebSocket-Protocol");
  }
  if (!extensions.empty()) {
    result.offered_extensions = parse_extension_names(
        extensions, 400U, "invalid_websocket_handshake",
        "Sec-WebSocket-Extensions");
  }
  return result;
}

void validate_websocket_response(
    std::uint16_t status, std::uint8_t http_major,
    std::uint8_t http_minor, std::span<const HeaderView> headers,
    const WebSocketRequestHandshake& request) {
  if (status != 101U || http_major != 1U || http_minor != 1U) {
    throw WebSocketHandshakeError(
        502U, "invalid_upstream_websocket_handshake",
        "The upstream did not return HTTP/1.1 101 Switching Protocols");
  }
  const auto selected = select_headers(headers);
  if (!selected.connection.has_value() ||
      !response_connection_is_upgrade(*selected.connection) ||
      !selected.upgrade.has_value() ||
      !ascii_case_equal(trim_ows(*selected.upgrade), "websocket")) {
    throw WebSocketHandshakeError(
        502U, "invalid_upstream_websocket_handshake",
        "The upstream WebSocket response is missing its upgrade fields");
  }
  if (!selected.accept.has_value() ||
      trim_ows(*selected.accept) != request.expected_accept) {
    throw WebSocketHandshakeError(
        502U, "invalid_upstream_websocket_handshake",
        "The upstream Sec-WebSocket-Accept proof is invalid");
  }
  if (selected.content_length || selected.transfer_encoding) {
    throw WebSocketHandshakeError(
        502U, "invalid_upstream_websocket_handshake",
        "The upstream 101 response must not contain HTTP body framing");
  }
  if (selected.subprotocol.has_value()) {
    const auto protocol = trim_ows(*selected.subprotocol);
    if (!valid_token(protocol) ||
        std::find(request.offered_subprotocols.begin(),
                  request.offered_subprotocols.end(), protocol) ==
            request.offered_subprotocols.end()) {
      throw WebSocketHandshakeError(
          502U, "invalid_upstream_websocket_handshake",
          "The upstream selected an unoffered WebSocket subprotocol");
    }
  }
  if (selected.extensions.has_value()) {
    const auto selected_extensions = parse_extension_names(
        *selected.extensions, 502U, "invalid_upstream_websocket_handshake",
        "The upstream Sec-WebSocket-Extensions field");
    for (const auto& extension : selected_extensions) {
      if (std::find(request.offered_extensions.begin(),
                    request.offered_extensions.end(), extension) ==
          request.offered_extensions.end()) {
        throw WebSocketHandshakeError(
            502U, "invalid_upstream_websocket_handshake",
            "The upstream selected an unoffered WebSocket extension");
      }
    }
  }
}

}  // namespace bonvoyage::http
