#include "bonvoyage/http/http1_validation.hh"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <limits>

namespace bonvoyage::http {
namespace {

bool contains_ctl(std::string_view value) {
  return std::any_of(value.begin(), value.end(), [](char c) {
    const auto byte = static_cast<unsigned char>(c);
    return byte < 0x20U || byte == 0x7fU;
  });
}

bool ascii_alnum(char value) {
  return (value >= 'a' && value <= 'z') ||
         (value >= 'A' && value <= 'Z') ||
         (value >= '0' && value <= '9');
}

std::size_t ascii_case_hash(std::string_view value) noexcept {
  std::uint64_t hash = 14695981039346656037ULL;
  for (auto character : value) {
    auto byte = static_cast<unsigned char>(character);
    if (byte >= 'A' && byte <= 'Z') {
      byte = static_cast<unsigned char>(byte + ('a' - 'A'));
    }
    hash ^= byte;
    hash *= 1099511628211ULL;
  }
  return static_cast<std::size_t>(hash);
}

bool valid_port(std::string_view value) {
  if (value.empty()) {
    return false;
  }
  std::uint32_t port = 0U;
  const auto [position, error] =
      std::from_chars(value.data(), value.data() + value.size(), port, 10);
  return error == std::errc{} && position == value.data() + value.size() &&
         port > 0U && port <= 65535U;
}

bool valid_dns_name(std::string_view value) {
  if (value.empty() || value.size() > 253U) {
    return false;
  }
  if (value.back() == '.') {
    value.remove_suffix(1U);
  }
  while (!value.empty()) {
    const auto separator = value.find('.');
    const auto label = value.substr(0U, separator);
    if (label.empty() || label.size() > 63U || !ascii_alnum(label.front()) ||
        !ascii_alnum(label.back()) ||
        !std::all_of(label.begin(), label.end(), [](char character) {
          return ascii_alnum(character) || character == '-';
        })) {
      return false;
    }
    if (separator == std::string_view::npos) {
      return true;
    }
    value.remove_prefix(separator + 1U);
  }
  return false;
}

bool valid_ipv6_literal(std::string_view value) {
  std::array<char, INET6_ADDRSTRLEN> text{};
  if (value.empty() || value.size() >= text.size()) {
    return false;
  }
  std::copy(value.begin(), value.end(), text.begin());
  std::array<unsigned char, 16U> address{};
  return inet_pton(AF_INET6, text.data(), address.data()) == 1;
}

bool valid_host_authority_impl(std::string_view value) {
  if (value.empty() || contains_ctl(value) ||
      value.find_first_of(" ,/@\\") != std::string_view::npos) {
    return false;
  }
  if (value.front() == '[') {
    const auto closing = value.find(']');
    if (closing == std::string_view::npos ||
        !valid_ipv6_literal(value.substr(1U, closing - 1U))) {
      return false;
    }
    const auto remainder = value.substr(closing + 1U);
    return remainder.empty() ||
           (remainder.front() == ':' && valid_port(remainder.substr(1U)));
  }
  const auto colon = value.find(':');
  if (colon == std::string_view::npos) {
    return valid_dns_name(value);
  }
  if (value.find(':', colon + 1U) != std::string_view::npos) {
    return false;
  }
  return valid_dns_name(value.substr(0U, colon)) &&
         valid_port(value.substr(colon + 1U));
}

template <typename Headers>
std::size_t response_head_size(std::string_view reason,
                               const Headers& headers,
                               bool close_connection,
                               std::size_t status_size) {
  constexpr std::string_view prefix = "HTTP/1.1 ";
  constexpr std::string_view separator = " ";
  constexpr std::string_view line_end = "\r\n";
  constexpr std::string_view keep_alive =
      "Connection: keep-alive\r\n\r\n";
  constexpr std::string_view close = "Connection: close\r\n\r\n";
  std::size_t size = prefix.size() + status_size + separator.size() +
                     reason.size() + line_end.size();
  for (const auto& header : headers) {
    const auto& [name, value] = header;
    size += name.size() + 2U + value.size() + line_end.size();
  }
  return size + (close_connection ? close.size() : keep_alive.size());
}

template <typename Headers, typename Append>
void append_response_head(std::string_view status, std::string_view reason,
                          const Headers& headers, bool close_connection,
                          Append append) {
  append("HTTP/1.1 ");
  append(status);
  append(" ");
  append(reason);
  append("\r\n");
  for (const auto& [name, value] : headers) {
    append(name);
    append(": ");
    append(value);
    append("\r\n");
  }
  append(close_connection ? "Connection: close\r\n\r\n"
                          : "Connection: keep-alive\r\n\r\n");
}

std::string_view serialize_status(std::uint16_t status,
                                  std::array<char, 5U>& storage) {
  const auto [position, error] = std::to_chars(
      storage.data(), storage.data() + storage.size(), status, 10);
  if (error != std::errc{}) {
    throw std::logic_error("HTTP response status serialization failed");
  }
  return {storage.data(), static_cast<std::size_t>(position - storage.data())};
}

std::uint64_t parse_content_length(std::string_view value) {
  if (value.empty() || value.find(',') != std::string_view::npos) {
    throw RequestError(400U, "invalid_content_length",
                       "Content-Length must contain one decimal value");
  }
  std::uint64_t length = 0U;
  const auto* begin = value.data();
  const auto* end = begin + value.size();
  const auto [position, error] = std::from_chars(begin, end, length, 10);
  if (error != std::errc{} || position != end) {
    throw RequestError(400U, "invalid_content_length",
                       "Content-Length is not a valid decimal value");
  }
  return length;
}

std::uint64_t parse_response_content_length(std::string_view value) {
  if (value.empty() || value.find(',') != std::string_view::npos) {
    throw std::runtime_error(
        "upstream Content-Length must contain one decimal value");
  }
  std::uint64_t length = 0U;
  const auto* begin = value.data();
  const auto* end = begin + value.size();
  const auto [position, error] = std::from_chars(begin, end, length, 10);
  if (error != std::errc{} || position != end) {
    throw std::runtime_error(
        "upstream Content-Length is not a valid decimal value");
  }
  return length;
}

}  // namespace

bool valid_host_authority(std::string_view value) noexcept {
  return valid_host_authority_impl(value);
}

RequestError::RequestError(std::uint16_t status_code, std::string code,
                           const std::string& message, bool close_connection)
    : std::runtime_error(message),
      status_code_(status_code),
      code_(std::move(code)),
      close_connection_(close_connection) {}

SelectedHttp1Headers select_http1_headers(
    const seastar::http::request& request) noexcept {
  SelectedHttp1Headers selected;
  const auto capture = [](RequestHeaderLookupResult& result,
                          std::string_view value) {
    if (result.present) {
      result.repeated = true;
      return;
    }
    result.value = value;
    result.present = true;
  };
  for (const auto& [name, value] : request._headers) {
    switch (name.size()) {
      case 4U:
        if (ascii_case_equal(name, "host")) {
          capture(selected.host, value);
        }
        break;
      case 6U:
        if (ascii_case_equal(name, "expect")) {
          capture(selected.expect, value);
        } else if (ascii_case_equal(name, "origin")) {
          capture(selected.origin, value);
        }
        break;
      case 7U:
        if (ascii_case_equal(name, "upgrade")) {
          capture(selected.upgrade, value);
        }
        break;
      case 10U:
        if (ascii_case_equal(name, "connection")) {
          capture(selected.connection, value);
        }
        break;
      case 14U:
        if (ascii_case_equal(name, "content-length")) {
          capture(selected.content_length, value);
        }
        break;
      case 15U:
        if (ascii_case_equal(name, "x-forwarded-for")) {
          capture(selected.forwarded_for, value);
        }
        break;
      case 17U:
        if (ascii_case_equal(name, "transfer-encoding")) {
          capture(selected.transfer_encoding, value);
        } else if (ascii_case_equal(name, "sec-websocket-key")) {
          capture(selected.websocket_key, value);
        }
        break;
      case 21U:
        if (ascii_case_equal(name, "sec-websocket-version")) {
          capture(selected.websocket_version, value);
        }
        break;
      case 22U:
        if (ascii_case_equal(name, "sec-websocket-protocol")) {
          capture(selected.websocket_protocol, value);
        }
        break;
      case 24U:
        if (ascii_case_equal(name, "sec-websocket-extensions")) {
          capture(selected.websocket_extensions, value);
        }
        break;
      case 29U:
        if (ascii_case_equal(name, "access-control-request-method")) {
          capture(selected.cors_method, value);
        }
        break;
      case 30U:
        if (ascii_case_equal(name, "access-control-request-headers")) {
          capture(selected.cors_headers, value);
        }
        break;
      default:
        break;
    }
  }
  return selected;
}

std::string lowercase(std::string_view value) {
  std::string result(value);
  std::transform(result.begin(), result.end(), result.begin(), [](char c) {
    return static_cast<char>(
        std::tolower(static_cast<unsigned char>(c)));
  });
  return result;
}

std::string_view trim_ows_view(std::string_view value) noexcept {
  while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
    value.remove_prefix(1U);
  }
  while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
    value.remove_suffix(1U);
  }
  return value;
}

std::string trim_ows(std::string_view value) {
  return std::string(trim_ows_view(value));
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

bool is_event_stream_content_type(std::string_view value) noexcept {
  value = trim_ows_view(value);
  const auto parameter = value.find(';');
  const auto media_type = trim_ows_view(value.substr(0U, parameter));
  return ascii_case_equal(media_type, "text/event-stream");
}

ConnectionTokenSet::ConnectionTokenSet(std::string_view connection) {
  std::size_t offset = 0U;
  while (offset <= connection.size()) {
    const auto separator = connection.find(',', offset);
    const auto candidate = trim_ows_view(connection.substr(
        offset, separator == std::string_view::npos ? std::string_view::npos
                                                    : separator - offset));
    if (!candidate.empty()) {
      entries_.push_back(Entry{ascii_case_hash(candidate), candidate});
    }
    if (separator == std::string_view::npos) {
      break;
    }
    offset = separator + 1U;
  }
  std::sort(entries_.begin(), entries_.end(),
            [](const Entry& left, const Entry& right) {
              return left.hash < right.hash;
            });
}

bool ConnectionTokenSet::contains(std::string_view token) const noexcept {
  const auto hash = ascii_case_hash(token);
  auto candidate = std::lower_bound(
      entries_.begin(), entries_.end(), hash,
      [](const Entry& entry, std::size_t expected) {
        return entry.hash < expected;
      });
  while (candidate != entries_.end() && candidate->hash == hash) {
    if (ascii_case_equal(candidate->token, token)) {
      return true;
    }
    ++candidate;
  }
  return false;
}

bool connection_has_token(std::string_view connection,
                          std::string_view token) {
  return ConnectionTokenSet(connection).contains(token);
}

bool is_hop_by_hop_header(std::string_view name,
                          const ConnectionTokenSet& connection) noexcept {
  constexpr std::array<std::string_view, 8U> fixed{
      "connection", "keep-alive", "proxy-authenticate",
      "proxy-authorization", "te", "trailer", "transfer-encoding",
      "upgrade"};
  if (std::any_of(fixed.begin(), fixed.end(), [name](std::string_view value) {
        return ascii_case_equal(name, value);
      })) {
    return true;
  }
  return connection.contains(name);
}

bool is_hop_by_hop_header(std::string_view name,
                          std::string_view connection) {
  return is_hop_by_hop_header(name, ConnectionTokenSet(connection));
}

std::string serialize_response_head(
    std::uint16_t status, std::string_view reason,
    const std::vector<std::pair<std::string, std::string>>& headers,
    bool close_connection) {
  std::array<char, 5U> status_storage{};
  const auto status_text = serialize_status(status, status_storage);
  std::string result;
  result.reserve(response_head_size(reason, headers, close_connection,
                                    status_text.size()));
  append_response_head(status_text, reason, headers, close_connection,
                       [&result](std::string_view part) {
                         result.append(part);
                       });
  return result;
}

std::string serialize_response_head_views(
    std::uint16_t status, std::string_view reason,
    std::span<const HeaderView> headers, bool close_connection) {
  std::array<char, 5U> status_storage{};
  const auto status_text = serialize_status(status, status_storage);
  std::string result;
  result.reserve(response_head_size(reason, headers, close_connection,
                                    status_text.size()));
  append_response_head(status_text, reason, headers, close_connection,
                       [&result](std::string_view part) {
                         result.append(part);
                       });
  return result;
}

seastar::temporary_buffer<char> serialize_response_head_buffer(
    std::uint16_t status, std::string_view reason,
    std::span<const HeaderView> headers, bool close_connection) {
  std::array<char, 5U> status_storage{};
  const auto status_text = serialize_status(status, status_storage);
  seastar::temporary_buffer<char> result(response_head_size(
      reason, headers, close_connection, status_text.size()));
  auto* cursor = result.get_write();
  append_response_head(status_text, reason, headers, close_connection,
                       [&cursor](std::string_view part) {
                         std::copy(part.begin(), part.end(), cursor);
                         cursor += part.size();
                       });
  return result;
}

BodyFraming validate_request(const seastar::http::request& request,
                             const RequestFramingHeaders& headers,
                             std::uint64_t max_request_body_bytes) {
  if (request._version != "1.0" && request._version != "1.1") {
    throw RequestError(505U, "unsupported_http_version",
                       "Only HTTP/1.0 and HTTP/1.1 are supported");
  }
  if (request._method.empty() || request._method == "CONNECT" ||
      request._method == "TRACE") {
    throw RequestError(405U, "unsupported_method",
                       "The request method is not enabled");
  }
  if (request._url.empty() || request._url.front() != '/') {
    throw RequestError(400U, "invalid_request_target",
                       "Only origin-form request targets are supported");
  }

  const auto host = headers.host;
  if (request._version == "1.1" && host.empty()) {
    throw RequestError(400U, "missing_host", "HTTP/1.1 requires Host");
  }
  if (!host.empty() && !valid_host_authority(host)) {
    throw RequestError(400U, "invalid_host",
                       "Host must contain a valid host and optional port");
  }
  const auto upgrade_value = headers.upgrade;
  const auto upgrade = trim_ows_view(upgrade_value);
  if (!upgrade.empty() && !ascii_case_equal(upgrade, "websocket")) {
    throw RequestError(426U, "upgrade_not_supported",
                       "Only route-enabled WebSocket upgrades are supported");
  }
  if (!headers.expect.empty()) {
    throw RequestError(417U, "expectation_not_supported",
                       "Expect is not enabled in Phase 1");
  }

  const auto content_length_value = headers.content_length;
  const auto transfer_encoding_value = headers.transfer_encoding;
  const auto content_length = trim_ows_view(content_length_value);
  const auto transfer_encoding = trim_ows_view(transfer_encoding_value);
  if (!content_length.empty() && !transfer_encoding.empty()) {
    throw RequestError(400U, "ambiguous_body_framing",
                       "Content-Length and Transfer-Encoding cannot be combined");
  }
  if (!transfer_encoding.empty()) {
    if (!ascii_case_equal(transfer_encoding, "chunked")) {
      throw RequestError(400U, "unsupported_transfer_encoding",
                         "Transfer-Encoding must be exactly chunked");
    }
    return BodyFraming{BodyKind::chunked, 0U};
  }
  if (!content_length.empty()) {
    const auto length = parse_content_length(content_length);
    if (length > max_request_body_bytes) {
      throw RequestError(413U, "request_body_too_large",
                         "Request body exceeds the configured limit");
    }
    return BodyFraming{length == 0U ? BodyKind::none
                                    : BodyKind::content_length,
                       length};
  }
  return {};
}

BodyFraming validate_request(const seastar::http::request& request,
                             std::uint64_t max_request_body_bytes) {
  // Seastar's get_header() returns owning sstrings. Keep them alive while the
  // borrowed overload consumes its views; the gateway's selected-header path
  // instead borrows directly from the request map.
  const auto host = request.get_header("Host");
  const auto upgrade = request.get_header("Upgrade");
  const auto expect = request.get_header("Expect");
  const auto content_length = request.get_header("Content-Length");
  const auto transfer_encoding = request.get_header("Transfer-Encoding");
  const RequestFramingHeaders headers{host, upgrade, expect, content_length,
                                      transfer_encoding};
  return validate_request(request, headers, max_request_body_bytes);
}

bool response_allows_body(std::string_view method,
                          std::uint16_t status) noexcept {
  return method != "HEAD" && response_status_allows_content(status);
}

bool response_status_allows_content(std::uint16_t status) noexcept {
  return status >= 200U && status != 204U && status != 205U &&
         status != 304U;
}

ResponseBodyFraming validate_response_framing(
    std::string_view method, std::uint16_t status,
    std::string_view content_length_value,
    std::string_view transfer_encoding_value) {
  const auto content_length = trim_ows_view(content_length_value);
  const auto transfer_encoding = trim_ows_view(transfer_encoding_value);
  if (!content_length.empty() && !transfer_encoding.empty()) {
    throw std::runtime_error(
        "upstream response combines Content-Length and Transfer-Encoding");
  }
  if (!transfer_encoding.empty() &&
      !ascii_case_equal(transfer_encoding, "chunked")) {
    throw std::runtime_error(
        "upstream Transfer-Encoding must be exactly chunked");
  }

  std::optional<std::uint64_t> parsed_length;
  if (!content_length.empty()) {
    parsed_length = parse_response_content_length(content_length);
  }
  if (!response_allows_body(method, status)) {
    if (!transfer_encoding.empty() ||
        ((status < 200U || status == 204U) && parsed_length.has_value()) ||
        (status == 205U && parsed_length.value_or(0U) != 0U)) {
      throw std::runtime_error(
          "upstream response uses body framing for a bodyless status");
    }
    return ResponseBodyFraming{ResponseBodyKind::none, parsed_length};
  }
  if (!transfer_encoding.empty()) {
    return ResponseBodyFraming{ResponseBodyKind::chunked, std::nullopt};
  }
  if (parsed_length.has_value()) {
    return ResponseBodyFraming{ResponseBodyKind::content_length,
                               parsed_length};
  }
  return ResponseBodyFraming{ResponseBodyKind::close_delimited,
                             std::nullopt};
}

std::unordered_map<std::string, std::string> normalized_headers(
    const seastar::http::request& request) {
  std::unordered_map<std::string, std::string> result;
  result.reserve(request._headers.size());
  for (const auto& [name, value] : request._headers) {
    result.emplace(lowercase(name), std::string(value));
  }
  return result;
}

}  // namespace bonvoyage::http
