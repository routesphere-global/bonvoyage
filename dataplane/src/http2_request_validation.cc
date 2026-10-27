#include "bonvoyage/http/http2_request_validation.hh"

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <string_view>

#include "bonvoyage/http/http1_validation.hh"

namespace bonvoyage::http {
namespace {

[[nodiscard]] bool valid_token(std::string_view value) noexcept {
  if (value.empty()) {
    return false;
  }
  constexpr std::string_view punctuation{"!#$%&'*+-.^_`|~"};
  return std::all_of(value.begin(), value.end(), [punctuation](char character) {
    const auto byte = static_cast<unsigned char>(character);
    return std::isalnum(byte) != 0 || punctuation.find(character) !=
                                         std::string_view::npos;
  });
}

[[nodiscard]] bool safe_value(std::string_view value) noexcept {
  return std::none_of(value.begin(), value.end(), [](char character) {
    const auto byte = static_cast<unsigned char>(character);
    return (byte < 0x20U && byte != '\t') || byte == 0x7fU;
  });
}

[[nodiscard]] bool lowercase_name(std::string_view name) noexcept {
  return std::none_of(name.begin(), name.end(), [](char character) {
    return character >= 'A' && character <= 'Z';
  });
}

[[nodiscard]] bool forbidden_connection_header(
    std::string_view name) noexcept {
  constexpr std::array<std::string_view, 5U> names{
      "connection", "keep-alive", "proxy-connection", "transfer-encoding",
      "upgrade"};
  return std::find(names.begin(), names.end(), name) != names.end();
}

[[nodiscard]] std::uint64_t parse_content_length(std::string_view raw) {
  const auto value = trim_ows_view(raw);
  std::uint64_t result = 0U;
  const auto [position, error] =
      std::from_chars(value.data(), value.data() + value.size(), result, 10);
  if (value.empty() || error != std::errc{} ||
      position != value.data() + value.size()) {
    throw RequestError(400U, "invalid_content_length",
                       "HTTP/2 Content-Length is invalid", false);
  }
  return result;
}

void assign_pseudo(std::string& destination, std::string_view name,
                   std::string_view value) {
  if (!destination.empty()) {
    throw RequestError(400U, "duplicate_pseudo_header",
                       "HTTP/2 pseudo-headers must not be repeated", false);
  }
  destination.assign(value);
  if (!safe_value(destination)) {
    throw RequestError(400U, "invalid_pseudo_header",
                       "HTTP/2 pseudo-header value is unsafe", false);
  }
  (void)name;
}

}  // namespace

Http2RequestHead validate_http2_request_headers(
    std::span<const Http2Header> headers, bool end_stream,
    std::uint64_t max_request_body_bytes) {
  Http2RequestHead result;
  bool regular_header_seen = false;
  bool content_length_seen = false;
  std::optional<std::string_view> host;

  for (const auto& header : headers) {
    const auto name = std::string_view(header.name);
    const auto value = std::string_view(header.value);
    if (name.empty() || !lowercase_name(name) || !safe_value(value)) {
      throw RequestError(400U, "invalid_http2_header",
                         "HTTP/2 request header is invalid", false);
    }
    if (name.front() == ':') {
      if (regular_header_seen) {
        throw RequestError(400U, "pseudo_header_order",
                           "HTTP/2 pseudo-headers must precede regular headers",
                           false);
      }
      if (name == ":method") {
        assign_pseudo(result.method, name, value);
      } else if (name == ":scheme") {
        assign_pseudo(result.scheme, name, value);
      } else if (name == ":authority") {
        assign_pseudo(result.authority, name, value);
      } else if (name == ":path") {
        assign_pseudo(result.path, name, value);
      } else {
        throw RequestError(400U, "unsupported_pseudo_header",
                           "HTTP/2 pseudo-header is unsupported", false);
      }
      continue;
    }

    regular_header_seen = true;
    if (!valid_token(name) || forbidden_connection_header(name)) {
      throw RequestError(400U, "connection_header_forbidden",
                         "Connection-specific HTTP/2 header is forbidden",
                         false);
    }
    if (name == "te" && !ascii_case_equal(trim_ows_view(value), "trailers")) {
      throw RequestError(400U, "invalid_te_header",
                         "HTTP/2 TE may contain only trailers", false);
    }
    if (name == "content-length") {
      if (content_length_seen) {
        throw RequestError(400U, "duplicate_content_length",
                           "HTTP/2 Content-Length must not be repeated", false);
      }
      content_length_seen = true;
      result.content_length = parse_content_length(value);
    } else if (name == "host") {
      if (host.has_value()) {
        throw RequestError(400U, "duplicate_host",
                           "HTTP/2 Host must not be repeated", false);
      }
      host = value;
    }
    result.headers.push_back(header);
  }

  if (!valid_token(result.method) || result.method == "CONNECT") {
    throw RequestError(405U, "unsupported_method",
                       "HTTP/2 method is missing or unsupported", false);
  }
  if (result.scheme != "https") {
    throw RequestError(400U, "invalid_scheme",
                       "TLS HTTP/2 requests require the https scheme", false);
  }
  if (!valid_host_authority(result.authority)) {
    throw RequestError(400U, "invalid_authority",
                       "HTTP/2 authority is missing or invalid", false);
  }
  if (result.path.empty() || result.path.front() != '/' ||
      result.path.find('#') != std::string::npos) {
    throw RequestError(400U, "invalid_path",
                       "HTTP/2 path must use origin form", false);
  }
  if (host.has_value() && !ascii_case_equal(trim_ows_view(*host),
                                             result.authority)) {
    throw RequestError(400U, "host_authority_mismatch",
                       "HTTP/2 Host and authority disagree", false);
  }
  if (result.content_length.value_or(0U) > max_request_body_bytes) {
    throw RequestError(413U, "request_body_too_large",
                       "Request body exceeds the configured limit", false);
  }
  if (end_stream && result.content_length.value_or(0U) != 0U) {
    throw RequestError(400U, "content_length_mismatch",
                       "HTTP/2 stream ended before its declared body", false);
  }
  return result;
}

}  // namespace bonvoyage::http
