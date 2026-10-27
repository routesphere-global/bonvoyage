#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <seastar/core/temporary_buffer.hh>
#include <seastar/http/request.hh>

#include "bonvoyage/http/header_view.hh"
#include "bonvoyage/http/request_header_lookup.hh"

namespace bonvoyage::http {

/** Supported HTTP/1 request-body framing modes after validation. */
enum class BodyKind {
  none,            ///< The request carries no body.
  content_length,  ///< A validated Content-Length delimits the body.
  chunked          ///< Transfer-Encoding: chunked delimits the body.
};

/** Validated request-body framing consumed by the downstream connection. */
struct BodyFraming final {
  /** Selected framing mode. */
  BodyKind kind{BodyKind::none};

  /** Declared body length when kind is content_length. */
  std::uint64_t content_length{};
};

/** Borrowed request fields needed by strict HTTP/1 framing validation. */
struct RequestFramingHeaders final {
  /** Borrowed Host field value. */
  std::string_view host;

  /** Borrowed Upgrade field value. */
  std::string_view upgrade;

  /** Borrowed Expect field value. */
  std::string_view expect;

  /** Borrowed Content-Length field value. */
  std::string_view content_length;

  /** Borrowed Transfer-Encoding field value. */
  std::string_view transfer_encoding;
};

/** Borrowed HTTP/1 fields selected during one bounded header-map scan. */
struct SelectedHttp1Headers final {
  /** Selected Host field. */
  RequestHeaderLookupResult host;
  /** Selected Connection field. */
  RequestHeaderLookupResult connection;
  /** Selected Upgrade field. */
  RequestHeaderLookupResult upgrade;
  /** Selected Expect field. */
  RequestHeaderLookupResult expect;
  /** Selected Content-Length field. */
  RequestHeaderLookupResult content_length;
  /** Selected Transfer-Encoding field. */
  RequestHeaderLookupResult transfer_encoding;
  /** Selected Sec-WebSocket-Version field. */
  RequestHeaderLookupResult websocket_version;
  /** Selected Sec-WebSocket-Key field. */
  RequestHeaderLookupResult websocket_key;
  /** Selected Sec-WebSocket-Protocol field. */
  RequestHeaderLookupResult websocket_protocol;
  /** Selected Sec-WebSocket-Extensions field. */
  RequestHeaderLookupResult websocket_extensions;
  /** Selected Origin field. */
  RequestHeaderLookupResult origin;
  /** Selected Access-Control-Request-Method field. */
  RequestHeaderLookupResult cors_method;
  /** Selected Access-Control-Request-Headers field. */
  RequestHeaderLookupResult cors_headers;
  /** Selected X-Forwarded-For field. */
  RequestHeaderLookupResult forwarded_for;
};

/** Selects gateway-owned HTTP/1 fields with one allocation-free map scan. */
[[nodiscard]] SelectedHttp1Headers select_http1_headers(
    const seastar::http::request& request) noexcept;

/** Supported HTTP/1 upstream response-body framing modes after validation. */
enum class ResponseBodyKind {
  none,             ///< The response is forbidden from carrying a body.
  content_length,   ///< A validated Content-Length delimits the body.
  chunked,          ///< Transfer-Encoding: chunked delimits the body.
  close_delimited   ///< Connection closure would delimit the body.
};

/** Validated upstream response framing used by downstream translators. */
struct ResponseBodyFraming final {
  /** Selected framing mode. */
  ResponseBodyKind kind{ResponseBodyKind::none};

  /** Declared representation length, including a HEAD response's length. */
  std::optional<std::uint64_t> content_length;
};

/** A protocol rejection that is safe to return to the downstream peer. */
class RequestError final : public std::runtime_error {
 public:
  /** Constructs a stable downstream error response description. */
  RequestError(std::uint16_t status_code, std::string code,
               const std::string& message, bool close_connection = true);

  /** Returns the HTTP response status. */
  [[nodiscard]] std::uint16_t status_code() const noexcept {
    return status_code_;
  }

  /** Returns the machine-readable error code. */
  [[nodiscard]] const std::string& code() const noexcept { return code_; }

  /** Returns whether the response must terminate the downstream connection. */
  [[nodiscard]] bool close_connection() const noexcept {
    return close_connection_;
  }

 private:
  std::uint16_t status_code_;
  std::string code_;
  bool close_connection_;
};

/** Strictly validates request framing before any upstream bytes are written. */
[[nodiscard]] BodyFraming validate_request(
    const seastar::http::request& request,
    std::uint64_t max_request_body_bytes);

/**
 * Strictly validates request framing using fields selected by the caller.
 *
 * The views are consumed synchronously. This overload lets a connection scan
 * its parsed header block once and reuse the same validated fields throughout
 * the request path.
 */
[[nodiscard]] BodyFraming validate_request(
    const seastar::http::request& request,
    const RequestFramingHeaders& headers,
    std::uint64_t max_request_body_bytes);

/** Returns whether a Host or :authority value uses strict authority form. */
[[nodiscard]] bool valid_host_authority(std::string_view value) noexcept;

/** Strictly validates an HTTP/1 upstream response's body delimiters. */
[[nodiscard]] ResponseBodyFraming validate_response_framing(
    std::string_view method, std::uint16_t status,
    std::string_view content_length, std::string_view transfer_encoding);

/** Returns whether the request method and status permit a response body. */
[[nodiscard]] bool response_allows_body(
    std::string_view method, std::uint16_t status) noexcept;

/** Returns whether a response status permits message content. */
[[nodiscard]] bool response_status_allows_content(
    std::uint16_t status) noexcept;

/** Returns lowercase copies used by route header matching. */
[[nodiscard]] std::unordered_map<std::string, std::string>
normalized_headers(const seastar::http::request& request);

/** Compares two HTTP protocol tokens using ASCII case folding. */
[[nodiscard]] bool ascii_case_equal(std::string_view left,
                                    std::string_view right) noexcept;

/** Returns whether a Content-Type value identifies an SSE event stream. */
[[nodiscard]] bool is_event_stream_content_type(
    std::string_view value) noexcept;

/** Parsed Connection nominations supporting bounded-time header lookup. */
class ConnectionTokenSet final {
 public:
  /** Parses comma-delimited tokens while borrowing the supplied value. */
  explicit ConnectionTokenSet(std::string_view connection);

  /** Returns whether a token was nominated, using ASCII case folding. */
  [[nodiscard]] bool contains(std::string_view token) const noexcept;

 private:
  struct Entry final {
    std::size_t hash{};
    std::string_view token;
  };

  std::vector<Entry> entries_;
};

/** Returns whether a comma-delimited Connection value contains a token. */
[[nodiscard]] bool connection_has_token(std::string_view connection,
                                        std::string_view token);

/** Identifies fixed and Connection-nominated hop-by-hop header names. */
[[nodiscard]] bool is_hop_by_hop_header(
    std::string_view name, const ConnectionTokenSet& connection) noexcept;

/** Convenience overload that parses a Connection value for one lookup. */
[[nodiscard]] bool is_hop_by_hop_header(
    std::string_view name, std::string_view connection);

/** Serializes a complete HTTP/1.1 response head for one buffered write. */
[[nodiscard]] std::string serialize_response_head(
    std::uint16_t status, std::string_view reason,
    const std::vector<std::pair<std::string, std::string>>& headers,
    bool close_connection);

/** Serializes borrowed response fields into the established buffered string. */
[[nodiscard]] std::string serialize_response_head_views(
    std::uint16_t status, std::string_view reason,
    std::span<const HeaderView> headers, bool close_connection);

/**
 * Serializes a response head directly into a movable Seastar buffer.
 *
 * Header views are consumed synchronously and are not retained. This permits
 * the proxy path to borrow the upstream parser's owned fields without making
 * transient string copies before transferring the completed buffer.
 */
[[nodiscard]] seastar::temporary_buffer<char> serialize_response_head_buffer(
    std::uint16_t status, std::string_view reason,
    std::span<const HeaderView> headers, bool close_connection);

/** Returns an ASCII-lowercase copy of a protocol token. */
[[nodiscard]] std::string lowercase(std::string_view value);

/** Removes HTTP optional whitespace from both ends of a field value. */
[[nodiscard]] std::string trim_ows(std::string_view value);

/** Returns a non-owning view with HTTP optional whitespace removed. */
[[nodiscard]] std::string_view trim_ows_view(std::string_view value) noexcept;

}  // namespace bonvoyage::http
