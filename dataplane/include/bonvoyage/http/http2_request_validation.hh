#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "bonvoyage/http/http2_session.hh"

namespace bonvoyage::http {

/** Validated HTTP/2 request metadata safe for routing and HTTP/1 upstreams. */
struct Http2RequestHead final {
  /** Required HTTP method pseudo-header. */
  std::string method;
  /** Required secure scheme for the first TLS-only integration. */
  std::string scheme;
  /** Required routing authority, including an optional port. */
  std::string authority;
  /** Required origin-form request target. */
  std::string path;
  /** Regular end-to-end request headers, preserving input order. */
  std::vector<Http2Header> headers;
  /** Declared body size, or no value for a flow-controlled streaming body. */
  std::optional<std::uint64_t> content_length;
};

/**
 * Validates one final decoded HTTP/2 request-header block.
 *
 * Throws RequestError for a stream-local rejection. The caller remains
 * responsible for checking the authority against TLS SNI and route ownership.
 */
[[nodiscard]] Http2RequestHead validate_http2_request_headers(
    std::span<const Http2Header> headers, bool end_stream,
    std::uint64_t max_request_body_bytes);

}  // namespace bonvoyage::http
