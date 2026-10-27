#pragma once

#include <seastar/core/temporary_buffer.hh>
#include <seastar/http/request.hh>

namespace bonvoyage::http {

/**
 * Serializes one validated HTTP/1.1 upstream request head into one buffer.
 *
 * The caller retains ownership of the request. Invalid request-line or header
 * bytes are rejected before any transport write can occur.
 */
[[nodiscard]] seastar::temporary_buffer<char> serialize_upstream_request_head(
    const seastar::http::request& request);

}  // namespace bonvoyage::http
