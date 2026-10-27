#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

#include <seastar/core/abort_source.hh>
#include <seastar/core/future.hh>
#include <seastar/http/client.hh>
#include <seastar/http/request.hh>

namespace bonvoyage::runtime {

/** Counters and gauges updated by one shard-local upstream HTTP/2 pool. */
struct UpstreamHttp2ClientMetrics final {
  /** Successfully established upstream HTTP/2 connections. */
  std::uint64_t* connections{};
  /** Upstream HTTP/2 transport, TLS, or setup failures. */
  std::uint64_t* connection_failures{};
  /** Fatal HTTP/2 connection-level protocol failures. */
  std::uint64_t* protocol_errors{};
  /** Locally admitted upstream request streams. */
  std::uint64_t* streams{};
  /** Request streams reset by the upstream peer. */
  std::uint64_t* stream_resets{};
  /** GOAWAY frames received from upstream peers. */
  std::uint64_t* goaways{};
  /** Streams cancelled because their downstream request ended. */
  std::uint64_t* request_cancellations{};
  /** Responses carrying a validated trailer block. */
  std::uint64_t* response_trailers{};
  /** Requests that waited for connection or stream capacity. */
  std::uint64_t* pool_waits{};
  /** Currently established, non-retired upstream connections. */
  std::uint64_t* active_connections{};
  /** Currently admitted upstream request streams. */
  std::uint64_t* active_streams{};
};

/**
 * Owns a bounded, multiplexed HTTP/2 connection pool on one Seastar shard.
 *
 * The supplied connection factory must return a TLS transport that negotiated
 * exactly `h2`. Requests never cross shards, peer SETTINGS can only reduce
 * stream admission, response DATA is flow-controlled until its consumer reads
 * it, and a draining or failed connection is replaced without restarting the
 * gateway.
 */
class ShardLocalUpstreamHttp2Client final {
 public:
  /** Callback invoked after a valid final response head is available. */
  using ReplyHandler =
      seastar::http::experimental::client::reply_handler;

  /** Constructs an initially disconnected shard-local pool. */
  ShardLocalUpstreamHttp2Client(
      std::unique_ptr<seastar::http::experimental::connection_factory>
          factory,
      std::uint32_t max_connections,
      std::uint32_t max_streams_per_connection,
      std::size_t max_response_header_bytes,
      UpstreamHttp2ClientMetrics metrics);

  ~ShardLocalUpstreamHttp2Client();

  ShardLocalUpstreamHttp2Client(
      const ShardLocalUpstreamHttp2Client&) = delete;
  ShardLocalUpstreamHttp2Client& operator=(
      const ShardLocalUpstreamHttp2Client&) = delete;

  /** Sends one request without policy retries. */
  seastar::future<> make_request(seastar::http::request request,
                                 ReplyHandler handler,
                                 seastar::abort_source* abort);

  /** Starts graceful GOAWAY drain and closes every owned transport. */
  seastar::future<> close();

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace bonvoyage::runtime
