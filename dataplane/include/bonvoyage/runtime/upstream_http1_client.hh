#pragma once

#include <chrono>
#include <concepts>
#include <cstddef>
#include <functional>
#include <memory>
#include <string_view>
#include <utility>

#include <seastar/core/abort_source.hh>
#include <seastar/core/future.hh>
#include <seastar/http/client.hh>
#include <seastar/http/request.hh>

namespace bonvoyage::runtime {

/** Receives the exact time spent awaiting shard-local HTTP/1 pool capacity. */
using Http1PoolWaitObserver =
    std::function<void(std::chrono::nanoseconds)>;

/**
 * Behavior-preserving adapter for Seastar's experimental HTTP/1 client.
 *
 * The adapter is the reference side of the upstream-client A/B. Selection is
 * compile-time so production requests do not pay for virtual dispatch.
 */
class SeastarReferenceHttp1Client final {
 public:
  /** Callback invoked after a complete upstream response head is parsed. */
  using ReplyHandler = seastar::http::experimental::client::reply_handler;

  /** Constructs one bounded shard-local connection pool. */
  SeastarReferenceHttp1Client(
      std::unique_ptr<seastar::http::experimental::connection_factory> factory,
      unsigned max_connections, std::size_t max_response_header_bytes,
      std::size_t max_chunk_metadata_bytes,
      Http1PoolWaitObserver pool_wait_observer = {},
      bool trust_connection_reuse = false);

  /** Closes every connection owned by this shard-local client. */
  seastar::future<> close();

  /** Sends one request without internal retries. */
  seastar::future<> make_request(seastar::http::request request,
                                 ReplyHandler handler,
                                 seastar::abort_source* abort);

 private:
  bool trust_connection_reuse_;
  seastar::http::experimental::client client_;
};

/**
 * Bounded shard-local candidate using llhttp for upstream response heads.
 *
 * The candidate owns its transport pool and remains behind a private build
 * selector until correctness, sanitizer, and dedicated-host A/B gates pass.
 */
class LlhttpCandidateHttp1Client final {
 public:
  /** Callback contract shared with the reference client. */
  using ReplyHandler = seastar::http::experimental::client::reply_handler;

  /** Constructs one bounded shard-local connection pool. */
  LlhttpCandidateHttp1Client(
      std::unique_ptr<seastar::http::experimental::connection_factory> factory,
      unsigned max_connections, std::size_t max_response_header_bytes,
      std::size_t max_chunk_metadata_bytes,
      Http1PoolWaitObserver pool_wait_observer = {},
      bool trust_connection_reuse = false);

  ~LlhttpCandidateHttp1Client();

  LlhttpCandidateHttp1Client(const LlhttpCandidateHttp1Client&) = delete;
  LlhttpCandidateHttp1Client& operator=(
      const LlhttpCandidateHttp1Client&) = delete;

  /** Closes idle transports and waits for checked-out transports to return. */
  seastar::future<> close();

  /** Sends one request without internal retries. */
  seastar::future<> make_request(seastar::http::request request,
                                 ReplyHandler handler,
                                 seastar::abort_source* abort);

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

/** Compile-time contract shared by upstream HTTP/1 client implementations. */
template <typename Client>
concept UpstreamHttp1Client = requires(
    Client& client, seastar::http::request request,
    typename Client::ReplyHandler handler, seastar::abort_source* abort) {
  { client.close() } -> std::same_as<seastar::future<>>;
  {
    client.make_request(std::move(request), std::move(handler), abort)
  } -> std::same_as<seastar::future<>>;
};

static_assert(UpstreamHttp1Client<SeastarReferenceHttp1Client>);
static_assert(UpstreamHttp1Client<LlhttpCandidateHttp1Client>);

#if defined(BONVOYAGE_UPSTREAM_HTTP1_CLIENT_SEASTAR_REFERENCE)
/** Active upstream client selected by the private build-time A/B option. */
using SelectedUpstreamHttp1Client = SeastarReferenceHttp1Client;

/** Stable diagnostic name recorded by build and benchmark evidence. */
inline constexpr std::string_view kSelectedUpstreamHttp1Client =
    "seastar-reference";
#elif defined(BONVOYAGE_UPSTREAM_HTTP1_CLIENT_LLHTTP_CANDIDATE)
/** Active private candidate selected for controlled A/B qualification. */
using SelectedUpstreamHttp1Client = LlhttpCandidateHttp1Client;

/** Stable diagnostic name recorded by build and benchmark evidence. */
inline constexpr std::string_view kSelectedUpstreamHttp1Client =
    "llhttp-candidate";
#else
#error "A supported BonVoyage upstream HTTP/1 client must be selected"
#endif

}  // namespace bonvoyage::runtime
