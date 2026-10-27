#include "bonvoyage/runtime/upstream_http1_client.hh"

#include <optional>

namespace bonvoyage::runtime {

SeastarReferenceHttp1Client::SeastarReferenceHttp1Client(
    std::unique_ptr<seastar::http::experimental::connection_factory> factory,
    unsigned max_connections, std::size_t max_response_header_bytes,
    std::size_t max_chunk_metadata_bytes,
    Http1PoolWaitObserver pool_wait_observer, bool trust_connection_reuse)
    : trust_connection_reuse_(trust_connection_reuse),
      client_(std::move(factory), max_connections,
              seastar::http::experimental::client::retry_requests::no, 0U,
              max_response_header_bytes, max_chunk_metadata_bytes,
              std::move(pool_wait_observer), trust_connection_reuse) {}

seastar::future<> SeastarReferenceHttp1Client::close() {
  return client_.close();
}

seastar::future<> SeastarReferenceHttp1Client::make_request(
    seastar::http::request request, ReplyHandler handler,
    seastar::abort_source* abort) {
  if (!trust_connection_reuse_) {
    request._headers["Connection"] = "close";
  }
  return client_.make_request(std::move(request), std::move(handler),
                              std::nullopt, abort);
}

}  // namespace bonvoyage::runtime
