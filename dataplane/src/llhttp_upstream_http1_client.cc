#include "bonvoyage/runtime/upstream_http1_client.hh"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <exception>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <seastar/core/condition-variable.hh>
#include <seastar/core/iostream.hh>
#include <seastar/core/when_all.hh>
#include <seastar/http/common.hh>
#include <seastar/http/exception.hh>
#include <seastar/http/internal/content_source.hh>
#include <seastar/http/reply.hh>
#include <seastar/util/log.hh>
#include <seastar/util/optimized_optional.hh>

#include "bonvoyage/http/http1_validation.hh"
#include "bonvoyage/http/upstream_request_serializer.hh"
#include "bonvoyage/http/upstream_response_head_parser.hh"

namespace bonvoyage::runtime {

namespace {

constexpr std::size_t kMaxResponseHeaderFields = 128U;
constexpr std::size_t kMaxInformationalResponses = 8U;
seastar::logger candidate_log("bonvoyage-upstream-client");

class ResponseHeadConsumer final {
 public:
  using Result = seastar::consumption_result<char>;

  explicit ResponseHeadConsumer(
      bonvoyage::http::UpstreamResponseHeadParser& parser)
      : parser_(parser) {}

  seastar::future<Result> operator()(
      seastar::temporary_buffer<char> data) {
    if (data.empty()) {
      return seastar::make_exception_future<Result>(
          seastar::httpd::response_parsing_exception(
              "upstream response ended before its header block"));
    }

    try {
      const auto prior_size = buffered_.size();
      std::optional<bonvoyage::http::ParsedUpstreamResponseHead> parsed;
      if (buffered_.empty()) {
        parsed = parser_.parse({data.get(), data.size()});
      } else {
        buffered_.append(data.get(), data.size());
        parsed = parser_.parse(buffered_);
      }
      if (!parsed.has_value()) {
        if (buffered_.empty()) {
          buffered_.assign(data.get(), data.size());
        }
        return seastar::make_ready_future<Result>(
            seastar::continue_consuming{});
      }

      populate_reply(*parsed);
      if (parsed->bytes_consumed < prior_size) {
        throw bonvoyage::http::UpstreamResponseHeadError(
            "response-head boundary precedes the current input buffer");
      }
      const auto consumed_from_current = parsed->bytes_consumed - prior_size;
      if (consumed_from_current > data.size()) {
        throw bonvoyage::http::UpstreamResponseHeadError(
            "response-head boundary exceeds the current input buffer");
      }
      auto remainder = data.share(consumed_from_current,
                                  data.size() - consumed_from_current);
      return seastar::make_ready_future<Result>(
          seastar::stop_consuming<char>(std::move(remainder)));
    } catch (const std::exception& error) {
      return seastar::make_exception_future<Result>(
          seastar::httpd::response_parsing_exception(error.what()));
    }
  }

  [[nodiscard]] std::unique_ptr<seastar::http::reply> take_reply() {
    if (reply_ == nullptr) {
      throw seastar::httpd::response_parsing_exception(
          "upstream response parser completed without a reply");
    }
    return std::move(reply_);
  }

  [[nodiscard]] bool keep_alive() const noexcept { return keep_alive_; }

 private:
  void populate_reply(
      const bonvoyage::http::ParsedUpstreamResponseHead& parsed) {
    reply_ = std::make_unique<seastar::http::reply>();
    reply_->_status =
        static_cast<seastar::http::reply::status_type>(parsed.status);
    const auto version = std::to_string(parsed.http_major) + "." +
                         std::to_string(parsed.http_minor);
    reply_->_version = seastar::sstring(version);
    reply_->_response_line =
        seastar::sstring(parsed.reason.data(), parsed.reason.size());
    reply_->_headers.reserve(parsed.headers.size());
    for (const auto& header : parsed.headers) {
      auto name = seastar::sstring(header.name.data(), header.name.size());
      auto value = seastar::sstring(header.value.data(), header.value.size());
      reply_->_headers.insert_or_assign(std::move(name), std::move(value));
    }
    keep_alive_ = parsed.keep_alive;
  }

  bonvoyage::http::UpstreamResponseHeadParser& parser_;
  std::string buffered_;
  std::unique_ptr<seastar::http::reply> reply_;
  bool keep_alive_{false};
};

struct ReceivedReply final {
  std::unique_ptr<seastar::http::reply> reply;
  bonvoyage::http::ResponseBodyFraming framing;
  bool keep_alive{false};
};

class CandidateConnection final {
 public:
  CandidateConnection(seastar::connected_socket socket,
                      std::size_t max_response_header_bytes,
                      std::size_t max_chunk_metadata_bytes)
      : socket_(std::move(socket)),
        input_(socket_.input()),
        output_(socket_.output()),
        input_shutdown_(socket_.wait_input_shutdown()),
        response_parser_(max_response_header_bytes,
                         kMaxResponseHeaderFields),
        max_chunk_metadata_bytes_(max_chunk_metadata_bytes) {}

  [[nodiscard]] bool reusable() const noexcept {
    return reusable_ && input_.buffered_bytes() == 0U;
  }

  void invalidate() noexcept { reusable_ = false; }

  void shutdown() noexcept {
    reusable_ = false;
    socket_.shutdown_input();
    socket_.shutdown_output();
  }

  seastar::future<> close() {
    if (closed_) {
      co_return;
    }
    closed_ = true;
    shutdown();
    auto input_closed = input_.close().handle_exception(
        [](const std::exception_ptr&) {});
    auto output_closed = output_.close().handle_exception(
        [](const std::exception_ptr&) {});
    co_await seastar::when_all(std::move(input_closed),
                               std::move(output_closed))
        .discard_result();
    co_await std::move(input_shutdown_).handle_exception(
        [](const std::exception_ptr&) {});
  }

  seastar::future<> make_request(
      seastar::http::request& request,
      LlhttpCandidateHttp1Client::ReplyHandler& handler,
      seastar::abort_source* abort) {
    if (abort != nullptr) {
      abort->check();
    }
    [[maybe_unused]] auto subscription =
        abort != nullptr
            ? abort->subscribe([this]() noexcept { shutdown(); })
            : seastar::optimized_optional<
                  seastar::abort_source::subscription>{};
    try {
      setup_request(request);
      auto serialized_head =
          bonvoyage::http::serialize_upstream_request_head(request);
      const auto has_body =
          static_cast<bool>(request.body_writer) || !request.content.empty();
      if (has_body) {
        // Seastar output streams cannot mix a queued zero-copy packet with
        // buffered writes. Keep a body-bearing head in the stream buffer so
        // the head and framed body are flushed together.
        co_await output_.write(serialized_head.get(), serialized_head.size());
      } else {
        co_await output_.write(std::move(serialized_head));
      }
      candidate_log.trace(
          "queued upstream request head: method={} content_length={} body_writer={} mode={}",
          request._method, request.content_length,
          static_cast<bool>(request.body_writer),
          has_body ? "buffered-with-body" : "zero-copy");

      std::optional<ReceivedReply> received;
      if (!request.get_header("Expect").empty()) {
        co_await output_.flush();
        for (std::size_t count = 0U; count <= kMaxInformationalResponses;
             ++count) {
          auto interim = co_await receive_reply(request._method);
          const auto status =
              static_cast<std::uint16_t>(interim.reply->_status);
          if (status == 100U) {
            break;
          }
          if (status == 101U) {
            throw seastar::httpd::response_parsing_exception(
                "upstream protocol upgrades are not supported");
          }
          if (status >= 200U) {
            received.emplace(std::move(interim));
            break;
          }
          if (count == kMaxInformationalResponses) {
            throw seastar::httpd::response_parsing_exception(
                "upstream sent too many informational responses");
          }
        }
      }
      if (!received.has_value()) {
        candidate_log.trace("starting upstream request body");
        co_await write_body(request);
        candidate_log.trace("upstream request body complete; flushing transport");
        co_await output_.flush();
        candidate_log.trace("upstream request flushed; awaiting response head");
        received.emplace(co_await receive_final_reply(request._method));
      }

      reusable_ = reusable_ && received->keep_alive;
      candidate_log.trace("received upstream response head: status={} reusable={}",
                          static_cast<std::uint16_t>(received->reply->_status),
                          reusable_);
      auto body = body_stream(*received);
      co_await handler(*received->reply, std::move(body));
      if (received->framing.kind ==
              bonvoyage::http::ResponseBodyKind::content_length &&
          received->reply->consumed_content <
              received->reply->content_length) {
        reusable_ = false;
      }
    } catch (...) {
      reusable_ = false;
      if (abort != nullptr && abort->abort_requested()) {
        throw seastar::abort_requested_exception{};
      }
      throw;
    }
  }

 private:
  static void setup_request(seastar::http::request& request) {
    if (request._version.empty()) {
      request._version = "1.1";
    }
    request._bytes_written = 0U;
    if (request.content_length != 0U) {
      if (!request.body_writer && request.content.empty()) {
        throw std::runtime_error(
            "upstream request body has no writer or buffered content");
      }
      request._headers["Content-Length"] =
          seastar::to_sstring(request.content_length);
    }
  }

  seastar::future<> write_body(const seastar::http::request& request) {
    if (request.body_writer) {
      if (request.content_length != 0U) {
        return request
            .body_writer(
                seastar::http::internal::make_http_content_length_output_stream(
                    output_, request.content_length, request._bytes_written))
            .then([&request] {
              if (request._bytes_written != request.content_length) {
                throw std::runtime_error(
                    "upstream request body writer produced a partial body");
              }
            });
      }
      return request
          .body_writer(
              seastar::http::internal::make_http_chunked_output_stream(output_))
          .then([this] { return output_.write("0\r\n\r\n"); });
    }
    if (!request.content.empty()) {
      return output_.write(request.content);
    }
    return seastar::make_ready_future<>();
  }

  seastar::future<ReceivedReply> receive_reply(
      std::string_view request_method) {
    ResponseHeadConsumer consumer(response_parser_);
    co_await input_.consume(consumer);
    auto reply = consumer.take_reply();
    bonvoyage::http::ResponseBodyFraming framing;
    try {
      framing = bonvoyage::http::validate_response_framing(
          request_method, static_cast<std::uint16_t>(reply->_status),
          reply->get_header("Content-Length"),
          reply->get_header("Transfer-Encoding"));
    } catch (const std::exception& error) {
      throw seastar::httpd::response_parsing_exception(error.what());
    }
    if (framing.kind ==
        bonvoyage::http::ResponseBodyKind::close_delimited) {
      throw seastar::httpd::response_parsing_exception(
          "close-delimited upstream responses are not accepted");
    }
    if (framing.content_length.value_or(0U) >
        std::numeric_limits<std::size_t>::max()) {
      throw seastar::httpd::response_parsing_exception(
          "upstream Content-Length exceeds the local address space");
    }
    reply->content_length = framing.content_length.has_value()
                                ? static_cast<std::size_t>(
                                      *framing.content_length)
                                : 0U;
    co_return ReceivedReply{std::move(reply), framing,
                            consumer.keep_alive()};
  }

  seastar::future<ReceivedReply> receive_final_reply(
      std::string_view request_method) {
    for (std::size_t count = 0U; count <= kMaxInformationalResponses;
         ++count) {
      auto received = co_await receive_reply(request_method);
      const auto status =
          static_cast<std::uint16_t>(received.reply->_status);
      if (status == 101U) {
        throw seastar::httpd::response_parsing_exception(
            "upstream protocol upgrades are not supported");
      }
      if (status >= 200U) {
        co_return received;
      }
      if (count == kMaxInformationalResponses) {
        throw seastar::httpd::response_parsing_exception(
            "upstream sent too many informational responses");
      }
    }
    throw seastar::httpd::response_parsing_exception(
        "upstream informational response limit was not enforced");
  }

  seastar::input_stream<char> body_stream(ReceivedReply& received) {
    if (received.framing.kind ==
        bonvoyage::http::ResponseBodyKind::chunked) {
      return seastar::input_stream<char>(seastar::data_source(
          std::make_unique<seastar::httpd::internal::chunked_source_impl>(
              input_, received.reply->chunk_extensions,
              received.reply->trailing_headers,
              max_chunk_metadata_bytes_)));
    }
    const auto body_length =
        received.framing.kind ==
                bonvoyage::http::ResponseBodyKind::content_length
            ? received.reply->content_length
            : 0U;
    return seastar::input_stream<char>(seastar::data_source(
        std::make_unique<seastar::httpd::internal::content_length_source_impl>(
            input_, body_length, &received.reply->consumed_content)));
  }

  seastar::connected_socket socket_;
  seastar::input_stream<char> input_;
  seastar::output_stream<char> output_;
  seastar::future<> input_shutdown_;
  bonvoyage::http::UpstreamResponseHeadParser response_parser_;
  std::size_t max_chunk_metadata_bytes_;
  bool reusable_{true};
  bool closed_{false};
};

}  // namespace

class LlhttpCandidateHttp1Client::Impl final {
 public:
  Impl(std::unique_ptr<seastar::http::experimental::connection_factory> factory,
       unsigned max_connections, std::size_t max_response_header_bytes,
       std::size_t max_chunk_metadata_bytes,
       Http1PoolWaitObserver pool_wait_observer,
       bool trust_connection_reuse)
      : factory_(std::move(factory)),
        max_connections_(max_connections),
        max_response_header_bytes_(max_response_header_bytes),
        max_chunk_metadata_bytes_(max_chunk_metadata_bytes),
        pool_wait_observer_(std::move(pool_wait_observer)),
        trust_connection_reuse_(trust_connection_reuse) {
    if (factory_ == nullptr) {
      throw std::invalid_argument("upstream connection factory is null");
    }
    if (max_connections_ == 0U) {
      throw std::invalid_argument("upstream connection limit is zero");
    }
  }

  seastar::future<> close() {
    if (closing_) {
      co_await available_.wait([this] { return connection_count_ == 0U; });
      co_return;
    }
    closing_ = true;
    available_.broadcast();
    while (!idle_.empty()) {
      auto connection = std::move(idle_.back());
      idle_.pop_back();
      co_await connection->close();
      --connection_count_;
    }
    available_.broadcast();
    co_await available_.wait([this] { return connection_count_ == 0U; });
  }

  seastar::future<> make_request(seastar::http::request request,
                                 ReplyHandler handler,
                                 seastar::abort_source* abort) {
    if (!trust_connection_reuse_) {
      request._headers["Connection"] = "close";
    }
    auto connection = co_await acquire(abort);
    std::exception_ptr failure;
    try {
      co_await connection->make_request(request, handler, abort);
    } catch (...) {
      connection->invalidate();
      failure = std::current_exception();
    }
    co_await release(std::move(connection));
    if (failure != nullptr) {
      std::rethrow_exception(failure);
    }
  }

 private:
  seastar::future<std::unique_ptr<CandidateConnection>> acquire(
      seastar::abort_source* abort) {
    std::optional<std::chrono::steady_clock::time_point> wait_started_at;
    while (true) {
      if (closing_) {
        observe_pool_wait(wait_started_at);
        throw std::runtime_error("upstream client is closing");
      }
      if (abort != nullptr && abort->abort_requested()) {
        observe_pool_wait(wait_started_at);
        abort->check();
      }
      if (!idle_.empty()) {
        auto connection = std::move(idle_.back());
        idle_.pop_back();
        observe_pool_wait(wait_started_at);
        co_return connection;
      }
      if (connection_count_ < max_connections_) {
        observe_pool_wait(wait_started_at);
        ++connection_count_;
        try {
          auto socket = co_await factory_->make(abort);
          co_return std::make_unique<CandidateConnection>(
              std::move(socket), max_response_header_bytes_,
              max_chunk_metadata_bytes_);
        } catch (...) {
          const auto failure = std::current_exception();
          --connection_count_;
          available_.broadcast();
          if (abort != nullptr && abort->abort_requested()) {
            throw seastar::abort_requested_exception{};
          }
          std::rethrow_exception(failure);
        }
      }

      [[maybe_unused]] auto subscription =
          abort != nullptr
              ? abort->subscribe(
                    [this]() noexcept { available_.broadcast(); })
              : seastar::optimized_optional<
                  seastar::abort_source::subscription>{};
      if (!wait_started_at.has_value()) {
        wait_started_at = std::chrono::steady_clock::now();
      }
      co_await available_.wait();
    }
  }

  void observe_pool_wait(
      std::optional<std::chrono::steady_clock::time_point>&
          wait_started_at) noexcept {
    if (!wait_started_at.has_value()) {
      return;
    }
    if (pool_wait_observer_) {
      try {
        pool_wait_observer_(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - *wait_started_at));
      } catch (...) {
        // Observability must not alter HTTP request behavior.
      }
    }
    wait_started_at.reset();
  }

  seastar::future<> release(
      std::unique_ptr<CandidateConnection> connection) {
    if (!closing_ && trust_connection_reuse_ && connection->reusable()) {
      idle_.push_back(std::move(connection));
      available_.signal();
      co_return;
    }
    co_await connection->close();
    --connection_count_;
    available_.broadcast();
  }

  std::unique_ptr<seastar::http::experimental::connection_factory> factory_;
  unsigned max_connections_;
  std::size_t max_response_header_bytes_;
  std::size_t max_chunk_metadata_bytes_;
  Http1PoolWaitObserver pool_wait_observer_;
  bool trust_connection_reuse_;
  std::size_t connection_count_{0U};
  std::vector<std::unique_ptr<CandidateConnection>> idle_;
  seastar::condition_variable available_;
  bool closing_{false};
};

LlhttpCandidateHttp1Client::LlhttpCandidateHttp1Client(
    std::unique_ptr<seastar::http::experimental::connection_factory> factory,
    unsigned max_connections, std::size_t max_response_header_bytes,
    std::size_t max_chunk_metadata_bytes,
    Http1PoolWaitObserver pool_wait_observer, bool trust_connection_reuse)
    : impl_(std::make_unique<Impl>(
          std::move(factory), max_connections, max_response_header_bytes,
          max_chunk_metadata_bytes, std::move(pool_wait_observer),
          trust_connection_reuse)) {}

LlhttpCandidateHttp1Client::~LlhttpCandidateHttp1Client() = default;

seastar::future<> LlhttpCandidateHttp1Client::close() {
  return impl_->close();
}

seastar::future<> LlhttpCandidateHttp1Client::make_request(
    seastar::http::request request, ReplyHandler handler,
    seastar::abort_source* abort) {
  return impl_->make_request(std::move(request), std::move(handler), abort);
}

}  // namespace bonvoyage::runtime
