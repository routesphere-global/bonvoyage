#include "bonvoyage/runtime/upstream_http2_client.hh"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <exception>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <nghttp2/nghttp2.h>

#include <seastar/core/condition-variable.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/gate.hh>
#include <seastar/core/iostream.hh>
#include <seastar/core/loop.hh>
#include <seastar/core/queue.hh>
#include <seastar/core/semaphore.hh>
#include <seastar/core/when_all.hh>
#include <seastar/http/reply.hh>
#include <seastar/net/api.hh>
#include <seastar/net/packet.hh>
#include <seastar/util/defer.hh>
#include <seastar/util/optimized_optional.hh>

#include "bonvoyage/http/http2_client_session.hh"
#include "bonvoyage/http/grpc_protocol.hh"

namespace bonvoyage::runtime {
namespace {

constexpr std::size_t kInputBufferBytes = 16U * 1024U;
constexpr std::size_t kRequestChunkBytes = 16U * 1024U;
constexpr std::size_t kResponseQueueChunks = 1'024U;
constexpr std::size_t kMaximumInformationalResponses = 8U;

class Http2PoolClosed final : public std::runtime_error {
 public:
  Http2PoolClosed() : std::runtime_error("upstream HTTP/2 pool is closed") {}
};

class Http2ConnectionUnavailable final : public std::runtime_error {
 public:
  Http2ConnectionUnavailable()
      : std::runtime_error("upstream HTTP/2 connection is unavailable") {}
};

class Http2PeerGoaway final : public std::runtime_error {
 public:
  Http2PeerGoaway()
      : std::runtime_error(
            "upstream HTTP/2 peer did not accept the request stream") {}
};

void increment(std::uint64_t* value) noexcept {
  if (value != nullptr) {
    ++*value;
  }
}

void decrement(std::uint64_t* value) noexcept {
  if (value != nullptr && *value != 0U) {
    --*value;
  }
}

[[nodiscard]] std::string lowercase(std::string_view value) {
  std::string result(value);
  std::transform(result.begin(), result.end(), result.begin(), [](char byte) {
    return static_cast<char>(
        std::tolower(static_cast<unsigned char>(byte)));
  });
  return result;
}

[[nodiscard]] bool forbidden_request_header(
    std::string_view name) noexcept {
  constexpr std::array<std::string_view, 7U> forbidden{
      "connection", "host", "keep-alive", "proxy-connection",
      "transfer-encoding", "upgrade", "http2-settings"};
  return std::find(forbidden.begin(), forbidden.end(), name) !=
         forbidden.end();
}

[[nodiscard]] bool sensitive_request_header(
    std::string_view name) noexcept {
  return name == "authorization" || name == "cookie" ||
         name == "proxy-authorization";
}

[[nodiscard]] std::vector<bonvoyage::http::Http2Header>
make_request_headers(const seastar::http::request& request) {
  const auto authority = request.get_header("Host");
  if (request._method.empty() || authority.empty() || request._url.empty()) {
    throw std::invalid_argument(
        "upstream HTTP/2 request requires method, authority, and path");
  }

  std::vector<bonvoyage::http::Http2Header> headers;
  headers.reserve(request._headers.size() + 5U);
  headers.push_back({":method", std::string(request._method), false});
  headers.push_back({":scheme", "https", false});
  headers.push_back({":authority", std::string(authority), false});
  headers.push_back({":path", std::string(request._url), false});

  for (const auto& [raw_name, raw_value] : request._headers) {
    auto name = lowercase(raw_name);
    if (forbidden_request_header(name) || name == "content-length") {
      continue;
    }
    if (name == "te" && raw_value != "trailers") {
      continue;
    }
    const auto never_index = sensitive_request_header(name);
    headers.push_back(
        {std::move(name), std::string(raw_value), never_index});
  }
  if (request.content_length != 0U) {
    headers.push_back(
        {"content-length", std::to_string(request.content_length), false});
  }
  return headers;
}

[[nodiscard]] bool request_has_body(
    const seastar::http::request& request) noexcept {
  return static_cast<bool>(request.body_writer) || !request.content.empty() ||
         request.content_length != 0U;
}

class LiveHttp2Connection;

struct LiveHttp2Stream final {
  LiveHttp2Stream(std::int32_t stream_id,
                  std::weak_ptr<LiveHttp2Connection> connection,
                  bool grpc)
      : stream_id(stream_id),
        connection(std::move(connection)),
        grpc(grpc),
        response_body(kResponseQueueChunks),
        response_head_future(response_head_promise.get_future()) {}

  void set_response_head(std::unique_ptr<seastar::http::reply> value) {
    if (response_head_set) {
      throw std::logic_error(
          "upstream HTTP/2 final response head was delivered twice");
    }
    reply = std::move(value);
    response_head_set = true;
    response_head_promise.set_value();
  }

  void finish_response() {
    if (response_terminal) {
      return;
    }
    response_terminal = true;
    if (!response_body.push(seastar::temporary_buffer<char>{})) {
      response_failed = true;
      response_body.abort(std::make_exception_ptr(std::runtime_error(
          "upstream HTTP/2 response queue exhausted its terminal reserve")));
    }
  }

  void fail(const std::exception_ptr& error) noexcept {
    if (!response_head_set) {
      response_head_set = true;
      response_head_promise.set_exception(error);
    }
    if (!response_terminal) {
      response_terminal = true;
      response_failed = true;
      response_body.abort(error);
    }
  }

  std::int32_t stream_id;
  std::weak_ptr<LiveHttp2Connection> connection;
  bool grpc{false};
  seastar::queue<seastar::temporary_buffer<char>> response_body;
  seastar::promise<> response_head_promise;
  seastar::future<> response_head_future;
  std::unique_ptr<seastar::http::reply> reply;
  std::size_t informational_responses{};
  bool response_head_set{false};
  bool response_terminal{false};
  bool response_failed{false};
  bool request_terminal{false};
  bool locally_cancelled{false};
};

class Http2ResponseBodySource final : public seastar::data_source_impl {
 public:
  explicit Http2ResponseBodySource(
      std::shared_ptr<LiveHttp2Stream> stream)
      : stream_(std::move(stream)) {}

  seastar::future<seastar::temporary_buffer<char>> get() override;
  seastar::future<> close() override;

 private:
  std::shared_ptr<LiveHttp2Stream> stream_;
  bool closed_{false};
};

class Http2RequestBodySink final : public seastar::data_sink_impl {
 public:
  Http2RequestBodySink(std::shared_ptr<LiveHttp2Connection> connection,
                       std::shared_ptr<LiveHttp2Stream> stream,
                       std::optional<std::size_t> expected_bytes)
      : connection_(std::move(connection)),
        stream_(std::move(stream)),
        expected_bytes_(expected_bytes) {}

  seastar::future<> put(seastar::net::packet data) override;
  seastar::future<> flush() override {
    return seastar::make_ready_future<>();
  }
  seastar::future<> close() override;
  std::size_t buffer_size() const noexcept override {
    return kRequestChunkBytes;
  }

 private:
  std::shared_ptr<LiveHttp2Connection> connection_;
  std::shared_ptr<LiveHttp2Stream> stream_;
  std::optional<std::size_t> expected_bytes_;
  std::size_t written_bytes_{};
  bool closed_{false};
};

class LiveHttp2Connection final
    : public std::enable_shared_from_this<LiveHttp2Connection> {
 public:
  using CapacityNotifier = std::function<void()>;

  LiveHttp2Connection(
      std::uint32_t max_streams,
      std::size_t max_response_header_bytes,
      UpstreamHttp2ClientMetrics metrics,
      CapacityNotifier capacity_notifier)
      : metrics_(metrics),
        capacity_notifier_(std::move(capacity_notifier)) {
    bonvoyage::http::Http2ClientLimits limits;
    limits.max_concurrent_streams = max_streams;
    limits.max_header_list_bytes = static_cast<std::uint32_t>(
        std::min<std::size_t>(max_response_header_bytes,
                              std::numeric_limits<std::uint32_t>::max()));
    limits.max_queued_event_bytes = std::max<std::size_t>(
        limits.max_queued_event_bytes, max_response_header_bytes * 2U);
    session_ =
        std::make_unique<bonvoyage::http::Http2ClientSession>(limits);
  }

  ~LiveHttp2Connection() = default;

  seastar::future<> start(
      seastar::http::experimental::connection_factory& factory,
      seastar::abort_source* abort) {
    try {
      socket_.emplace(co_await factory.make(abort));
    } catch (...) {
      fail_connection(std::current_exception());
      throw;
    }
    input_.emplace(socket_->input(
        seastar::connected_socket_input_stream_config{
            .buffer_size = kInputBufferBytes,
            .min_buffer_size = 512U,
            .max_buffer_size = kInputBufferBytes}));
    output_.emplace(socket_->output(kInputBufferBytes));
    connected_ = true;
    increment(metrics_.connections);
    increment(metrics_.active_connections);
    co_await pump_output();
    auto self = shared_from_this();
    (void)seastar::with_gate(background_gate_, [self] {
      return self->read_loop();
    }).handle_exception([self](const std::exception_ptr& error) {
      self->fail_connection(error);
    });
  }

  [[nodiscard]] bool try_reserve() noexcept {
    if (!can_accept()) {
      return false;
    }
    ++reservations_;
    return true;
  }

  [[nodiscard]] bool can_accept() const noexcept {
    return connected_ && !failed_ && !closing_ &&
           !session_->is_draining() &&
           session_->available_stream_capacity() > reservations_;
  }

  [[nodiscard]] bool failed() const noexcept { return failed_; }
  [[nodiscard]] bool draining() const noexcept {
    return session_->is_draining();
  }
  [[nodiscard]] bool retireable() const noexcept {
    return failed_ || (draining() && active_streams() == 0U);
  }
  [[nodiscard]] std::size_t active_streams() const noexcept {
    return streams_.size() + reservations_;
  }

  seastar::future<> make_reserved_request(
      seastar::http::request request,
      ShardLocalUpstreamHttp2Client::ReplyHandler handler,
      seastar::abort_source* abort) {
    if (reservations_ == 0U) {
      throw std::logic_error(
          "upstream HTTP/2 request has no stream reservation");
    }
    --reservations_;
    const auto grpc = bonvoyage::http::is_grpc_content_type(
        request.get_header("Content-Type"));
    auto headers = make_request_headers(request);
    const auto has_body = request_has_body(request);
    const auto stream_id = session_->submit_request(headers, !has_body);
    auto stream = std::make_shared<LiveHttp2Stream>(
        stream_id, weak_from_this(), grpc);
    if (!streams_.emplace(stream_id, stream).second) {
      session_->reset_stream(stream_id, NGHTTP2_INTERNAL_ERROR);
      throw std::logic_error("duplicate upstream HTTP/2 stream id");
    }
    increment(metrics_.streams);
    increment(metrics_.active_streams);
    capacity_notifier_();

    seastar::optimized_optional<seastar::abort_source::subscription>
        subscription;
    if (abort != nullptr) {
      if (abort->abort_requested()) {
        co_await cancel_stream(stream, true);
        throw seastar::abort_requested_exception{};
      }
      auto weak = weak_from_this();
      subscription = abort->subscribe([weak, stream]() noexcept {
        if (auto self = weak.lock()) {
          self->cancel_from_callback(stream);
        }
      });
    }

    auto send = send_request_body(stream, std::move(request))
                    .handle_exception([stream](std::exception_ptr error) {
                      stream->fail(error);
                      return seastar::make_exception_future<>(error);
                    });
    auto receive = receive_response(stream, std::move(handler));
    receive = std::move(receive).handle_exception(
        [self = shared_from_this(), stream](
            std::exception_ptr error) {
          return self->cancel_and_rethrow(stream, std::move(error));
        });

    std::exception_ptr operation_error;
    try {
      co_await seastar::when_all_succeed(std::move(send),
                                        std::move(receive));
    } catch (...) {
      operation_error = std::current_exception();
    }
    if (operation_error != nullptr) {
      co_await cancel_stream(stream, false).handle_exception(
          [](const std::exception_ptr&) {});
      std::rethrow_exception(operation_error);
    }
  }

  seastar::future<> submit_request_data(
      const std::shared_ptr<LiveHttp2Stream>& stream,
      std::span<const std::uint8_t> data, bool end_stream) {
    std::size_t offset = 0U;
    do {
      if (failed_ || stream->locally_cancelled) {
        throw seastar::abort_requested_exception{};
      }
      const auto remaining = data.size() - offset;
      const auto size = std::min(kRequestChunkBytes, remaining);
      const auto final_fragment = offset + size == data.size();
      const auto fragment_end = end_stream && final_fragment;
      const auto fragment = data.subspan(offset, size);
      bool accepted = false;
      std::uint64_t observed_epoch = 0U;
      {
        auto units = co_await seastar::get_units(session_mutex_, 1U);
        accepted = session_->try_submit_data(stream->stream_id, fragment,
                                             fragment_end);
        observed_epoch = progress_epoch_;
      }
      if (accepted) {
        offset += size;
        if (fragment_end) {
          stream->request_terminal = true;
        }
        co_await pump_output();
        if (data.empty()) {
          break;
        }
        continue;
      }
      co_await progress_.wait([this, &stream, observed_epoch] {
        return failed_ || stream->locally_cancelled ||
               progress_epoch_ != observed_epoch;
      });
    } while (offset < data.size() || (data.empty() && end_stream));
  }

  seastar::future<> acknowledge_response_data(
      std::int32_t stream_id, std::size_t bytes) {
    if (bytes == 0U || failed_) {
      co_return;
    }
    {
      auto units = co_await seastar::get_units(session_mutex_, 1U);
      session_->acknowledge_data(stream_id, bytes);
      ++progress_epoch_;
      progress_.broadcast();
    }
    co_await pump_output();
  }

  seastar::future<> cancel_stream(
      const std::shared_ptr<LiveHttp2Stream>& stream,
      bool downstream_cancelled) {
    if (stream->locally_cancelled ||
        (stream->response_terminal && !stream->response_failed)) {
      co_return;
    }
    stream->locally_cancelled = true;
    if (downstream_cancelled) {
      increment(metrics_.request_cancellations);
    }
    stream->fail(std::make_exception_ptr(
        seastar::abort_requested_exception{}));
    if (!failed_) {
      {
        auto units = co_await seastar::get_units(session_mutex_, 1U);
        session_->reset_stream(stream->stream_id, NGHTTP2_CANCEL);
        ++progress_epoch_;
        progress_.broadcast();
      }
      co_await pump_output();
    }
  }

  seastar::future<> close() {
    if (closed_) {
      co_return;
    }
    closing_ = true;
    capacity_notifier_();
    if (connected_ && !failed_ && !session_->is_draining()) {
      {
        auto units = co_await seastar::get_units(session_mutex_, 1U);
        session_->begin_graceful_shutdown();
      }
      co_await pump_output().handle_exception(
          [](const std::exception_ptr&) {});
    }
    fail_connection(std::make_exception_ptr(Http2PoolClosed{}), false);
    if (socket_.has_value()) {
      socket_->shutdown_input();
      socket_->shutdown_output();
    }
    co_await background_gate_.close();
    if (input_.has_value()) {
      co_await input_->close().handle_exception(
          [](const std::exception_ptr&) {});
    }
    if (output_.has_value()) {
      co_await output_->close().handle_exception(
          [](const std::exception_ptr&) {});
    }
    closed_ = true;
  }

 private:
  seastar::future<> receive_response(
      const std::shared_ptr<LiveHttp2Stream>& stream,
      ShardLocalUpstreamHttp2Client::ReplyHandler handler) {
    co_await pump_output();
    co_await std::move(stream->response_head_future);
    auto body = seastar::input_stream<char>(seastar::data_source(
        std::make_unique<Http2ResponseBodySource>(stream)));
    co_await handler(*stream->reply, std::move(body));
  }

  seastar::future<> cancel_and_rethrow(
      const std::shared_ptr<LiveHttp2Stream>& stream,
      std::exception_ptr error) {
    co_await cancel_stream(stream, false).handle_exception(
        [](const std::exception_ptr&) {});
    std::rethrow_exception(error);
  }

  seastar::future<> send_request_body(
      const std::shared_ptr<LiveHttp2Stream>& stream,
      seastar::http::request request) {
    if (request.body_writer) {
      const auto expected = request.content_length == 0U
                                ? std::nullopt
                                : std::optional<std::size_t>(
                                      request.content_length);
      auto output = seastar::output_stream<char>(
          seastar::data_sink(std::make_unique<Http2RequestBodySink>(
              shared_from_this(), stream, expected)),
          kRequestChunkBytes);
      co_await request.body_writer(std::move(output));
      co_return;
    }
    if (!request.content.empty()) {
      if (request.content_length != 0U &&
          request.content_length != request.content.size()) {
        throw std::invalid_argument(
            "upstream HTTP/2 request body does not match Content-Length");
      }
      const auto bytes = std::span<const std::uint8_t>(
          reinterpret_cast<const std::uint8_t*>(request.content.data()),
          request.content.size());
      co_await submit_request_data(stream, bytes, true);
      co_return;
    }
    if (request.content_length != 0U) {
      throw std::invalid_argument(
          "upstream HTTP/2 request ended before Content-Length bytes");
    }
  }

  void cancel_from_callback(
      const std::shared_ptr<LiveHttp2Stream>& stream) noexcept {
    if (stream->locally_cancelled || stream->response_terminal) {
      return;
    }
    stream->locally_cancelled = true;
    increment(metrics_.request_cancellations);
    stream->fail(std::make_exception_ptr(
        seastar::abort_requested_exception{}));
    ++progress_epoch_;
    progress_.broadcast();
    auto self = shared_from_this();
    (void)seastar::with_gate(background_gate_, [self, stream] {
      return self->reset_cancelled_stream(stream);
    }).handle_exception([](const std::exception_ptr&) {});
  }

  seastar::future<> reset_cancelled_stream(
      const std::shared_ptr<LiveHttp2Stream>& stream) {
    if (failed_) {
      co_return;
    }
    {
      auto units = co_await seastar::get_units(session_mutex_, 1U);
      session_->reset_stream(stream->stream_id, NGHTTP2_CANCEL);
      ++progress_epoch_;
      progress_.broadcast();
    }
    co_await pump_output();
  }

  seastar::future<> read_loop() {
    try {
      while (!failed_ && !closing_) {
        auto data = co_await input_->read_up_to(kInputBufferBytes);
        if (data.empty()) {
          throw Http2ConnectionUnavailable{};
        }
        const auto input = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(data.get()), data.size());
        std::size_t offset = 0U;
        while (offset < input.size()) {
          std::size_t consumed = 0U;
          std::vector<bonvoyage::http::Http2ClientEvent> events;
          {
            auto units = co_await seastar::get_units(session_mutex_, 1U);
            consumed = session_->receive(input.subspan(offset));
            events = session_->take_events();
            ++progress_epoch_;
            progress_.broadcast();
          }
          if (consumed == 0U && events.empty()) {
            throw std::runtime_error(
                "upstream HTTP/2 client made no input progress");
          }
          offset += consumed;
          co_await dispatch_events(std::move(events));
          co_await pump_output();
        }
      }
    } catch (const bonvoyage::http::Http2ProtocolError&) {
      increment(metrics_.protocol_errors);
      fail_connection(std::current_exception());
    } catch (...) {
      fail_connection(std::current_exception());
    }
  }

  seastar::future<> dispatch_events(
      std::vector<bonvoyage::http::Http2ClientEvent> events) {
    for (auto& event : events) {
      if (event.kind == bonvoyage::http::Http2ClientEventKind::goaway) {
        increment(metrics_.goaways);
        for (auto& [stream_id, stream] : streams_) {
          if (stream_id > event.last_stream_id &&
              !stream->response_head_set) {
            stream->fail(std::make_exception_ptr(Http2PeerGoaway{}));
          }
        }
        capacity_notifier_();
        continue;
      }

      const auto found = streams_.find(event.stream_id);
      if (found == streams_.end()) {
        continue;
      }
      auto& stream = found->second;
      if ((stream->locally_cancelled || stream->response_failed) &&
          event.kind != bonvoyage::http::Http2ClientEventKind::stream_reset &&
          event.kind != bonvoyage::http::Http2ClientEventKind::stream_closed) {
        if (event.kind == bonvoyage::http::Http2ClientEventKind::data &&
            !event.data.empty()) {
          co_await acknowledge_response_data(event.stream_id,
                                             event.data.size());
        }
        continue;
      }
      switch (event.kind) {
        case bonvoyage::http::Http2ClientEventKind::response_headers: {
          if (event.status < 200U) {
            ++stream->informational_responses;
            if (event.status == 101U ||
                stream->informational_responses >
                    kMaximumInformationalResponses) {
              stream->fail(std::make_exception_ptr(std::runtime_error(
                  "invalid upstream HTTP/2 informational response")));
              co_await reset_stream(stream, NGHTTP2_PROTOCOL_ERROR);
            }
            break;
          }
          auto reply = std::make_unique<seastar::http::reply>();
          reply->_status = static_cast<seastar::http::reply::status_type>(
              event.status);
          reply->_version = "2";
          reply->_headers.reserve(event.headers.size());
          for (auto& header : event.headers) {
            if (header.name == ":status") {
              continue;
            }
            auto name = seastar::sstring(header.name);
            auto value = seastar::sstring(header.value);
            const auto existing = reply->_headers.find(name);
            if (stream->grpc && existing != reply->_headers.end()) {
              existing->second += ",";
              existing->second += value;
            } else {
              reply->_headers.insert_or_assign(std::move(name),
                                               std::move(value));
            }
          }
          stream->set_response_head(std::move(reply));
          break;
        }
        case bonvoyage::http::Http2ClientEventKind::response_trailers:
          if (stream->reply == nullptr) {
            stream->fail(std::make_exception_ptr(std::runtime_error(
                "upstream HTTP/2 trailers preceded the final response")));
            co_await reset_stream(stream, NGHTTP2_PROTOCOL_ERROR);
            break;
          }
          for (auto& trailer : event.headers) {
            auto name = seastar::sstring(trailer.name);
            auto value = seastar::sstring(trailer.value);
            const auto existing =
                stream->reply->trailing_headers.find(name);
            if (stream->grpc &&
                existing != stream->reply->trailing_headers.end()) {
              existing->second += ",";
              existing->second += value;
            } else {
              stream->reply->trailing_headers.insert_or_assign(
                  std::move(name), std::move(value));
            }
          }
          increment(metrics_.response_trailers);
          break;
        case bonvoyage::http::Http2ClientEventKind::data: {
          if (event.data.empty()) {
            break;
          }
          seastar::temporary_buffer<char> buffer(event.data.size());
          std::memcpy(buffer.get_write(), event.data.data(),
                      event.data.size());
          if (!stream->response_body.push(std::move(buffer))) {
            stream->fail(std::make_exception_ptr(std::runtime_error(
                "upstream HTTP/2 response queue is full")));
            co_await reset_stream(stream, NGHTTP2_ENHANCE_YOUR_CALM);
          }
          break;
        }
        case bonvoyage::http::Http2ClientEventKind::stream_end:
          stream->finish_response();
          break;
        case bonvoyage::http::Http2ClientEventKind::stream_reset:
          increment(metrics_.stream_resets);
          stream->fail(std::make_exception_ptr(std::runtime_error(
              "upstream HTTP/2 peer reset the request stream")));
          break;
        case bonvoyage::http::Http2ClientEventKind::stream_closed:
          if (event.error_code != NGHTTP2_NO_ERROR) {
            stream->fail(std::make_exception_ptr(std::runtime_error(
                "upstream HTTP/2 request stream closed with an error")));
          } else if (!stream->response_head_set) {
            stream->fail(std::make_exception_ptr(std::runtime_error(
                "upstream HTTP/2 stream closed without a final response")));
          } else if (!stream->response_terminal) {
            stream->finish_response();
          }
          streams_.erase(found);
          decrement(metrics_.active_streams);
          capacity_notifier_();
          break;
        case bonvoyage::http::Http2ClientEventKind::goaway:
          break;
      }
    }
  }

  seastar::future<> reset_stream(
      const std::shared_ptr<LiveHttp2Stream>& stream,
      std::uint32_t error_code) {
    if (failed_) {
      co_return;
    }
    {
      auto units = co_await seastar::get_units(session_mutex_, 1U);
      session_->reset_stream(stream->stream_id, error_code);
      ++progress_epoch_;
      progress_.broadcast();
    }
    co_await pump_output();
  }

  seastar::future<> pump_output() {
    if (!connected_ || failed_) {
      co_return;
    }
    auto output_units = co_await seastar::get_units(output_mutex_, 1U);
    try {
      while (!failed_) {
        std::vector<std::uint8_t> chunk;
        {
          auto session_units =
              co_await seastar::get_units(session_mutex_, 1U);
          chunk = session_->take_output_chunk();
        }
        if (chunk.empty()) {
          break;
        }
        seastar::temporary_buffer<char> output(chunk.size());
        std::memcpy(output.get_write(), chunk.data(), chunk.size());
        co_await output_->write(std::move(output));
        {
          auto session_units =
              co_await seastar::get_units(session_mutex_, 1U);
          session_->acknowledge_output_chunk();
          ++progress_epoch_;
          progress_.broadcast();
        }
      }
      co_await output_->flush();
    } catch (...) {
      fail_connection(std::current_exception());
      throw;
    }
  }

  void fail_connection(const std::exception_ptr& error,
                       bool count_failure = true) noexcept {
    if (failed_) {
      return;
    }
    failed_ = true;
    if (count_failure) {
      increment(metrics_.connection_failures);
    }
    if (connected_) {
      decrement(metrics_.active_connections);
    }
    for (auto& [stream_id, stream] : streams_) {
      static_cast<void>(stream_id);
      stream->fail(error);
      decrement(metrics_.active_streams);
    }
    streams_.clear();
    reservations_ = 0U;
    if (socket_.has_value()) {
      socket_->shutdown_input();
      socket_->shutdown_output();
    }
    ++progress_epoch_;
    progress_.broadcast();
    capacity_notifier_();
  }

  UpstreamHttp2ClientMetrics metrics_;
  CapacityNotifier capacity_notifier_;
  std::unique_ptr<bonvoyage::http::Http2ClientSession> session_;
  std::optional<seastar::connected_socket> socket_;
  std::optional<seastar::input_stream<char>> input_;
  std::optional<seastar::output_stream<char>> output_;
  std::unordered_map<std::int32_t, std::shared_ptr<LiveHttp2Stream>> streams_;
  seastar::semaphore session_mutex_{1U};
  seastar::semaphore output_mutex_{1U};
  seastar::condition_variable progress_;
  seastar::gate background_gate_;
  std::uint64_t progress_epoch_{};
  std::size_t reservations_{};
  bool connected_{false};
  bool failed_{false};
  bool closing_{false};
  bool closed_{false};
};

seastar::future<seastar::temporary_buffer<char>>
Http2ResponseBodySource::get() {
  if (closed_) {
    co_return seastar::temporary_buffer<char>{};
  }
  auto data = co_await stream_->response_body.pop_eventually();
  if (data.empty()) {
    closed_ = true;
    co_return data;
  }
  if (auto connection = stream_->connection.lock()) {
    co_await connection->acknowledge_response_data(stream_->stream_id,
                                                   data.size());
  }
  co_return data;
}

seastar::future<> Http2ResponseBodySource::close() {
  if (closed_) {
    co_return;
  }
  closed_ = true;
  if (!stream_->response_terminal) {
    if (auto connection = stream_->connection.lock()) {
      co_await connection->cancel_stream(stream_, false);
    }
  }
}

seastar::future<> Http2RequestBodySink::put(seastar::net::packet data) {
  if (closed_) {
    throw std::logic_error("upstream HTTP/2 request body sink is closed");
  }
  auto fragments = data.release();
  for (auto& fragment : fragments) {
    if (expected_bytes_.has_value() &&
        (written_bytes_ > *expected_bytes_ ||
         fragment.size() > *expected_bytes_ - written_bytes_)) {
      throw std::invalid_argument(
          "upstream HTTP/2 request body exceeds Content-Length");
    }
    const auto bytes = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(fragment.get()),
        fragment.size());
    co_await connection_->submit_request_data(stream_, bytes, false);
    written_bytes_ += fragment.size();
  }
}

seastar::future<> Http2RequestBodySink::close() {
  if (closed_) {
    co_return;
  }
  closed_ = true;
  if (expected_bytes_.has_value() && written_bytes_ != *expected_bytes_) {
    throw std::invalid_argument(
        "upstream HTTP/2 request body ended before Content-Length bytes");
  }
  co_await connection_->submit_request_data(stream_, {}, true);
}

}  // namespace

class ShardLocalUpstreamHttp2Client::Impl final {
 public:
  Impl(std::unique_ptr<seastar::http::experimental::connection_factory>
           factory,
       std::uint32_t max_connections,
       std::uint32_t max_streams_per_connection,
       std::size_t max_response_header_bytes,
       UpstreamHttp2ClientMetrics metrics)
      : factory_(std::move(factory)),
        max_connections_(max_connections),
        max_streams_per_connection_(max_streams_per_connection),
        max_response_header_bytes_(max_response_header_bytes),
        metrics_(metrics) {
    if (factory_ == nullptr || max_connections_ == 0U ||
        max_streams_per_connection_ == 0U ||
        max_response_header_bytes_ == 0U) {
      throw std::invalid_argument(
          "upstream HTTP/2 pool limits and factory must be nonzero");
    }
    connections_.reserve(max_connections_);
  }

  seastar::future<> make_request(
      seastar::http::request request,
      ShardLocalUpstreamHttp2Client::ReplyHandler handler,
      seastar::abort_source* abort) {
    while (true) {
      if (closing_) {
        throw Http2PoolClosed{};
      }
      if (abort != nullptr && abort->abort_requested()) {
        throw seastar::abort_requested_exception{};
      }
      reap_retireable();
      for (const auto& connection : connections_) {
        if (connection->try_reserve()) {
          co_await connection->make_reserved_request(
              std::move(request), std::move(handler), abort);
          co_return;
        }
      }
      if (accepting_connection_count() < max_connections_) {
        auto connection = std::make_shared<LiveHttp2Connection>(
            max_streams_per_connection_, max_response_header_bytes_, metrics_,
            [this] { capacity_.broadcast(); });
        connections_.push_back(connection);
        try {
          co_await connection->start(*factory_, abort);
        } catch (...) {
          reap_retireable();
          throw;
        }
        if (!connection->try_reserve()) {
          throw Http2ConnectionUnavailable{};
        }
        co_await connection->make_reserved_request(
            std::move(request), std::move(handler), abort);
        co_return;
      }

      increment(metrics_.pool_waits);
      seastar::optimized_optional<seastar::abort_source::subscription>
          subscription;
      if (abort != nullptr) {
        subscription = abort->subscribe(
            [this]() noexcept { capacity_.broadcast(); });
      }
      co_await capacity_.wait([this, abort] {
        return closing_ ||
               (abort != nullptr && abort->abort_requested()) ||
               has_capacity();
      });
    }
  }

  seastar::future<> close() {
    if (closing_) {
      co_return;
    }
    closing_ = true;
    capacity_.broadcast();
    auto connections = std::move(connections_);
    co_await seastar::parallel_for_each(
        connections, [](const std::shared_ptr<LiveHttp2Connection>& connection) {
          return connection->close();
        });
    co_await retirement_gate_.close();
  }

 private:
  [[nodiscard]] std::size_t accepting_connection_count() const noexcept {
    return static_cast<std::size_t>(std::count_if(
        connections_.begin(), connections_.end(), [](const auto& connection) {
          return !connection->failed() && !connection->draining();
        }));
  }

  [[nodiscard]] bool has_capacity() const noexcept {
    if (accepting_connection_count() < max_connections_) {
      return true;
    }
    return std::any_of(connections_.begin(), connections_.end(),
                       [](const auto& connection) {
                         return connection->can_accept() ||
                                connection->retireable();
                       });
  }

  void reap_retireable() {
    auto current = connections_.begin();
    while (current != connections_.end()) {
      if (!(*current)->retireable()) {
        ++current;
        continue;
      }
      auto connection = std::move(*current);
      current = connections_.erase(current);
      (void)seastar::with_gate(retirement_gate_, [connection] {
        return connection->close();
      }).handle_exception([](const std::exception_ptr&) {});
    }
  }

  std::unique_ptr<seastar::http::experimental::connection_factory> factory_;
  std::uint32_t max_connections_;
  std::uint32_t max_streams_per_connection_;
  std::size_t max_response_header_bytes_;
  UpstreamHttp2ClientMetrics metrics_;
  std::vector<std::shared_ptr<LiveHttp2Connection>> connections_;
  seastar::condition_variable capacity_;
  seastar::gate retirement_gate_;
  bool closing_{false};
};

ShardLocalUpstreamHttp2Client::ShardLocalUpstreamHttp2Client(
    std::unique_ptr<seastar::http::experimental::connection_factory> factory,
    std::uint32_t max_connections,
    std::uint32_t max_streams_per_connection,
    std::size_t max_response_header_bytes,
    UpstreamHttp2ClientMetrics metrics)
    : impl_(std::make_unique<Impl>(
          std::move(factory), max_connections, max_streams_per_connection,
          max_response_header_bytes, metrics)) {}

ShardLocalUpstreamHttp2Client::~ShardLocalUpstreamHttp2Client() = default;

seastar::future<> ShardLocalUpstreamHttp2Client::make_request(
    seastar::http::request request, ReplyHandler handler,
    seastar::abort_source* abort) {
  return impl_->make_request(std::move(request), std::move(handler), abort);
}

seastar::future<> ShardLocalUpstreamHttp2Client::close() {
  return impl_->close();
}

}  // namespace bonvoyage::runtime
