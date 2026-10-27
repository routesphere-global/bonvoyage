#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <nghttp2/nghttp2.h>

#include "bonvoyage/http/http2_session.hh"

namespace {

using bonvoyage::http::Http2Event;
using bonvoyage::http::Http2EventKind;
using bonvoyage::http::Http2Header;
using bonvoyage::http::Http2Limits;
using bonvoyage::http::Http2ProtocolError;
using bonvoyage::http::Http2ServerSession;

void require(bool condition, const char* message) {
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

void require_nghttp2(int result, const char* message) {
  if (result < 0) {
    std::cerr << message << ": " << nghttp2_strerror(result) << '\n';
    std::exit(1);
  }
}

[[nodiscard]] nghttp2_nv native_header(const Http2Header& header) noexcept {
  return nghttp2_nv{
      const_cast<std::uint8_t*>(reinterpret_cast<const std::uint8_t*>(
          header.name.data())),
      const_cast<std::uint8_t*>(reinterpret_cast<const std::uint8_t*>(
          header.value.data())),
      header.name.size(), header.value.size(), NGHTTP2_NV_FLAG_NONE};
}

class TestClient final {
 public:
  TestClient() {
    require_nghttp2(nghttp2_session_callbacks_new(&callbacks_),
                    "create test client callbacks");
    nghttp2_session_callbacks_set_on_frame_recv_callback(
        callbacks_, &TestClient::on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_header_callback(
        callbacks_, &TestClient::on_header_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(
        callbacks_, &TestClient::on_stream_close_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
        callbacks_, &TestClient::on_data_chunk_recv_callback);
    require_nghttp2(
        nghttp2_session_client_new(&session_, callbacks_, this),
        "create test client session");
    require_nghttp2(
        nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, nullptr, 0U),
        "submit test client settings");
  }

  ~TestClient() {
    nghttp2_session_del(session_);
    nghttp2_session_callbacks_del(callbacks_);
  }

  TestClient(const TestClient&) = delete;
  TestClient& operator=(const TestClient&) = delete;

  [[nodiscard]] std::int32_t submit_request(
      const std::vector<Http2Header>& headers) {
    std::vector<nghttp2_nv> native_headers;
    native_headers.reserve(headers.size());
    for (const auto& header : headers) {
      native_headers.push_back(native_header(header));
    }
    const auto stream_id = nghttp2_submit_request2(
        session_, nullptr, native_headers.data(), native_headers.size(),
        nullptr, nullptr);
    require(stream_id > 0, "submit header-only test request failed");
    return stream_id;
  }

  void set_next_stream_id(std::int32_t stream_id) {
    require_nghttp2(nghttp2_session_set_next_stream_id(session_, stream_id),
                    "set next test client stream ID");
  }

  void set_initial_response_window(std::uint32_t bytes) {
    const nghttp2_settings_entry setting{
        NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, bytes};
    require_nghttp2(
        nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, &setting, 1U),
        "set test client response window");
  }

  void grant_response_credit(std::int32_t stream_id, std::int32_t bytes) {
    require_nghttp2(
        nghttp2_submit_window_update(session_, NGHTTP2_FLAG_NONE, stream_id,
                                     bytes),
        "grant test client response credit");
  }

  void reset_stream(std::int32_t stream_id, std::uint32_t error_code) {
    require_nghttp2(
        nghttp2_submit_rst_stream(session_, NGHTTP2_FLAG_NONE, stream_id,
                                  error_code),
        "reset test client stream");
  }

  [[nodiscard]] std::int32_t submit_request_with_body(
      const std::vector<Http2Header>& headers, std::string body) {
    body_ = std::move(body);
    body_offset_ = 0U;
    std::vector<nghttp2_nv> native_headers;
    native_headers.reserve(headers.size());
    for (const auto& header : headers) {
      native_headers.push_back(native_header(header));
    }
    nghttp2_data_provider2 provider{};
    provider.source.ptr = this;
    provider.read_callback = &TestClient::read_body_callback;
    const auto stream_id = nghttp2_submit_request2(
        session_, nullptr, native_headers.data(), native_headers.size(),
        &provider, nullptr);
    require(stream_id > 0, "submit test request body failed");
    return stream_id;
  }

  [[nodiscard]] std::vector<std::uint8_t> take_output() {
    std::vector<std::uint8_t> output;
    for (;;) {
      const std::uint8_t* data = nullptr;
      const auto result = nghttp2_session_mem_send2(session_, &data);
      require(result >= 0, "serialize test client output failed");
      if (result == 0) {
        break;
      }
      const auto size = static_cast<std::size_t>(result);
      output.insert(output.end(), data, data + size);
    }
    return output;
  }

  void receive(std::span<const std::uint8_t> input) {
    const auto result =
        nghttp2_session_mem_recv2(session_, input.data(), input.size());
    require(result >= 0, "test client rejected server output");
    require(static_cast<std::size_t>(result) == input.size(),
            "test client did not consume all server output");
    require(!callback_failed_, "test client callback failed");
  }

  [[nodiscard]] std::uint32_t setting(nghttp2_settings_id id) const {
    const auto iterator = settings_.find(static_cast<int>(id));
    require(iterator != settings_.end(), "expected server setting was absent");
    return iterator->second;
  }

  [[nodiscard]] std::string_view response_status() const noexcept {
    return response_status_;
  }

  [[nodiscard]] std::uint32_t close_error() const noexcept {
    return close_error_;
  }

  [[nodiscard]] std::string_view response_body() const noexcept {
    return response_body_;
  }

  [[nodiscard]] bool saw_stream_close() const noexcept {
    return saw_stream_close_;
  }

  [[nodiscard]] std::int32_t last_closed_stream_id() const noexcept {
    return last_closed_stream_id_;
  }

  [[nodiscard]] bool saw_goaway() const noexcept { return saw_goaway_; }

  [[nodiscard]] std::string_view response_trailer(
      std::string_view name) const noexcept {
    const auto iterator = std::find_if(
        response_trailers_.begin(), response_trailers_.end(),
        [name](const Http2Header& header) { return header.name == name; });
    return iterator == response_trailers_.end()
               ? std::string_view{}
               : std::string_view(iterator->value);
  }

  [[nodiscard]] std::uint32_t goaway_error() const noexcept {
    return goaway_error_;
  }

 private:
  template <typename Callback>
  int guard(Callback callback) noexcept {
    try {
      return callback();
    } catch (...) {
      callback_failed_ = true;
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }

  static int on_frame_recv_callback(nghttp2_session*,
                                    const nghttp2_frame* frame,
                                    void* user_data) noexcept {
    auto& self = *static_cast<TestClient*>(user_data);
    return self.guard([&self, frame] {
      if (frame->hd.type == NGHTTP2_SETTINGS &&
          (frame->hd.flags & NGHTTP2_FLAG_ACK) == 0U) {
        for (std::size_t index = 0U; index < frame->settings.niv; ++index) {
          const auto& entry = frame->settings.iv[index];
          self.settings_[static_cast<int>(entry.settings_id)] = entry.value;
        }
      } else if (frame->hd.type == NGHTTP2_GOAWAY) {
        self.saw_goaway_ = true;
        self.goaway_error_ = frame->goaway.error_code;
      }
      return 0;
    });
  }

  static int on_header_callback(nghttp2_session*, const nghttp2_frame* frame,
                                const std::uint8_t* name,
                                std::size_t name_length,
                                const std::uint8_t* value,
                                std::size_t value_length, std::uint8_t,
                                void* user_data) noexcept {
    auto& self = *static_cast<TestClient*>(user_data);
    return self.guard([&self, frame, name, name_length, value, value_length] {
      if (frame->hd.type == NGHTTP2_HEADERS &&
          frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
          std::string_view(reinterpret_cast<const char*>(name), name_length) ==
              ":status") {
        self.response_status_.assign(
            reinterpret_cast<const char*>(value), value_length);
      } else if (frame->hd.type == NGHTTP2_HEADERS &&
                 frame->headers.cat == NGHTTP2_HCAT_HEADERS) {
        self.response_trailers_.push_back(
            {std::string(reinterpret_cast<const char*>(name), name_length),
             std::string(reinterpret_cast<const char*>(value), value_length),
             false});
      }
      return 0;
    });
  }

  static int on_stream_close_callback(nghttp2_session*, std::int32_t stream_id,
                                      std::uint32_t error_code,
                                      void* user_data) noexcept {
    auto& self = *static_cast<TestClient*>(user_data);
    self.close_error_ = error_code;
    self.saw_stream_close_ = true;
    self.last_closed_stream_id_ = stream_id;
    return 0;
  }

  static int on_data_chunk_recv_callback(
      nghttp2_session*, std::uint8_t, std::int32_t,
      const std::uint8_t* data, std::size_t length,
      void* user_data) noexcept {
    auto& self = *static_cast<TestClient*>(user_data);
    return self.guard([&self, data, length] {
      self.response_body_.append(reinterpret_cast<const char*>(data), length);
      return 0;
    });
  }

  static nghttp2_ssize read_body_callback(
      nghttp2_session*, std::int32_t, std::uint8_t* buffer,
      std::size_t length, std::uint32_t* data_flags,
      nghttp2_data_source* source, void*) noexcept {
    auto& self = *static_cast<TestClient*>(source->ptr);
    const auto remaining = self.body_.size() - self.body_offset_;
    const auto copied = std::min(length, remaining);
    std::copy_n(self.body_.data() + self.body_offset_, copied, buffer);
    self.body_offset_ += copied;
    if (self.body_offset_ == self.body_.size()) {
      *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    return static_cast<nghttp2_ssize>(copied);
  }

  nghttp2_session_callbacks* callbacks_{nullptr};
  nghttp2_session* session_{nullptr};
  std::unordered_map<int, std::uint32_t> settings_;
  std::string response_status_;
  std::string response_body_;
  std::string body_;
  std::vector<Http2Header> response_trailers_;
  std::size_t body_offset_{};
  std::uint32_t close_error_{};
  std::uint32_t goaway_error_{};
  std::int32_t last_closed_stream_id_{};
  bool saw_goaway_{false};
  bool saw_stream_close_{false};
  bool callback_failed_{false};
};

[[nodiscard]] std::vector<Http2Header> request_headers(
    std::string_view method = "GET", std::string_view path = "/ready") {
  return {{":method", std::string(method), false},
          {":scheme", "https", false},
          {":authority", "api.example.test", false},
          {":path", std::string(path), false}};
}

[[nodiscard]] std::vector<std::uint8_t> take_server_output(
    Http2ServerSession& server) {
  std::vector<std::uint8_t> output;
  for (;;) {
    auto chunk = server.take_output_chunk();
    if (chunk.empty()) {
      break;
    }
    output.insert(output.end(), chunk.begin(), chunk.end());
  }
  return output;
}

[[nodiscard]] std::vector<std::uint8_t> raw_frame(
    std::uint8_t type, std::uint8_t flags, std::int32_t stream_id,
    std::span<const std::uint8_t> payload = {}) {
  require(payload.size() <= 0x00ff'ffffU,
          "test HTTP/2 frame payload is too large");
  const auto length = static_cast<std::uint32_t>(payload.size());
  const auto encoded_stream_id = static_cast<std::uint32_t>(stream_id) &
                                 0x7fff'ffffU;
  std::vector<std::uint8_t> frame(9U + payload.size());
  frame[0] = static_cast<std::uint8_t>(length >> 16U);
  frame[1] = static_cast<std::uint8_t>(length >> 8U);
  frame[2] = static_cast<std::uint8_t>(length);
  frame[3] = type;
  frame[4] = flags;
  frame[5] = static_cast<std::uint8_t>(encoded_stream_id >> 24U);
  frame[6] = static_cast<std::uint8_t>(encoded_stream_id >> 16U);
  frame[7] = static_cast<std::uint8_t>(encoded_stream_id >> 8U);
  frame[8] = static_cast<std::uint8_t>(encoded_stream_id);
  std::copy(payload.begin(), payload.end(), frame.begin() + 9);
  return frame;
}

[[nodiscard]] std::array<std::uint8_t, 4U> encoded_u32(
    std::uint32_t value) {
  return {static_cast<std::uint8_t>(value >> 24U),
          static_cast<std::uint8_t>(value >> 16U),
          static_cast<std::uint8_t>(value >> 8U),
          static_cast<std::uint8_t>(value)};
}

void feed_all(Http2ServerSession& server,
              std::span<const std::uint8_t> input) {
  std::size_t offset = 0U;
  while (offset < input.size()) {
    const auto consumed = server.receive(input.subspan(offset));
    require(consumed > 0U, "HTTP/2 server made no input progress");
    offset += consumed;
    if (offset < input.size()) {
      (void)server.take_events();
    }
  }
}

void exchange_initial_settings(Http2ServerSession& server,
                               TestClient& client) {
  client.receive(take_server_output(server));
  feed_all(server, client.take_output());
  const auto server_ack = take_server_output(server);
  if (!server_ack.empty()) {
    client.receive(server_ack);
  }
}

[[nodiscard]] const Http2Event* find_event(
    const std::vector<Http2Event>& events, Http2EventKind kind) {
  const auto iterator = std::find_if(
      events.begin(), events.end(),
      [kind](const Http2Event& event) { return event.kind == kind; });
  return iterator == events.end() ? nullptr : &*iterator;
}

[[nodiscard]] std::string_view header_value(const Http2Event& event,
                                            std::string_view name) {
  const auto iterator = std::find_if(
      event.headers.begin(), event.headers.end(),
      [name](const Http2Header& header) { return header.name == name; });
  require(iterator != event.headers.end(), "expected HTTP/2 header was absent");
  return iterator->value;
}

void test_settings_and_incremental_round_trip() {
  Http2ServerSession server;
  TestClient client;

  require(server.wants_write(), "initial HTTP/2 SETTINGS were not queued");
  const auto initial_settings = take_server_output(server);
  client.receive(initial_settings);
  require(client.setting(NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS) == 100U,
          "unexpected max concurrent streams setting");
  require(client.setting(NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE) ==
              32U * 1024U,
          "unexpected max header list setting");
  require(client.setting(NGHTTP2_SETTINGS_NO_RFC7540_PRIORITIES) == 1U,
          "RFC 7540 priorities were not disabled");

  const auto stream_id = client.submit_request(request_headers());
  const auto request_wire = client.take_output();
  for (const auto byte : request_wire) {
    const std::array<std::uint8_t, 1U> one_byte{byte};
    require(server.receive(one_byte) == 1U,
            "incremental HTTP/2 input was not consumed");
  }

  const auto events = server.take_events();
  const auto* request = find_event(events, Http2EventKind::request_headers);
  require(request != nullptr, "HTTP/2 request headers event was not emitted");
  require(request->stream_id == stream_id && request->end_stream,
          "HTTP/2 request stream metadata changed");
  require(header_value(*request, ":method") == "GET",
          "HTTP/2 method was not decoded");
  require(header_value(*request, ":path") == "/ready",
          "HTTP/2 path was not decoded");
  require(server.queued_event_bytes() == 0U,
          "draining events did not release queue accounting");

  const std::array<Http2Header, 1U> response_headers{
      Http2Header{"content-length", "0", false}};
  server.submit_empty_response(stream_id, 200U, response_headers);
  bool rejected_uppercase = false;
  try {
    const std::array<Http2Header, 1U> invalid{
        Http2Header{"X-Bad", "value", false}};
    server.submit_empty_response(stream_id + 2, 200U, invalid);
  } catch (const std::invalid_argument&) {
    rejected_uppercase = true;
  }
  require(rejected_uppercase, "uppercase HTTP/2 response header was accepted");

  bool rejected_duplicate_response = false;
  try {
    server.submit_empty_response(stream_id, 204U);
  } catch (const std::logic_error&) {
    rejected_duplicate_response = true;
  }
  require(rejected_duplicate_response,
          "duplicate HTTP/2 final response was accepted");

  client.receive(take_server_output(server));
  require(client.response_status() == "200",
          "HTTP/2 response status was not serialized");
  require(client.close_error() == NGHTTP2_NO_ERROR,
          "successful HTTP/2 stream closed with an error");
  require(client.saw_stream_close(),
          "successful HTTP/2 stream did not complete its lifecycle");
}

void test_streaming_response_and_output_backpressure() {
  Http2Limits limits;
  limits.max_queued_response_bytes = 16U * 1024U;
  Http2ServerSession server(limits);
  TestClient client;

  client.receive(take_server_output(server));
  const auto stream_id = client.submit_request(request_headers());
  feed_all(server, client.take_output());
  (void)server.take_events();

  const std::array<Http2Header, 2U> response_headers{
      Http2Header{"content-type", "text/plain", false},
      Http2Header{"content-length", "16389", false}};
  server.submit_response_headers(stream_id, 200U, response_headers, false);
  client.receive(take_server_output(server));
  require(client.response_status() == "200",
          "streaming HTTP/2 response headers were not serialized");

  const std::vector<std::uint8_t> first(16U * 1024U, 'a');
  require(server.try_submit_data(stream_id, first, false),
          "one bounded HTTP/2 response frame was rejected");
  const std::array<std::uint8_t, 1U> overflow{'b'};
  require(!server.try_submit_data(stream_id, overflow, false),
          "HTTP/2 response queue exceeded its memory bound");
  require(server.queued_response_bytes() == first.size(),
          "queued response DATA accounting is incorrect");
  client.receive(take_server_output(server));
  require(server.queued_response_bytes() == 0U,
          "serialized response DATA did not release queue accounting");

  const std::array<std::uint8_t, 5U> final{'h', 'e', 'l', 'l', 'o'};
  require(server.try_submit_data(stream_id, final, true),
          "final HTTP/2 response DATA was rejected");
  client.receive(take_server_output(server));
  require(client.response_body().size() == first.size() + final.size(),
          "streaming HTTP/2 response length changed");
  require(client.response_body().substr(first.size()) == "hello",
          "final HTTP/2 response DATA changed");
  require(client.saw_stream_close() &&
              client.close_error() == NGHTTP2_NO_ERROR,
          "streaming HTTP/2 response did not close cleanly");
}

void test_streaming_response_trailers() {
  Http2ServerSession server;
  TestClient client;

  exchange_initial_settings(server, client);
  const auto stream_id =
      client.submit_request(request_headers("POST", "/echo.v1.Echo/Unary"));
  feed_all(server, client.take_output());
  (void)server.take_events();

  const std::array<Http2Header, 1U> response_headers{
      Http2Header{"content-type", "application/grpc", false}};
  server.submit_response_headers(stream_id, 200U, response_headers, false);
  const std::array<std::uint8_t, 8U> body{
      0U, 0U, 0U, 0U, 3U, 'o', 'k', '!'};
  require(server.try_submit_data(stream_id, body, false),
          "gRPC response DATA was rejected");
  const std::array<Http2Header, 2U> trailers{{
      {"grpc-status", "0", true},
      {"x-trace-id", "trace-1", false},
  }};
  server.submit_response_trailers(stream_id, trailers);
  client.receive(take_server_output(server));

  require(client.response_status() == "200",
          "gRPC response status was not serialized");
  require(client.response_body().size() == body.size(),
          "gRPC response body changed before trailers");
  require(client.response_trailer("grpc-status") == "0" &&
              client.response_trailer("x-trace-id") == "trace-1",
          "gRPC response trailers were not preserved");
  require(client.saw_stream_close() &&
              client.close_error() == NGHTTP2_NO_ERROR,
          "gRPC trailer block did not close the stream cleanly");

  bool rejected_second_trailers = false;
  try {
    server.submit_response_trailers(stream_id, trailers);
  } catch (const std::logic_error&) {
    rejected_second_trailers = true;
  }
  require(rejected_second_trailers,
          "duplicate HTTP/2 response trailers were accepted");
}

void test_reset_releases_queued_response_and_preserves_progress(
    bool peer_reset) {
  Http2Limits limits;
  limits.max_queued_response_bytes = 16U * 1024U;
  Http2ServerSession server(limits);
  TestClient client;
  client.set_initial_response_window(0U);
  exchange_initial_settings(server, client);

  const auto blocked = client.submit_request(request_headers("GET", "/blocked"));
  const auto healthy = client.submit_request(request_headers("GET", "/healthy"));
  feed_all(server, client.take_output());
  (void)server.take_events();
  server.submit_response_headers(blocked, 200U, {}, false);
  server.submit_response_headers(healthy, 200U, {}, false);
  const std::vector<std::uint8_t> queued(limits.max_queued_response_bytes, 'x');
  require(server.try_submit_data(blocked, queued, true),
          "failed to fill the stalled response queue");
  client.receive(take_server_output(server));
  require(client.response_body().empty() && !client.saw_stream_close(),
          "zero-window response unexpectedly emitted DATA or completed");
  require(server.queued_response_bytes() == queued.size(),
          "stalled terminal DATA did not retain its queue accounting");

  const std::array<std::uint8_t, 3U> body{'o', 'k', '!'};
  require(!server.try_submit_data(healthy, body, true),
          "healthy DATA bypassed the full response queue");

  // HEAD can progress without DATA credit even while the shared queue is full.
  const auto canary = client.submit_request(request_headers("HEAD", "/canary"));
  feed_all(server, client.take_output());
  (void)server.take_events();
  server.submit_empty_response(canary, 204U);
  client.receive(take_server_output(server));
  require(client.last_closed_stream_id() == canary &&
              client.close_error() == NGHTTP2_NO_ERROR &&
              client.response_status() == "204",
          "HEAD canary stalled behind zero-window DATA");
  require(server.queued_response_bytes() == queued.size(),
          "HEAD canary disturbed the stalled response queue");
  (void)server.take_events();

  const auto reset_code = peer_reset ? NGHTTP2_CANCEL : NGHTTP2_INTERNAL_ERROR;
  if (peer_reset) {
    client.reset_stream(blocked, reset_code);
    feed_all(server, client.take_output());
  } else {
    server.reset_stream(blocked, reset_code);
  }
  client.receive(take_server_output(server));
  const auto events = server.take_events();
  const auto* closed = find_event(events, Http2EventKind::stream_closed);
  require(closed != nullptr && closed->stream_id == blocked &&
              closed->error_code == reset_code,
          "reset did not emit the stalled stream closure");
  require(client.last_closed_stream_id() == blocked &&
              client.close_error() == reset_code,
          "stalled response did not close with the expected reset");
  require(server.queued_response_bytes() == 0U,
          "reset failed to release queued terminal response bytes");

  require(server.try_submit_data(healthy, body, true),
          "reset did not unblock healthy response admission");
  client.grant_response_credit(healthy, static_cast<std::int32_t>(body.size()));
  feed_all(server, client.take_output());
  client.receive(take_server_output(server));
  require(client.response_body() == "ok!" &&
              client.last_closed_stream_id() == healthy &&
              client.close_error() == NGHTTP2_NO_ERROR,
          "healthy response did not complete intact after the reset");
  require(server.queued_response_bytes() == 0U &&
              server.dropped_events() == 0U,
          "reset recovery leaked queued bytes or lost lifecycle events");
  require(server.wants_read() && !server.should_close_transport() &&
              !client.saw_goaway(),
          "stream-scoped reset incorrectly terminated the connection");
}

void test_bounded_data_backpressure() {
  Http2Limits limits;
  limits.max_header_list_bytes = 1U * 1024U;
  limits.max_queued_event_bytes = 20U * 1024U;
  Http2ServerSession server(limits);
  TestClient client;

  const std::string body(40U * 1024U, 'x');
  const auto stream_id =
      client.submit_request_with_body(request_headers("POST", "/upload"), body);
  const auto wire = client.take_output();
  std::size_t offset = 0U;
  std::string received;
  bool observed_partial_receive = false;
  bool observed_stream_end = false;

  while (offset < wire.size()) {
    const auto consumed = server.receive(
        std::span<const std::uint8_t>(wire).subspan(offset));
    require(consumed > 0U, "backpressured HTTP/2 input made no progress");
    observed_partial_receive =
        observed_partial_receive || consumed < wire.size() - offset;
    offset += consumed;

    auto events = server.take_events();
    for (const auto& event : events) {
      if (event.kind == Http2EventKind::data) {
        received.append(reinterpret_cast<const char*>(event.data.data()),
                        event.data.size());
        server.acknowledge_data(event.stream_id, event.data.size());
      } else if (event.kind == Http2EventKind::stream_end) {
        observed_stream_end = true;
      }
    }
  }

  require(observed_partial_receive,
          "bounded event queue did not apply HTTP/2 input backpressure");
  require(received == body, "HTTP/2 DATA changed across bounded delivery");
  require(observed_stream_end, "HTTP/2 DATA end event was not emitted");
  require(server.rejected_streams() == 0U,
          "bounded HTTP/2 body was incorrectly rejected");
  require(stream_id > 0, "HTTP/2 body stream ID was invalid");
}

void test_header_limit_reset() {
  Http2Limits limits;
  limits.max_header_fields = 4U;
  Http2ServerSession server(limits);
  TestClient client;
  auto headers = request_headers();
  headers.push_back({"x-over-limit", "true", false});
  (void)client.submit_request(headers);
  feed_all(server, client.take_output());

  const auto events = server.take_events();
  require(find_event(events, Http2EventKind::request_headers) == nullptr,
          "over-limit HTTP/2 headers reached the application");
  require(server.rejected_streams() == 1U,
          "over-limit HTTP/2 stream was not counted");
  client.receive(take_server_output(server));
  require(client.close_error() == NGHTTP2_ENHANCE_YOUR_CALM,
          "over-limit HTTP/2 stream used the wrong reset code");
}

void test_bad_preface_and_limit_validation() {
  bool bad_limit_rejected = false;
  try {
    Http2Limits limits;
    limits.max_frame_bytes = 1'024U;
    Http2ServerSession invalid(limits);
  } catch (const std::invalid_argument&) {
    bad_limit_rejected = true;
  }
  require(bad_limit_rejected, "invalid HTTP/2 frame limit was accepted");

  Http2ServerSession server;
  const std::array<std::uint8_t, 1U> invalid_magic{'X'};
  bool bad_magic_rejected = false;
  try {
    (void)server.receive(invalid_magic);
  } catch (const Http2ProtocolError& error) {
    bad_magic_rejected =
        error.library_error_code() == NGHTTP2_ERR_BAD_CLIENT_MAGIC;
  }
  require(bad_magic_rejected, "invalid HTTP/2 client preface was accepted");
}

void test_graceful_goaway() {
  Http2ServerSession server;
  TestClient client;
  server.begin_graceful_shutdown();
  require(server.is_draining(), "HTTP/2 session did not enter drain state");
  client.receive(take_server_output(server));
  require(client.saw_goaway(), "HTTP/2 graceful shutdown omitted GOAWAY");

  server.begin_graceful_shutdown();
  require(take_server_output(server).empty(),
          "repeated HTTP/2 drain queued another GOAWAY");
}

void test_connection_error_reaches_terminal_state() {
  Http2ServerSession server;
  TestClient client;
  exchange_initial_settings(server, client);

  const std::array<std::uint8_t, 7U> malformed_ping{};
  feed_all(server,
           raw_frame(NGHTTP2_PING, NGHTTP2_FLAG_NONE, 0, malformed_ping));
  client.receive(take_server_output(server));
  require(client.saw_goaway(), "invalid PING did not produce GOAWAY");
  require(client.goaway_error() == NGHTTP2_FRAME_SIZE_ERROR,
          "invalid PING used the wrong connection error");
  require(server.should_close_transport(),
          "fatal HTTP/2 error did not complete protocol I/O");
}

void test_peer_goaway_reaches_terminal_state() {
  Http2ServerSession server;
  TestClient client;
  exchange_initial_settings(server, client);

  std::array<std::uint8_t, 8U> payload{};
  const auto unknown_error = encoded_u32(0xfeed'beefU);
  std::copy(unknown_error.begin(), unknown_error.end(), payload.begin() + 4);
  feed_all(server,
           raw_frame(NGHTTP2_GOAWAY, NGHTTP2_FLAG_NONE, 0, payload));
  require(server.should_close_transport(),
          "peer GOAWAY without active streams did not complete protocol I/O");
}

void test_priority_stream_zero_is_connection_error() {
  Http2ServerSession server;
  TestClient client;
  exchange_initial_settings(server, client);

  const std::array<std::uint8_t, 5U> priority{};
  feed_all(server,
           raw_frame(NGHTTP2_PRIORITY, NGHTTP2_FLAG_NONE, 0, priority));
  client.receive(take_server_output(server));
  require(client.saw_goaway(), "PRIORITY stream zero did not produce GOAWAY");
  require(client.goaway_error() == NGHTTP2_PROTOCOL_ERROR,
          "PRIORITY stream zero used the wrong connection error");
  require(server.should_close_transport(),
          "PRIORITY stream zero did not terminate protocol I/O");
}

void test_skipped_stream_identifier_is_connection_error() {
  Http2ServerSession server;
  TestClient client;
  exchange_initial_settings(server, client);
  client.set_next_stream_id(5);
  require(client.submit_request(request_headers()) == 5,
          "test client did not open stream five");
  feed_all(server, client.take_output());
  (void)server.take_events();

  feed_all(server,
           raw_frame(NGHTTP2_HEADERS,
                     NGHTTP2_FLAG_END_HEADERS | NGHTTP2_FLAG_END_STREAM, 3));
  client.receive(take_server_output(server));
  require(client.saw_goaway(), "skipped stream ID did not produce GOAWAY");
  require(client.goaway_error() == NGHTTP2_PROTOCOL_ERROR,
          "skipped stream ID used the wrong connection error");
  require(server.should_close_transport(),
          "skipped stream ID did not terminate protocol I/O");
}

void test_recent_local_reset_preserves_race_tolerance() {
  Http2ServerSession server;
  TestClient client;
  exchange_initial_settings(server, client);
  const auto stream_id = client.submit_request(request_headers());
  feed_all(server, client.take_output());
  (void)server.take_events();
  server.reset_stream(stream_id, NGHTTP2_CANCEL);
  client.receive(take_server_output(server));

  feed_all(server,
           raw_frame(NGHTTP2_HEADERS,
                     NGHTTP2_FLAG_END_HEADERS | NGHTTP2_FLAG_END_STREAM,
                     stream_id));
  require(!server.should_close_transport(),
          "late HEADERS after a local reset incorrectly terminated session");
}

void test_stream_window_overflow_is_stream_scoped() {
  Http2ServerSession server;
  TestClient client;
  exchange_initial_settings(server, client);
  const auto stream_id = client.submit_request(request_headers());
  feed_all(server, client.take_output());
  (void)server.take_events();

  const auto to_max = encoded_u32(
      static_cast<std::uint32_t>(NGHTTP2_MAX_WINDOW_SIZE -
                                 NGHTTP2_INITIAL_WINDOW_SIZE));
  feed_all(server, raw_frame(NGHTTP2_WINDOW_UPDATE, NGHTTP2_FLAG_NONE,
                             stream_id, to_max));
  const auto overflow = encoded_u32(1U);
  feed_all(server, raw_frame(NGHTTP2_WINDOW_UPDATE, NGHTTP2_FLAG_NONE,
                             stream_id, overflow));
  client.receive(take_server_output(server));
  require(!client.saw_goaway(),
          "stream window overflow incorrectly terminated the connection");
  require(client.saw_stream_close() &&
              client.close_error() == NGHTTP2_FLOW_CONTROL_ERROR,
          "stream window overflow did not produce FLOW_CONTROL_ERROR reset");
  require(server.wants_read(),
          "stream window overflow stopped unrelated connection processing");
}

}  // namespace

int main() {
  test_settings_and_incremental_round_trip();
  test_streaming_response_and_output_backpressure();
  test_streaming_response_trailers();
  test_reset_releases_queued_response_and_preserves_progress(false);
  test_reset_releases_queued_response_and_preserves_progress(true);
  test_bounded_data_backpressure();
  test_header_limit_reset();
  test_bad_preface_and_limit_validation();
  test_graceful_goaway();
  test_connection_error_reaches_terminal_state();
  test_peer_goaway_reaches_terminal_state();
  test_priority_stream_zero_is_connection_error();
  test_skipped_stream_identifier_is_connection_error();
  test_recent_local_reset_preserves_race_tolerance();
  test_stream_window_overflow_is_stream_scoped();
  return 0;
}
