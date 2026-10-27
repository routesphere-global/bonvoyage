#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <nghttp2/nghttp2.h>

#include "bonvoyage/http/http2_client_session.hh"

namespace {

using bonvoyage::http::Http2ClientEvent;
using bonvoyage::http::Http2ClientEventKind;
using bonvoyage::http::Http2ClientLimits;
using bonvoyage::http::Http2ClientSession;
using bonvoyage::http::Http2Header;

void require(bool condition, std::string_view message) {
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
  const auto flags = header.never_index ? NGHTTP2_NV_FLAG_NO_INDEX
                                        : NGHTTP2_NV_FLAG_NONE;
  return nghttp2_nv{
      const_cast<std::uint8_t*>(reinterpret_cast<const std::uint8_t*>(
          header.name.data())),
      const_cast<std::uint8_t*>(reinterpret_cast<const std::uint8_t*>(
          header.value.data())),
      header.name.size(), header.value.size(),
      static_cast<std::uint8_t>(flags)};
}

class TestServer final {
 public:
  explicit TestServer(std::uint32_t max_concurrent_streams = 100U) {
    require_nghttp2(nghttp2_session_callbacks_new(&callbacks_),
                    "create test server callbacks");
    nghttp2_session_callbacks_set_on_frame_recv_callback(
        callbacks_, &TestServer::on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_header_callback(
        callbacks_, &TestServer::on_header_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
        callbacks_, &TestServer::on_data_chunk_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(
        callbacks_, &TestServer::on_stream_close_callback);
    require_nghttp2(
        nghttp2_session_server_new(&session_, callbacks_, this),
        "create test server session");
    const std::array<nghttp2_settings_entry, 2U> settings{{
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, max_concurrent_streams},
        {NGHTTP2_SETTINGS_ENABLE_PUSH, 0U},
    }};
    require_nghttp2(
        nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, settings.data(),
                                settings.size()),
        "submit test server settings");
  }

  ~TestServer() {
    nghttp2_session_del(session_);
    nghttp2_session_callbacks_del(callbacks_);
  }

  TestServer(const TestServer&) = delete;
  TestServer& operator=(const TestServer&) = delete;

  void receive(std::span<const std::uint8_t> input) {
    const auto result =
        nghttp2_session_mem_recv2(session_, input.data(), input.size());
    require(result >= 0, "test server rejected client output");
    require(static_cast<std::size_t>(result) == input.size(),
            "test server did not consume all client output");
    require(!callback_failed_, "test server callback failed");
  }

  [[nodiscard]] std::vector<std::uint8_t> take_output_chunk() {
    const std::uint8_t* data = nullptr;
    const auto result = nghttp2_session_mem_send2(session_, &data);
    require(result >= 0, "serialize test server output failed");
    const auto size = static_cast<std::size_t>(result);
    return size == 0U ? std::vector<std::uint8_t>{}
                      : std::vector<std::uint8_t>{data, data + size};
  }

  [[nodiscard]] std::vector<std::uint8_t> take_output() {
    std::vector<std::uint8_t> output;
    for (;;) {
      auto chunk = take_output_chunk();
      if (chunk.empty()) {
        break;
      }
      output.insert(output.end(), chunk.begin(), chunk.end());
    }
    return output;
  }

  void submit_informational(std::int32_t stream_id, std::uint16_t status) {
    const std::array<Http2Header, 1U> headers{{
        {":status", std::to_string(status), false},
    }};
    const auto native = native_header(headers.front());
    require_nghttp2(
        nghttp2_submit_headers(session_, NGHTTP2_FLAG_NONE, stream_id,
                               nullptr, &native, 1U, nullptr),
        "submit informational response");
  }

  void submit_empty_response(
      std::int32_t stream_id, std::uint16_t status,
      std::span<const Http2Header> headers = {}) {
    const auto status_value = std::to_string(status);
    const Http2Header status_header{":status", status_value, false};
    std::vector<nghttp2_nv> native;
    native.reserve(headers.size() + 1U);
    native.push_back(native_header(status_header));
    for (const auto& header : headers) {
      native.push_back(native_header(header));
    }
    require_nghttp2(
        nghttp2_submit_response2(session_, stream_id, native.data(),
                                 native.size(), nullptr),
        "submit empty test response");
  }

  void submit_streaming_response(std::int32_t stream_id,
                                 std::uint16_t status,
                                 std::span<const Http2Header> headers,
                                 std::vector<std::uint8_t> body,
                                 bool leave_open_for_trailers) {
    response_bodies_[stream_id] =
        ResponseBody{std::move(body), 0U, leave_open_for_trailers};
    const auto status_value = std::to_string(status);
    const Http2Header status_header{":status", status_value, false};
    std::vector<nghttp2_nv> native;
    native.reserve(headers.size() + 1U);
    native.push_back(native_header(status_header));
    for (const auto& header : headers) {
      native.push_back(native_header(header));
    }
    nghttp2_data_provider2 provider{};
    provider.source.ptr = this;
    provider.read_callback = &TestServer::read_response_data_callback;
    require_nghttp2(
        nghttp2_submit_response2(session_, stream_id, native.data(),
                                 native.size(), &provider),
        "submit streaming test response");
  }

  void submit_trailers(std::int32_t stream_id,
                       std::span<const Http2Header> trailers) {
    std::vector<nghttp2_nv> native;
    native.reserve(trailers.size());
    for (const auto& trailer : trailers) {
      native.push_back(native_header(trailer));
    }
    require_nghttp2(
        nghttp2_submit_trailer(session_, stream_id, native.data(),
                               native.size()),
        "submit test response trailers");
  }

  void reset_stream(std::int32_t stream_id, std::uint32_t error_code) {
    require_nghttp2(
        nghttp2_submit_rst_stream(session_, NGHTTP2_FLAG_NONE, stream_id,
                                  error_code),
        "submit test stream reset");
  }

  void submit_goaway(std::int32_t last_stream_id, std::uint32_t error_code,
                     std::string_view debug_data) {
    require_nghttp2(
        nghttp2_submit_goaway(
            session_, NGHTTP2_FLAG_NONE, last_stream_id, error_code,
            reinterpret_cast<const std::uint8_t*>(debug_data.data()),
            debug_data.size()),
        "submit test GOAWAY");
  }

  [[nodiscard]] std::uint32_t client_setting(nghttp2_settings_id id) const {
    const auto iterator = client_settings_.find(static_cast<int>(id));
    require(iterator != client_settings_.end(),
            "expected client setting was absent");
    return iterator->second;
  }

  [[nodiscard]] const std::vector<Http2Header>& request_headers(
      std::int32_t stream_id) const {
    return request_headers_.at(stream_id);
  }

  [[nodiscard]] const std::vector<std::uint8_t>& request_body(
      std::int32_t stream_id) const {
    return request_bodies_.at(stream_id);
  }

  [[nodiscard]] bool request_ended(std::int32_t stream_id) const {
    const auto iterator = request_ended_.find(stream_id);
    return iterator != request_ended_.end() && iterator->second;
  }

  [[nodiscard]] std::uint32_t close_error(std::int32_t stream_id) const {
    const auto iterator = close_errors_.find(stream_id);
    return iterator == close_errors_.end()
               ? std::numeric_limits<std::uint32_t>::max()
               : iterator->second;
  }

  [[nodiscard]] std::uint32_t received_reset_error(
      std::int32_t stream_id) const {
    const auto iterator = received_reset_errors_.find(stream_id);
    return iterator == received_reset_errors_.end()
               ? std::numeric_limits<std::uint32_t>::max()
               : iterator->second;
  }

 private:
  struct ResponseBody final {
    std::vector<std::uint8_t> data;
    std::size_t offset{};
    bool leave_open_for_trailers{false};
  };

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
    auto& self = *static_cast<TestServer*>(user_data);
    return self.guard([&self, frame] {
      if (frame->hd.type == NGHTTP2_SETTINGS &&
          (frame->hd.flags & NGHTTP2_FLAG_ACK) == 0U) {
        for (std::size_t index = 0U; index < frame->settings.niv; ++index) {
          const auto& entry = frame->settings.iv[index];
          self.client_settings_[static_cast<int>(entry.settings_id)] =
              entry.value;
        }
      }
      if ((frame->hd.type == NGHTTP2_HEADERS ||
           frame->hd.type == NGHTTP2_DATA) &&
          (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0U) {
        self.request_ended_[frame->hd.stream_id] = true;
      }
      if (frame->hd.type == NGHTTP2_RST_STREAM) {
        self.received_reset_errors_[frame->hd.stream_id] =
            frame->rst_stream.error_code;
      }
      return 0;
    });
  }

  static int on_header_callback(nghttp2_session*, const nghttp2_frame* frame,
                                const std::uint8_t* name,
                                std::size_t name_length,
                                const std::uint8_t* value,
                                std::size_t value_length, std::uint8_t flags,
                                void* user_data) noexcept {
    auto& self = *static_cast<TestServer*>(user_data);
    return self.guard([&self, frame, name, name_length, value, value_length,
                       flags] {
      if (frame->hd.type == NGHTTP2_HEADERS &&
          frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
        self.request_headers_[frame->hd.stream_id].push_back(Http2Header{
            std::string(reinterpret_cast<const char*>(name), name_length),
            std::string(reinterpret_cast<const char*>(value), value_length),
            (flags & NGHTTP2_NV_FLAG_NO_INDEX) != 0U});
      }
      return 0;
    });
  }

  static int on_data_chunk_recv_callback(
      nghttp2_session*, std::uint8_t, std::int32_t stream_id,
      const std::uint8_t* data, std::size_t length,
      void* user_data) noexcept {
    auto& self = *static_cast<TestServer*>(user_data);
    return self.guard([&self, stream_id, data, length] {
      auto& body = self.request_bodies_[stream_id];
      body.insert(body.end(), data, data + length);
      return 0;
    });
  }

  static int on_stream_close_callback(nghttp2_session*,
                                      std::int32_t stream_id,
                                      std::uint32_t error_code,
                                      void* user_data) noexcept {
    auto& self = *static_cast<TestServer*>(user_data);
    self.close_errors_[stream_id] = error_code;
    return 0;
  }

  static nghttp2_ssize read_response_data_callback(
      nghttp2_session*, std::int32_t stream_id, std::uint8_t* buffer,
      std::size_t length, std::uint32_t* data_flags,
      nghttp2_data_source*, void* user_data) noexcept {
    auto& self = *static_cast<TestServer*>(user_data);
    try {
      auto& body = self.response_bodies_.at(stream_id);
      const auto remaining = body.data.size() - body.offset;
      const auto copied = std::min(length, remaining);
      if (copied != 0U) {
        std::memcpy(buffer, body.data.data() + body.offset, copied);
        body.offset += copied;
      }
      if (body.offset == body.data.size()) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        if (body.leave_open_for_trailers) {
          *data_flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
        }
      }
      return static_cast<nghttp2_ssize>(copied);
    } catch (...) {
      self.callback_failed_ = true;
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
  nghttp2_session_callbacks* callbacks_{nullptr};
  nghttp2_session* session_{nullptr};
  std::unordered_map<int, std::uint32_t> client_settings_;
  std::unordered_map<std::int32_t, std::vector<Http2Header>> request_headers_;
  std::unordered_map<std::int32_t, std::vector<std::uint8_t>> request_bodies_;
  std::unordered_map<std::int32_t, bool> request_ended_;
  std::unordered_map<std::int32_t, std::uint32_t> close_errors_;
  std::unordered_map<std::int32_t, std::uint32_t> received_reset_errors_;
  std::unordered_map<std::int32_t, ResponseBody> response_bodies_;
  bool callback_failed_{false};
};

[[nodiscard]] std::vector<Http2Header> request_headers(
    std::string_view method = "GET", std::string_view path = "/ready") {
  return {{":method", std::string(method), false},
          {":scheme", "https", false},
          {":authority", "api.example.test", false},
          {":path", std::string(path), false}};
}

[[nodiscard]] std::vector<std::uint8_t> take_client_output(
    Http2ClientSession& client) {
  std::vector<std::uint8_t> output;
  for (;;) {
    auto chunk = client.take_output_chunk();
    if (chunk.empty()) {
      break;
    }
    output.insert(output.end(), chunk.begin(), chunk.end());
    client.acknowledge_output_chunk();
  }
  return output;
}

[[nodiscard]] std::vector<std::uint8_t> raw_frame(
    std::uint8_t type, std::uint8_t flags, std::int32_t stream_id,
    std::span<const std::uint8_t> payload = {}) {
  require(payload.size() <= 0x00ff'ffffU,
          "test HTTP/2 frame payload is too large");
  const auto length = static_cast<std::uint32_t>(payload.size());
  const auto encoded_stream_id =
      static_cast<std::uint32_t>(stream_id) & 0x7fff'ffffU;
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

void feed_client(Http2ClientSession& client,
                 std::span<const std::uint8_t> input) {
  const auto consumed = client.receive(input);
  require(consumed == input.size(), "client did not consume all server output");
}

void exchange_initial_settings(Http2ClientSession& client,
                               TestServer& server) {
  server.receive(take_client_output(client));
  feed_client(client, server.take_output());
  server.receive(take_client_output(client));
}

[[nodiscard]] const Http2ClientEvent* find_event(
    const std::vector<Http2ClientEvent>& events, Http2ClientEventKind kind,
    std::int32_t stream_id = 0) {
  const auto iterator = std::find_if(
      events.begin(), events.end(), [kind, stream_id](const auto& event) {
        return event.kind == kind &&
               (stream_id == 0 || event.stream_id == stream_id);
      });
  return iterator == events.end() ? nullptr : &*iterator;
}

void test_initial_negotiation_and_multiplexed_capacity() {
  Http2ClientLimits pre_settings_limits;
  pre_settings_limits.max_concurrent_streams = 500U;
  Http2ClientSession pre_settings_client(pre_settings_limits);
  require(pre_settings_client.peer_max_concurrent_streams() == 100U &&
              pre_settings_client.available_stream_capacity() == 100U,
          "pre-SETTINGS capacity did not match nghttp2's conservative limit");
  auto outstanding_output = pre_settings_client.take_output_chunk();
  require(!outstanding_output.empty() &&
              pre_settings_client.output_chunk_pending_acknowledgement(),
          "serialized output ownership was not recorded");
  bool overlapping_output_rejected = false;
  try {
    (void)pre_settings_client.take_output_chunk();
  } catch (const std::logic_error&) {
    overlapping_output_rejected = true;
  }
  require(overlapping_output_rejected,
          "a second output chunk bypassed transport ownership");
  pre_settings_client.acknowledge_output_chunk();
  require(!pre_settings_client.output_chunk_pending_acknowledgement(),
          "transport output acknowledgement was not recorded");

  Http2ClientLimits limits;
  limits.max_concurrent_streams = 3U;
  Http2ClientSession client(limits);
  TestServer server(2U);
  exchange_initial_settings(client, server);

  require(server.client_setting(NGHTTP2_SETTINGS_ENABLE_PUSH) == 0U,
          "client did not disable server push");
  require(server.client_setting(NGHTTP2_SETTINGS_MAX_FRAME_SIZE) ==
              limits.max_frame_bytes,
          "client advertised the wrong maximum frame size");
  require(client.peer_settings_received(),
          "client did not record peer SETTINGS");
  require(client.peer_max_concurrent_streams() == 2U,
          "client did not record peer stream capacity");
  require(client.available_stream_capacity() == 2U,
          "effective stream capacity was not local/peer minimum");

  auto first_headers = request_headers("GET", "/one");
  first_headers.push_back({"authorization", "secret", true});
  const auto first = client.submit_request(first_headers, true);
  const auto second = client.submit_request(request_headers("GET", "/two"),
                                            true);
  require(first != second && client.active_streams() == 2U,
          "client did not maintain multiplexed stream state");
  bool exhausted = false;
  try {
    (void)client.submit_request(request_headers("GET", "/three"), true);
  } catch (const std::length_error&) {
    exhausted = true;
  }
  require(exhausted, "peer stream capacity was not enforced");

  server.receive(take_client_output(client));
  const auto& received = server.request_headers(first);
  require(received.back().name == "authorization" &&
              received.back().never_index,
          "outbound never-index flag was not preserved");

  server.submit_informational(first, 103U);
  server.submit_empty_response(first, 204U);
  server.submit_empty_response(second, 200U);
  feed_client(client, server.take_output());
  const auto events = client.take_events();
  const auto informational = std::find_if(
      events.begin(), events.end(), [first](const auto& event) {
        return event.kind == Http2ClientEventKind::response_headers &&
               event.stream_id == first && event.status == 103U;
      });
  const auto final = std::find_if(
      events.begin(), events.end(), [first](const auto& event) {
        return event.kind == Http2ClientEventKind::response_headers &&
               event.stream_id == first && event.status == 204U;
      });
  require(informational != events.end() && final != events.end(),
          "incremental informational/final response headers were lost");
  require(client.active_streams() == 0U &&
              client.available_stream_capacity() == 2U,
          "closed streams did not restore capacity");
}

void test_streaming_request_response_trailers_and_flow_control() {
  Http2ClientLimits limits;
  limits.max_queued_request_bytes = 16'384U;
  limits.max_queued_request_bytes_per_stream = 16'384U;
  Http2ClientSession client(limits);
  TestServer server;
  exchange_initial_settings(client, server);

  const auto stream_id =
      client.submit_request(request_headers("POST", "/stream"), false);
  server.receive(take_client_output(client));

  const std::vector<std::uint8_t> first_chunk(16'384U, 0x5aU);
  require(client.try_submit_data(stream_id, first_chunk, false),
          "bounded request DATA was rejected");
  const std::array<std::uint8_t, 1U> tail{0x7fU};
  require(!client.try_submit_data(stream_id, tail, true),
          "request DATA queue exceeded its configured bound");
  require(client.queued_request_bytes() == first_chunk.size(),
          "request DATA queue accounting is incorrect");
  server.receive(take_client_output(client));
  require(client.queued_request_bytes() == 0U,
          "serialized request DATA retained queue accounting");
  require(client.try_submit_data(stream_id, tail, true),
          "deferred request provider did not resume");
  server.receive(take_client_output(client));
  require(server.request_body(stream_id).size() == first_chunk.size() + 1U &&
              server.request_ended(stream_id),
          "streaming request body or END_STREAM was lost");

  const std::array<Http2Header, 1U> response_headers{{
      {"content-type", "application/octet-stream", false},
  }};
  const std::vector<std::uint8_t> response_body{'r', 'e', 's', 'p', 'o',
                                                 'n', 's', 'e'};
  server.submit_streaming_response(stream_id, 200U, response_headers,
                                   response_body, true);
  feed_client(client, server.take_output());
  auto events = client.take_events();
  const auto* headers_event =
      find_event(events, Http2ClientEventKind::response_headers, stream_id);
  const auto* data_event =
      find_event(events, Http2ClientEventKind::data, stream_id);
  require(headers_event != nullptr && headers_event->status == 200U,
          "streaming response headers were not emitted");
  require(data_event != nullptr && data_event->data == response_body,
          "streaming response DATA was not emitted");
  require(client.unacknowledged_data_bytes() == response_body.size(),
          "manual flow-control debt was not recorded");
  client.acknowledge_data(stream_id, response_body.size());
  require(client.unacknowledged_data_bytes() == 0U,
          "manual flow-control acknowledgement did not clear debt");

  const std::array<Http2Header, 2U> trailers{{
      {"grpc-status", "0", true},
      {"grpc-message", "complete", false},
  }};
  server.submit_trailers(stream_id, trailers);
  feed_client(client, server.take_output());
  events = client.take_events();
  const auto* trailer_event =
      find_event(events, Http2ClientEventKind::response_trailers, stream_id);
  require(trailer_event != nullptr && trailer_event->end_stream &&
              trailer_event->headers.size() == 2U &&
              trailer_event->headers.front().name == "grpc-status" &&
              trailer_event->headers.front().never_index,
          "response trailers or never-index flag were not preserved");
  require(find_event(events, Http2ClientEventKind::stream_end, stream_id) !=
              nullptr &&
              find_event(events, Http2ClientEventKind::stream_closed,
                         stream_id) != nullptr,
          "trailer END_STREAM lifecycle events were not emitted");
}

void test_request_fragment_count_is_bounded() {
  Http2ClientLimits limits;
  limits.max_queued_request_chunks = 2U;
  limits.max_queued_request_chunks_per_stream = 2U;
  Http2ClientSession client(limits);
  TestServer server;
  exchange_initial_settings(client, server);
  const auto stream_id =
      client.submit_request(request_headers("POST", "/fragments"), false);
  server.receive(take_client_output(client));

  const std::array<std::uint8_t, 1U> first{0x01U};
  const std::array<std::uint8_t, 1U> second{0x02U};
  const std::array<std::uint8_t, 1U> third{0x03U};
  require(client.try_submit_data(stream_id, first, false) &&
              client.try_submit_data(stream_id, second, false),
          "request fragment bound rejected admitted fragments");
  require(!client.try_submit_data(stream_id, third, true),
          "request fragment count exceeded its configured bound");
  require(client.queued_request_bytes() == 2U,
          "fragment-count rejection corrupted byte accounting");

  server.receive(take_client_output(client));
  require(client.try_submit_data(stream_id, third, true),
          "draining retained fragments did not restore fragment capacity");
  server.receive(take_client_output(client));
  require(server.request_body(stream_id) ==
              std::vector<std::uint8_t>({0x01U, 0x02U, 0x03U}) &&
              server.request_ended(stream_id),
          "fragment-count enforcement changed request DATA ordering");
}

void test_event_queue_backpressure_is_bounded() {
  Http2ClientLimits limits;
  limits.max_header_fields = 4U;
  limits.max_queued_event_bytes = 96U * 1024U;
  Http2ClientSession client(limits);
  TestServer server;
  exchange_initial_settings(client, server);
  const auto stream_id =
      client.submit_request(request_headers("GET", "/large"), true);
  server.receive(take_client_output(client));

  const std::vector<std::uint8_t> body(61'440U, 0x2aU);
  server.submit_streaming_response(stream_id, 200U, {}, body, false);
  auto header_chunk = server.take_output_chunk();
  feed_client(client, header_chunk);
  (void)client.take_events();

  auto data_wire = server.take_output();
  const auto consumed = client.receive(data_wire);
  require(consumed > 0U && consumed < data_wire.size(),
          "bounded event queue did not apply incremental backpressure");
  require(client.queued_event_bytes() <= limits.max_queued_event_bytes,
          "response event queue exceeded its configured bound");
  auto events = client.take_events();
  std::size_t acknowledged = 0U;
  for (const auto& event : events) {
    if (event.kind == Http2ClientEventKind::data) {
      acknowledged += event.data.size();
    }
  }
  client.acknowledge_data(stream_id, acknowledged);
  feed_client(client, std::span<const std::uint8_t>(data_wire).subspan(consumed));
  events = client.take_events();
  acknowledged = 0U;
  for (const auto& event : events) {
    if (event.kind == Http2ClientEventKind::data) {
      acknowledged += event.data.size();
    }
  }
  require(client.active_streams() == 0U,
          "test did not reach stream close before final acknowledgement");
  client.acknowledge_data(stream_id, acknowledged);
  require(client.unacknowledged_data_bytes() == 0U,
          "backpressured DATA left flow-control debt");
}

void test_terminal_events_survive_normal_queue_pressure() {
  Http2ClientLimits limits;
  limits.max_concurrent_streams = 1U;
  limits.max_header_fields = 4U;
  limits.max_queued_event_bytes = 48U * 1024U;
  Http2ClientSession client(limits);
  TestServer server;
  exchange_initial_settings(client, server);
  const auto stream_id =
      client.submit_request(request_headers("GET", "/event-pressure"), true);
  server.receive(take_client_output(client));

  for (std::size_t index = 0U; index < 256U; ++index) {
    server.submit_informational(stream_id, 103U);
  }
  feed_client(client, server.take_output());
  server.receive(take_client_output(client));

  const auto events = client.take_events();
  require(client.dropped_events() > 0U,
          "normal event pressure did not exercise bounded rejection");
  require(find_event(events, Http2ClientEventKind::stream_closed, stream_id) !=
              nullptr,
          "terminal stream closure was displaced by normal event pressure");
}

void test_resets_and_goaway() {
  Http2ClientSession client;
  TestServer server;
  exchange_initial_settings(client, server);
  const auto first =
      client.submit_request(request_headers("GET", "/reset"), true);
  const auto second =
      client.submit_request(request_headers("GET", "/goaway"), true);
  server.receive(take_client_output(client));
  server.reset_stream(first, NGHTTP2_CANCEL);
  server.submit_goaway(second, NGHTTP2_NO_ERROR, "maintenance");
  feed_client(client, server.take_output());
  const auto events = client.take_events();
  const auto* reset =
      find_event(events, Http2ClientEventKind::stream_reset, first);
  const auto* goaway = find_event(events, Http2ClientEventKind::goaway);
  require(reset != nullptr && reset->error_code == NGHTTP2_CANCEL,
          "peer RST_STREAM event was not preserved");
  require(goaway != nullptr && goaway->last_stream_id == second &&
              std::string(goaway->data.begin(), goaway->data.end()) ==
                  "maintenance",
          "peer GOAWAY metadata was not preserved");
  require(client.is_draining() && client.available_stream_capacity() == 0U,
          "peer GOAWAY did not stop new stream admission");
  bool rejected = false;
  try {
    (void)client.submit_request(request_headers(), true);
  } catch (const std::logic_error&) {
    rejected = true;
  }
  require(rejected, "draining client accepted a new request");

  Http2ClientSession empty_debug_client;
  TestServer empty_debug_server;
  exchange_initial_settings(empty_debug_client, empty_debug_server);
  empty_debug_server.submit_goaway(0, NGHTTP2_NO_ERROR, {});
  feed_client(empty_debug_client, empty_debug_server.take_output());
  const auto empty_debug_events = empty_debug_client.take_events();
  const auto* empty_goaway =
      find_event(empty_debug_events, Http2ClientEventKind::goaway);
  require(empty_goaway != nullptr && empty_goaway->data.empty(),
          "zero-length GOAWAY debug data was not handled safely");
}

void test_fail_closed_validation_and_over_limits() {
  bool bad_limit_rejected = false;
  try {
    Http2ClientLimits limits;
    limits.max_frame_bytes = 1'024U;
    Http2ClientSession invalid(limits);
  } catch (const std::invalid_argument&) {
    bad_limit_rejected = true;
  }
  require(bad_limit_rejected, "invalid client frame limit was accepted");

  bool stream_limit_rejected = false;
  try {
    Http2ClientLimits limits;
    limits.max_concurrent_streams = 1'001U;
    Http2ClientSession invalid(limits);
  } catch (const std::invalid_argument&) {
    stream_limit_rejected = true;
  }
  require(stream_limit_rejected,
          "client stream limit above config contract was accepted");

  Http2ClientSession client;
  auto malformed = request_headers();
  malformed[0].name = ":path";
  bool pseudo_rejected = false;
  try {
    (void)client.submit_request(malformed, true);
  } catch (const std::invalid_argument&) {
    pseudo_rejected = true;
  }
  require(pseudo_rejected, "malformed request pseudo-headers were accepted");

  malformed = request_headers();
  malformed.push_back({"Connection", "close", false});
  bool uppercase_rejected = false;
  try {
    (void)client.submit_request(malformed, true);
  } catch (const std::invalid_argument&) {
    uppercase_rejected = true;
  }
  require(uppercase_rejected, "invalid regular request header was accepted");

  bool connect_rejected = false;
  try {
    (void)client.submit_request(request_headers("CONNECT", "/tunnel"), true);
  } catch (const std::invalid_argument&) {
    connect_rejected = true;
  }
  require(connect_rejected, "regular-request API accepted CONNECT");

  bool star_get_rejected = false;
  try {
    (void)client.submit_request(request_headers("GET", "*"), true);
  } catch (const std::invalid_argument&) {
    star_get_rejected = true;
  }
  require(star_get_rejected, "non-OPTIONS request accepted star path");
  const auto options_stream =
      client.submit_request(request_headers("OPTIONS", "*"), true);
  require(options_stream > 0, "OPTIONS star request was rejected");

  malformed = request_headers();
  malformed[2].value = "bad authority";
  bool authority_rejected = false;
  try {
    (void)client.submit_request(malformed, true);
  } catch (const std::invalid_argument&) {
    authority_rejected = true;
  }
  require(authority_rejected, "invalid request authority was accepted");

  malformed = request_headers();
  malformed[3].value = "/bad path";
  bool path_rejected = false;
  try {
    (void)client.submit_request(malformed, true);
  } catch (const std::invalid_argument&) {
    path_rejected = true;
  }
  require(path_rejected, "invalid request path was accepted");

  Http2ClientLimits tight_limits;
  tight_limits.max_header_fields = 4U;
  Http2ClientSession tight_client(tight_limits);
  TestServer server;
  exchange_initial_settings(tight_client, server);
  const auto stream_id =
      tight_client.submit_request(request_headers(), true);
  server.receive(take_client_output(tight_client));
  const std::array<Http2Header, 4U> too_many{{
      {"x-one", "1", false},
      {"x-two", "2", false},
      {"x-three", "3", false},
      {"x-four", "4", false},
  }};
  server.submit_empty_response(stream_id, 200U, too_many);
  feed_client(tight_client, server.take_output());
  require(tight_client.rejected_streams() == 1U,
          "over-limit response header block was not rejected");
  require(find_event(tight_client.take_events(),
                     Http2ClientEventKind::response_headers, stream_id) ==
              nullptr,
          "over-limit response reached the application");
  server.receive(take_client_output(tight_client));
  require(server.received_reset_error(stream_id) ==
              NGHTTP2_ENHANCE_YOUR_CALM,
          "over-limit response used the wrong reset code");

  Http2ClientSession status_client;
  TestServer status_server;
  exchange_initial_settings(status_client, status_server);
  const auto status_stream =
      status_client.submit_request(request_headers(), true);
  status_server.receive(take_client_output(status_client));
  status_server.submit_informational(status_stream, 101U);
  feed_client(status_client, status_server.take_output());
  require(status_client.rejected_streams() == 1U,
          "HTTP/2 status 101 was not rejected");
  require(find_event(status_client.take_events(),
                     Http2ClientEventKind::response_headers,
                     status_stream) == nullptr,
          "HTTP/2 status 101 reached the application");
  status_server.receive(take_client_output(status_client));
  require(status_server.received_reset_error(status_stream) ==
              NGHTTP2_PROTOCOL_ERROR,
          "HTTP/2 status 101 used the wrong stream error scope");

  Http2ClientSession invalid_field_client;
  TestServer invalid_field_server;
  exchange_initial_settings(invalid_field_client, invalid_field_server);
  const auto invalid_field_stream =
      invalid_field_client.submit_request(request_headers(), true);
  invalid_field_server.receive(take_client_output(invalid_field_client));
  const std::array<Http2Header, 1U> invalid_response_field{{
      {"x-invalid", "line\rbreak", false},
  }};
  invalid_field_server.submit_empty_response(invalid_field_stream, 200U,
                                             invalid_response_field);
  feed_client(invalid_field_client, invalid_field_server.take_output());
  require(invalid_field_client.rejected_streams() == 1U,
          "invalid regular response field was ignored");
  require(find_event(invalid_field_client.take_events(),
                     Http2ClientEventKind::response_headers,
                     invalid_field_stream) == nullptr,
          "invalid regular response field reached the application");
  invalid_field_server.receive(take_client_output(invalid_field_client));
  require(invalid_field_server.received_reset_error(invalid_field_stream) ==
              NGHTTP2_PROTOCOL_ERROR,
          "invalid regular response field used the wrong stream error");

  Http2ClientSession trailer_client;
  TestServer trailer_server;
  exchange_initial_settings(trailer_client, trailer_server);
  const auto trailer_stream =
      trailer_client.submit_request(request_headers(), true);
  trailer_server.receive(take_client_output(trailer_client));
  trailer_server.submit_streaming_response(trailer_stream, 200U, {}, {},
                                           true);
  feed_client(trailer_client, trailer_server.take_output());
  (void)trailer_client.take_events();
  const std::array<Http2Header, 1U> framing_trailer{{
      {"content-type", "application/json", false},
  }};
  trailer_server.submit_trailers(trailer_stream, framing_trailer);
  feed_client(trailer_client, trailer_server.take_output());
  require(trailer_client.rejected_streams() == 1U,
          "response representation field in trailers was not rejected");
  require(find_event(trailer_client.take_events(),
                     Http2ClientEventKind::response_trailers,
                     trailer_stream) == nullptr,
          "response framing trailer reached the application");
  trailer_server.receive(take_client_output(trailer_client));
  require(trailer_server.received_reset_error(trailer_stream) ==
              NGHTTP2_PROTOCOL_ERROR,
          "forbidden response trailer used the wrong stream error scope");

  Http2ClientSession early_data_client;
  TestServer early_data_server;
  exchange_initial_settings(early_data_client, early_data_server);
  const auto early_data_stream =
      early_data_client.submit_request(request_headers(), true);
  early_data_server.receive(take_client_output(early_data_client));
  const std::array<std::uint8_t, 1U> early_payload{0x01U};
  feed_client(early_data_client,
              raw_frame(NGHTTP2_DATA, NGHTTP2_FLAG_END_STREAM,
                        early_data_stream, early_payload));
  const auto early_data_output = take_client_output(early_data_client);
  early_data_server.receive(early_data_output);
  const auto early_data_reset =
      early_data_server.received_reset_error(early_data_stream);
  require(early_data_reset == NGHTTP2_PROTOCOL_ERROR,
          "DATA before final response headers used stream error " +
              std::to_string(early_data_reset));
}

}  // namespace

int main() {
  test_initial_negotiation_and_multiplexed_capacity();
  test_streaming_request_response_trailers_and_flow_control();
  test_request_fragment_count_is_bounded();
  test_event_queue_backpressure_is_bounded();
  test_terminal_events_survive_normal_queue_pressure();
  test_resets_and_goaway();
  test_fail_closed_validation_and_over_limits();
  return 0;
}
