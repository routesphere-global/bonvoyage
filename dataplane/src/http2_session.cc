#include "bonvoyage/http/http2_session.hh"

#include <algorithm>
#include <array>
#include <cstring>
#include <deque>
#include <limits>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include <nghttp2/nghttp2.h>

namespace bonvoyage::http {
namespace {

constexpr std::size_t kEventAccountingOverhead = 64U;
constexpr std::size_t kRecentLocalResetLimit = 1'024U;
constexpr std::uint32_t kMinFrameBytes = 16'384U;
constexpr std::uint32_t kMaxFrameBytes = 16'777'215U;

[[nodiscard]] std::string nghttp2_message(std::string_view operation,
                                         int error_code,
                                         std::string_view callback_failure) {
  std::string message(operation);
  message.append(": ");
  message.append(nghttp2_strerror(error_code));
  if (!callback_failure.empty()) {
    message.append(" (");
    message.append(callback_failure);
    message.push_back(')');
  }
  return message;
}

void require_nghttp2(int result, std::string_view operation,
                     std::string_view callback_failure = {}) {
  if (result < 0) {
    throw Http2ProtocolError(
        result, nghttp2_message(operation, result, callback_failure));
  }
}

[[nodiscard]] bool is_lowercase_header_name(std::string_view name) noexcept {
  return std::none_of(name.begin(), name.end(), [](char character) {
    return character >= 'A' && character <= 'Z';
  });
}

[[nodiscard]] bool is_connection_specific(std::string_view name) noexcept {
  constexpr std::array<std::string_view, 6U> disallowed{
      "connection", "keep-alive", "proxy-connection",
      "te",         "transfer-encoding", "upgrade"};
  return std::find(disallowed.begin(), disallowed.end(), name) !=
         disallowed.end();
}

[[nodiscard]] std::size_t header_field_size(std::size_t name_size,
                                            std::size_t value_size) {
  constexpr auto maximum = std::numeric_limits<std::size_t>::max();
  if (name_size > maximum - value_size ||
      name_size + value_size > maximum - 32U) {
    throw std::overflow_error("HTTP/2 header field size overflow");
  }
  return name_size + value_size + 32U;
}

[[nodiscard]] std::size_t checked_add(std::size_t left, std::size_t right,
                                      std::string_view description) {
  if (right > std::numeric_limits<std::size_t>::max() - left) {
    throw std::overflow_error(std::string(description));
  }
  return left + right;
}

[[nodiscard]] std::size_t checked_multiply(std::size_t left,
                                           std::size_t right,
                                           std::string_view description) {
  if (left != 0U &&
      right > std::numeric_limits<std::size_t>::max() / left) {
    throw std::overflow_error(std::string(description));
  }
  return left * right;
}

void validate_limits(const Http2Limits& limits) {
  if (limits.max_concurrent_streams == 0U) {
    throw std::invalid_argument("HTTP/2 max_concurrent_streams must be nonzero");
  }
  if (limits.initial_stream_window_bytes >
      static_cast<std::uint32_t>(NGHTTP2_MAX_WINDOW_SIZE)) {
    throw std::invalid_argument("HTTP/2 initial stream window is too large");
  }
  if (limits.max_frame_bytes < kMinFrameBytes ||
      limits.max_frame_bytes > kMaxFrameBytes) {
    throw std::invalid_argument("HTTP/2 max frame size is outside RFC bounds");
  }
  if (limits.max_header_list_bytes == 0U ||
      limits.max_header_fields == 0U) {
    throw std::invalid_argument("HTTP/2 header limits must be nonzero");
  }

  const auto maximum_header_storage = checked_add(
      limits.max_header_list_bytes,
      checked_multiply(limits.max_header_fields, sizeof(Http2Header),
                       "HTTP/2 header field accounting overflow"),
      "HTTP/2 header event accounting overflow");
  const auto largest_event =
      checked_add(std::max<std::size_t>(maximum_header_storage,
                                        limits.max_frame_bytes),
                  kEventAccountingOverhead,
                  "HTTP/2 event accounting overflow");
  if (limits.max_queued_event_bytes < largest_event) {
    throw std::invalid_argument(
        "HTTP/2 event queue must hold one maximum-sized event");
  }
  if (limits.max_output_chunk_bytes <
      static_cast<std::size_t>(limits.max_frame_bytes) + 9U) {
    throw std::invalid_argument(
        "HTTP/2 output bound must hold one maximum-sized frame");
  }
  if (limits.max_queued_response_bytes < limits.max_frame_bytes) {
    throw std::invalid_argument(
        "HTTP/2 response queue must hold one maximum-sized DATA frame");
  }
  if (limits.max_settings_entries == 0U ||
      limits.max_continuation_frames == 0U ||
      limits.max_outbound_ack_frames == 0U) {
    throw std::invalid_argument("HTTP/2 protocol flood limits must be nonzero");
  }
  if (limits.reset_rate_burst == 0U ||
      limits.reset_rate_per_second == 0U ||
      limits.glitch_rate_burst == 0U ||
      limits.glitch_rate_per_second == 0U) {
    throw std::invalid_argument("HTTP/2 rate limits must be nonzero");
  }
}

[[nodiscard]] nghttp2_nv native_header(const std::string& name,
                                       const std::string& value,
                                       bool never_index) noexcept {
  const auto flags = never_index ? NGHTTP2_NV_FLAG_NO_INDEX
                                 : NGHTTP2_NV_FLAG_NONE;
  return nghttp2_nv{
      const_cast<std::uint8_t*>(
          reinterpret_cast<const std::uint8_t*>(name.data())),
      const_cast<std::uint8_t*>(
          reinterpret_cast<const std::uint8_t*>(value.data())),
      name.size(), value.size(), static_cast<std::uint8_t>(flags)};
}

}  // namespace

Http2ProtocolError::Http2ProtocolError(int library_error_code,
                                       const std::string& message)
    : std::runtime_error(message), library_error_code_(library_error_code) {}

class Http2ServerSession::Impl final {
 public:
  explicit Impl(Http2Limits limits) : limits_(limits) {
    validate_limits(limits_);

    nghttp2_session_callbacks* callbacks = nullptr;
    require_nghttp2(nghttp2_session_callbacks_new(&callbacks),
                    "create HTTP/2 callbacks");
    callbacks_ = callbacks;

    nghttp2_session_callbacks_set_on_begin_headers_callback(
        callbacks_, &Impl::on_begin_headers_callback);
    nghttp2_session_callbacks_set_on_begin_frame_callback(
        callbacks_, &Impl::on_begin_frame_callback);
    nghttp2_session_callbacks_set_on_header_callback(
        callbacks_, &Impl::on_header_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(
        callbacks_, &Impl::on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
        callbacks_, &Impl::on_data_chunk_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(
        callbacks_, &Impl::on_stream_close_callback);

    nghttp2_option* option = nullptr;
    try {
      require_nghttp2(nghttp2_option_new(&option),
                      "create HTTP/2 session options");
      nghttp2_option_set_no_auto_window_update(option, 1);
      nghttp2_option_set_max_send_header_block_length(
          option, limits_.max_header_list_bytes);
      nghttp2_option_set_max_deflate_dynamic_table_size(
          option, limits_.header_table_bytes);
      nghttp2_option_set_max_outbound_ack(option,
                                          limits_.max_outbound_ack_frames);
      nghttp2_option_set_max_settings(option, limits_.max_settings_entries);
      nghttp2_option_set_max_continuations(
          option, limits_.max_continuation_frames);
      nghttp2_option_set_stream_reset_rate_limit(
          option, limits_.reset_rate_burst, limits_.reset_rate_per_second);
      nghttp2_option_set_glitch_rate_limit(
          option, limits_.glitch_rate_burst, limits_.glitch_rate_per_second);

      require_nghttp2(
          nghttp2_session_server_new2(&session_, callbacks_, this, option),
          "create HTTP/2 server session");
      nghttp2_option_del(option);
      option = nullptr;

      const std::array<nghttp2_settings_entry, 6U> settings{{
          {NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, limits_.header_table_bytes},
          {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
           limits_.max_concurrent_streams},
          {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
           limits_.initial_stream_window_bytes},
          {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, limits_.max_frame_bytes},
          {NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE,
           limits_.max_header_list_bytes},
          {NGHTTP2_SETTINGS_NO_RFC7540_PRIORITIES, 1U},
      }};
      require_nghttp2(
          nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE,
                                  settings.data(), settings.size()),
          "submit HTTP/2 server settings");
    } catch (...) {
      nghttp2_option_del(option);
      nghttp2_session_del(session_);
      session_ = nullptr;
      nghttp2_session_callbacks_del(callbacks_);
      callbacks_ = nullptr;
      throw;
    }
  }

  ~Impl() {
    nghttp2_session_del(session_);
    nghttp2_session_callbacks_del(callbacks_);
  }

  [[nodiscard]] std::size_t receive(
      std::span<const std::uint8_t> input) {
    callback_failure_ = {};
    callback_paused_ = false;
    const auto result =
        nghttp2_session_mem_recv2(session_, input.data(), input.size());
    if (result < 0) {
      const auto error_code = static_cast<int>(result);
      throw Http2ProtocolError(
          error_code,
          nghttp2_message("process HTTP/2 input", error_code,
                          callback_failure_));
    }
    if (callback_paused_ && static_cast<std::size_t>(result) == input.size()) {
      callback_paused_ = false;
      const auto resume_result =
          nghttp2_session_mem_recv2(session_, nullptr, 0U);
      if (resume_result < 0) {
        const auto error_code = static_cast<int>(resume_result);
        throw Http2ProtocolError(
            error_code,
            nghttp2_message("resume paused HTTP/2 input", error_code,
                            callback_failure_));
      }
    }
    return static_cast<std::size_t>(result);
  }

  [[nodiscard]] std::vector<std::uint8_t> take_output_chunk() {
    callback_failure_ = {};
    const std::uint8_t* data = nullptr;
    const auto result = nghttp2_session_mem_send2(session_, &data);
    if (result < 0) {
      const auto error_code = static_cast<int>(result);
      throw Http2ProtocolError(
          error_code,
          nghttp2_message("serialize HTTP/2 output", error_code,
                          callback_failure_));
    }
    const auto size = static_cast<std::size_t>(result);
    if (size > limits_.max_output_chunk_bytes) {
      throw Http2ProtocolError(
          NGHTTP2_ERR_FRAME_SIZE_ERROR,
          "serialize HTTP/2 output: generated chunk exceeds local bound");
    }
    if (size == 0U) {
      return {};
    }
    return {data, data + size};
  }

  [[nodiscard]] std::vector<Http2Event> take_events() {
    std::vector<Http2Event> result;
    result.swap(events_);
    queued_event_bytes_ = 0U;
    return result;
  }

  void acknowledge_data(std::int32_t stream_id, std::size_t bytes) {
    if (stream_id <= 0) {
      throw std::invalid_argument("HTTP/2 stream ID must be positive");
    }
    if (bytes == 0U) {
      return;
    }
    require_nghttp2(nghttp2_session_consume(session_, stream_id, bytes),
                    "release HTTP/2 inbound flow-control credit");
  }

  void submit_empty_response(std::int32_t stream_id, std::uint16_t status,
                             std::span<const Http2Header> headers) {
    submit_response_headers(stream_id, status, headers, true);
  }

  void submit_response_headers(std::int32_t stream_id, std::uint16_t status,
                               std::span<const Http2Header> headers,
                               bool end_stream) {
    if (stream_id <= 0) {
      throw std::invalid_argument("HTTP/2 stream ID must be positive");
    }
    if (status < 200U || status > 599U) {
      throw std::invalid_argument(
          "header-only HTTP/2 response status must be final");
    }
    if (responded_streams_.contains(stream_id)) {
      throw std::logic_error("HTTP/2 stream already has a final response");
    }
    if (headers.size() >= limits_.max_header_fields) {
      throw std::invalid_argument("HTTP/2 response has too many headers");
    }

    const std::string status_value = std::to_string(status);
    const std::string status_name = ":status";
    auto header_bytes = header_field_size(status_name.size(),
                                          status_value.size());
    std::vector<nghttp2_nv> native_headers;
    native_headers.reserve(headers.size() + 1U);
    native_headers.push_back(native_header(status_name, status_value, false));

    for (const auto& header : headers) {
      const auto name = std::string_view(header.name);
      if (name.empty() || name.front() == ':' ||
          !is_lowercase_header_name(name) || is_connection_specific(name) ||
          nghttp2_check_header_name(
              reinterpret_cast<const std::uint8_t*>(name.data()),
              name.size()) == 0 ||
          nghttp2_check_header_value_rfc9113(
              reinterpret_cast<const std::uint8_t*>(header.value.data()),
              header.value.size()) == 0) {
        throw std::invalid_argument("invalid HTTP/2 response header");
      }
      const auto field_bytes =
          header_field_size(header.name.size(), header.value.size());
      if (header_bytes > limits_.max_header_list_bytes ||
          field_bytes > limits_.max_header_list_bytes - header_bytes) {
        throw std::invalid_argument("HTTP/2 response headers are too large");
      }
      header_bytes += field_bytes;
      native_headers.push_back(
          native_header(header.name, header.value, header.never_index));
    }

    const auto [response_iterator, inserted] =
        responded_streams_.insert(stream_id);
    if (!inserted) {
      throw std::logic_error("HTTP/2 stream already has a final response");
    }
    auto outbound_iterator = outbound_streams_.end();
    if (!end_stream) {
      const auto [iterator, outbound_inserted] =
          outbound_streams_.try_emplace(stream_id);
      if (!outbound_inserted) {
        responded_streams_.erase(response_iterator);
        throw std::logic_error("HTTP/2 response body state already exists");
      }
      outbound_iterator = iterator;
    }
    try {
      nghttp2_data_provider2 provider{};
      const nghttp2_data_provider2* provider_pointer = nullptr;
      if (!end_stream) {
        provider.source.ptr = this;
        provider.read_callback = &Impl::read_response_data_callback;
        provider_pointer = &provider;
      }
      require_nghttp2(
          nghttp2_submit_response2(session_, stream_id, native_headers.data(),
                                   native_headers.size(), provider_pointer),
          "submit HTTP/2 response headers");
    } catch (...) {
      if (outbound_iterator != outbound_streams_.end()) {
        outbound_streams_.erase(outbound_iterator);
      }
      responded_streams_.erase(response_iterator);
      throw;
    }
  }

  [[nodiscard]] bool try_submit_data(
      std::int32_t stream_id, std::span<const std::uint8_t> data,
      bool end_stream) {
    if (stream_id <= 0) {
      throw std::invalid_argument("HTTP/2 stream ID must be positive");
    }
    const auto iterator = outbound_streams_.find(stream_id);
    if (iterator == outbound_streams_.end()) {
      throw std::logic_error("HTTP/2 stream has no open response body");
    }
    auto& outbound = iterator->second;
    if (outbound.end_stream_queued) {
      throw std::logic_error("HTTP/2 response body is already complete");
    }
    if (data.size() > limits_.max_queued_response_bytes ||
        data.size() > limits_.max_queued_response_bytes -
                          std::min(queued_response_bytes_,
                                   limits_.max_queued_response_bytes)) {
      return false;
    }
    if (!data.empty()) {
      outbound.chunks.emplace_back(data.begin(), data.end());
      queued_response_bytes_ += data.size();
    }
    outbound.end_stream_queued = end_stream;
    if (outbound.deferred) {
      outbound.deferred = false;
      require_nghttp2(nghttp2_session_resume_data(session_, stream_id),
                      "resume HTTP/2 response DATA");
    }
    return true;
  }

  void submit_response_trailers(
      std::int32_t stream_id, std::span<const Http2Header> trailers) {
    if (stream_id <= 0) {
      throw std::invalid_argument("HTTP/2 stream ID must be positive");
    }
    const auto iterator = outbound_streams_.find(stream_id);
    if (iterator == outbound_streams_.end()) {
      throw std::logic_error("HTTP/2 stream has no open response body");
    }
    auto& outbound = iterator->second;
    if (outbound.end_stream_queued) {
      throw std::logic_error("HTTP/2 response body is already complete");
    }
    if (trailers.empty() || trailers.size() > limits_.max_header_fields) {
      throw std::invalid_argument(
          "HTTP/2 response trailer count is outside the configured bound");
    }

    std::size_t trailer_bytes = 0U;
    for (const auto& trailer : trailers) {
      const auto name = std::string_view(trailer.name);
      if (name.empty() || name.front() == ':' ||
          !is_lowercase_header_name(name) || is_connection_specific(name) ||
          name == "content-length" || name == "host" || name == "trailer" ||
          nghttp2_check_header_name(
              reinterpret_cast<const std::uint8_t*>(name.data()),
              name.size()) == 0 ||
          nghttp2_check_header_value_rfc9113(
              reinterpret_cast<const std::uint8_t*>(trailer.value.data()),
              trailer.value.size()) == 0) {
        throw std::invalid_argument("invalid HTTP/2 response trailer");
      }
      const auto field_bytes =
          header_field_size(trailer.name.size(), trailer.value.size());
      if (trailer_bytes > limits_.max_header_list_bytes ||
          field_bytes > limits_.max_header_list_bytes - trailer_bytes) {
        throw std::invalid_argument("HTTP/2 response trailers are too large");
      }
      trailer_bytes += field_bytes;
    }

    outbound.trailers.assign(trailers.begin(), trailers.end());
    outbound.end_stream_queued = true;
    if (outbound.deferred) {
      outbound.deferred = false;
      require_nghttp2(nghttp2_session_resume_data(session_, stream_id),
                      "resume HTTP/2 response before trailers");
    }
  }

  void reset_stream(std::int32_t stream_id, std::uint32_t error_code) {
    if (stream_id <= 0) {
      throw std::invalid_argument("HTTP/2 stream ID must be positive");
    }
    require_nghttp2(
        nghttp2_submit_rst_stream(session_, NGHTTP2_FLAG_NONE, stream_id,
                                  error_code),
        "submit HTTP/2 stream reset");
    remember_local_reset(stream_id);
  }

  void begin_graceful_shutdown() {
    if (draining_) {
      return;
    }
    const auto last_stream_id = nghttp2_session_get_last_proc_stream_id(session_);
    require_nghttp2(
        nghttp2_submit_goaway(session_, NGHTTP2_FLAG_NONE, last_stream_id,
                              NGHTTP2_NO_ERROR, nullptr, 0U),
        "submit HTTP/2 GOAWAY");
    draining_ = true;
  }

  [[nodiscard]] bool wants_read() const noexcept {
    return nghttp2_session_want_read(session_) != 0;
  }

  [[nodiscard]] bool wants_write() const noexcept {
    return nghttp2_session_want_write(session_) != 0;
  }

  [[nodiscard]] bool should_close_transport() const noexcept {
    return !wants_read() && !wants_write();
  }

  [[nodiscard]] bool is_draining() const noexcept { return draining_; }

  [[nodiscard]] std::size_t queued_event_bytes() const noexcept {
    return queued_event_bytes_;
  }

  [[nodiscard]] std::size_t queued_response_bytes() const noexcept {
    return queued_response_bytes_;
  }

  [[nodiscard]] std::uint64_t rejected_streams() const noexcept {
    return rejected_streams_;
  }

  [[nodiscard]] std::uint64_t dropped_events() const noexcept {
    return dropped_events_;
  }

 private:
  enum class HeaderBlockKind { request, trailers };

  struct HeaderBlock final {
    HeaderBlockKind kind{HeaderBlockKind::request};
    std::vector<Http2Header> headers;
    std::size_t header_list_bytes{};
    std::size_t event_bytes{};
  };

  struct OutboundStream final {
    std::deque<std::vector<std::uint8_t>> chunks;
    std::vector<Http2Header> trailers;
    std::size_t front_offset{};
    bool end_stream_queued{false};
    bool trailers_submitted{false};
    bool deferred{false};
  };

  static int on_begin_headers_callback(nghttp2_session* session,
                                       const nghttp2_frame* frame,
                                       void* user_data) noexcept {
    return static_cast<Impl*>(user_data)->guard_callback(
        "begin headers", [session, frame](Impl& self) {
          return self.on_begin_headers(session, frame);
        });
  }

  static int on_begin_frame_callback(nghttp2_session* session,
                                     const nghttp2_frame_hd* frame,
                                     void* user_data) noexcept {
    return static_cast<Impl*>(user_data)->guard_callback(
        "begin frame", [session, frame](Impl& self) {
          return self.on_begin_frame(session, frame);
        });
  }

  static int on_header_callback(nghttp2_session* session,
                                const nghttp2_frame* frame,
                                const std::uint8_t* name,
                                std::size_t name_length,
                                const std::uint8_t* value,
                                std::size_t value_length, std::uint8_t flags,
                                void* user_data) noexcept {
    return static_cast<Impl*>(user_data)->guard_callback(
        "decode header", [=](Impl& self) {
          return self.on_header(session, frame, name, name_length, value,
                                value_length, flags);
        });
  }

  static int on_frame_recv_callback(nghttp2_session* session,
                                    const nghttp2_frame* frame,
                                    void* user_data) noexcept {
    return static_cast<Impl*>(user_data)->guard_callback(
        "receive frame", [session, frame](Impl& self) {
          return self.on_frame_recv(session, frame);
        });
  }

  static int on_data_chunk_recv_callback(nghttp2_session* session,
                                         std::uint8_t flags,
                                         std::int32_t stream_id,
                                         const std::uint8_t* data,
                                         std::size_t length,
                                         void* user_data) noexcept {
    return static_cast<Impl*>(user_data)->guard_callback(
        "receive DATA", [=](Impl& self) {
          return self.on_data_chunk(session, flags, stream_id, data, length);
        });
  }

  static int on_stream_close_callback(nghttp2_session* session,
                                      std::int32_t stream_id,
                                      std::uint32_t error_code,
                                      void* user_data) noexcept {
    return static_cast<Impl*>(user_data)->guard_callback(
        "close stream", [=](Impl& self) {
          return self.on_stream_close(session, stream_id, error_code);
        });
  }

  static nghttp2_ssize read_response_data_callback(
      nghttp2_session*, std::int32_t stream_id, std::uint8_t* buffer,
      std::size_t length, std::uint32_t* data_flags,
      nghttp2_data_source*, void* user_data) noexcept {
    auto& self = *static_cast<Impl*>(user_data);
    try {
      return self.read_response_data(stream_id, buffer, length, data_flags);
    } catch (const std::exception&) {
      self.callback_failure_ = "serialize response DATA";
    } catch (...) {
      self.callback_failure_ = "serialize response DATA";
    }
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  template <typename Callback>
  int guard_callback(std::string_view operation, Callback callback) noexcept {
    try {
      return callback(*this);
    } catch (const std::exception&) {
      callback_failure_ = operation;
    } catch (...) {
      callback_failure_ = operation;
    }
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  int on_begin_headers(nghttp2_session*, const nghttp2_frame* frame) {
    if (frame->hd.type != NGHTTP2_HEADERS) {
      return 0;
    }
    HeaderBlockKind kind;
    if (frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
      kind = HeaderBlockKind::request;
      highest_peer_stream_id_ =
          std::max(highest_peer_stream_id_, frame->hd.stream_id);
      active_peer_streams_.insert(frame->hd.stream_id);
    } else if (frame->headers.cat == NGHTTP2_HCAT_HEADERS) {
      kind = HeaderBlockKind::trailers;
    } else {
      return 0;
    }
    auto [iterator, inserted] =
        header_blocks_.try_emplace(frame->hd.stream_id,
                                   HeaderBlock{kind, {}, 0U, 0U});
    if (!inserted) {
      throw std::logic_error("overlapping HTTP/2 header blocks");
    }
    iterator->second.headers.reserve(
        std::min<std::size_t>(limits_.max_header_fields, 16U));
    return 0;
  }

  int on_begin_frame(nghttp2_session* session,
                     const nghttp2_frame_hd* frame) {
    if (frame->type != NGHTTP2_HEADERS || frame->stream_id <= 0 ||
        (frame->stream_id & 1) == 0 ||
        frame->stream_id > highest_peer_stream_id_ ||
        active_peer_streams_.contains(frame->stream_id) ||
        recent_local_resets_.contains(frame->stream_id)) {
      return 0;
    }

    require_nghttp2(
        nghttp2_session_terminate_session(session, NGHTTP2_PROTOCOL_ERROR),
        "terminate HTTP/2 session after reused or skipped stream ID");
    return 0;
  }

  int on_header(nghttp2_session* session, const nghttp2_frame* frame,
                const std::uint8_t* name, std::size_t name_length,
                const std::uint8_t* value, std::size_t value_length,
                std::uint8_t flags) {
    const auto iterator = header_blocks_.find(frame->hd.stream_id);
    if (iterator == header_blocks_.end()) {
      throw std::logic_error("HTTP/2 header arrived without a header block");
    }
    auto& block = iterator->second;
    const auto field_bytes = header_field_size(name_length, value_length);
    if (block.headers.size() >= limits_.max_header_fields ||
        block.header_list_bytes > limits_.max_header_list_bytes ||
        field_bytes >
            limits_.max_header_list_bytes - block.header_list_bytes) {
      reject_stream(session, frame->hd.stream_id);
      header_blocks_.erase(iterator);
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

    block.header_list_bytes += field_bytes;
    block.event_bytes = checked_add(
        block.event_bytes,
        checked_add(
            name_length,
            checked_add(value_length, sizeof(Http2Header),
                        "HTTP/2 header event field accounting overflow"),
            "HTTP/2 header event field accounting overflow"),
        "HTTP/2 header event accounting overflow");
    block.headers.push_back(Http2Header{
        std::string(reinterpret_cast<const char*>(name), name_length),
        std::string(reinterpret_cast<const char*>(value), value_length),
        (flags & NGHTTP2_NV_FLAG_NO_INDEX) != 0U});
    return 0;
  }

  int on_frame_recv(nghttp2_session* session, const nghttp2_frame* frame) {
    if (frame->hd.type == NGHTTP2_HEADERS) {
      const auto iterator = header_blocks_.find(frame->hd.stream_id);
      if (iterator != header_blocks_.end()) {
        auto block = std::move(iterator->second);
        header_blocks_.erase(iterator);
        Http2Event event;
        event.kind = block.kind == HeaderBlockKind::request
                         ? Http2EventKind::request_headers
                         : Http2EventKind::request_trailers;
        event.stream_id = frame->hd.stream_id;
        event.headers = std::move(block.headers);
        event.end_stream =
            (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0U;
        if (!queue_event(std::move(event), block.event_bytes)) {
          reject_stream(session, frame->hd.stream_id);
        }
      }
      return 0;
    }

    if (frame->hd.type == NGHTTP2_DATA &&
        (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0U &&
        !discarded_streams_.contains(frame->hd.stream_id)) {
      Http2Event event;
      event.kind = Http2EventKind::stream_end;
      event.stream_id = frame->hd.stream_id;
      event.end_stream = true;
      if (!queue_event(std::move(event), 0U)) {
        reject_stream(session, frame->hd.stream_id);
      }
    }
    return 0;
  }

  int on_data_chunk(nghttp2_session* session, std::uint8_t,
                    std::int32_t stream_id, const std::uint8_t* data,
                    std::size_t length) {
    if (discarded_streams_.contains(stream_id)) {
      require_nghttp2(nghttp2_session_consume_connection(session, length),
                      "release discarded HTTP/2 connection credit");
      return 0;
    }

    Http2Event event;
    event.kind = Http2EventKind::data;
    event.stream_id = stream_id;
    event.data.assign(data, data + length);
    if (!queue_event(std::move(event), length)) {
      require_nghttp2(nghttp2_session_consume_connection(session, length),
                      "release rejected HTTP/2 connection credit");
      reject_stream(session, stream_id);
      return 0;
    }
    const auto remaining =
        limits_.max_queued_event_bytes - queued_event_bytes_;
    const auto next_data_event =
        static_cast<std::size_t>(limits_.max_frame_bytes) +
        kEventAccountingOverhead;
    if (remaining < next_data_event) {
      callback_paused_ = true;
      return NGHTTP2_ERR_PAUSE;
    }
    return 0;
  }

  int on_stream_close(nghttp2_session*, std::int32_t stream_id,
                      std::uint32_t error_code) {
    header_blocks_.erase(stream_id);
    discarded_streams_.erase(stream_id);
    responded_streams_.erase(stream_id);
    active_peer_streams_.erase(stream_id);
    const auto outbound = outbound_streams_.find(stream_id);
    if (outbound != outbound_streams_.end()) {
      bool first_chunk = true;
      for (const auto& chunk : outbound->second.chunks) {
        const auto offset =
            first_chunk ? outbound->second.front_offset : 0U;
        queued_response_bytes_ -= chunk.size() - offset;
        first_chunk = false;
      }
      outbound_streams_.erase(outbound);
    }
    Http2Event event;
    event.kind = Http2EventKind::stream_closed;
    event.stream_id = stream_id;
    event.error_code = error_code;
    if (!queue_event(std::move(event), 0U)) {
      ++dropped_events_;
    }
    return 0;
  }

  nghttp2_ssize read_response_data(std::int32_t stream_id,
                                   std::uint8_t* buffer,
                                   std::size_t length,
                                   std::uint32_t* data_flags) {
    const auto iterator = outbound_streams_.find(stream_id);
    if (iterator == outbound_streams_.end()) {
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    auto& outbound = iterator->second;
    if (outbound.chunks.empty()) {
      if (outbound.end_stream_queued) {
        finish_response_data(stream_id, outbound, data_flags);
        return 0;
      }
      outbound.deferred = true;
      return NGHTTP2_ERR_DEFERRED;
    }

    std::size_t copied = 0U;
    while (copied < length && !outbound.chunks.empty()) {
      auto& chunk = outbound.chunks.front();
      const auto available = chunk.size() - outbound.front_offset;
      const auto amount = std::min(length - copied, available);
      std::memcpy(buffer + copied, chunk.data() + outbound.front_offset,
                  amount);
      copied += amount;
      outbound.front_offset += amount;
      queued_response_bytes_ -= amount;
      if (outbound.front_offset == chunk.size()) {
        outbound.chunks.pop_front();
        outbound.front_offset = 0U;
      }
    }
    if (outbound.chunks.empty() && outbound.end_stream_queued) {
      finish_response_data(stream_id, outbound, data_flags);
    }
    return static_cast<nghttp2_ssize>(copied);
  }

  void finish_response_data(std::int32_t stream_id,
                            OutboundStream& outbound,
                            std::uint32_t* data_flags) {
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    if (outbound.trailers.empty()) {
      return;
    }
    if (outbound.trailers_submitted) {
      throw std::logic_error("HTTP/2 response trailers were submitted twice");
    }
    std::vector<nghttp2_nv> native_trailers;
    native_trailers.reserve(outbound.trailers.size());
    for (const auto& trailer : outbound.trailers) {
      native_trailers.push_back(
          native_header(trailer.name, trailer.value, trailer.never_index));
    }
    require_nghttp2(
        nghttp2_submit_trailer(session_, stream_id, native_trailers.data(),
                               native_trailers.size()),
        "submit HTTP/2 response trailers");
    outbound.trailers_submitted = true;
    *data_flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
  }

  [[nodiscard]] bool queue_event(Http2Event event,
                                 std::size_t payload_bytes) {
    if (payload_bytes >
        std::numeric_limits<std::size_t>::max() - kEventAccountingOverhead) {
      return false;
    }
    const auto event_bytes = payload_bytes + kEventAccountingOverhead;
    if (event_bytes > limits_.max_queued_event_bytes -
                          std::min(queued_event_bytes_,
                                   limits_.max_queued_event_bytes)) {
      return false;
    }
    events_.push_back(std::move(event));
    queued_event_bytes_ += event_bytes;
    return true;
  }

  void reject_stream(nghttp2_session* session, std::int32_t stream_id) {
    if (!discarded_streams_.insert(stream_id).second) {
      return;
    }
    require_nghttp2(
        nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, stream_id,
                                  NGHTTP2_ENHANCE_YOUR_CALM),
        "reject resource-exhausting HTTP/2 stream");
    remember_local_reset(stream_id);
    ++rejected_streams_;
  }

  void remember_local_reset(std::int32_t stream_id) {
    if (!recent_local_resets_.insert(stream_id).second) {
      return;
    }
    recent_local_reset_order_.push_back(stream_id);
    if (recent_local_reset_order_.size() > kRecentLocalResetLimit) {
      recent_local_resets_.erase(recent_local_reset_order_.front());
      recent_local_reset_order_.pop_front();
    }
  }

  Http2Limits limits_;
  nghttp2_session_callbacks* callbacks_{nullptr};
  nghttp2_session* session_{nullptr};
  std::unordered_map<std::int32_t, HeaderBlock> header_blocks_;
  std::unordered_map<std::int32_t, OutboundStream> outbound_streams_;
  std::unordered_set<std::int32_t> discarded_streams_;
  std::unordered_set<std::int32_t> responded_streams_;
  std::unordered_set<std::int32_t> active_peer_streams_;
  std::unordered_set<std::int32_t> recent_local_resets_;
  std::deque<std::int32_t> recent_local_reset_order_;
  std::vector<Http2Event> events_;
  std::size_t queued_event_bytes_{};
  std::size_t queued_response_bytes_{};
  std::uint64_t rejected_streams_{};
  std::uint64_t dropped_events_{};
  std::int32_t highest_peer_stream_id_{};
  bool draining_{false};
  bool callback_paused_{false};
  std::string_view callback_failure_;
};

Http2ServerSession::Http2ServerSession(Http2Limits limits)
    : impl_(std::make_unique<Impl>(limits)) {}

Http2ServerSession::~Http2ServerSession() = default;

std::size_t Http2ServerSession::receive(
    std::span<const std::uint8_t> input) {
  return impl_->receive(input);
}

std::vector<std::uint8_t> Http2ServerSession::take_output_chunk() {
  return impl_->take_output_chunk();
}

std::vector<Http2Event> Http2ServerSession::take_events() {
  return impl_->take_events();
}

void Http2ServerSession::acknowledge_data(std::int32_t stream_id,
                                         std::size_t bytes) {
  impl_->acknowledge_data(stream_id, bytes);
}

void Http2ServerSession::submit_empty_response(
    std::int32_t stream_id, std::uint16_t status,
    std::span<const Http2Header> headers) {
  impl_->submit_empty_response(stream_id, status, headers);
}

void Http2ServerSession::submit_response_headers(
    std::int32_t stream_id, std::uint16_t status,
    std::span<const Http2Header> headers, bool end_stream) {
  impl_->submit_response_headers(stream_id, status, headers, end_stream);
}

void Http2ServerSession::submit_response_trailers(
    std::int32_t stream_id, std::span<const Http2Header> trailers) {
  impl_->submit_response_trailers(stream_id, trailers);
}

bool Http2ServerSession::try_submit_data(
    std::int32_t stream_id, std::span<const std::uint8_t> data,
    bool end_stream) {
  return impl_->try_submit_data(stream_id, data, end_stream);
}

void Http2ServerSession::reset_stream(std::int32_t stream_id,
                                     std::uint32_t error_code) {
  impl_->reset_stream(stream_id, error_code);
}

void Http2ServerSession::begin_graceful_shutdown() {
  impl_->begin_graceful_shutdown();
}

bool Http2ServerSession::wants_read() const noexcept {
  return impl_->wants_read();
}

bool Http2ServerSession::wants_write() const noexcept {
  return impl_->wants_write();
}

bool Http2ServerSession::should_close_transport() const noexcept {
  return impl_->should_close_transport();
}

bool Http2ServerSession::is_draining() const noexcept {
  return impl_->is_draining();
}

std::size_t Http2ServerSession::queued_event_bytes() const noexcept {
  return impl_->queued_event_bytes();
}

std::size_t Http2ServerSession::queued_response_bytes() const noexcept {
  return impl_->queued_response_bytes();
}

std::uint64_t Http2ServerSession::rejected_streams() const noexcept {
  return impl_->rejected_streams();
}

std::uint64_t Http2ServerSession::dropped_events() const noexcept {
  return impl_->dropped_events();
}

}  // namespace bonvoyage::http
