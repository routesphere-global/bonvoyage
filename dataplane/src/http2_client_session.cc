#include "bonvoyage/http/http2_client_session.hh"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <deque>
#include <limits>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include <nghttp2/nghttp2.h>

namespace bonvoyage::http {
namespace {

constexpr std::size_t kAllocationAccountingOverhead = 64U;
constexpr std::size_t kEventAccountingOverhead =
    sizeof(Http2ClientEvent) + kAllocationAccountingOverhead;
constexpr std::size_t kTerminalEventsPerStream = 3U;
constexpr std::uint32_t kPreSettingsMaxConcurrentStreams = 100U;
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

[[nodiscard]] std::size_t header_field_size(std::size_t name_size,
                                            std::size_t value_size) {
  return checked_add(checked_add(name_size, value_size,
                                 "HTTP/2 header field size overflow"),
                     32U, "HTTP/2 header field size overflow");
}

[[nodiscard]] std::size_t accounted_event_bytes(
    const Http2ClientEvent& event) {
  auto bytes = kEventAccountingOverhead;
  if (!event.data.empty()) {
    bytes = checked_add(
        bytes,
        checked_add(event.data.capacity(), kAllocationAccountingOverhead,
                    "HTTP/2 client event accounting overflow"),
        "HTTP/2 client event accounting overflow");
  }
  if (!event.headers.empty()) {
    bytes = checked_add(
        bytes,
        checked_add(
            checked_multiply(event.headers.capacity(), sizeof(Http2Header),
                             "HTTP/2 client event accounting overflow"),
            kAllocationAccountingOverhead,
            "HTTP/2 client event accounting overflow"),
        "HTTP/2 client event accounting overflow");
    for (const auto& header : event.headers) {
      bytes = checked_add(
          bytes,
          checked_add(
              checked_add(header.name.capacity(), header.value.capacity(),
                          "HTTP/2 client event accounting overflow"),
              2U * kAllocationAccountingOverhead,
              "HTTP/2 client event accounting overflow"),
          "HTTP/2 client event accounting overflow");
    }
  }
  return bytes;
}

[[nodiscard]] bool is_lowercase_header_name(std::string_view name) noexcept {
  return std::none_of(name.begin(), name.end(), [](char character) {
    return character >= 'A' && character <= 'Z';
  });
}

[[nodiscard]] bool is_forbidden_connection_header(
    std::string_view name) noexcept {
  constexpr std::array<std::string_view, 5U> disallowed{
      "connection", "keep-alive", "proxy-connection", "transfer-encoding",
      "upgrade"};
  return std::find(disallowed.begin(), disallowed.end(), name) !=
         disallowed.end();
}

[[nodiscard]] bool is_allowed_response_trailer(
    std::string_view name) noexcept {
  constexpr std::array<std::string_view, 7U> forbidden{
      "content-encoding", "content-length", "content-range", "content-type",
      "host", "te", "trailer"};
  return !is_forbidden_connection_header(name) &&
         std::find(forbidden.begin(), forbidden.end(), name) ==
             forbidden.end();
}

[[nodiscard]] bool is_token(std::string_view value) noexcept {
  if (value.empty()) {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [](char character) {
    constexpr std::string_view punctuation{"!#$%&'*+-.^_`|~"};
    const auto byte = static_cast<unsigned char>(character);
    return (byte >= static_cast<unsigned char>('0') &&
            byte <= static_cast<unsigned char>('9')) ||
           (byte >= static_cast<unsigned char>('A') &&
            byte <= static_cast<unsigned char>('Z')) ||
           (byte >= static_cast<unsigned char>('a') &&
            byte <= static_cast<unsigned char>('z')) ||
           punctuation.find(character) != std::string_view::npos;
  });
}

[[nodiscard]] bool valid_header_value(std::string_view value) noexcept {
  return nghttp2_check_header_value_rfc9113(
             reinterpret_cast<const std::uint8_t*>(value.data()),
             value.size()) != 0;
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

void validate_limits(const Http2ClientLimits& limits) {
  if (limits.max_concurrent_streams == 0U ||
      limits.max_concurrent_streams > 1'000U) {
    throw std::invalid_argument(
        "HTTP/2 client max_concurrent_streams must be in [1, 1000]");
  }
  if (limits.initial_stream_window_bytes >
      static_cast<std::uint32_t>(NGHTTP2_MAX_WINDOW_SIZE)) {
    throw std::invalid_argument("HTTP/2 client stream window is too large");
  }
  if (limits.max_frame_bytes < kMinFrameBytes ||
      limits.max_frame_bytes > kMaxFrameBytes) {
    throw std::invalid_argument(
        "HTTP/2 client max frame size is outside RFC bounds");
  }
  if (limits.max_header_list_bytes == 0U ||
      limits.max_header_fields < 4U) {
    throw std::invalid_argument("HTTP/2 client header limits are too small");
  }

  const auto maximum_header_storage = checked_add(
      limits.max_header_list_bytes,
      checked_multiply(limits.max_header_fields,
                       sizeof(Http2Header) +
                           2U * kAllocationAccountingOverhead,
                       "HTTP/2 client header accounting overflow"),
      "HTTP/2 client header accounting overflow");
  const auto largest_event = checked_add(
      std::max<std::size_t>(
          maximum_header_storage,
          checked_add(limits.max_frame_bytes,
                      kAllocationAccountingOverhead,
                      "HTTP/2 client event accounting overflow")),
      kEventAccountingOverhead, "HTTP/2 client event accounting overflow");
  const auto terminal_event_budget = checked_multiply(
      limits.max_concurrent_streams,
      checked_multiply(kTerminalEventsPerStream, kEventAccountingOverhead,
                       "HTTP/2 client terminal-event accounting overflow"),
      "HTTP/2 client terminal-event accounting overflow");
  const auto goaway_event_budget = checked_add(
      checked_add(kEventAccountingOverhead, limits.max_goaway_debug_bytes,
                  "HTTP/2 client GOAWAY accounting overflow"),
      kAllocationAccountingOverhead,
      "HTTP/2 client GOAWAY accounting overflow");
  const auto required_event_budget = checked_add(
      largest_event,
      checked_add(terminal_event_budget, goaway_event_budget,
                  "HTTP/2 client event accounting overflow"),
      "HTTP/2 client event accounting overflow");
  if (limits.max_queued_event_bytes < required_event_budget) {
    throw std::invalid_argument(
        "HTTP/2 client event queue cannot reserve payload, terminal, and GOAWAY events");
  }
  if (limits.max_output_chunk_bytes <
      static_cast<std::size_t>(limits.max_frame_bytes) + 9U) {
    throw std::invalid_argument(
        "HTTP/2 client output bound must hold one maximum-sized frame");
  }
  if (limits.max_queued_request_bytes_per_stream < limits.max_frame_bytes ||
      limits.max_queued_request_bytes <
          limits.max_queued_request_bytes_per_stream) {
    throw std::invalid_argument(
        "HTTP/2 client request queues must hold one maximum-sized DATA frame");
  }
  if (limits.max_queued_request_chunks == 0U ||
      limits.max_queued_request_chunks_per_stream == 0U ||
      limits.max_queued_request_chunks_per_stream >
          limits.max_queued_request_chunks) {
    throw std::invalid_argument(
        "HTTP/2 client request-fragment limits are inconsistent");
  }
  if (limits.max_settings_entries == 0U ||
      limits.max_continuation_frames == 0U ||
      limits.max_outbound_ack_frames == 0U) {
    throw std::invalid_argument(
        "HTTP/2 client protocol flood limits must be nonzero");
  }
  if (limits.reset_rate_burst == 0U ||
      limits.reset_rate_per_second == 0U ||
      limits.glitch_rate_burst == 0U ||
      limits.glitch_rate_per_second == 0U) {
    throw std::invalid_argument("HTTP/2 client rate limits must be nonzero");
  }
  if (limits.max_goaway_debug_bytes > limits.max_frame_bytes) {
    throw std::invalid_argument(
        "HTTP/2 client GOAWAY debug bound exceeds the frame bound");
  }
}

void validate_regular_request_headers(
    std::span<const Http2Header> headers, const Http2ClientLimits& limits) {
  constexpr std::array<std::string_view, 4U> pseudo_names{
      ":method", ":scheme", ":authority", ":path"};
  if (headers.size() < pseudo_names.size() ||
      headers.size() > limits.max_header_fields) {
    throw std::invalid_argument(
        "HTTP/2 request has an invalid header field count");
  }

  std::size_t header_bytes = 0U;
  for (std::size_t index = 0U; index < headers.size(); ++index) {
    const auto& header = headers[index];
    const auto name = std::string_view(header.name);
    const auto value = std::string_view(header.value);
    const auto field_bytes = header_field_size(name.size(), value.size());
    if (header_bytes > limits.max_header_list_bytes ||
        field_bytes > limits.max_header_list_bytes - header_bytes) {
      throw std::invalid_argument("HTTP/2 request headers are too large");
    }
    header_bytes += field_bytes;

    if (index < pseudo_names.size()) {
      if (name != pseudo_names[index] || !valid_header_value(value)) {
        throw std::invalid_argument(
            "HTTP/2 regular request pseudo-headers are invalid");
      }
      continue;
    }
    if (name.empty() || name.front() == ':' ||
        !is_lowercase_header_name(name) ||
        is_forbidden_connection_header(name) ||
        nghttp2_check_header_name(
            reinterpret_cast<const std::uint8_t*>(name.data()),
            name.size()) == 0 ||
        !valid_header_value(value) ||
        (name == "te" && value != "trailers")) {
      throw std::invalid_argument("invalid HTTP/2 request header");
    }
  }

  if (!is_token(headers[0].value) || headers[0].value == "CONNECT" ||
      (headers[1].value != "http" && headers[1].value != "https") ||
      headers[2].value.empty() ||
      nghttp2_check_authority(
          reinterpret_cast<const std::uint8_t*>(headers[2].value.data()),
          headers[2].value.size()) == 0 ||
      headers[3].value.empty() ||
      nghttp2_check_path(
          reinterpret_cast<const std::uint8_t*>(headers[3].value.data()),
          headers[3].value.size()) == 0 ||
      (headers[3].value != "*" && headers[3].value.front() != '/') ||
      (headers[3].value == "*" && headers[0].value != "OPTIONS") ||
      headers[3].value.find('#') != std::string::npos) {
    throw std::invalid_argument(
        "HTTP/2 regular request pseudo-header values are invalid");
  }
}

[[nodiscard]] std::uint16_t parse_status(std::string_view value) {
  std::uint16_t status = 0U;
  const auto [end, error] =
      std::from_chars(value.data(), value.data() + value.size(), status);
  if (error != std::errc{} || end != value.data() + value.size() ||
      value.size() != 3U || status < 100U || status > 599U ||
      status == 101U) {
    throw std::invalid_argument("invalid HTTP/2 response :status");
  }
  return status;
}

}  // namespace

class Http2ClientSession::Impl final {
 public:
  explicit Impl(Http2ClientLimits limits) : limits_(limits) {
    validate_limits(limits_);
    terminal_event_budget_ =
        static_cast<std::size_t>(limits_.max_concurrent_streams) *
        kTerminalEventsPerStream * kEventAccountingOverhead;
    goaway_event_budget_ = kEventAccountingOverhead +
                           limits_.max_goaway_debug_bytes +
                           kAllocationAccountingOverhead;
    normal_event_budget_ = limits_.max_queued_event_bytes -
                           terminal_event_budget_ - goaway_event_budget_;

    nghttp2_session_callbacks* callbacks = nullptr;
    require_nghttp2(nghttp2_session_callbacks_new(&callbacks),
                    "create HTTP/2 client callbacks");
    callbacks_ = callbacks;
    nghttp2_session_callbacks_set_on_begin_headers_callback(
        callbacks_, &Impl::on_begin_headers_callback);
    nghttp2_session_callbacks_set_on_header_callback(
        callbacks_, &Impl::on_header_callback);
    nghttp2_session_callbacks_set_on_invalid_header_callback(
        callbacks_, &Impl::on_invalid_header_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(
        callbacks_, &Impl::on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(
        callbacks_, &Impl::on_invalid_frame_recv_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
        callbacks_, &Impl::on_data_chunk_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(
        callbacks_, &Impl::on_stream_close_callback);

    nghttp2_option* option = nullptr;
    try {
      require_nghttp2(nghttp2_option_new(&option),
                      "create HTTP/2 client options");
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
          nghttp2_session_client_new2(&session_, callbacks_, this, option),
          "create HTTP/2 client session");
      nghttp2_option_del(option);
      option = nullptr;

      const std::array<nghttp2_settings_entry, 6U> settings{{
          {NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, limits_.header_table_bytes},
          {NGHTTP2_SETTINGS_ENABLE_PUSH, 0U},
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
          "submit HTTP/2 client settings");
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
          nghttp2_message("process HTTP/2 server input", error_code,
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
            nghttp2_message("resume paused HTTP/2 server input", error_code,
                            callback_failure_));
      }
    }
    return static_cast<std::size_t>(result);
  }

  [[nodiscard]] std::vector<std::uint8_t> take_output_chunk() {
    if (output_chunk_pending_acknowledgement_) {
      throw std::logic_error(
          "HTTP/2 client output chunk is still owned by the transport");
    }
    callback_failure_ = {};
    const std::uint8_t* data = nullptr;
    const auto result = nghttp2_session_mem_send2(session_, &data);
    if (result < 0) {
      const auto error_code = static_cast<int>(result);
      throw Http2ProtocolError(
          error_code,
          nghttp2_message("serialize HTTP/2 client output", error_code,
                          callback_failure_));
    }
    const auto size = static_cast<std::size_t>(result);
    if (size > limits_.max_output_chunk_bytes) {
      throw Http2ProtocolError(
          NGHTTP2_ERR_FRAME_SIZE_ERROR,
          "serialize HTTP/2 client output: generated chunk exceeds local bound");
    }
    if (size == 0U) {
      return {};
    }
    output_chunk_pending_acknowledgement_ = true;
    return {data, data + size};
  }

  void acknowledge_output_chunk() {
    if (!output_chunk_pending_acknowledgement_) {
      throw std::logic_error(
          "HTTP/2 client has no output chunk awaiting acknowledgement");
    }
    output_chunk_pending_acknowledgement_ = false;
  }

  [[nodiscard]] bool output_chunk_pending_acknowledgement() const noexcept {
    return output_chunk_pending_acknowledgement_;
  }

  [[nodiscard]] std::vector<Http2ClientEvent> take_events() {
    std::vector<Http2ClientEvent> result;
    result.swap(events_);
    queued_normal_event_bytes_ = 0U;
    queued_terminal_event_bytes_ = 0U;
    queued_goaway_event_bytes_ = 0U;
    return result;
  }

  [[nodiscard]] std::int32_t submit_request(
      std::span<const Http2Header> headers, bool end_stream) {
    validate_regular_request_headers(headers, limits_);
    if (draining_) {
      throw std::logic_error("HTTP/2 client session is draining");
    }
    if (available_stream_capacity() == 0U) {
      throw std::length_error("HTTP/2 client stream capacity is exhausted");
    }

    std::vector<nghttp2_nv> native_headers;
    native_headers.reserve(headers.size());
    for (const auto& header : headers) {
      native_headers.push_back(native_header(header));
    }

    nghttp2_data_provider2 provider{};
    const nghttp2_data_provider2* provider_pointer = nullptr;
    if (!end_stream) {
      provider.source.ptr = this;
      provider.read_callback = &Impl::read_request_data_callback;
      provider_pointer = &provider;
    }
    const auto stream_id = nghttp2_submit_request2(
        session_, nullptr, native_headers.data(), native_headers.size(),
        provider_pointer, nullptr);
    require_nghttp2(stream_id, "submit HTTP/2 request headers");
    const auto [iterator, inserted] = streams_.try_emplace(stream_id);
    if (!inserted) {
      throw std::logic_error("HTTP/2 client reused a local stream ID");
    }
    iterator->second.request.end_stream_queued = end_stream;
    active_terminal_reservation_bytes_ +=
        kTerminalEventsPerStream * kEventAccountingOverhead;
    return stream_id;
  }

  [[nodiscard]] bool try_submit_data(
      std::int32_t stream_id, std::span<const std::uint8_t> data,
      bool end_stream) {
    if (stream_id <= 0 || (stream_id & 1) == 0) {
      throw std::invalid_argument(
          "HTTP/2 client stream ID must be positive and odd");
    }
    const auto iterator = streams_.find(stream_id);
    if (iterator == streams_.end()) {
      throw std::logic_error("HTTP/2 client request stream is not active");
    }
    auto& request = iterator->second.request;
    if (request.end_stream_queued) {
      throw std::logic_error("HTTP/2 client request body is already complete");
    }
    if ((!data.empty() &&
         (request.chunks.size() >=
              limits_.max_queued_request_chunks_per_stream ||
          queued_request_chunks_ >= limits_.max_queued_request_chunks)) ||
        data.size() > limits_.max_queued_request_bytes_per_stream ||
        data.size() > limits_.max_queued_request_bytes ||
        request.queued_bytes > limits_.max_queued_request_bytes_per_stream ||
        data.size() >
            limits_.max_queued_request_bytes_per_stream - request.queued_bytes ||
        queued_request_bytes_ > limits_.max_queued_request_bytes ||
        data.size() >
            limits_.max_queued_request_bytes - queued_request_bytes_) {
      return false;
    }
    if (!data.empty()) {
      request.chunks.emplace_back(data.begin(), data.end());
      ++queued_request_chunks_;
      request.queued_bytes += data.size();
      queued_request_bytes_ += data.size();
    }
    request.end_stream_queued = end_stream;
    if (request.deferred && (!data.empty() || end_stream)) {
      request.deferred = false;
      require_nghttp2(nghttp2_session_resume_data(session_, stream_id),
                      "resume HTTP/2 request DATA");
    }
    return true;
  }

  void acknowledge_data(std::int32_t stream_id, std::size_t bytes) {
    if (stream_id <= 0 || (stream_id & 1) == 0) {
      throw std::invalid_argument(
          "HTTP/2 client stream ID must be positive and odd");
    }
    if (bytes == 0U) {
      return;
    }
    const auto pending = pending_acknowledgements_.find(stream_id);
    if (pending == pending_acknowledgements_.end() ||
        bytes > pending->second) {
      throw std::invalid_argument(
          "HTTP/2 response acknowledgement exceeds delivered DATA");
    }
    if (streams_.contains(stream_id)) {
      require_nghttp2(nghttp2_session_consume(session_, stream_id, bytes),
                      "release HTTP/2 response flow-control credit");
    } else {
      require_nghttp2(nghttp2_session_consume_connection(session_, bytes),
                      "release closed HTTP/2 response connection credit");
    }
    pending->second -= bytes;
    unacknowledged_data_bytes_ -= bytes;
    if (pending->second == 0U) {
      pending_acknowledgements_.erase(pending);
    }
  }

  void reset_stream(std::int32_t stream_id, std::uint32_t error_code) {
    if (stream_id <= 0 || (stream_id & 1) == 0) {
      throw std::invalid_argument(
          "HTTP/2 client stream ID must be positive and odd");
    }
    if (!streams_.contains(stream_id)) {
      throw std::logic_error("HTTP/2 client request stream is not active");
    }
    require_nghttp2(
        nghttp2_submit_rst_stream(session_, NGHTTP2_FLAG_NONE, stream_id,
                                  error_code),
        "submit HTTP/2 client stream reset");
  }

  void begin_graceful_shutdown() {
    if (draining_) {
      return;
    }
    require_nghttp2(
        nghttp2_submit_goaway(
            session_, NGHTTP2_FLAG_NONE,
            nghttp2_session_get_last_proc_stream_id(session_), NGHTTP2_NO_ERROR,
            nullptr, 0U),
        "submit HTTP/2 client GOAWAY");
    draining_ = true;
  }

  [[nodiscard]] bool wants_read() const noexcept {
    return nghttp2_session_want_read(session_) != 0;
  }

  [[nodiscard]] bool wants_write() const noexcept {
    return nghttp2_session_want_write(session_) != 0;
  }

  [[nodiscard]] bool should_close_transport() const noexcept {
    return !output_chunk_pending_acknowledgement_ && !wants_read() &&
           !wants_write();
  }

  [[nodiscard]] bool is_draining() const noexcept { return draining_; }

  [[nodiscard]] bool peer_settings_received() const noexcept {
    return peer_settings_received_;
  }

  [[nodiscard]] std::uint32_t peer_max_concurrent_streams() const noexcept {
    return peer_max_concurrent_streams_;
  }

  [[nodiscard]] std::size_t active_streams() const noexcept {
    return streams_.size();
  }

  [[nodiscard]] std::size_t available_stream_capacity() const noexcept {
    if (draining_) {
      return 0U;
    }
    auto effective_limit = std::min<std::uint64_t>(
        limits_.max_concurrent_streams, peer_max_concurrent_streams_);
    const auto reserved_terminal_bytes =
        active_terminal_reservation_bytes_ + queued_terminal_event_bytes_;
    const auto free_terminal_bytes =
        reserved_terminal_bytes >= terminal_event_budget_
            ? 0U
            : terminal_event_budget_ - reserved_terminal_bytes;
    const auto terminal_capacity =
        free_terminal_bytes /
        (kTerminalEventsPerStream * kEventAccountingOverhead);
    effective_limit = std::min<std::uint64_t>(effective_limit,
                                              terminal_capacity + streams_.size());
    const auto active = static_cast<std::uint64_t>(streams_.size());
    if (active >= effective_limit) {
      return 0U;
    }
    const auto available = effective_limit - active;
    return available > std::numeric_limits<std::size_t>::max()
               ? std::numeric_limits<std::size_t>::max()
               : static_cast<std::size_t>(available);
  }

  [[nodiscard]] std::size_t queued_request_bytes() const noexcept {
    return queued_request_bytes_;
  }

  [[nodiscard]] std::size_t queued_event_bytes() const noexcept {
    return queued_normal_event_bytes_ + queued_terminal_event_bytes_ +
           queued_goaway_event_bytes_;
  }

  [[nodiscard]] std::size_t unacknowledged_data_bytes() const noexcept {
    return unacknowledged_data_bytes_;
  }

  [[nodiscard]] std::uint64_t rejected_streams() const noexcept {
    return rejected_streams_;
  }

  [[nodiscard]] std::uint64_t dropped_events() const noexcept {
    return dropped_events_;
  }

 private:
  struct OutboundRequest final {
    std::deque<std::vector<std::uint8_t>> chunks;
    std::size_t front_offset{};
    std::size_t queued_bytes{};
    bool end_stream_queued{false};
    bool deferred{false};
  };

  struct StreamState final {
    OutboundRequest request;
    bool final_response_received{false};
    bool remote_end_received{false};
    std::size_t terminal_events_remaining{kTerminalEventsPerStream};
  };

  struct HeaderBlock final {
    std::vector<Http2Header> headers;
    std::size_t header_list_bytes{};
    std::uint16_t status{};
    bool saw_status{false};
    bool saw_regular_header{false};
    bool trailer_block{false};
  };

  static int on_begin_headers_callback(nghttp2_session* session,
                                       const nghttp2_frame* frame,
                                       void* user_data) noexcept {
    return static_cast<Impl*>(user_data)->guard_callback(
        "begin response headers", [session, frame](Impl& self) {
          return self.on_begin_headers(session, frame);
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
        "decode response header", [=](Impl& self) {
          return self.on_header(session, frame, name, name_length, value,
                                value_length, flags);
        });
  }

  static int on_invalid_header_callback(
      nghttp2_session* session, const nghttp2_frame* frame,
      const std::uint8_t*, std::size_t, const std::uint8_t*, std::size_t,
      std::uint8_t, void* user_data) noexcept {
    return static_cast<Impl*>(user_data)->guard_callback(
        "reject invalid response header", [session, frame](Impl& self) {
          return self.on_invalid_header(session, frame);
        });
  }

  static int on_frame_recv_callback(nghttp2_session* session,
                                    const nghttp2_frame* frame,
                                    void* user_data) noexcept {
    return static_cast<Impl*>(user_data)->guard_callback(
        "receive server frame", [session, frame](Impl& self) {
          return self.on_frame_recv(session, frame);
        });
  }

  static int on_invalid_frame_recv_callback(nghttp2_session*,
                                            const nghttp2_frame* frame,
                                            int,
                                            void* user_data) noexcept {
    return static_cast<Impl*>(user_data)->guard_callback(
        "reject invalid server frame", [frame](Impl& self) {
          return self.on_invalid_frame_recv(frame);
        });
  }

  static int on_data_chunk_recv_callback(
      nghttp2_session* session, std::uint8_t flags, std::int32_t stream_id,
      const std::uint8_t* data, std::size_t length,
      void* user_data) noexcept {
    return static_cast<Impl*>(user_data)->guard_callback(
        "receive response DATA", [=](Impl& self) {
          return self.on_data_chunk(session, flags, stream_id, data, length);
        });
  }

  static int on_stream_close_callback(nghttp2_session* session,
                                      std::int32_t stream_id,
                                      std::uint32_t error_code,
                                      void* user_data) noexcept {
    return static_cast<Impl*>(user_data)->guard_callback(
        "close client stream", [=](Impl& self) {
          return self.on_stream_close(session, stream_id, error_code);
        });
  }

  static nghttp2_ssize read_request_data_callback(
      nghttp2_session*, std::int32_t stream_id, std::uint8_t* buffer,
      std::size_t length, std::uint32_t* data_flags,
      nghttp2_data_source*, void* user_data) noexcept {
    auto& self = *static_cast<Impl*>(user_data);
    try {
      return self.read_request_data(stream_id, buffer, length, data_flags);
    } catch (const std::exception&) {
      self.callback_failure_ = "serialize request DATA";
    } catch (...) {
      self.callback_failure_ = "serialize request DATA";
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
    if (frame->hd.type != NGHTTP2_HEADERS ||
        (frame->headers.cat != NGHTTP2_HCAT_RESPONSE &&
         frame->headers.cat != NGHTTP2_HCAT_HEADERS)) {
      return 0;
    }
    if (!streams_.contains(frame->hd.stream_id)) {
      throw std::logic_error("response headers target an unknown stream");
    }
    const auto stream = streams_.find(frame->hd.stream_id);
    HeaderBlock block;
    block.trailer_block = stream->second.final_response_received;
    const auto [iterator, inserted] =
        header_blocks_.try_emplace(frame->hd.stream_id, std::move(block));
    if (!inserted) {
      throw std::logic_error("overlapping HTTP/2 response header blocks");
    }
    iterator->second.headers.reserve(
        std::min<std::size_t>(limits_.max_header_fields, 16U));
    return 0;
  }

  int on_invalid_header(nghttp2_session* session,
                        const nghttp2_frame* frame) {
    if (frame->hd.stream_id > 0 && streams_.contains(frame->hd.stream_id)) {
      reject_stream(session, frame->hd.stream_id, NGHTTP2_PROTOCOL_ERROR);
    }
    return 0;
  }

  int on_header(nghttp2_session* session, const nghttp2_frame* frame,
                const std::uint8_t* name, std::size_t name_length,
                const std::uint8_t* value, std::size_t value_length,
                std::uint8_t flags) {
    if (rejected_stream_ids_.contains(frame->hd.stream_id)) {
      return 0;
    }
    const auto iterator = header_blocks_.find(frame->hd.stream_id);
    if (iterator == header_blocks_.end()) {
      throw std::logic_error(
          "HTTP/2 response field arrived without a header block");
    }
    auto& block = iterator->second;
    const auto field_bytes = header_field_size(name_length, value_length);
    if (block.headers.size() >= limits_.max_header_fields ||
        block.header_list_bytes > limits_.max_header_list_bytes ||
        field_bytes >
            limits_.max_header_list_bytes - block.header_list_bytes) {
      reject_stream(session, frame->hd.stream_id,
                    NGHTTP2_ENHANCE_YOUR_CALM);
      return 0;
    }

    const auto name_view = std::string_view(
        reinterpret_cast<const char*>(name), name_length);
    const auto value_view = std::string_view(
        reinterpret_cast<const char*>(value), value_length);
    if (name_view == ":status") {
      if (block.saw_status || block.saw_regular_header) {
        reject_stream(session, frame->hd.stream_id, NGHTTP2_PROTOCOL_ERROR);
        return 0;
      }
      try {
        block.status = parse_status(value_view);
      } catch (const std::invalid_argument&) {
        reject_stream(session, frame->hd.stream_id, NGHTTP2_PROTOCOL_ERROR);
        return 0;
      }
      block.saw_status = true;
    } else {
      if (name_view.empty() || name_view.front() == ':' ||
          !is_lowercase_header_name(name_view) ||
          is_forbidden_connection_header(name_view) || name_view == "te" ||
          (block.trailer_block &&
           !is_allowed_response_trailer(name_view)) ||
          nghttp2_check_header_name(name, name_length) == 0 ||
          nghttp2_check_header_value_rfc9113(value, value_length) == 0) {
        reject_stream(session, frame->hd.stream_id, NGHTTP2_PROTOCOL_ERROR);
        return 0;
      }
      block.saw_regular_header = true;
    }

    block.header_list_bytes += field_bytes;
    block.headers.push_back(Http2Header{
        std::string(name_view), std::string(value_view),
        (flags & NGHTTP2_NV_FLAG_NO_INDEX) != 0U});
    return 0;
  }

  int on_frame_recv(nghttp2_session* session, const nghttp2_frame* frame) {
    if (frame->hd.type == NGHTTP2_SETTINGS &&
        (frame->hd.flags & NGHTTP2_FLAG_ACK) == 0U) {
      peer_settings_received_ = true;
      peer_max_concurrent_streams_ = nghttp2_session_get_remote_settings(
          session, NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS);
      return 0;
    }

    if (frame->hd.type == NGHTTP2_HEADERS) {
      finish_header_block(session, frame);
      return 0;
    }

    if (frame->hd.type == NGHTTP2_DATA &&
        (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0U) {
      queue_stream_end(frame->hd.stream_id);
      return 0;
    }

    if (frame->hd.type == NGHTTP2_RST_STREAM) {
      const auto stream = streams_.find(frame->hd.stream_id);
      if (stream == streams_.end()) {
        return 0;
      }
      Http2ClientEvent event;
      event.kind = Http2ClientEventKind::stream_reset;
      event.stream_id = frame->hd.stream_id;
      event.error_code = frame->rst_stream.error_code;
      queue_terminal_event(stream->second, std::move(event));
      return 0;
    }

    if (frame->hd.type == NGHTTP2_GOAWAY) {
      draining_ = true;
      Http2ClientEvent event;
      event.kind = Http2ClientEventKind::goaway;
      event.last_stream_id = frame->goaway.last_stream_id;
      event.error_code = frame->goaway.error_code;
      const auto retained_debug_bytes = std::min<std::size_t>(
          frame->goaway.opaque_data_len, limits_.max_goaway_debug_bytes);
      if (retained_debug_bytes != 0U) {
        event.data.assign(frame->goaway.opaque_data,
                          frame->goaway.opaque_data +
                              retained_debug_bytes);
      }
      queue_goaway_event(std::move(event));
    }
    return 0;
  }

  int on_invalid_frame_recv(const nghttp2_frame* frame) {
    const auto stream_id = frame->hd.stream_id;
    if (stream_id == 0) {
      draining_ = true;
      return 0;
    }
    if (!streams_.contains(stream_id) || !mark_rejected_stream(stream_id)) {
      return 0;
    }

    return 0;
  }

  int on_data_chunk(nghttp2_session* session, std::uint8_t,
                    std::int32_t stream_id, const std::uint8_t* data,
                    std::size_t length) {
    const auto stream = streams_.find(stream_id);
    if (stream == streams_.end() ||
        !stream->second.final_response_received ||
        stream->second.remote_end_received) {
      require_nghttp2(nghttp2_session_consume_connection(session, length),
                      "release rejected HTTP/2 response connection credit");
      reject_stream(session, stream_id, NGHTTP2_PROTOCOL_ERROR);
      return 0;
    }

    Http2ClientEvent event;
    event.kind = Http2ClientEventKind::data;
    event.stream_id = stream_id;
    event.data.assign(data, data + length);
    if (!queue_event(std::move(event))) {
      ++dropped_events_;
      require_nghttp2(nghttp2_session_consume_connection(session, length),
                      "release over-limit HTTP/2 response connection credit");
      reject_stream(session, stream_id, NGHTTP2_ENHANCE_YOUR_CALM);
      return 0;
    }
    pending_acknowledgements_[stream_id] = checked_add(
        pending_acknowledgements_[stream_id], length,
        "HTTP/2 response acknowledgement accounting overflow");
    unacknowledged_data_bytes_ = checked_add(
        unacknowledged_data_bytes_, length,
        "HTTP/2 response acknowledgement accounting overflow");

    const auto remaining = normal_event_budget_ - queued_normal_event_bytes_;
    const auto next_data_event = static_cast<std::size_t>(
                                     limits_.max_frame_bytes) +
                                 kEventAccountingOverhead +
                                 kAllocationAccountingOverhead;
    if (remaining < next_data_event) {
      callback_paused_ = true;
      return NGHTTP2_ERR_PAUSE;
    }
    return 0;
  }

  int on_stream_close(nghttp2_session*, std::int32_t stream_id,
                      std::uint32_t error_code) {
    header_blocks_.erase(stream_id);
    rejected_stream_ids_.erase(stream_id);
    const auto stream = streams_.find(stream_id);
    if (stream != streams_.end()) {
      queued_request_bytes_ -= stream->second.request.queued_bytes;
      queued_request_chunks_ -= stream->second.request.chunks.size();
      Http2ClientEvent event;
      event.kind = Http2ClientEventKind::stream_closed;
      event.stream_id = stream_id;
      event.error_code = error_code;
      queue_terminal_event(stream->second, std::move(event));
      active_terminal_reservation_bytes_ -=
          stream->second.terminal_events_remaining *
          kEventAccountingOverhead;
      streams_.erase(stream);
    }
    return 0;
  }

  nghttp2_ssize read_request_data(std::int32_t stream_id,
                                  std::uint8_t* buffer, std::size_t length,
                                  std::uint32_t* data_flags) {
    const auto iterator = streams_.find(stream_id);
    if (iterator == streams_.end()) {
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    auto& request = iterator->second.request;
    if (request.chunks.empty()) {
      if (request.end_stream_queued) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        return 0;
      }
      request.deferred = true;
      return NGHTTP2_ERR_DEFERRED;
    }

    std::size_t copied = 0U;
    while (copied < length && !request.chunks.empty()) {
      auto& chunk = request.chunks.front();
      const auto available = chunk.size() - request.front_offset;
      const auto amount = std::min(length - copied, available);
      std::memcpy(buffer + copied, chunk.data() + request.front_offset,
                  amount);
      copied += amount;
      request.front_offset += amount;
      request.queued_bytes -= amount;
      queued_request_bytes_ -= amount;
      if (request.front_offset == chunk.size()) {
        request.chunks.pop_front();
        --queued_request_chunks_;
        request.front_offset = 0U;
      }
    }
    if (request.chunks.empty() && request.end_stream_queued) {
      *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    return static_cast<nghttp2_ssize>(copied);
  }

  void finish_header_block(nghttp2_session* session,
                           const nghttp2_frame* frame) {
    const auto iterator = header_blocks_.find(frame->hd.stream_id);
    if (iterator == header_blocks_.end()) {
      return;
    }
    auto block = std::move(iterator->second);
    header_blocks_.erase(iterator);
    const auto stream = streams_.find(frame->hd.stream_id);
    if (stream == streams_.end()) {
      return;
    }

    Http2ClientEvent event;
    event.stream_id = frame->hd.stream_id;
    event.headers = std::move(block.headers);
    event.status = block.status;
    event.end_stream = (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0U;
    if (block.saw_status) {
      if (stream->second.final_response_received) {
        reject_stream(session, frame->hd.stream_id, NGHTTP2_PROTOCOL_ERROR);
        return;
      }
      event.kind = Http2ClientEventKind::response_headers;
      if (block.status >= 200U) {
        stream->second.final_response_received = true;
      } else if (event.end_stream) {
        reject_stream(session, frame->hd.stream_id, NGHTTP2_PROTOCOL_ERROR);
        return;
      }
    } else {
      if (!stream->second.final_response_received || !event.end_stream) {
        reject_stream(session, frame->hd.stream_id, NGHTTP2_PROTOCOL_ERROR);
        return;
      }
      event.kind = Http2ClientEventKind::response_trailers;
    }

    if (!queue_event(std::move(event))) {
      ++dropped_events_;
      reject_stream(session, frame->hd.stream_id,
                    NGHTTP2_ENHANCE_YOUR_CALM);
      return;
    }
    if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0U) {
      queue_stream_end(frame->hd.stream_id);
    }
  }

  void queue_stream_end(std::int32_t stream_id) {
    const auto stream = streams_.find(stream_id);
    if (stream == streams_.end() || stream->second.remote_end_received) {
      return;
    }
    stream->second.remote_end_received = true;
    Http2ClientEvent event;
    event.kind = Http2ClientEventKind::stream_end;
    event.stream_id = stream_id;
    event.end_stream = true;
    queue_terminal_event(stream->second, std::move(event));
  }

  [[nodiscard]] bool queue_event(Http2ClientEvent event) {
    const auto event_bytes = accounted_event_bytes(event);
    if (queued_normal_event_bytes_ > normal_event_budget_ ||
        event_bytes > normal_event_budget_ - queued_normal_event_bytes_) {
      return false;
    }
    events_.push_back(std::move(event));
    queued_normal_event_bytes_ += event_bytes;
    return true;
  }

  void queue_terminal_event(StreamState& stream, Http2ClientEvent event) {
    const auto event_bytes = accounted_event_bytes(event);
    if (event_bytes != kEventAccountingOverhead ||
        stream.terminal_events_remaining == 0U ||
        active_terminal_reservation_bytes_ < event_bytes ||
        queued_terminal_event_bytes_ > terminal_event_budget_ ||
        event_bytes >
            terminal_event_budget_ - queued_terminal_event_bytes_) {
      throw std::logic_error(
          "HTTP/2 client terminal-event reservation invariant failed");
    }
    --stream.terminal_events_remaining;
    active_terminal_reservation_bytes_ -= event_bytes;
    queued_terminal_event_bytes_ += event_bytes;
    events_.push_back(std::move(event));
  }

  void queue_goaway_event(Http2ClientEvent event) {
    const auto event_bytes = accounted_event_bytes(event);
    if (event_bytes > goaway_event_budget_) {
      throw std::logic_error(
          "HTTP/2 client GOAWAY-event reservation invariant failed");
    }
    const auto existing = std::find_if(
        events_.begin(), events_.end(), [](const auto& queued) {
          return queued.kind == Http2ClientEventKind::goaway;
        });
    if (existing == events_.end()) {
      events_.push_back(std::move(event));
    } else {
      *existing = std::move(event);
    }
    queued_goaway_event_bytes_ = event_bytes;
  }

  void reject_stream(nghttp2_session* session, std::int32_t stream_id,
                     std::uint32_t error_code) {
    if (!mark_rejected_stream(stream_id)) {
      return;
    }
    require_nghttp2(
        nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, stream_id,
                                  error_code),
        "reject invalid or resource-exhausting HTTP/2 response");
  }

  [[nodiscard]] bool mark_rejected_stream(std::int32_t stream_id) {
    if (stream_id <= 0 || !rejected_stream_ids_.insert(stream_id).second) {
      return false;
    }
    header_blocks_.erase(stream_id);
    ++rejected_streams_;
    return true;
  }

  Http2ClientLimits limits_;
  nghttp2_session_callbacks* callbacks_{nullptr};
  nghttp2_session* session_{nullptr};
  std::unordered_map<std::int32_t, StreamState> streams_;
  std::unordered_map<std::int32_t, HeaderBlock> header_blocks_;
  std::unordered_map<std::int32_t, std::size_t> pending_acknowledgements_;
  std::unordered_set<std::int32_t> rejected_stream_ids_;
  std::vector<Http2ClientEvent> events_;
  std::size_t queued_request_bytes_{};
  std::size_t queued_request_chunks_{};
  std::size_t normal_event_budget_{};
  std::size_t terminal_event_budget_{};
  std::size_t goaway_event_budget_{};
  std::size_t queued_normal_event_bytes_{};
  std::size_t queued_terminal_event_bytes_{};
  std::size_t queued_goaway_event_bytes_{};
  std::size_t active_terminal_reservation_bytes_{};
  std::size_t unacknowledged_data_bytes_{};
  std::uint32_t peer_max_concurrent_streams_{
      kPreSettingsMaxConcurrentStreams};
  std::uint64_t rejected_streams_{};
  std::uint64_t dropped_events_{};
  bool draining_{false};
  bool peer_settings_received_{false};
  bool callback_paused_{false};
  bool output_chunk_pending_acknowledgement_{false};
  std::string_view callback_failure_;
};

Http2ClientSession::Http2ClientSession(Http2ClientLimits limits)
    : impl_(std::make_unique<Impl>(limits)) {}

Http2ClientSession::~Http2ClientSession() = default;

std::size_t Http2ClientSession::receive(
    std::span<const std::uint8_t> input) {
  return impl_->receive(input);
}

std::vector<std::uint8_t> Http2ClientSession::take_output_chunk() {
  return impl_->take_output_chunk();
}

void Http2ClientSession::acknowledge_output_chunk() {
  impl_->acknowledge_output_chunk();
}

bool Http2ClientSession::output_chunk_pending_acknowledgement() const noexcept {
  return impl_->output_chunk_pending_acknowledgement();
}

std::vector<Http2ClientEvent> Http2ClientSession::take_events() {
  return impl_->take_events();
}

std::int32_t Http2ClientSession::submit_request(
    std::span<const Http2Header> headers, bool end_stream) {
  return impl_->submit_request(headers, end_stream);
}

bool Http2ClientSession::try_submit_data(
    std::int32_t stream_id, std::span<const std::uint8_t> data,
    bool end_stream) {
  return impl_->try_submit_data(stream_id, data, end_stream);
}

void Http2ClientSession::acknowledge_data(std::int32_t stream_id,
                                         std::size_t bytes) {
  impl_->acknowledge_data(stream_id, bytes);
}

void Http2ClientSession::reset_stream(std::int32_t stream_id,
                                     std::uint32_t error_code) {
  impl_->reset_stream(stream_id, error_code);
}

void Http2ClientSession::begin_graceful_shutdown() {
  impl_->begin_graceful_shutdown();
}

bool Http2ClientSession::wants_read() const noexcept {
  return impl_->wants_read();
}

bool Http2ClientSession::wants_write() const noexcept {
  return impl_->wants_write();
}

bool Http2ClientSession::should_close_transport() const noexcept {
  return impl_->should_close_transport();
}

bool Http2ClientSession::is_draining() const noexcept {
  return impl_->is_draining();
}

bool Http2ClientSession::peer_settings_received() const noexcept {
  return impl_->peer_settings_received();
}

std::uint32_t Http2ClientSession::peer_max_concurrent_streams() const noexcept {
  return impl_->peer_max_concurrent_streams();
}

std::size_t Http2ClientSession::active_streams() const noexcept {
  return impl_->active_streams();
}

std::size_t Http2ClientSession::available_stream_capacity() const noexcept {
  return impl_->available_stream_capacity();
}

std::size_t Http2ClientSession::queued_request_bytes() const noexcept {
  return impl_->queued_request_bytes();
}

std::size_t Http2ClientSession::queued_event_bytes() const noexcept {
  return impl_->queued_event_bytes();
}

std::size_t Http2ClientSession::unacknowledged_data_bytes() const noexcept {
  return impl_->unacknowledged_data_bytes();
}

std::uint64_t Http2ClientSession::rejected_streams() const noexcept {
  return impl_->rejected_streams();
}

std::uint64_t Http2ClientSession::dropped_events() const noexcept {
  return impl_->dropped_events();
}

}  // namespace bonvoyage::http
