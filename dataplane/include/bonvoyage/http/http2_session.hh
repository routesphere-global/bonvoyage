#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace bonvoyage::http {

/** Resource and protocol limits advertised by one downstream HTTP/2 session. */
struct Http2Limits final {
  /** Maximum peer-initiated streams advertised in SETTINGS. */
  std::uint32_t max_concurrent_streams{100U};
  /** Per-stream receive window advertised in SETTINGS. */
  std::uint32_t initial_stream_window_bytes{65'535U};
  /** Largest accepted frame payload advertised in SETTINGS. */
  std::uint32_t max_frame_bytes{16'384U};
  /** Maximum RFC-accounted decoded header-list size per block. */
  std::uint32_t max_header_list_bytes{32U * 1024U};
  /** Maximum inbound and outbound HPACK dynamic-table size. */
  std::uint32_t header_table_bytes{4U * 1024U};
  /** Maximum decoded fields in one request or trailer block. */
  std::size_t max_header_fields{100U};
  /** Local memory budget for owned events awaiting application work. */
  std::size_t max_queued_event_bytes{256U * 1024U};
  /** Local bound for one serialized protocol-engine output chunk. */
  std::size_t max_output_chunk_bytes{64U * 1024U};
  /** Total response DATA retained while peer flow control is exhausted. */
  std::size_t max_queued_response_bytes{256U * 1024U};
  /** Maximum accepted entries in one peer SETTINGS frame. */
  std::size_t max_settings_entries{16U};
  /** Maximum CONTINUATION frames accepted for one header block. */
  std::size_t max_continuation_frames{8U};
  /** Maximum pending automatic SETTINGS and PING acknowledgements. */
  std::size_t max_outbound_ack_frames{128U};
  /** Initial and maximum token count for peer stream resets. */
  std::uint64_t reset_rate_burst{100U};
  /** Peer stream-reset tokens replenished each second. */
  std::uint64_t reset_rate_per_second{33U};
  /** Initial and maximum suspicious-protocol-event token count. */
  std::uint64_t glitch_rate_burst{1'000U};
  /** Suspicious-protocol-event tokens replenished each second. */
  std::uint64_t glitch_rate_per_second{330U};
};

/** One decoded HTTP/2 header field. */
struct Http2Header final {
  /** Lowercase field name, including ':' for decoded pseudo-headers. */
  std::string name;
  /** Decoded field value. */
  std::string value;
  /** Whether forwarding must preserve a never-indexed representation. */
  bool never_index{false};
};

/** Events emitted by the transport-neutral HTTP/2 protocol engine. */
enum class Http2EventKind {
  request_headers,   ///< Initial request pseudo-headers and fields.
  request_trailers,  ///< Trailer fields received after request DATA.
  data,              ///< One bounded request-body fragment.
  stream_end,        ///< END_STREAM completed a DATA sequence.
  stream_closed      ///< The protocol stream reached closed state.
};

/** An owned event that can safely outlive the input buffer passed to receive. */
struct Http2Event final {
  /** Event payload discriminator. */
  Http2EventKind kind{Http2EventKind::request_headers};
  /** Peer-initiated stream receiving the event. */
  std::int32_t stream_id{};
  /** Owned decoded fields for header and trailer events. */
  std::vector<Http2Header> headers;
  /** Owned payload for DATA events. */
  std::vector<std::uint8_t> data;
  /** HTTP/2 error code for stream_closed events. */
  std::uint32_t error_code{};
  /** Whether this header block also half-closed the peer stream side. */
  bool end_stream{false};
};

/** Fatal protocol-engine failure requiring the connection to be closed. */
class Http2ProtocolError final : public std::runtime_error {
 public:
  /** Constructs an error retaining the native nghttp2 error code. */
  Http2ProtocolError(int library_error_code, const std::string& message);

  /** Returns the native nghttp2 error code for metrics and diagnostics. */
  [[nodiscard]] int library_error_code() const noexcept {
    return library_error_code_;
  }

 private:
  int library_error_code_;
};

/**
 * Owns one server-side HTTP/2 protocol session without owning network I/O.
 *
 * The object must remain on its creating shard. Input is incremental, output
 * is returned one bounded protocol chunk at a time, and DATA flow-control
 * credit is released only through acknowledge_data(). The live listener owns
 * transport, TLS, timeout, cancellation, and graceful-drain behavior.
 */
class Http2ServerSession final {
 public:
  /** Creates a server session and queues its initial SETTINGS frame. */
  explicit Http2ServerSession(Http2Limits limits = {});
  ~Http2ServerSession();

  Http2ServerSession(const Http2ServerSession&) = delete;
  Http2ServerSession& operator=(const Http2ServerSession&) = delete;
  Http2ServerSession(Http2ServerSession&&) = delete;
  Http2ServerSession& operator=(Http2ServerSession&&) = delete;

  /**
   * Processes as much input as possible and returns the consumed byte count.
   * A partial count signals event-queue backpressure; the caller must retain
   * and resubmit the unconsumed suffix after draining events.
   */
  [[nodiscard]] std::size_t receive(std::span<const std::uint8_t> input);

  /** Returns one serialized protocol chunk, or an empty vector when idle. */
  [[nodiscard]] std::vector<std::uint8_t> take_output_chunk();

  /** Moves all currently queued request/stream events to the caller. */
  [[nodiscard]] std::vector<Http2Event> take_events();

  /** Releases connection and stream window credit after DATA is consumed. */
  void acknowledge_data(std::int32_t stream_id, std::size_t bytes);

  /** Submits a final header-only response and closes the local stream side. */
  void submit_empty_response(
      std::int32_t stream_id, std::uint16_t status,
      std::span<const Http2Header> headers = {});

  /**
   * Submits final response headers, optionally keeping the stream open for
   * bounded DATA supplied through try_submit_data().
   */
  void submit_response_headers(
      std::int32_t stream_id, std::uint16_t status,
      std::span<const Http2Header> headers, bool end_stream);

  /**
   * Queues one owned response DATA fragment without exceeding the session
   * response-memory budget. Returns false when transport backpressure must be
   * awaited before retrying the same fragment.
   */
  [[nodiscard]] bool try_submit_data(
      std::int32_t stream_id, std::span<const std::uint8_t> data,
      bool end_stream);

  /**
   * Completes an open response body with one validated trailer block.
   *
   * The body provider emits EOF without END_STREAM and the trailer HEADERS
   * block closes the stream, as required by nghttp2.
   */
  void submit_response_trailers(
      std::int32_t stream_id, std::span<const Http2Header> trailers);

  /** Resets a stream using an HTTP/2 wire error code. */
  void reset_stream(std::int32_t stream_id, std::uint32_t error_code);

  /** Queues one graceful GOAWAY using the last fully processed stream ID. */
  void begin_graceful_shutdown();

  /** Returns whether the protocol engine still expects peer input. */
  [[nodiscard]] bool wants_read() const noexcept;

  /** Returns whether serialized output is pending. */
  [[nodiscard]] bool wants_write() const noexcept;

  /** Returns whether all final protocol output is drained and I/O can close. */
  [[nodiscard]] bool should_close_transport() const noexcept;

  /** Returns whether graceful shutdown has begun. */
  [[nodiscard]] bool is_draining() const noexcept;

  /** Returns queued event memory as conservatively accounted bytes. */
  [[nodiscard]] std::size_t queued_event_bytes() const noexcept;

  /** Returns response DATA bytes retained behind peer flow control. */
  [[nodiscard]] std::size_t queued_response_bytes() const noexcept;

  /** Returns streams rejected by BonVoyage's local resource limits. */
  [[nodiscard]] std::uint64_t rejected_streams() const noexcept;

  /** Returns lifecycle events dropped because the bounded queue was full. */
  [[nodiscard]] std::uint64_t dropped_events() const noexcept;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace bonvoyage::http
