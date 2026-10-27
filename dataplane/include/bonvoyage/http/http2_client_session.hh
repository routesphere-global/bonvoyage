#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "bonvoyage/http/http2_session.hh"

namespace bonvoyage::http {

/** Resource and protocol limits for one upstream HTTP/2 client session. */
struct Http2ClientLimits final {
  /** Maximum locally initiated streams active at the same time. */
  std::uint32_t max_concurrent_streams{100U};
  /** Receive window advertised for each response stream. */
  std::uint32_t initial_stream_window_bytes{65'535U};
  /** Largest accepted frame payload advertised in SETTINGS. */
  std::uint32_t max_frame_bytes{16'384U};
  /** Maximum RFC-accounted decoded header-list size per block. */
  std::uint32_t max_header_list_bytes{32U * 1024U};
  /** Maximum inbound and outbound HPACK dynamic-table size. */
  std::uint32_t header_table_bytes{4U * 1024U};
  /** Maximum decoded or submitted fields in one header block. */
  std::size_t max_header_fields{100U};
  /** Local memory budget for owned response and reserved terminal events. */
  std::size_t max_queued_event_bytes{1U * 1024U * 1024U};
  /** Local bound for one serialized protocol-engine output chunk. */
  std::size_t max_output_chunk_bytes{64U * 1024U};
  /** Total request DATA retained behind transport or peer backpressure. */
  std::size_t max_queued_request_bytes{256U * 1024U};
  /** Per-stream subset of the request DATA memory budget. */
  std::size_t max_queued_request_bytes_per_stream{64U * 1024U};
  /** Maximum retained request fragments across the connection. */
  std::size_t max_queued_request_chunks{1'024U};
  /** Per-stream subset of the retained request-fragment bound. */
  std::size_t max_queued_request_chunks_per_stream{128U};
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
  /** Maximum GOAWAY debug payload retained for the application. */
  std::size_t max_goaway_debug_bytes{4U * 1024U};
};

/** Events emitted by the transport-neutral upstream HTTP/2 client engine. */
enum class Http2ClientEventKind {
  response_headers,   ///< One informational or final response header block.
  response_trailers,  ///< A final trailer block received after response DATA.
  data,               ///< One bounded response-body fragment.
  stream_end,         ///< END_STREAM completed the remote response side.
  stream_reset,       ///< The peer sent RST_STREAM for a local stream.
  stream_closed,      ///< The protocol stream reached closed state.
  goaway              ///< The peer sent connection-level GOAWAY.
};

/** An owned event that can safely outlive the input passed to receive(). */
struct Http2ClientEvent final {
  /** Event payload discriminator. */
  Http2ClientEventKind kind{Http2ClientEventKind::response_headers};
  /** Locally initiated stream associated with the event, or zero for GOAWAY. */
  std::int32_t stream_id{};
  /** Owned fields for response-header and trailer events. */
  std::vector<Http2Header> headers;
  /** Parsed response status, or zero for non-header events. */
  std::uint16_t status{};
  /** Owned response DATA or bounded GOAWAY debug payload. */
  std::vector<std::uint8_t> data;
  /** HTTP/2 error code for reset, close, and GOAWAY events. */
  std::uint32_t error_code{};
  /** Last stream accepted by the peer for a GOAWAY event. */
  std::int32_t last_stream_id{};
  /** Whether this header block also completed the remote response side. */
  bool end_stream{false};
};

/**
 * Owns one client-side HTTP/2 protocol session without owning network I/O.
 *
 * The caller owns transport, TLS, timeout, cancellation, and shard affinity.
 * Input may be incremental, output is returned one bounded chunk at a time,
 * request DATA uses an explicitly bounded deferred provider, and response DATA
 * flow-control credit is released only through acknowledge_data().
 */
class Http2ClientSession final {
 public:
  /** Creates a client session and queues the connection preface and SETTINGS. */
  explicit Http2ClientSession(Http2ClientLimits limits = {});
  ~Http2ClientSession();

  Http2ClientSession(const Http2ClientSession&) = delete;
  Http2ClientSession& operator=(const Http2ClientSession&) = delete;
  Http2ClientSession(Http2ClientSession&&) = delete;
  Http2ClientSession& operator=(Http2ClientSession&&) = delete;

  /**
   * Processes input and returns its consumed byte count.
   *
   * A partial count signals event-queue backpressure. The caller must retain
   * and resubmit the unconsumed suffix after draining events.
   */
  [[nodiscard]] std::size_t receive(std::span<const std::uint8_t> input);

  /**
   * Returns one serialized preface/frame chunk, or an empty vector if idle.
   *
   * The caller must finish handing the returned bytes to its transport and
   * call acknowledge_output_chunk() before requesting another chunk.
   */
  [[nodiscard]] std::vector<std::uint8_t> take_output_chunk();

  /** Confirms that the previously returned output chunk reached the transport. */
  void acknowledge_output_chunk();

  /** Returns whether one output chunk still awaits transport acknowledgement. */
  [[nodiscard]] bool output_chunk_pending_acknowledgement() const noexcept;

  /** Moves all currently queued response and lifecycle events to the caller. */
  [[nodiscard]] std::vector<Http2ClientEvent> take_events();

  /**
   * Opens one regular HTTP request stream after validating every field.
   *
   * Pseudo-headers must be exactly :method, :scheme, :authority, and :path in
   * that order, followed by lowercase regular fields. The call throws when
   * local/peer stream capacity is exhausted or GOAWAY drain has begun.
   */
  [[nodiscard]] std::int32_t submit_request(
      std::span<const Http2Header> headers, bool end_stream);

  /**
   * Queues one owned request DATA fragment within global and stream budgets.
   *
   * Returns false without consuming the fragment when the queue is full.
   * Supplying end_stream marks the request body complete and resumes a data
   * provider previously deferred by transport or peer flow control.
   */
  [[nodiscard]] bool try_submit_data(
      std::int32_t stream_id, std::span<const std::uint8_t> data,
      bool end_stream);

  /** Releases connection and stream receive-window credit after DATA use. */
  void acknowledge_data(std::int32_t stream_id, std::size_t bytes);

  /** Resets one locally initiated stream using an HTTP/2 wire error code. */
  void reset_stream(std::int32_t stream_id, std::uint32_t error_code);

  /** Sends one graceful GOAWAY and rejects subsequent request submissions. */
  void begin_graceful_shutdown();

  /** Returns whether nghttp2 still expects peer input. */
  [[nodiscard]] bool wants_read() const noexcept;

  /** Returns whether serialized protocol output is pending. */
  [[nodiscard]] bool wants_write() const noexcept;

  /**
   * Returns whether protocol output, including caller-owned output, is drained.
   * The transport must separately flush its own buffers before closing.
   */
  [[nodiscard]] bool should_close_transport() const noexcept;

  /** Returns whether local or peer GOAWAY has started connection drain. */
  [[nodiscard]] bool is_draining() const noexcept;

  /** Returns whether a non-ACK peer SETTINGS frame has been processed. */
  [[nodiscard]] bool peer_settings_received() const noexcept;

  /**
   * Returns the peer's MAX_CONCURRENT_STREAMS allowance, using nghttp2's
   * conservative pre-SETTINGS default until the peer sends SETTINGS.
   */
  [[nodiscard]] std::uint32_t peer_max_concurrent_streams() const noexcept;

  /** Returns the number of locally initiated streams not yet closed. */
  [[nodiscard]] std::size_t active_streams() const noexcept;

  /** Returns request streams currently permitted by local and peer limits. */
  [[nodiscard]] std::size_t available_stream_capacity() const noexcept;

  /** Returns request DATA bytes retained by all deferred providers. */
  [[nodiscard]] std::size_t queued_request_bytes() const noexcept;

  /** Returns response-event memory conservatively accounted to the queue. */
  [[nodiscard]] std::size_t queued_event_bytes() const noexcept;

  /** Returns response DATA bytes awaiting flow-control acknowledgement. */
  [[nodiscard]] std::size_t unacknowledged_data_bytes() const noexcept;

  /** Returns streams rejected because peer input exceeded local limits. */
  [[nodiscard]] std::uint64_t rejected_streams() const noexcept;

  /** Returns non-terminal events suppressed when queue pressure reset a stream. */
  [[nodiscard]] std::uint64_t dropped_events() const noexcept;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace bonvoyage::http
