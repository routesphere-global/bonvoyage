#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <vector>

#include "bonvoyage/http/http2_client_session.hh"

namespace {

using bonvoyage::http::Http2ClientEventKind;
using bonvoyage::http::Http2ClientSession;
using bonvoyage::http::Http2Header;
using bonvoyage::http::Http2ProtocolError;

constexpr std::size_t kMaxInputBytes = 64U * 1024U;
constexpr std::size_t kMaxOutputChunks = 4'096U;
constexpr std::size_t kMaxOutputBytes = 64U * 1024U * 1024U;
constexpr std::size_t kMaxStalledReceives = 2U;

struct HarnessState final {
  std::uint8_t output_fold{};
};

void drain_output(Http2ClientSession& session, HarnessState& state) {
  std::size_t output_bytes = 0U;
  for (std::size_t chunk_index = 0U; chunk_index < kMaxOutputChunks;
       ++chunk_index) {
    auto chunk = session.take_output_chunk();
    if (chunk.empty()) {
      return;
    }
    if (chunk.size() > kMaxOutputBytes - output_bytes) {
      std::abort();
    }
    output_bytes += chunk.size();
    state.output_fold = static_cast<std::uint8_t>(
        state.output_fold ^ chunk.front() ^ chunk.back());
    session.acknowledge_output_chunk();
  }

  // A finite input must never generate an unbounded protocol-output loop.
  std::abort();
}

void drain_events(Http2ClientSession& session) {
  const auto events = session.take_events();
  for (const auto& event : events) {
    if (event.kind != Http2ClientEventKind::data || event.data.empty() ||
        event.stream_id <= 0) {
      continue;
    }
    try {
      session.acknowledge_data(event.stream_id, event.data.size());
    } catch (const Http2ProtocolError&) {
      // A later frame in the receive call may already have closed the stream.
    }
  }
}

void drain_session(Http2ClientSession& session, HarnessState& state) {
  drain_events(session);
  drain_output(session, state);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
  const auto bounded_size = std::min(size, kMaxInputBytes);
  HarnessState state;

  try {
    Http2ClientSession session;
    drain_output(session, state);

    const std::array<Http2Header, 4U> request{{
        {":method", "GET", false},
        {":scheme", "https", false},
        {":authority", "upstream.example.test", false},
        {":path", "/fuzz", false},
    }};
    (void)session.submit_request(request, true);
    drain_output(session, state);

    if (bounded_size == 0U) {
      return static_cast<int>(state.output_fold & 0U);
    }

    const std::span<const std::uint8_t> input(data, bounded_size);
    std::size_t offset = 0U;
    std::size_t stalled_receives = 0U;
    while (offset < input.size()) {
      const auto selector_index =
          (offset + input.size() - 1U) % input.size();
      const auto requested_chunk =
          1U + static_cast<std::size_t>(input[selector_index] % 31U);
      const auto chunk_size =
          std::min(requested_chunk, input.size() - offset);

      std::size_t consumed = 0U;
      try {
        consumed = session.receive(input.subspan(offset, chunk_size));
      } catch (const Http2ProtocolError&) {
        drain_session(session, state);
        break;
      }

      drain_session(session, state);
      if (consumed == 0U) {
        ++stalled_receives;
        if (stalled_receives >= kMaxStalledReceives) {
          break;
        }
        continue;
      }

      stalled_receives = 0U;
      offset += consumed;
    }

    drain_session(session, state);
    try {
      session.begin_graceful_shutdown();
      drain_session(session, state);
    } catch (const Http2ProtocolError&) {
      drain_session(session, state);
    }
  } catch (const Http2ProtocolError&) {
    // Invalid server wire input is expected; sanitizer findings still stop.
  }

  return static_cast<int>(state.output_fold & 0U);
}
