#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace bonvoyage::runtime {

/** W3C trace identifier carried as 16 binary octets. */
using TraceId = std::array<std::uint8_t, 16U>;

/** W3C parent/span identifier carried as 8 binary octets. */
using SpanId = std::array<std::uint8_t, 8U>;

/** Valid fields extracted from one W3C traceparent header. */
struct ParsedTraceParent final {
  TraceId trace_id{};     ///< Trace identity retained across participating hops.
  SpanId parent_id{};     ///< Identifier of the immediate remote parent.
  std::uint8_t flags{};   ///< Supported sampled and random trace flags.
};

/**
 * Parses a W3C traceparent value.
 *
 * Version 00 is accepted only in its exact 55-byte form. Future versions retain
 * the known prefix when their extension framing is syntactically valid. Invalid,
 * comma-joined, uppercase, all-zero, or version ff values return no context.
 */
[[nodiscard]] std::optional<ParsedTraceParent> parse_traceparent(
    std::string_view value) noexcept;

/** Formats one canonical version-00 traceparent value. */
[[nodiscard]] std::string format_traceparent(
    const TraceId& trace_id, const SpanId& parent_id,
    std::uint8_t flags);

/** Returns whether a header is owned by the tracing propagation boundary. */
[[nodiscard]] bool is_trace_propagation_header(
    std::string_view name) noexcept;

/** Shard-local, cryptographically seeded generator for hot-path trace IDs. */
class TraceIdGenerator final {
 public:
  /** Seeds the generator from the operating system through GnuTLS. */
  TraceIdGenerator();

  /** Deterministic constructor used by protocol unit tests. */
  explicit TraceIdGenerator(std::array<std::uint64_t, 4U> seed);

  /** Returns one nonzero 128-bit trace identifier. */
  [[nodiscard]] TraceId next_trace_id() noexcept;

  /** Returns one nonzero 64-bit span identifier. */
  [[nodiscard]] SpanId next_span_id() noexcept;

 private:
  [[nodiscard]] std::uint64_t next_word() noexcept;

  std::array<std::uint64_t, 4U> state_{};
};

}  // namespace bonvoyage::runtime
