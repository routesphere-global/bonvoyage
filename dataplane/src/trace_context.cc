#include "bonvoyage/runtime/trace_context.hh"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstring>
#include <stdexcept>

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

namespace bonvoyage::runtime {
namespace {

constexpr std::uint8_t kSupportedTraceFlags = 0x03U;
constexpr std::size_t kTraceparentSize = 55U;

std::optional<std::uint8_t> decode_hex(char value) noexcept {
  if (value >= '0' && value <= '9') {
    return static_cast<std::uint8_t>(value - '0');
  }
  if (value >= 'a' && value <= 'f') {
    return static_cast<std::uint8_t>(10 + value - 'a');
  }
  return std::nullopt;
}

template <std::size_t Size>
bool decode_bytes(std::string_view value,
                  std::array<std::uint8_t, Size>& output) noexcept {
  if (value.size() != output.size() * 2U) {
    return false;
  }
  for (std::size_t index = 0U; index < output.size(); ++index) {
    const auto high = decode_hex(value[index * 2U]);
    const auto low = decode_hex(value[index * 2U + 1U]);
    if (!high.has_value() || !low.has_value()) {
      return false;
    }
    output[index] = static_cast<std::uint8_t>((*high << 4U) | *low);
  }
  return true;
}

template <std::size_t Size>
bool all_zero(const std::array<std::uint8_t, Size>& value) noexcept {
  return std::all_of(value.begin(), value.end(),
                     [](std::uint8_t byte) { return byte == 0U; });
}

char encode_hex(std::uint8_t value) noexcept {
  constexpr char digits[] = "0123456789abcdef";
  return digits[value & 0x0fU];
}

template <std::size_t Size>
void append_hex(std::string& output,
                const std::array<std::uint8_t, Size>& value) {
  for (const auto byte : value) {
    output.push_back(encode_hex(static_cast<std::uint8_t>(byte >> 4U)));
    output.push_back(encode_hex(byte));
  }
}

bool ascii_case_equal(std::string_view left,
                      std::string_view right) noexcept {
  if (left.size() != right.size()) {
    return false;
  }
  for (std::size_t index = 0U; index < left.size(); ++index) {
    auto lower = [](char value) noexcept {
      return value >= 'A' && value <= 'Z'
                 ? static_cast<char>(value + ('a' - 'A'))
                 : value;
    };
    if (lower(left[index]) != lower(right[index])) {
      return false;
    }
  }
  return true;
}

}  // namespace

std::optional<ParsedTraceParent> parse_traceparent(
    std::string_view value) noexcept {
  if (value.size() < kTraceparentSize || value.find(',') != std::string_view::npos ||
      value[2] != '-' || value[35] != '-' || value[52] != '-') {
    return std::nullopt;
  }

  const auto version_high = decode_hex(value[0]);
  const auto version_low = decode_hex(value[1]);
  if (!version_high.has_value() || !version_low.has_value()) {
    return std::nullopt;
  }
  const auto version =
      static_cast<std::uint8_t>((*version_high << 4U) | *version_low);
  if (version == 0xffU || (version == 0U && value.size() != kTraceparentSize) ||
      (version != 0U && value.size() > kTraceparentSize &&
       value[kTraceparentSize] != '-')) {
    return std::nullopt;
  }

  ParsedTraceParent result;
  if (!decode_bytes(value.substr(3U, 32U), result.trace_id) ||
      !decode_bytes(value.substr(36U, 16U), result.parent_id) ||
      all_zero(result.trace_id) || all_zero(result.parent_id)) {
    return std::nullopt;
  }
  std::array<std::uint8_t, 1U> flags{};
  if (!decode_bytes(value.substr(53U, 2U), flags)) {
    return std::nullopt;
  }
  result.flags = static_cast<std::uint8_t>(flags[0] & kSupportedTraceFlags);
  return result;
}

std::string format_traceparent(const TraceId& trace_id,
                               const SpanId& parent_id,
                               std::uint8_t flags) {
  if (all_zero(trace_id) || all_zero(parent_id)) {
    throw std::invalid_argument("traceparent identifiers must be nonzero");
  }
  std::string result;
  result.reserve(kTraceparentSize);
  result.append("00-");
  append_hex(result, trace_id);
  result.push_back('-');
  append_hex(result, parent_id);
  result.push_back('-');
  const auto bounded_flags =
      static_cast<std::uint8_t>(flags & kSupportedTraceFlags);
  result.push_back(encode_hex(static_cast<std::uint8_t>(bounded_flags >> 4U)));
  result.push_back(encode_hex(bounded_flags));
  return result;
}

bool is_trace_propagation_header(std::string_view name) noexcept {
  return ascii_case_equal(name, "traceparent") ||
         ascii_case_equal(name, "tracestate") ||
         ascii_case_equal(name, "baggage");
}

TraceIdGenerator::TraceIdGenerator() {
  const auto result =
      gnutls_rnd(GNUTLS_RND_KEY, state_.data(), sizeof(state_));
  if (result < 0) {
    throw std::runtime_error(std::string("trace ID seed generation failed: ") +
                             gnutls_strerror(result));
  }
  if (std::all_of(state_.begin(), state_.end(),
                  [](std::uint64_t value) { return value == 0U; })) {
    state_[0] = 0x9e3779b97f4a7c15ULL;
  }
}

TraceIdGenerator::TraceIdGenerator(std::array<std::uint64_t, 4U> seed)
    : state_(seed) {
  if (std::all_of(state_.begin(), state_.end(),
                  [](std::uint64_t value) { return value == 0U; })) {
    throw std::invalid_argument("trace ID generator seed must be nonzero");
  }
}

std::uint64_t TraceIdGenerator::next_word() noexcept {
  const auto result = std::rotl(state_[1] * 5U, 7) * 9U;
  const auto shift = state_[1] << 17U;
  state_[2] ^= state_[0];
  state_[3] ^= state_[1];
  state_[1] ^= state_[2];
  state_[0] ^= state_[3];
  state_[2] ^= shift;
  state_[3] = std::rotl(state_[3], 45);
  return result;
}

TraceId TraceIdGenerator::next_trace_id() noexcept {
  TraceId result{};
  do {
    const auto high = next_word();
    const auto low = next_word();
    std::memcpy(result.data(), &high, sizeof(high));
    std::memcpy(result.data() + sizeof(high), &low, sizeof(low));
  } while (all_zero(result));
  return result;
}

SpanId TraceIdGenerator::next_span_id() noexcept {
  SpanId result{};
  do {
    const auto value = next_word();
    std::memcpy(result.data(), &value, sizeof(value));
  } while (all_zero(result));
  return result;
}

}  // namespace bonvoyage::runtime
