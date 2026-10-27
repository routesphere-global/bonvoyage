#include "bonvoyage/http/grpc_protocol.hh"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>

namespace bonvoyage::http {
namespace {

constexpr std::uint64_t kMaximumTimeoutDigits = 99'999'999U;

[[nodiscard]] bool ascii_case_equal(std::string_view left,
                                    std::string_view right) noexcept {
  return left.size() == right.size() &&
         std::equal(left.begin(), left.end(), right.begin(),
                    [](char lhs, char rhs) {
                      return std::tolower(static_cast<unsigned char>(lhs)) ==
                             std::tolower(static_cast<unsigned char>(rhs));
                    });
}

[[nodiscard]] bool valid_metadata_name(std::string_view name) noexcept {
  return !name.empty() &&
         std::all_of(name.begin(), name.end(), [](char character) {
           const auto byte = static_cast<unsigned char>(character);
           return (byte >= static_cast<unsigned char>('0') &&
                   byte <= static_cast<unsigned char>('9')) ||
                  (byte >= static_cast<unsigned char>('a') &&
                   byte <= static_cast<unsigned char>('z')) ||
                  character == '_' || character == '-' || character == '.';
         });
}

[[nodiscard]] bool valid_ascii_metadata_value(
    std::string_view value) noexcept {
  return std::all_of(value.begin(), value.end(), [](char character) {
    const auto byte = static_cast<unsigned char>(character);
    return byte >= 0x20U && byte <= 0x7eU;
  });
}

[[nodiscard]] bool is_base64_character(char character) noexcept {
  const auto byte = static_cast<unsigned char>(character);
  return (byte >= static_cast<unsigned char>('A') &&
          byte <= static_cast<unsigned char>('Z')) ||
         (byte >= static_cast<unsigned char>('a') &&
          byte <= static_cast<unsigned char>('z')) ||
         (byte >= static_cast<unsigned char>('0') &&
          byte <= static_cast<unsigned char>('9')) ||
         character == '+' || character == '/';
}

[[nodiscard]] bool valid_base64_value(std::string_view value) noexcept {
  if (value.empty()) {
    return true;
  }
  const auto padding = value.ends_with("==")
                           ? 2U
                           : (value.ends_with('=') ? 1U : 0U);
  if (padding != 0U && value.size() % 4U != 0U) {
    return false;
  }
  const auto encoded_size = value.size() - padding;
  if (!std::all_of(value.begin(), value.begin() +
                                      static_cast<std::ptrdiff_t>(encoded_size),
                   is_base64_character)) {
    return false;
  }
  if (!std::all_of(value.begin() +
                       static_cast<std::ptrdiff_t>(encoded_size),
                   value.end(), [](char character) {
                     return character == '=';
                   })) {
    return false;
  }
  const auto remainder = encoded_size % 4U;
  return remainder != 1U;
}

void validate_binary_metadata_value(std::string_view value) {
  std::size_t offset = 0U;
  while (offset <= value.size()) {
    const auto separator = value.find(',', offset);
    const auto end = separator == std::string_view::npos
                         ? value.size()
                         : separator;
    if (!valid_base64_value(value.substr(offset, end - offset))) {
      throw std::invalid_argument("invalid gRPC binary metadata value");
    }
    if (separator == std::string_view::npos) {
      break;
    }
    offset = separator + 1U;
  }
}

[[nodiscard]] bool valid_grpc_message(std::string_view value) noexcept {
  for (std::size_t index = 0U; index < value.size(); ++index) {
    const auto byte = static_cast<unsigned char>(value[index]);
    if (value[index] == '%') {
      if (index + 2U >= value.size() ||
          !std::isxdigit(static_cast<unsigned char>(value[index + 1U])) ||
          !std::isxdigit(static_cast<unsigned char>(value[index + 2U]))) {
        return false;
      }
      index += 2U;
      continue;
    }
    if (byte < 0x20U || byte > 0x7eU) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] std::uint32_t parse_grpc_status(std::string_view value) {
  if (value.empty() || value.size() > 2U ||
      !std::all_of(value.begin(), value.end(), [](char character) {
        return character >= '0' && character <= '9';
      })) {
    throw std::invalid_argument("invalid grpc-status trailer");
  }
  std::uint32_t result = 0U;
  for (const auto character : value) {
    result = result * 10U +
             static_cast<std::uint32_t>(character - '0');
  }
  if (result > 16U) {
    throw std::invalid_argument("grpc-status is outside the canonical range");
  }
  return result;
}

[[nodiscard]] bool reserved_trailer_name(std::string_view name) noexcept {
  constexpr std::array<std::string_view, 3U> allowed_reserved{
      "grpc-message", "grpc-status", "grpc-status-details-bin"};
  if (std::find(allowed_reserved.begin(), allowed_reserved.end(), name) !=
      allowed_reserved.end()) {
    return false;
  }
  return name.starts_with("grpc-") || name == "content-length" ||
         name == "content-type" || name == "host" || name == "te" ||
         name == "trailer" || name == "transfer-encoding";
}

[[nodiscard]] std::uint64_t timeout_multiplier(char unit) {
  switch (unit) {
    case 'H':
      return 3'600'000'000'000ULL;
    case 'M':
      return 60'000'000'000ULL;
    case 'S':
      return 1'000'000'000ULL;
    case 'm':
      return 1'000'000ULL;
    case 'u':
      return 1'000ULL;
    case 'n':
      return 1ULL;
    default:
      throw std::invalid_argument("invalid grpc-timeout unit");
  }
}

[[nodiscard]] std::uint64_t ceil_divide(std::uint64_t value,
                                        std::uint64_t divisor) noexcept {
  return value / divisor + (value % divisor == 0U ? 0U : 1U);
}

}  // namespace

bool is_grpc_content_type(std::string_view value) noexcept {
  constexpr std::string_view media_type{"application/grpc"};
  if (value.size() < media_type.size() ||
      !ascii_case_equal(value.substr(0U, media_type.size()), media_type)) {
    return false;
  }
  return value.size() == media_type.size() ||
         value[media_type.size()] == '+';
}

bool is_grpc_method_path(std::string_view value) noexcept {
  if (value.size() < 4U || value.front() != '/') {
    return false;
  }
  const auto separator = value.find('/', 1U);
  return separator != std::string_view::npos && separator > 1U &&
         separator + 1U < value.size() &&
         value.find('?', separator + 1U) == std::string_view::npos;
}

std::chrono::nanoseconds parse_grpc_timeout(std::string_view value) {
  if (value.size() < 2U || value.size() > 9U) {
    throw std::invalid_argument("grpc-timeout must contain 1-8 digits and a unit");
  }
  const auto digits = value.substr(0U, value.size() - 1U);
  if (digits.empty() || digits.size() > 8U ||
      !std::all_of(digits.begin(), digits.end(), [](char character) {
        return character >= '0' && character <= '9';
      })) {
    throw std::invalid_argument("invalid grpc-timeout digits");
  }
  std::uint64_t count = 0U;
  for (const auto character : digits) {
    count = count * 10U +
            static_cast<std::uint64_t>(character - '0');
  }
  if (count == 0U) {
    throw std::invalid_argument("grpc-timeout must be positive");
  }
  const auto multiplier = timeout_multiplier(value.back());
  const auto maximum = static_cast<std::uint64_t>(
      std::chrono::nanoseconds::max().count());
  if (count > maximum / multiplier) {
    return std::chrono::nanoseconds::max();
  }
  return std::chrono::nanoseconds(count * multiplier);
}

std::string format_grpc_timeout(std::chrono::nanoseconds value) {
  auto nanoseconds = value.count();
  if (nanoseconds <= 0) {
    return "1n";
  }
  const auto count = static_cast<std::uint64_t>(nanoseconds);
  constexpr std::array<std::pair<char, std::uint64_t>, 6U> units{{
      {'n', 1ULL},
      {'u', 1'000ULL},
      {'m', 1'000'000ULL},
      {'S', 1'000'000'000ULL},
      {'M', 60'000'000'000ULL},
      {'H', 3'600'000'000'000ULL},
  }};
  for (const auto& [unit, divisor] : units) {
    const auto encoded = ceil_divide(count, divisor);
    if (encoded <= kMaximumTimeoutDigits) {
      return std::to_string(encoded) + unit;
    }
  }
  return std::to_string(kMaximumTimeoutDigits) + "H";
}

void validate_grpc_metadata(std::string_view name,
                            std::string_view value) {
  if (!valid_metadata_name(name) || name.starts_with("grpc-")) {
    throw std::invalid_argument("invalid gRPC custom metadata name");
  }
  if (name.ends_with("-bin")) {
    validate_binary_metadata_value(value);
  } else if (!valid_ascii_metadata_value(value)) {
    throw std::invalid_argument("invalid gRPC ASCII metadata value");
  }
}

GrpcTrailerInfo validate_grpc_response_trailers(
    std::span<const Http2Header> trailers) {
  GrpcTrailerInfo result;
  bool saw_status = false;
  bool saw_message = false;
  bool saw_details = false;
  for (const auto& trailer : trailers) {
    if (reserved_trailer_name(trailer.name)) {
      throw std::invalid_argument("forbidden gRPC response trailer");
    }
    if (trailer.name == "grpc-status") {
      if (saw_status) {
        throw std::invalid_argument("duplicate grpc-status trailer");
      }
      result.status = parse_grpc_status(trailer.value);
      saw_status = true;
    } else if (trailer.name == "grpc-message") {
      if (saw_message || !valid_grpc_message(trailer.value)) {
        throw std::invalid_argument("invalid grpc-message trailer");
      }
      saw_message = true;
    } else if (trailer.name == "grpc-status-details-bin") {
      if (saw_details) {
        throw std::invalid_argument(
            "duplicate grpc-status-details-bin trailer");
      }
      validate_binary_metadata_value(trailer.value);
      saw_details = true;
    } else {
      validate_grpc_metadata(trailer.name, trailer.value);
      ++result.custom_metadata_fields;
    }
  }
  if (!saw_status) {
    throw std::invalid_argument("gRPC response omitted grpc-status");
  }
  return result;
}

std::string encode_grpc_message(std::string_view value) {
  constexpr char hex[] = "0123456789ABCDEF";
  std::string result;
  result.reserve(value.size());
  for (const auto character : value) {
    const auto byte = static_cast<unsigned char>(character);
    if (byte >= 0x20U && byte <= 0x7eU && character != '%') {
      result.push_back(character);
      continue;
    }
    result.push_back('%');
    result.push_back(hex[byte >> 4U]);
    result.push_back(hex[byte & 0x0fU]);
  }
  return result;
}

GrpcUnaryMessageValidator::GrpcUnaryMessageValidator(
    bool compression_allowed) noexcept
    : compression_allowed_(compression_allowed) {}

void GrpcUnaryMessageValidator::consume(
    std::span<const std::uint8_t> data) {
  std::size_t offset = 0U;
  while (offset < data.size()) {
    if (message_complete_) {
      throw std::invalid_argument(
          "gRPC unary body contains more than one message");
    }
    if (!message_started_) {
      while (prefix_bytes_ < std::size(prefix_) && offset < data.size()) {
        prefix_[prefix_bytes_++] = data[offset++];
      }
      if (prefix_bytes_ != std::size(prefix_)) {
        return;
      }
      if (prefix_[0] > 1U || (prefix_[0] == 1U && !compression_allowed_)) {
        throw std::invalid_argument("invalid gRPC compression flag");
      }
      declared_length_ =
          (static_cast<std::uint32_t>(prefix_[1]) << 24U) |
          (static_cast<std::uint32_t>(prefix_[2]) << 16U) |
          (static_cast<std::uint32_t>(prefix_[3]) << 8U) |
          static_cast<std::uint32_t>(prefix_[4]);
      payload_remaining_ = declared_length_;
      message_started_ = true;
      if (payload_remaining_ == 0U) {
        message_complete_ = true;
      }
      continue;
    }
    const auto available = data.size() - offset;
    const auto consumed = std::min<std::size_t>(payload_remaining_, available);
    payload_remaining_ -= static_cast<std::uint32_t>(consumed);
    offset += consumed;
    if (payload_remaining_ == 0U) {
      message_complete_ = true;
    }
  }
}

void GrpcUnaryMessageValidator::finish(bool require_message) const {
  if ((message_started_ && !message_complete_) ||
      (!message_started_ && prefix_bytes_ != 0U)) {
    throw std::invalid_argument("truncated gRPC length-prefixed message");
  }
  if (require_message && !message_complete_) {
    throw std::invalid_argument("gRPC unary request omitted its message");
  }
}

bool GrpcUnaryMessageValidator::has_message() const noexcept {
  return message_complete_;
}

}  // namespace bonvoyage::http
