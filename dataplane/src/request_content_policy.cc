#include "bonvoyage/runtime/request_content_policy.hh"

#include <algorithm>
#include <cstddef>
#include <stdexcept>
#include <utility>

namespace bonvoyage::runtime {
namespace {

constexpr std::size_t kMaximumContentTypes = 16U;
constexpr std::size_t kMaximumContentTypeBytes = 128U;
constexpr std::size_t kMaximumIncomingContentTypeBytes = 1024U;
constexpr std::size_t kMaximumMediaTypeParameters = 16U;

[[nodiscard]] bool is_token_character(unsigned char value) noexcept {
  if ((value >= '0' && value <= '9') ||
      (value >= 'A' && value <= 'Z') ||
      (value >= 'a' && value <= 'z')) {
    return true;
  }
  switch (value) {
    case '!':
    case '#':
    case '$':
    case '%':
    case '&':
    case '\'':
    case '*':
    case '+':
    case '-':
    case '.':
    case '^':
    case '_':
    case '`':
    case '|':
    case '~':
      return true;
    default:
      return false;
  }
}

[[nodiscard]] bool is_lowercase_token(std::string_view value) noexcept {
  if (value.empty()) {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [](char character) {
    const auto byte = static_cast<unsigned char>(character);
    return is_token_character(byte) && !(byte >= 'A' && byte <= 'Z');
  });
}

void skip_ows(std::string_view value, std::size_t& position) noexcept {
  while (position < value.size() &&
         (value[position] == ' ' || value[position] == '\t')) {
    ++position;
  }
}

[[nodiscard]] std::string_view parse_token(std::string_view value,
                                           std::size_t& position) noexcept {
  const auto start = position;
  while (position < value.size() &&
         is_token_character(static_cast<unsigned char>(value[position]))) {
    ++position;
  }
  return value.substr(start, position - start);
}

[[nodiscard]] bool parse_quoted_string(std::string_view value,
                                       std::size_t& position) noexcept {
  if (position >= value.size() || value[position] != '"') {
    return false;
  }
  ++position;
  while (position < value.size()) {
    const auto byte = static_cast<unsigned char>(value[position++]);
    if (byte == '"') {
      return true;
    }
    if (byte == '\\') {
      if (position >= value.size()) {
        return false;
      }
      const auto escaped = static_cast<unsigned char>(value[position++]);
      if (!(escaped == '\t' || escaped == ' ' ||
            (escaped >= 0x21U && escaped <= 0x7eU) || escaped >= 0x80U)) {
        return false;
      }
      continue;
    }
    if (!(byte == '\t' || byte == ' ' || byte == 0x21U ||
          (byte >= 0x23U && byte <= 0x5bU) ||
          (byte >= 0x5dU && byte <= 0x7eU) || byte >= 0x80U)) {
      return false;
    }
  }
  return false;
}

struct ParsedMediaType final {
  std::string_view type;
  std::string_view subtype;
  bool valid{false};
};

[[nodiscard]] ParsedMediaType parse_media_type(
    std::string_view value) noexcept {
  std::size_t position = 0U;
  skip_ows(value, position);
  const auto type = parse_token(value, position);
  if (type.empty() || position >= value.size() || value[position] != '/') {
    return {};
  }
  ++position;
  const auto subtype = parse_token(value, position);
  if (subtype.empty()) {
    return {};
  }
  skip_ows(value, position);
  std::size_t parameter_count = 0U;
  while (position < value.size()) {
    if (++parameter_count > kMaximumMediaTypeParameters) {
      return {};
    }
    if (value[position] != ';') {
      return {};
    }
    ++position;
    skip_ows(value, position);
    if (parse_token(value, position).empty()) {
      return {};
    }
    skip_ows(value, position);
    if (position >= value.size() || value[position] != '=') {
      return {};
    }
    ++position;
    skip_ows(value, position);
    if (position >= value.size()) {
      return {};
    }
    if (value[position] == '"') {
      if (!parse_quoted_string(value, position)) {
        return {};
      }
    } else if (parse_token(value, position).empty()) {
      return {};
    }
    skip_ows(value, position);
  }
  return ParsedMediaType{type, subtype, true};
}

[[nodiscard]] bool ascii_case_equal(std::string_view left,
                                    std::string_view right) noexcept {
  if (left.size() != right.size()) {
    return false;
  }
  for (std::size_t index = 0U; index < left.size(); ++index) {
    auto left_byte = static_cast<unsigned char>(left[index]);
    auto right_byte = static_cast<unsigned char>(right[index]);
    if (left_byte >= 'A' && left_byte <= 'Z') {
      left_byte = static_cast<unsigned char>(left_byte + ('a' - 'A'));
    }
    if (right_byte >= 'A' && right_byte <= 'Z') {
      right_byte = static_cast<unsigned char>(right_byte + ('a' - 'A'));
    }
    if (left_byte != right_byte) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] bool matches_configured_type(
    std::string_view configured, const ParsedMediaType& parsed) noexcept {
  if (configured.size() != parsed.type.size() + 1U + parsed.subtype.size()) {
    return false;
  }
  return ascii_case_equal(configured.substr(0U, parsed.type.size()),
                          parsed.type) &&
         configured[parsed.type.size()] == '/' &&
         ascii_case_equal(configured.substr(parsed.type.size() + 1U),
                          parsed.subtype);
}

[[nodiscard]] bool canonical_configured_media_type(
    std::string_view value) noexcept {
  if (value.empty() || value.size() > kMaximumContentTypeBytes ||
      value.find('*') != std::string_view::npos) {
    return false;
  }
  const auto slash = value.find('/');
  return slash != std::string_view::npos &&
         slash == value.rfind('/') &&
         is_lowercase_token(value.substr(0U, slash)) &&
         is_lowercase_token(value.substr(slash + 1U));
}

}  // namespace

RequestContentPolicy::RequestContentPolicy(
    std::optional<std::uint64_t> maximum_body_bytes,
    std::vector<std::string> allowed_content_types)
    : maximum_body_bytes_(maximum_body_bytes),
      allowed_content_types_(std::move(allowed_content_types)) {
  if (!maximum_body_bytes_.has_value() && allowed_content_types_.empty()) {
    throw std::invalid_argument("policy must configure a body limit or media types");
  }
  if (maximum_body_bytes_.has_value() && *maximum_body_bytes_ == 0U) {
    throw std::invalid_argument("maximum body bytes must be positive");
  }
  if (allowed_content_types_.size() > kMaximumContentTypes) {
    throw std::invalid_argument("too many allowed content types");
  }
  for (const auto& value : allowed_content_types_) {
    if (!canonical_configured_media_type(value)) {
      throw std::invalid_argument(
          "allowed content types must be canonical lowercase media types");
    }
  }
  std::sort(allowed_content_types_.begin(), allowed_content_types_.end());
  if (std::adjacent_find(allowed_content_types_.begin(),
                         allowed_content_types_.end()) !=
      allowed_content_types_.end()) {
    throw std::invalid_argument("allowed content types must be unique");
  }
  for (const auto& value : allowed_content_types_) {
    if (!accept_header_value_.empty()) {
      accept_header_value_ += ", ";
    }
    accept_header_value_ += value;
  }
}

RequestContentTypeDecision RequestContentPolicy::evaluate_content_type(
    std::string_view value, bool present, bool repeated,
    bool body_capable) const noexcept {
  if (allowed_content_types_.empty()) {
    return RequestContentTypeDecision::allowed;
  }
  if (repeated) {
    return RequestContentTypeDecision::malformed;
  }
  if (!present) {
    return body_capable ? RequestContentTypeDecision::required
                        : RequestContentTypeDecision::allowed;
  }
  if (value.size() > kMaximumIncomingContentTypeBytes) {
    return RequestContentTypeDecision::too_large;
  }
  const auto parsed = parse_media_type(value);
  if (!parsed.valid) {
    return RequestContentTypeDecision::malformed;
  }
  const auto allowed = std::any_of(
      allowed_content_types_.begin(), allowed_content_types_.end(),
      [&parsed](const std::string& configured) {
        return matches_configured_type(configured, parsed);
      });
  return allowed ? RequestContentTypeDecision::allowed
                 : RequestContentTypeDecision::unsupported;
}

}  // namespace bonvoyage::runtime
