#include "bonvoyage/runtime/cors_policy.hh"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace bonvoyage::runtime {
namespace {

constexpr std::size_t kMaximumOrigins = 32U;
constexpr std::size_t kMaximumMethods = 16U;
constexpr std::size_t kMaximumHeaders = 32U;
constexpr std::size_t kMaximumOriginBytes = 512U;
constexpr std::size_t kMaximumMethodBytes = 32U;
constexpr std::size_t kMaximumHeaderNameBytes = 128U;
constexpr std::size_t kMaximumRequestHeadersBytes = 2048U;
constexpr std::uint32_t kMaximumMaxAgeSeconds = 86400U;

bool ascii_case_equal(std::string_view left, std::string_view right) noexcept {
  if (left.size() != right.size()) {
    return false;
  }
  for (std::size_t index = 0U; index < left.size(); ++index) {
    auto lhs = static_cast<unsigned char>(left[index]);
    auto rhs = static_cast<unsigned char>(right[index]);
    if (lhs >= 'A' && lhs <= 'Z') {
      lhs = static_cast<unsigned char>(lhs + ('a' - 'A'));
    }
    if (rhs >= 'A' && rhs <= 'Z') {
      rhs = static_cast<unsigned char>(rhs + ('a' - 'A'));
    }
    if (lhs != rhs) {
      return false;
    }
  }
  return true;
}

bool valid_http_token(std::string_view value) noexcept {
  if (value.empty()) {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [](char character) {
    const auto byte = static_cast<unsigned char>(character);
    if ((byte >= '0' && byte <= '9') || (byte >= 'A' && byte <= 'Z') ||
        (byte >= 'a' && byte <= 'z')) {
      return true;
    }
    switch (byte) {
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
  });
}

bool valid_uppercase_method(std::string_view method) noexcept {
  return !method.empty() && method.size() <= kMaximumMethodBytes &&
         method != "*" && valid_http_token(method) &&
         std::none_of(method.begin(), method.end(), [](char character) {
           return character >= 'a' && character <= 'z';
         });
}

bool reserved_cors_request_header(std::string_view name) noexcept {
  return name == "access-control-request-headers" ||
         name == "access-control-request-method" || name == "connection" ||
         name == "content-length" || name == "host" || name == "origin" ||
         name == "proxy-connection" || name == "te" || name == "trailer" ||
         name == "transfer-encoding" || name == "upgrade" ||
         name.starts_with("access-control-");
}

bool valid_dns_host(std::string_view host) noexcept {
  if (host.empty() || host.size() > 253U || host.back() == '.') {
    return false;
  }
  std::size_t label_size = 0U;
  bool label_starts_with_hyphen = false;
  char previous = '\0';
  for (const auto character : host) {
    if (character == '.') {
      if (label_size == 0U || label_size > 63U ||
          label_starts_with_hyphen || previous == '-') {
        return false;
      }
      label_size = 0U;
      label_starts_with_hyphen = false;
      previous = character;
      continue;
    }
    if (!((character >= 'a' && character <= 'z') ||
          (character >= '0' && character <= '9') || character == '-')) {
      return false;
    }
    if (label_size == 0U) {
      label_starts_with_hyphen = character == '-';
    }
    ++label_size;
    previous = character;
  }
  return label_size != 0U && label_size <= 63U &&
         !label_starts_with_hyphen && previous != '-';
}

bool valid_port(std::string_view value, bool secure) noexcept {
  if (value.empty() || (value.size() > 1U && value.front() == '0')) {
    return false;
  }
  std::uint32_t port = 0U;
  const auto [position, error] = std::from_chars(
      value.data(), value.data() + value.size(), port, 10);
  if (error != std::errc{} || position != value.data() + value.size() ||
      port == 0U || port > 65535U) {
    return false;
  }
  return (secure && port != 443U) || (!secure && port != 80U);
}

bool valid_authority(std::string_view authority, bool secure) noexcept {
  if (authority.empty() || authority.find_first_of("/?#@ ") !=
                               std::string_view::npos) {
    return false;
  }
  if (authority.front() == '[') {
    const auto close = authority.find(']');
    if (close == std::string_view::npos || close == 1U) {
      return false;
    }
    const auto address = authority.substr(1U, close - 1U);
    std::array<unsigned char, 16U> bytes{};
    if (inet_pton(AF_INET6, std::string(address).c_str(), bytes.data()) != 1) {
      return false;
    }
    std::array<char, INET6_ADDRSTRLEN> canonical{};
    if (inet_ntop(AF_INET6, bytes.data(), canonical.data(), canonical.size()) ==
            nullptr ||
        address != canonical.data()) {
      return false;
    }
    if (close + 1U == authority.size()) {
      return true;
    }
    return authority[close + 1U] == ':' &&
           valid_port(authority.substr(close + 2U), secure);
  }

  const auto separator = authority.rfind(':');
  auto host = authority;
  if (separator != std::string_view::npos) {
    host = authority.substr(0U, separator);
    if (!valid_port(authority.substr(separator + 1U), secure)) {
      return false;
    }
  }
  if (host.empty()) {
    return false;
  }
  std::array<unsigned char, 4U> ipv4{};
  if (inet_pton(AF_INET, std::string(host).c_str(), ipv4.data()) == 1) {
    std::array<char, INET_ADDRSTRLEN> canonical{};
    return inet_ntop(AF_INET, ipv4.data(), canonical.data(),
                     canonical.size()) != nullptr &&
           host == canonical.data();
  }
  return valid_dns_host(host);
}

std::string join(const std::vector<std::string>& values) {
  std::string result;
  for (const auto& value : values) {
    if (!result.empty()) {
      result += ", ";
    }
    result += value;
  }
  return result;
}

template <typename Validator>
void normalize_unique(std::vector<std::string>& values, std::size_t maximum,
                      Validator&& validator, std::string_view field) {
  if (values.size() > maximum) {
    throw std::invalid_argument(std::string(field) + " exceeds its bound");
  }
  for (const auto& value : values) {
    if (!validator(value)) {
      throw std::invalid_argument(std::string(field) +
                                  " contains an invalid value");
    }
  }
  std::sort(values.begin(), values.end());
  if (std::adjacent_find(values.begin(), values.end()) != values.end()) {
    throw std::invalid_argument(std::string(field) +
                                " contains a duplicate value");
  }
}

}  // namespace

bool is_canonical_cors_origin(std::string_view origin) noexcept {
  if (origin.size() < 8U || origin.size() > kMaximumOriginBytes) {
    return false;
  }
  bool secure = false;
  if (origin.starts_with("http://")) {
    origin.remove_prefix(7U);
  } else if (origin.starts_with("https://")) {
    origin.remove_prefix(8U);
    secure = true;
  } else {
    return false;
  }
  return valid_authority(origin, secure);
}

bool is_canonical_cors_method(std::string_view method) noexcept {
  return valid_uppercase_method(method);
}

CorsPolicy::CorsPolicy(bool allow_any_origin,
                       std::vector<std::string> allowed_origins,
                       std::vector<std::string> allowed_methods,
                       std::vector<std::string> allowed_headers,
                       std::vector<std::string> exposed_headers,
                       bool allow_credentials,
                       std::uint32_t max_age_seconds)
    : allow_any_origin_(allow_any_origin),
      allow_credentials_(allow_credentials),
      max_age_seconds_(max_age_seconds),
      allowed_origins_(std::move(allowed_origins)),
      allowed_methods_(std::move(allowed_methods)),
      allowed_headers_(std::move(allowed_headers)) {
  if (allow_any_origin_ == !allowed_origins_.empty()) {
    throw std::invalid_argument(
        "exactly one of allow_any_origin and allowed_origins is required");
  }
  if (allow_any_origin_ && allow_credentials_) {
    throw std::invalid_argument(
        "allow_any_origin cannot be combined with allow_credentials");
  }
  if (max_age_seconds_ > kMaximumMaxAgeSeconds) {
    throw std::invalid_argument("max_age_seconds exceeds 86400");
  }
  normalize_unique(allowed_origins_, kMaximumOrigins,
                   is_canonical_cors_origin, "allowed_origins");
  if (allowed_methods_.empty()) {
    throw std::invalid_argument("allowed_methods must not be empty");
  }
  normalize_unique(allowed_methods_, kMaximumMethods,
                   valid_uppercase_method, "allowed_methods");
  normalize_unique(
      allowed_headers_, kMaximumHeaders,
      [](std::string_view value) {
        return value != "*" && value.size() <= kMaximumHeaderNameBytes &&
               valid_http_token(value) &&
               !reserved_cors_request_header(value) &&
               std::none_of(value.begin(), value.end(), [](char character) {
                 return character >= 'A' && character <= 'Z';
               });
      },
      "allowed_headers");
  normalize_unique(
      exposed_headers, kMaximumHeaders,
      [](std::string_view value) {
        return value != "*" && value != "set-cookie" &&
               value != "set-cookie2" &&
               !value.starts_with("access-control-") &&
               value.size() <= kMaximumHeaderNameBytes &&
               valid_http_token(value) &&
               std::none_of(value.begin(), value.end(), [](char character) {
                 return character >= 'A' && character <= 'Z';
               });
      },
      "exposed_headers");
  allowed_methods_value_ = join(allowed_methods_);
  allowed_headers_value_ = join(allowed_headers_);
  exposed_headers_value_ = join(exposed_headers);
  max_age_value_ = std::to_string(max_age_seconds_);
}

bool CorsPolicy::allows_origin(std::string_view origin) const noexcept {
  return response_origin(origin).has_value();
}

std::optional<std::string_view> CorsPolicy::response_origin(
    std::string_view origin) const noexcept {
  if (!is_canonical_cors_origin(origin)) {
    return std::nullopt;
  }
  if (allow_any_origin_) {
    return std::string_view{"*"};
  }
  const auto match = std::lower_bound(allowed_origins_.begin(),
                                     allowed_origins_.end(), origin);
  if (match == allowed_origins_.end() || *match != origin) {
    return std::nullopt;
  }
  return std::string_view{*match};
}

bool CorsPolicy::allows_method(std::string_view method) const noexcept {
  return valid_uppercase_method(method) &&
         std::binary_search(allowed_methods_.begin(), allowed_methods_.end(),
                            method);
}

CorsHeaderDecision CorsPolicy::allows_request_headers(
    std::string_view value) const noexcept {
  if (value.empty()) {
    return CorsHeaderDecision::allowed;
  }
  if (value.size() > kMaximumRequestHeadersBytes) {
    return CorsHeaderDecision::malformed;
  }
  std::size_t count = 0U;
  while (!value.empty()) {
    const auto comma = value.find(',');
    auto field = value.substr(0U, comma);
    while (!field.empty() &&
           (field.front() == ' ' || field.front() == '\t')) {
      field.remove_prefix(1U);
    }
    while (!field.empty() &&
           (field.back() == ' ' || field.back() == '\t')) {
      field.remove_suffix(1U);
    }
    ++count;
    if (count > kMaximumHeaders || field.empty() ||
        field.size() > kMaximumHeaderNameBytes || !valid_http_token(field)) {
      return CorsHeaderDecision::malformed;
    }
    if (std::none_of(allowed_headers_.begin(), allowed_headers_.end(),
                     [field](const std::string& allowed) {
                       return ascii_case_equal(field, allowed);
                     })) {
      return CorsHeaderDecision::denied;
    }
    if (comma == std::string_view::npos) {
      break;
    }
    value.remove_prefix(comma + 1U);
    if (value.empty()) {
      return CorsHeaderDecision::malformed;
    }
  }
  return CorsHeaderDecision::allowed;
}

bool is_cors_response_header(std::string_view name) noexcept {
  constexpr std::string_view prefix{"access-control-"};
  if (name.size() < prefix.size()) {
    return false;
  }
  return ascii_case_equal(name.substr(0U, prefix.size()), prefix);
}

}  // namespace bonvoyage::runtime
