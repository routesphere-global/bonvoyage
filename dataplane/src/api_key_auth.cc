#include "bonvoyage/runtime/api_key_auth.hh"

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace bonvoyage::runtime {
namespace {

using ApiKeyTag = std::array<std::uint8_t, 32U>;

bool valid_api_key(std::string_view value) noexcept {
  if (value.size() < kMinimumApiKeyBytes ||
      value.size() > kMaximumApiKeyBytes) {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [](const char character) {
    const auto byte = static_cast<unsigned char>(character);
    // A comma is excluded so repeated HTTP/1 field lines cannot become one
    // syntactically valid credential after list-field normalization.
    return byte >= 0x21U && byte <= 0x7eU && character != ',';
  });
}

ApiKeyTag derive_tag(std::string_view value,
                     const ApiKeyPepper& pepper) {
  ApiKeyTag tag{};
  const auto status = gnutls_hmac_fast(
      GNUTLS_MAC_SHA256, pepper.data(), pepper.size(), value.data(),
      value.size(), tag.data());
  if (status < 0) {
    throw std::runtime_error(std::string("HMAC-SHA-256 failed: ") +
                             gnutls_strerror(status));
  }
  return tag;
}

bool constant_time_equal(const ApiKeyTag& left,
                         const ApiKeyTag& right) noexcept {
  return gnutls_memcmp(left.data(), right.data(), left.size()) == 0;
}

}  // namespace

ApiKeyPepper generate_api_key_pepper() {
  ApiKeyPepper pepper{};
  const auto status =
      gnutls_rnd(GNUTLS_RND_KEY, pepper.data(), pepper.size());
  if (status < 0) {
    throw std::runtime_error(std::string("API-key pepper generation failed: ") +
                             gnutls_strerror(status));
  }
  return pepper;
}

void secure_erase(std::string& value) noexcept {
  secure_erase(std::span<char>{value.data(), value.size()});
  value.clear();
}

void secure_erase(std::span<char> value) noexcept {
  if (!value.empty()) {
    gnutls_memset(value.data(), 0, value.size());
  }
}

void secure_erase(ApiKeyPepper& value) noexcept {
  gnutls_memset(value.data(), 0, value.size());
}

ApiKeyCredentialSet::ApiKeyCredentialSet(
    ApiKeyCredentialSet&& other) noexcept
    : pepper_(other.pepper_), tags_(std::move(other.tags_)) {
  other.erase();
}

ApiKeyCredentialSet& ApiKeyCredentialSet::operator=(
    ApiKeyCredentialSet&& other) noexcept {
  if (this != &other) {
    erase();
    pepper_ = other.pepper_;
    tags_ = std::move(other.tags_);
    other.erase();
  }
  return *this;
}

ApiKeyCredentialSet::~ApiKeyCredentialSet() noexcept { erase(); }

void ApiKeyCredentialSet::erase() noexcept {
  secure_erase(pepper_);
  for (auto& tag : tags_) {
    gnutls_memset(tag.data(), 0, tag.size());
  }
  tags_.clear();
}

ApiKeyCredentialSet ApiKeyCredentialSet::compile(
    std::string_view secret_bytes, const ApiKeyPepper& pepper) {
  if (secret_bytes.empty() ||
      secret_bytes.size() > kMaximumApiKeySecretBytes) {
    throw std::invalid_argument(
        "API-key secret must contain between 1 byte and 16 KiB");
  }

  ApiKeyCredentialSet result;
  result.pepper_ = pepper;
  std::size_t cursor = 0U;
  std::size_t line_number = 1U;
  while (cursor < secret_bytes.size()) {
    const auto newline = secret_bytes.find('\n', cursor);
    const auto end = newline == std::string_view::npos
                         ? secret_bytes.size()
                         : newline;
    auto key = secret_bytes.substr(cursor, end - cursor);
    if (!key.empty() && key.back() == '\r') {
      key.remove_suffix(1U);
    }
    if (!valid_api_key(key)) {
      throw std::invalid_argument(
          "API-key secret line " + std::to_string(line_number) +
          " must contain 16-128 visible ASCII bytes without commas or whitespace");
    }
    if (result.tags_.size() >= kMaximumApiKeyCredentials) {
      throw std::invalid_argument(
          "API-key secret must not contain more than 64 credentials");
    }
    auto tag = derive_tag(key, pepper);
    const auto duplicate = std::any_of(
        result.tags_.begin(), result.tags_.end(), [&tag](const auto& existing) {
          return constant_time_equal(existing, tag);
        });
    if (duplicate) {
      throw std::invalid_argument("API-key secret contains a duplicate credential");
    }
    result.tags_.push_back(tag);

    if (newline == std::string_view::npos) {
      break;
    }
    cursor = newline + 1U;
    ++line_number;
  }
  return result;
}

bool ApiKeyCredentialSet::authorizes(
    std::string_view candidate) const noexcept {
  if (!valid_api_key(candidate)) {
    return false;
  }
  Tag candidate_tag{};
  const auto status = gnutls_hmac_fast(
      GNUTLS_MAC_SHA256, pepper_.data(), pepper_.size(), candidate.data(),
      candidate.size(), candidate_tag.data());
  if (status < 0) {
    return false;
  }

  unsigned int matched = 0U;
  for (const auto& tag : tags_) {
    matched |= static_cast<unsigned int>(
        gnutls_memcmp(tag.data(), candidate_tag.data(), tag.size()) == 0);
  }
  gnutls_memset(candidate_tag.data(), 0, candidate_tag.size());
  return matched != 0U;
}

}  // namespace bonvoyage::runtime
