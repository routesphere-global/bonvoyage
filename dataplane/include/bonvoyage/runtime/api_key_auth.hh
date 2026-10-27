#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bonvoyage::runtime {

/** Minimum accepted API-key length in bytes. */
inline constexpr std::size_t kMinimumApiKeyBytes = 16U;

/** Maximum accepted API-key length in bytes. */
inline constexpr std::size_t kMaximumApiKeyBytes = 128U;

/** Maximum credentials loaded from one static secret file. */
inline constexpr std::size_t kMaximumApiKeyCredentials = 64U;

/** Maximum bytes read from one static API-key secret file. */
inline constexpr std::uint64_t kMaximumApiKeySecretBytes = 16U * 1024U;

/** Process-local key used to derive nonreversible in-memory credential tags. */
using ApiKeyPepper = std::array<std::uint8_t, 32U>;

/** Generates a cryptographically strong process-local HMAC key. */
[[nodiscard]] ApiKeyPepper generate_api_key_pepper();

/** Erases a temporary plaintext secret buffer with a nonoptimizable primitive. */
void secure_erase(std::string& value) noexcept;

/** Erases a mutable plaintext byte range with a nonoptimizable primitive. */
void secure_erase(std::span<char> value) noexcept;

/** Erases a temporary process-local HMAC key. */
void secure_erase(ApiKeyPepper& value) noexcept;

/**
 * Bounded static API-key table prepared for one data-plane shard.
 *
 * Secret files contain one key per line. Plaintext values are converted to
 * process-local HMAC-SHA-256 tags during startup and are never retained here.
 */
class ApiKeyCredentialSet final {
 public:
  /** Credential tables cannot be copied because they own sensitive state. */
  ApiKeyCredentialSet(const ApiKeyCredentialSet&) = delete;
  /** Credential tables cannot be copy-assigned. */
  ApiKeyCredentialSet& operator=(const ApiKeyCredentialSet&) = delete;
  /** Transfers one credential table and erases the moved-from state. */
  ApiKeyCredentialSet(ApiKeyCredentialSet&& other) noexcept;
  /** Replaces this table and erases both prior and moved-from state. */
  ApiKeyCredentialSet& operator=(ApiKeyCredentialSet&& other) noexcept;
  /** Erases the HMAC pepper and prepared tags before releasing storage. */
  ~ApiKeyCredentialSet() noexcept;

  /** Parses and prepares a strict credential file or throws invalid_argument. */
  [[nodiscard]] static ApiKeyCredentialSet compile(
      std::string_view secret_bytes, const ApiKeyPepper& pepper);

  /** Validates one complete header value using a full constant-time tag scan. */
  [[nodiscard]] bool authorizes(std::string_view candidate) const noexcept;

  /** Returns the bounded number of loaded credentials. */
  [[nodiscard]] std::size_t size() const noexcept { return tags_.size(); }

 private:
  using Tag = std::array<std::uint8_t, 32U>;

  ApiKeyCredentialSet() = default;
  void erase() noexcept;

  ApiKeyPepper pepper_{};
  std::vector<Tag> tags_;
};

}  // namespace bonvoyage::runtime
