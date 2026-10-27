#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace bonvoyage::runtime {

/** Maximum accepted serialized JWKS size. */
inline constexpr std::size_t kMaximumJwtJwksBytes = 64U * 1024U;

/** Maximum accepted compact JWT size, excluding the Bearer scheme. */
inline constexpr std::size_t kMaximumJwtBytes = 8U * 1024U;

/** Asymmetric signature algorithms admitted by the BonVoyage JWT profile. */
enum class JwtAlgorithm {
  rs256,  ///< RSASSA-PKCS1-v1_5 using SHA-256.
  ps256,  ///< RSASSA-PSS using SHA-256 and an RFC-compliant salt length.
  es256,  ///< ECDSA using the P-256 curve and SHA-256.
};

/** One configured string claim that must exactly match the token value. */
struct JwtClaimRequirement final {
  /** Nonreserved claim name. */
  std::string name;
  /** Required string value. */
  std::string exact;
};

/** Fully validated route policy used to prepare a shard-local checker. */
struct JwtValidationPolicy final {
  /** Exact expected issuer URI. */
  std::string issuer;
  /** Required audience entry. */
  std::string audience;
  /** Exact expected JOSE `typ` value, or empty when the route omits this check. */
  std::string required_type;
  /** Explicit asymmetric signature algorithm allowlist. */
  std::vector<JwtAlgorithm> algorithms;
  /** Maximum accepted clock skew in seconds. */
  std::uint32_t clock_skew_seconds{};
  /** Maximum interval from `iat` to `exp` in seconds. */
  std::uint32_t max_token_lifetime_seconds{};
  /** Scope values that must all be present. */
  std::vector<std::string> required_scopes;
  /** Nonreserved string claims that must exactly match configured values. */
  std::vector<JwtClaimRequirement> required_claims;
};

/** Outcome classes kept deliberately independent of parser error details. */
enum class JwtAuthorizationResult {
  authorized,          ///< Signature, registered claims, and policy passed.
  invalid_token,       ///< Authentication or registered-claim validation failed.
  insufficient_scope, ///< Signature passed but route authorization failed.
};

/**
 * Immutable public verification keys compiled from one mounted JWKS document.
 *
 * The key set rejects private, symmetric, undersized, ambiguously purposed,
 * and unsupported keys before a listener is opened. Instances may be shared by
 * multiple route checkers on one shard.
 */
class JwtKeySet final {
 public:
  /** Parses and validates a bounded JWKS document or throws invalid_argument. */
  static std::shared_ptr<const JwtKeySet> compile(std::string_view jwks);

  /** Key sets cannot be copied because they own prepared provider state. */
  JwtKeySet(const JwtKeySet&) = delete;
  /** Key sets cannot be copy-assigned. */
  JwtKeySet& operator=(const JwtKeySet&) = delete;
  /** Key sets cannot be moved after validators reference them. */
  JwtKeySet(JwtKeySet&&) = delete;
  /** Key sets cannot be move-assigned. */
  JwtKeySet& operator=(JwtKeySet&&) = delete;
  /** Releases the prepared provider key set. */
  ~JwtKeySet();

 private:
  struct Impl;
  explicit JwtKeySet(std::unique_ptr<Impl> impl) noexcept;

  std::unique_ptr<Impl> impl_;

  friend class JwtValidator;
};

/**
 * Synchronous, shard-owned verifier for one route policy.
 *
 * Verification performs no network access and no cross-shard work. The object
 * is intentionally non-copyable because LibJWT checker state is reused within
 * the owning Seastar shard.
 */
class JwtValidator final {
 public:
  /** Prepares a route checker or throws invalid_argument. */
  JwtValidator(std::shared_ptr<const JwtKeySet> keys,
               JwtValidationPolicy policy);

  /** Validators cannot be copied because checker state is shard-owned. */
  JwtValidator(const JwtValidator&) = delete;
  /** Validators cannot be copy-assigned. */
  JwtValidator& operator=(const JwtValidator&) = delete;
  /** Validators cannot be moved while the shard owns their checker state. */
  JwtValidator(JwtValidator&&) = delete;
  /** Validators cannot be move-assigned. */
  JwtValidator& operator=(JwtValidator&&) = delete;
  /** Releases the prepared route checker. */
  ~JwtValidator();

  /** Authenticates and authorizes one complete Authorization field value. */
  [[nodiscard]] JwtAuthorizationResult authorize_bearer(
      std::string_view authorization) noexcept;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace bonvoyage::runtime
