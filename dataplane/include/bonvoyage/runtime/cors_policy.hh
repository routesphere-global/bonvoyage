#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace bonvoyage::runtime {

/** Result of validating Access-Control-Request-Headers against one policy. */
enum class CorsHeaderDecision {
  allowed,    ///< Every requested field is syntactically valid and allowed.
  malformed,  ///< The field list is invalid or exceeds its fixed bounds.
  denied      ///< At least one valid field name is outside the allowlist.
};

/** Immutable route-level browser cross-origin policy. */
class CorsPolicy final {
 public:
  /** Validates and prepares one policy or throws std::invalid_argument. */
  CorsPolicy(bool allow_any_origin, std::vector<std::string> allowed_origins,
             std::vector<std::string> allowed_methods,
             std::vector<std::string> allowed_headers,
             std::vector<std::string> exposed_headers,
             bool allow_credentials, std::uint32_t max_age_seconds);

  /** Returns whether one canonical serialized origin is allowed. */
  [[nodiscard]] bool allows_origin(std::string_view origin) const noexcept;

  /**
   * Returns the allowed response origin, or nullopt for a denied origin.
   * Exact matches borrow immutable policy storage, never the request buffer;
   * keep this policy alive and unmoved until response serialization completes.
   * Wildcard matches reference the static "*" literal.
   */
  [[nodiscard]] std::optional<std::string_view> response_origin(
      std::string_view origin) const noexcept;

  /** Returns whether one uppercase HTTP method is allowed. */
  [[nodiscard]] bool allows_method(std::string_view method) const noexcept;

  /** Validates one comma-delimited preflight request-header field. */
  [[nodiscard]] CorsHeaderDecision allows_request_headers(
      std::string_view value) const noexcept;

  /** Returns whether a non-credential wildcard origin is emitted. */
  [[nodiscard]] bool allow_any_origin() const noexcept {
    return allow_any_origin_;
  }

  /** Returns whether browser credentials are permitted. */
  [[nodiscard]] bool allow_credentials() const noexcept {
    return allow_credentials_;
  }

  /** Returns the bounded browser preflight cache lifetime. */
  [[nodiscard]] std::uint32_t max_age_seconds() const noexcept {
    return max_age_seconds_;
  }

  /** Returns the preformatted Access-Control-Max-Age value. */
  [[nodiscard]] const std::string& max_age_value() const noexcept {
    return max_age_value_;
  }

  /** Returns the prejoined Access-Control-Allow-Methods value. */
  [[nodiscard]] const std::string& allowed_methods_value() const noexcept {
    return allowed_methods_value_;
  }

  /** Returns the prejoined Access-Control-Allow-Headers value. */
  [[nodiscard]] const std::string& allowed_headers_value() const noexcept {
    return allowed_headers_value_;
  }

  /** Returns the prejoined Access-Control-Expose-Headers value. */
  [[nodiscard]] const std::string& exposed_headers_value() const noexcept {
    return exposed_headers_value_;
  }

 private:
  bool allow_any_origin_{};
  bool allow_credentials_{};
  std::uint32_t max_age_seconds_{};
  std::vector<std::string> allowed_origins_;
  std::vector<std::string> allowed_methods_;
  std::vector<std::string> allowed_headers_;
  std::string allowed_methods_value_;
  std::string allowed_headers_value_;
  std::string exposed_headers_value_;
  std::string max_age_value_;
};

/** Returns whether a response field belongs to the CORS policy surface. */
[[nodiscard]] bool is_cors_response_header(std::string_view name) noexcept;

/** Returns whether a value is a canonical supported serialized origin. */
[[nodiscard]] bool is_canonical_cors_origin(std::string_view origin) noexcept;

/** Returns whether a value is a canonical uppercase HTTP method token. */
[[nodiscard]] bool is_canonical_cors_method(std::string_view method) noexcept;

}  // namespace bonvoyage::runtime
