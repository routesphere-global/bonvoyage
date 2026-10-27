#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace bonvoyage::runtime {

/** Result of applying one prepared route Content-Type allowlist. */
enum class RequestContentTypeDecision {
  allowed,      ///< The field is absent when optional or matches the allowlist.
  required,     ///< A body-capable request omitted Content-Type.
  malformed,    ///< Content-Type is repeated or violates RFC 9110 syntax.
  unsupported,  ///< The parsed base media type is outside the allowlist.
  too_large     ///< The field exceeds the bounded parser input size.
};

/**
 * Immutable route request-content policy prepared before listener startup.
 *
 * Media-type evaluation performs no allocation. Configured values are sorted
 * canonical lowercase base media types without parameters or wildcards.
 */
class RequestContentPolicy final {
 public:
  /** Validates and prepares one non-empty policy. */
  RequestContentPolicy(
      std::optional<std::uint64_t> maximum_body_bytes,
      std::vector<std::string> allowed_content_types);

  /** Returns the optional route ceiling below the snapshot-wide body limit. */
  [[nodiscard]] std::optional<std::uint64_t> maximum_body_bytes() const
      noexcept {
    return maximum_body_bytes_;
  }

  /** Returns whether this policy constrains the Content-Type field. */
  [[nodiscard]] bool constrains_content_type() const noexcept {
    return !allowed_content_types_.empty();
  }

  /** Returns canonical configured media types for diagnostics and tests. */
  [[nodiscard]] const std::vector<std::string>& allowed_content_types() const
      noexcept {
    return allowed_content_types_;
  }

  /** Returns the prepared Accept response-field value for a 415 response. */
  [[nodiscard]] const std::string& accept_header_value() const noexcept {
    return accept_header_value_;
  }

  /**
   * Parses and evaluates one protocol-normalized Content-Type lookup.
   *
   * Parameters are syntax-checked and ignored for base media-type matching.
   */
  [[nodiscard]] RequestContentTypeDecision evaluate_content_type(
      std::string_view value, bool present, bool repeated,
      bool body_capable) const noexcept;

 private:
  std::optional<std::uint64_t> maximum_body_bytes_;
  std::vector<std::string> allowed_content_types_;
  std::string accept_header_value_;
};

}  // namespace bonvoyage::runtime
