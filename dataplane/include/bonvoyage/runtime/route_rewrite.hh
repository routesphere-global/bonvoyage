#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace bonvoyage::runtime {

/** Supported immutable upstream path rewrite operations. */
enum class PathRewriteOperation {
  replace,         ///< Replace the complete downstream path.
  replace_prefix,  ///< Replace only the matched route prefix.
};

/** One prevalidated path rewrite owned by an immutable runtime snapshot. */
struct PathRewrite final {
  /** Prepared operation selected by the route contract. */
  PathRewriteOperation operation{PathRewriteOperation::replace};

  /** Static replacement path without a query component. */
  std::string value;
};

/** Prevalidated upstream authority and path rewrites for one route. */
struct RouteRewrite final {
  /** Prepared Host authority, including an optional port. */
  std::optional<std::string> authority;

  /** Optional static path or matched-prefix replacement. */
  std::optional<PathRewrite> path;
};

/**
 * Rewrites an origin-form request target while preserving its raw query.
 *
 * The returned value is absent when the rewritten target exceeds
 * max_target_bytes. A prefix rewrite throws std::invalid_argument only when
 * the caller violates the prevalidated route-prefix invariant.
 */
[[nodiscard]] std::optional<std::string> rewrite_request_target(
    std::string_view original_target, std::string_view matched_prefix,
    const PathRewrite& rewrite, std::size_t max_target_bytes);

}  // namespace bonvoyage::runtime
