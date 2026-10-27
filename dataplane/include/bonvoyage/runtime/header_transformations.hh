#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace bonvoyage::runtime {

/** Supported immutable route header-mutation operations. */
enum class HeaderMutationOperation {
  set,     ///< Replace every existing field instance with one configured value.
  append,  ///< Add one comma-delimited value to a combinable field.
  remove   ///< Remove every existing field instance.
};

/** One snapshot-prepared mutation of a lowercase end-to-end field. */
struct HeaderMutation final {
  /** Operation applied after protocol and security sanitation. */
  HeaderMutationOperation operation{HeaderMutationOperation::remove};

  /** Canonical lowercase field name. */
  std::string name;

  /** Static configured value; empty only for remove. */
  std::string value;
};

/** Route-local request and response mutation plans. */
struct HeaderTransformations final {
  /** Mutations applied to the sanitized upstream request. */
  std::vector<HeaderMutation> request;

  /** Mutations applied to the sanitized downstream response. */
  std::vector<HeaderMutation> response;
};

/** Owned protocol-neutral field used only on configured mutation paths. */
using MutableHeader = std::pair<std::string, std::string>;

/**
 * Applies a prepared mutation list and verifies the resulting decoded size.
 *
 * The caller retains the mutated fields when true is returned. False means
 * the resulting name, value, and HTTP/1 delimiter bytes exceeded max_bytes;
 * callers must reject the request or response without serializing the list.
 */
[[nodiscard]] bool apply_header_mutations(
    std::vector<MutableHeader>& headers,
    std::span<const HeaderMutation> mutations,
    std::size_t max_bytes);

}  // namespace bonvoyage::runtime
