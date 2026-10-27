#pragma once

#include <string_view>

namespace bonvoyage::http {

/** Result of an allocation-free lookup in one parsed request header block. */
struct RequestHeaderLookupResult final {
  /** First matching field value, borrowed from the parsed request. */
  std::string_view value;

  /** Whether at least one field with the requested name was present. */
  bool present{false};

  /** Whether multiple fields with the requested name were present. */
  bool repeated{false};
};

}  // namespace bonvoyage::http
