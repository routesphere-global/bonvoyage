#pragma once

#include <string_view>

namespace bonvoyage::http {

/** A borrowed HTTP field consumed synchronously by parser or serializer code. */
struct HeaderView final {
  /** Field name owned by the caller for the lifetime of this view. */
  std::string_view name;

  /** Field value owned by the caller for the lifetime of this view. */
  std::string_view value;
};

}  // namespace bonvoyage::http
