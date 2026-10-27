#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string_view>

#include "bonvoyage/runtime/route_rewrite.hh"

namespace {

using bonvoyage::runtime::PathRewrite;
using bonvoyage::runtime::PathRewriteOperation;

void require(bool condition, const char* message) {
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

}  // namespace

int main() {
  const PathRewrite replace{PathRewriteOperation::replace,
                            "/internal/catalog"};
  const auto replaced = bonvoyage::runtime::rewrite_request_target(
      "/catalog?view=%2Fraw&empty=", {}, replace, 4096U);
  require(replaced == "/internal/catalog?view=%2Fraw&empty=",
          "full replacement did not preserve the raw query");

  const PathRewrite prefix{PathRewriteOperation::replace_prefix, "/v2/"};
  const auto prefixed = bonvoyage::runtime::rewrite_request_target(
      "/legacy/orders/%7Eopen?cursor=a%2Fb", "/legacy/", prefix, 4096U);
  require(prefixed == "/v2/orders/%7Eopen?cursor=a%2Fb",
          "prefix replacement changed the suffix or raw query");

  const auto exact_prefix = bonvoyage::runtime::rewrite_request_target(
      "/legacy/?q=1", "/legacy/", prefix, 4096U);
  require(exact_prefix == "/v2/?q=1",
          "exact-prefix replacement produced an incorrect path");

  require(!bonvoyage::runtime::rewrite_request_target(
               "/catalog?query=too-long", {}, replace, 20U)
               .has_value(),
          "an oversized rewritten target was accepted");

  bool mismatch_rejected = false;
  try {
    (void)bonvoyage::runtime::rewrite_request_target(
        "/other/path", "/legacy/", prefix, 4096U);
  } catch (const std::invalid_argument&) {
    mismatch_rejected = true;
  }
  require(mismatch_rejected,
          "a violated prepared-prefix invariant was not rejected");

  std::cout << "route rewrites passed\n";
  return 0;
}
