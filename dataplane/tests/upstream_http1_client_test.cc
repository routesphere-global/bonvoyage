#include <string_view>

#include "bonvoyage/runtime/upstream_http1_client.hh"

int main() {
  static_assert(bonvoyage::runtime::UpstreamHttp1Client<
                bonvoyage::runtime::SelectedUpstreamHttp1Client>);
#if defined(BONVOYAGE_UPSTREAM_HTTP1_CLIENT_SEASTAR_REFERENCE)
  static_assert(bonvoyage::runtime::kSelectedUpstreamHttp1Client ==
                std::string_view{"seastar-reference"});
#elif defined(BONVOYAGE_UPSTREAM_HTTP1_CLIENT_LLHTTP_CANDIDATE)
  static_assert(bonvoyage::runtime::kSelectedUpstreamHttp1Client ==
                std::string_view{"llhttp-candidate"});
#endif
  return 0;
}
