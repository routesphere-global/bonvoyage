#include "bonvoyage/runtime/client_identity.hh"

#include <cstdlib>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using bonvoyage::runtime::ClientAddressResolver;
using bonvoyage::runtime::ClientAddressSource;
using bonvoyage::runtime::TrustedProxyPolicy;
using bonvoyage::runtime::is_forwarded_identity_header;

void require(bool condition, const char* message) {
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

void require_invalid(const std::vector<std::string>& networks,
                     const char* message) {
  bool rejected = false;
  try {
    (void)TrustedProxyPolicy(networks);
  } catch (const std::invalid_argument&) {
    rejected = true;
  }
  require(rejected, message);
}

bonvoyage::runtime::ClientAddressResolution resolve_one(
    const ClientAddressResolver& resolver,
    std::optional<std::string_view> value) {
  if (!value.has_value()) {
    return resolver.resolve(std::span<const std::string_view>{});
  }
  const std::array fields{*value};
  return resolver.resolve(fields);
}

}  // namespace

int main() {
  const std::vector<std::string> networks{
      "10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"};
  const TrustedProxyPolicy policy(networks);
  require(policy.size() == 3U, "trusted network count changed");
  require(policy.trusts("10.4.5.6"), "trusted IPv4 peer was rejected");
  require(policy.trusts("2001:db8::7"), "trusted IPv6 peer was rejected");
  require(!policy.trusts("198.51.100.7"), "untrusted peer was accepted");
  require(policy.trusts("::ffff:10.4.5.6"),
          "IPv4-mapped socket peer was not normalized");

  const ClientAddressResolver untrusted(&policy, "198.51.100.7");
  auto result = resolve_one(untrusted, "not-an-address");
  require(result.source == ClientAddressSource::direct_peer &&
              result.address.empty() &&
              untrusted.direct_peer_address() == "198.51.100.7",
          "untrusted peer influenced client identity");

  const ClientAddressResolver trusted(&policy, "10.0.0.3");
  result = resolve_one(trusted, std::nullopt);
  require(result.source == ClientAddressSource::direct_peer &&
              result.address.empty() &&
              trusted.direct_peer_address() == "10.0.0.3",
          "absent forwarding field did not use the direct peer");

  result = resolve_one(trusted, "198.51.100.9, 192.168.1.2");
  require(result.source == ClientAddressSource::trusted_forwarded_for &&
              result.address == "198.51.100.9" &&
              result.forwarded_hops == 2U,
          "trusted proxy chain did not select the first untrusted hop");

  result = resolve_one(trusted, "203.0.113.77, 198.51.100.9");
  require(result.address == "198.51.100.9",
          "spoofed leftmost address bypassed right-to-left trust");

  result = resolve_one(trusted, "192.168.1.9, 10.1.1.1");
  require(result.address == "192.168.1.9",
          "all-trusted chain did not select its leftmost address");

  const ClientAddressResolver trusted_ipv6(&policy, "2001:db8::1");
  result = resolve_one(trusted_ipv6, "2001:db9::7, 2001:db8::2");
  require(result.address == "2001:db9::7",
          "IPv6 chain did not resolve correctly");

  for (const auto invalid : {std::string_view{}, std::string_view{"unknown"},
                             std::string_view{"198.51.100.1,"},
                             std::string_view{"198.51.100.1:443"}}) {
    result = resolve_one(trusted, invalid);
    require(result.source == ClientAddressSource::invalid_forwarded_for,
            "malformed trusted forwarding field was accepted");
  }
  const std::array repeated_fields{std::string_view{"198.51.100.1"},
                                   std::string_view{"10.1.1.1"}};
  result = trusted.resolve(repeated_fields);
  require(result.source == ClientAddressSource::trusted_forwarded_for &&
              result.address == "198.51.100.1" &&
              result.forwarded_hops == 2U,
          "repeated forwarding fields were not normalized in wire order");

  std::string too_many;
  for (std::size_t index = 0U;
       index < bonvoyage::runtime::kMaximumForwardedForHops + 1U; ++index) {
    if (!too_many.empty()) {
      too_many += ',';
    }
    too_many += "10.0.0.1";
  }
  result = resolve_one(trusted, too_many);
  require(result.source == ClientAddressSource::invalid_forwarded_for,
          "overlong forwarding chain was accepted");

  const std::string oversized(
      bonvoyage::runtime::kMaximumForwardedForBytes + 1U, '1');
  result = resolve_one(trusted, oversized);
  require(result.source == ClientAddressSource::invalid_forwarded_for,
          "oversized forwarding chain was accepted");

  require_invalid({}, "empty trusted policy was accepted");
  require_invalid({"10.0.0.1/8"}, "CIDR host bits were accepted");
  require_invalid({"proxy.example/24"}, "CIDR hostname was accepted");
  require_invalid({"::ffff:10.0.0.0/104"},
                  "IPv4-mapped CIDR was accepted");
  require_invalid({"10.0.0.0/8", "10.0.0.0/8"},
                  "duplicate CIDR was accepted");

  require(is_forwarded_identity_header("Forwarded"),
          "Forwarded was not sanitized");
  require(is_forwarded_identity_header("X-Forwarded-Custom"),
          "X-Forwarded-* was not sanitized");
  require(is_forwarded_identity_header("x-real-ip"),
          "X-Real-IP was not sanitized");
  require(is_forwarded_identity_header("CF-Connecting-IP"),
          "vendor client identity was not sanitized");
  require(!is_forwarded_identity_header("X-Request-ID"),
          "unrelated request header was sanitized");

  return 0;
}
