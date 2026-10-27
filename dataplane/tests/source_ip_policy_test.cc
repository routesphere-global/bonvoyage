#include "bonvoyage/runtime/client_identity.hh"

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using bonvoyage::runtime::SourceIpPolicy;

void require(bool condition, const char* message) {
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

void require_invalid(const std::vector<std::string>& allow,
                     const std::vector<std::string>& deny,
                     const char* message) {
  try {
    (void)SourceIpPolicy(allow, deny);
  } catch (const std::invalid_argument&) {
    return;
  }
  require(false, message);
}

}  // namespace

int main() {
  const std::vector<std::string> allow_only_cidrs{
      "198.51.100.0/24", "2001:db8::/32"};
  const SourceIpPolicy allow_only(allow_only_cidrs,
                                  std::vector<std::string>{});
  require(allow_only.allow_size() == 2U && allow_only.deny_size() == 0U,
          "allow-only policy count changed");
  require(allow_only.allows("198.51.100.17"),
          "allowed IPv4 address was rejected");
  require(allow_only.allows("2001:db8:1::17"),
          "allowed IPv6 address was rejected");
  require(allow_only.allows("::ffff:198.51.100.17"),
          "IPv4-mapped client address was not normalized");
  require(!allow_only.allows("203.0.113.17"),
          "allow-list miss was admitted");

  const std::vector<std::string> deny_only_cidrs{"203.0.113.0/24"};
  const SourceIpPolicy deny_only(std::vector<std::string>{},
                                 deny_only_cidrs);
  require(deny_only.allow_size() == 0U && deny_only.deny_size() == 1U,
          "deny-only policy count changed");
  require(!deny_only.allows("203.0.113.17"),
          "denied client address was admitted");
  require(deny_only.allows("198.51.100.17"),
          "deny-only policy did not default to allow");

  const std::vector<std::string> broad_ipv4_allow{"198.51.100.0/24"};
  const std::vector<std::string> narrow_ipv4_deny{"198.51.100.128/25"};
  const SourceIpPolicy deny_precedence(broad_ipv4_allow, narrow_ipv4_deny);
  require(deny_precedence.allows("198.51.100.127"),
          "broad allow did not admit an address outside the deny subnet");
  require(!deny_precedence.allows("198.51.100.128"),
          "narrow deny did not take precedence over broad allow");

  const std::vector<std::string> broad_ipv6_allow{"2001:db8:1::/48"};
  const std::vector<std::string> narrow_ipv6_deny{
      "2001:db8:1:dead::/64"};
  const SourceIpPolicy ipv6_precedence(broad_ipv6_allow, narrow_ipv6_deny);
  require(ipv6_precedence.allows("2001:db8:1:beef::1"),
          "IPv6 allow network was not matched");
  require(!ipv6_precedence.allows("2001:db8:1:dead::1"),
          "IPv6 deny network did not take precedence");
  require(!ipv6_precedence.allows("not-an-address"),
          "malformed effective client address did not fail closed");

  require_invalid({}, {}, "empty source IP policy was accepted");
  require_invalid({"198.51.100.1/24"}, {},
                  "source IP CIDR host bits were accepted");
  require_invalid({"2001:0db8::/32"}, {},
                  "non-canonical source IP CIDR was accepted");
  require_invalid({"client.example/24"}, {},
                  "source IP CIDR hostname was accepted");
  require_invalid({"::ffff:198.51.100.0/120"}, {},
                  "IPv4-mapped source IP CIDR was accepted");
  require_invalid({"198.51.100.0/24", "198.51.100.0/24"}, {},
                  "duplicate source IP allow CIDR was accepted");
  require_invalid({"198.51.100.0/24"}, {"198.51.100.0/24"},
                  "source IP CIDR present in both lists was accepted");

  std::vector<std::string> oversized;
  oversized.reserve(bonvoyage::runtime::kMaximumSourceIpCidrs + 1U);
  for (std::size_t index = 0U;
       index < bonvoyage::runtime::kMaximumSourceIpCidrs + 1U; ++index) {
    oversized.push_back("198.51.100." + std::to_string(index) + "/32");
  }
  require_invalid(oversized, {}, "oversized source IP policy was accepted");

  return 0;
}
