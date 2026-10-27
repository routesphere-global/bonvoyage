#include "bonvoyage/runtime/client_identity.hh"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace bonvoyage::runtime {
namespace {

struct ParsedAddress final {
  std::array<std::uint8_t, 16U> bytes{};
  bool ipv6{};
};

[[nodiscard]] std::string_view trim_ows(std::string_view value) noexcept {
  while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
    value.remove_prefix(1U);
  }
  while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
    value.remove_suffix(1U);
  }
  return value;
}

[[nodiscard]] std::optional<ParsedAddress> parse_address(
    std::string_view value) noexcept {
  if (value.empty() || value.find('\0') != std::string_view::npos) {
    return std::nullopt;
  }
  if (value.size() >= INET6_ADDRSTRLEN) {
    return std::nullopt;
  }
  std::array<char, INET6_ADDRSTRLEN> text{};
  std::memcpy(text.data(), value.data(), value.size());
  ParsedAddress result;
  std::array<std::uint8_t, 4U> ipv4{};
  if (inet_pton(AF_INET, text.data(), ipv4.data()) == 1) {
    std::copy(ipv4.begin(), ipv4.end(), result.bytes.begin());
    return result;
  }
  if (inet_pton(AF_INET6, text.data(), result.bytes.data()) != 1) {
    return std::nullopt;
  }
  constexpr std::array<std::uint8_t, 12U> mapped_prefix{
      0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0xffU, 0xffU};
  if (std::equal(mapped_prefix.begin(), mapped_prefix.end(),
                 result.bytes.begin())) {
    std::array<std::uint8_t, 4U> mapped{};
    std::copy(result.bytes.begin() + 12, result.bytes.end(), mapped.begin());
    std::fill(result.bytes.begin() + 4, result.bytes.end(), 0U);
    std::copy(mapped.begin(), mapped.end(), result.bytes.begin());
    return result;
  }
  result.ipv6 = true;
  return result;
}

[[nodiscard]] std::string canonical_address(const ParsedAddress& address) {
  std::array<char, INET6_ADDRSTRLEN> output{};
  const auto family = address.ipv6 ? AF_INET6 : AF_INET;
  if (inet_ntop(family, address.bytes.data(), output.data(), output.size()) ==
      nullptr) {
    throw std::runtime_error("could not format a numeric client address");
  }
  return output.data();
}

[[nodiscard]] bool ascii_case_equal(std::string_view left,
                                    std::string_view right) noexcept {
  if (left.size() != right.size()) {
    return false;
  }
  for (std::size_t index = 0U; index < left.size(); ++index) {
    auto lhs = static_cast<unsigned char>(left[index]);
    auto rhs = static_cast<unsigned char>(right[index]);
    if (lhs >= 'A' && lhs <= 'Z') {
      lhs = static_cast<unsigned char>(lhs + ('a' - 'A'));
    }
    if (rhs >= 'A' && rhs <= 'Z') {
      rhs = static_cast<unsigned char>(rhs + ('a' - 'A'));
    }
    if (lhs != rhs) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] bool ascii_case_starts_with(std::string_view value,
                                          std::string_view prefix) noexcept {
  return value.size() >= prefix.size() &&
         ascii_case_equal(value.substr(0U, prefix.size()), prefix);
}

}  // namespace

TrustedProxyPolicy::TrustedProxyPolicy(
    std::span<const std::string> trusted_cidrs) {
  if (trusted_cidrs.empty() ||
      trusted_cidrs.size() > kMaximumTrustedProxyCidrs) {
    throw std::invalid_argument(
        "trusted proxy policy must contain between 1 and 64 CIDRs");
  }
  networks_.reserve(trusted_cidrs.size());
  for (const auto& raw : trusted_cidrs) {
    const auto slash = raw.find('/');
    if (slash == std::string::npos || slash == 0U ||
        slash + 1U == raw.size() || raw.find('/', slash + 1U) !=
                                           std::string::npos) {
      throw std::invalid_argument("trusted proxy CIDR is malformed");
    }
    const auto address_text = std::string_view(raw).substr(0U, slash);
    if (address_text.find(':') != std::string_view::npos &&
        address_text.find('.') != std::string_view::npos) {
      throw std::invalid_argument(
          "IPv4-mapped IPv6 trusted proxy CIDRs are not supported");
    }
    const auto address = parse_address(address_text);
    if (!address.has_value()) {
      throw std::invalid_argument(
          "trusted proxy CIDR must contain a numeric address");
    }
    unsigned int prefix = 0U;
    const auto prefix_text = std::string_view(raw).substr(slash + 1U);
    const auto [position, error] = std::from_chars(
        prefix_text.data(), prefix_text.data() + prefix_text.size(), prefix);
    const auto maximum_prefix = address->ipv6 ? 128U : 32U;
    if (error != std::errc{} ||
        position != prefix_text.data() + prefix_text.size() ||
        prefix > maximum_prefix) {
      throw std::invalid_argument("trusted proxy CIDR prefix is invalid");
    }
    Network network{address->bytes, static_cast<std::uint8_t>(prefix),
                    address->ipv6};
    const auto byte_count = network.ipv6 ? 16U : 4U;
    for (std::size_t index = 0U; index < byte_count; ++index) {
      const auto consumed_bits = static_cast<unsigned int>(index * 8U);
      const auto remaining = prefix > consumed_bits
                                 ? std::min(8U, prefix - consumed_bits)
                                 : 0U;
      const auto mask = remaining == 0U
                            ? 0U
                            : static_cast<unsigned int>(0xffU << (8U - remaining)) &
                                  0xffU;
      if ((static_cast<unsigned int>(network.bytes[index]) & ~mask) != 0U) {
        throw std::invalid_argument(
            "trusted proxy CIDR has host bits set");
      }
    }
    const auto canonical =
        canonical_address(*address) + "/" + std::to_string(prefix);
    if (raw != canonical) {
      throw std::invalid_argument(
          "trusted proxy CIDR must use canonical numeric form");
    }
    if (std::any_of(networks_.begin(), networks_.end(),
                    [&network](const Network& existing) {
                      return existing.ipv6 == network.ipv6 &&
                             existing.prefix_length == network.prefix_length &&
                             existing.bytes == network.bytes;
                    })) {
      throw std::invalid_argument("trusted proxy CIDR is duplicated");
    }
    networks_.push_back(network);
  }
}

bool TrustedProxyPolicy::contains(
    const std::array<std::uint8_t, 16U>& bytes, bool ipv6) const noexcept {
  for (const auto& network : networks_) {
    if (network.ipv6 != ipv6) {
      continue;
    }
    const auto complete_bytes =
        static_cast<std::size_t>(network.prefix_length / 8U);
    const auto remaining_bits =
        static_cast<unsigned int>(network.prefix_length % 8U);
    if (!std::equal(network.bytes.begin(),
                    network.bytes.begin() + complete_bytes, bytes.begin())) {
      continue;
    }
    if (remaining_bits != 0U) {
      const auto mask = static_cast<unsigned int>(
          0xffU << (8U - remaining_bits));
      if ((static_cast<unsigned int>(network.bytes[complete_bytes]) & mask) !=
          (static_cast<unsigned int>(bytes[complete_bytes]) & mask)) {
        continue;
      }
    }
    return true;
  }
  return false;
}

bool TrustedProxyPolicy::trusts(std::string_view address) const noexcept {
  const auto parsed = parse_address(address);
  return parsed.has_value() && contains(parsed->bytes, parsed->ipv6);
}

SourceIpPolicy::SourceIpPolicy(
    const std::span<const std::string> allow_cidrs,
    const std::span<const std::string> deny_cidrs) {
  const auto total = allow_cidrs.size() + deny_cidrs.size();
  if (total == 0U || total > kMaximumSourceIpCidrs) {
    throw std::invalid_argument(
        "source IP policy must contain between 1 and 64 total CIDRs");
  }
  try {
    if (!allow_cidrs.empty()) {
      allow_.emplace(allow_cidrs);
    }
  } catch (const std::invalid_argument&) {
    throw std::invalid_argument(
        "source IP allow list contains an invalid or duplicate CIDR");
  }
  try {
    if (!deny_cidrs.empty()) {
      deny_.emplace(deny_cidrs);
    }
  } catch (const std::invalid_argument&) {
    throw std::invalid_argument(
        "source IP deny list contains an invalid or duplicate CIDR");
  }
  if (allow_.has_value() && deny_.has_value()) {
    for (const auto& allowed : allow_->networks_) {
      const auto duplicated =
          std::any_of(deny_->networks_.begin(), deny_->networks_.end(),
                      [&allowed](const TrustedProxyPolicy::Network& denied) {
                        return allowed.ipv6 == denied.ipv6 &&
                               allowed.prefix_length == denied.prefix_length &&
                               allowed.bytes == denied.bytes;
                      });
      if (duplicated) {
        throw std::invalid_argument(
            "source IP CIDR cannot appear in both allow and deny lists");
      }
    }
  }
}

bool SourceIpPolicy::allows(std::string_view address) const noexcept {
  const auto parsed = parse_address(address);
  if (!parsed.has_value()) {
    return false;
  }
  if (deny_.has_value() &&
      deny_->contains(parsed->bytes, parsed->ipv6)) {
    return false;
  }
  return !allow_.has_value() ||
         allow_->contains(parsed->bytes, parsed->ipv6);
}

ClientAddressResolver::ClientAddressResolver(
    const TrustedProxyPolicy* policy, std::string direct_peer_address)
    : policy_(policy),
      direct_peer_address_(std::move(direct_peer_address)),
      direct_peer_is_trusted_(policy_ != nullptr &&
                              policy_->trusts(direct_peer_address_)) {}

ClientAddressResolution ClientAddressResolver::resolve(
    std::span<const std::string_view> forwarded_for_fields) const {
  if (!direct_peer_is_trusted_ || forwarded_for_fields.empty()) {
    return ClientAddressResolution{ClientAddressSource::direct_peer, {}, 0U};
  }

  std::array<ParsedAddress, kMaximumForwardedForHops> addresses{};
  std::size_t count = 0U;
  std::size_t logical_bytes = 0U;
  for (std::size_t field_index = 0U;
       field_index < forwarded_for_fields.size(); ++field_index) {
    const auto raw = forwarded_for_fields[field_index];
    if (field_index != 0U) {
      if (logical_bytes == kMaximumForwardedForBytes) {
        return ClientAddressResolution{
            ClientAddressSource::invalid_forwarded_for, {}, count};
      }
      ++logical_bytes;
    }
    if (raw.empty() || raw.size() > kMaximumForwardedForBytes - logical_bytes) {
      return ClientAddressResolution{
          ClientAddressSource::invalid_forwarded_for, {}, count};
    }
    logical_bytes += raw.size();

    std::size_t offset = 0U;
    while (offset <= raw.size()) {
      const auto comma = raw.find(',', offset);
      const auto end = comma == std::string_view::npos ? raw.size() : comma;
      const auto token = trim_ows(raw.substr(offset, end - offset));
      if (token.empty() || count == addresses.size()) {
        return ClientAddressResolution{
            ClientAddressSource::invalid_forwarded_for, {}, count};
      }
      const auto parsed = parse_address(token);
      if (!parsed.has_value()) {
        return ClientAddressResolution{
            ClientAddressSource::invalid_forwarded_for, {}, count};
      }
      addresses[count++] = *parsed;
      if (comma == std::string_view::npos) {
        break;
      }
      offset = comma + 1U;
    }
  }

  ParsedAddress selected = addresses.front();
  for (std::size_t index = count; index > 0U; --index) {
    selected = addresses[index - 1U];
    if (!policy_->contains(selected.bytes, selected.ipv6)) {
      break;
    }
  }
  return ClientAddressResolution{ClientAddressSource::trusted_forwarded_for,
                                 canonical_address(selected), count};
}

bool is_forwarded_identity_header(std::string_view name) noexcept {
  return ascii_case_equal(name, "forwarded") ||
         ascii_case_starts_with(name, "x-forwarded-") ||
         ascii_case_equal(name, "x-real-ip") ||
         ascii_case_equal(name, "true-client-ip") ||
         ascii_case_equal(name, "client-ip") ||
         ascii_case_equal(name, "cf-connecting-ip");
}

}  // namespace bonvoyage::runtime
