#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bonvoyage::runtime {

/** Maximum trusted networks accepted by one listener. */
inline constexpr std::size_t kMaximumTrustedProxyCidrs = 64U;

/** Maximum combined allow and deny networks accepted by one route. */
inline constexpr std::size_t kMaximumSourceIpCidrs = 64U;

/** Maximum addresses accepted from one X-Forwarded-For field. */
inline constexpr std::size_t kMaximumForwardedForHops = 32U;

/** Maximum bytes parsed from one X-Forwarded-For field. */
inline constexpr std::size_t kMaximumForwardedForBytes = 2048U;

/** Origin and validation result for one effective client address. */
enum class ClientAddressSource {
  direct_peer,            ///< The connected socket peer is authoritative.
  trusted_forwarded_for,  ///< A trusted peer supplied a valid proxy chain.
  invalid_forwarded_for   ///< A trusted peer supplied an invalid chain.
};

/** Effective client address selected at the downstream trust boundary. */
struct ClientAddressResolution final {
  /** Resolution outcome. */
  ClientAddressSource source{ClientAddressSource::direct_peer};

  /** Canonical forwarded address; empty for direct peers and invalid chains. */
  std::string address;

  /** Number of parsed X-Forwarded-For entries. */
  std::size_t forwarded_hops{};
};

/** Precompiled numeric networks trusted to provide client identity. */
class TrustedProxyPolicy final {
 public:
  /**
   * Compiles canonical IPv4 and IPv6 CIDRs.
   *
   * Throws std::invalid_argument for an empty, duplicate, malformed,
   * non-network, or oversized policy.
   */
  explicit TrustedProxyPolicy(std::span<const std::string> trusted_cidrs);

  /** Returns whether one numeric socket peer belongs to a trusted network. */
  [[nodiscard]] bool trusts(std::string_view address) const noexcept;

  /** Returns the number of precompiled trusted networks. */
  [[nodiscard]] std::size_t size() const noexcept { return networks_.size(); }

 private:
  struct Network final {
    std::array<std::uint8_t, 16U> bytes{};
    std::uint8_t prefix_length{};
    bool ipv6{};
  };

  [[nodiscard]] bool contains(
      const std::array<std::uint8_t, 16U>& bytes,
      bool ipv6) const noexcept;

  std::vector<Network> networks_;

  friend class ClientAddressResolver;
  friend class SourceIpPolicy;
};

/** Bounded route policy evaluated against the canonical client address. */
class SourceIpPolicy final {
 public:
  /**
   * Compiles canonical IPv4 and IPv6 allow and deny CIDRs.
   *
   * At least one list must be non-empty, the combined count cannot exceed 64,
   * and the same network cannot appear in both lists. Deny matches take
   * precedence. Throws std::invalid_argument for an invalid policy.
   */
  SourceIpPolicy(std::span<const std::string> allow_cidrs,
                 std::span<const std::string> deny_cidrs);

  /** Returns whether one canonical effective client address is permitted. */
  [[nodiscard]] bool allows(std::string_view address) const noexcept;

  /** Returns the number of configured allow networks. */
  [[nodiscard]] std::size_t allow_size() const noexcept {
    return allow_ == std::nullopt ? 0U : allow_->size();
  }

  /** Returns the number of configured deny networks. */
  [[nodiscard]] std::size_t deny_size() const noexcept {
    return deny_ == std::nullopt ? 0U : deny_->size();
  }

 private:
  std::optional<TrustedProxyPolicy> allow_;
  std::optional<TrustedProxyPolicy> deny_;
};

/** Per-connection resolver that caches direct-peer trust. */
class ClientAddressResolver final {
 public:
  /** Binds an optional immutable policy to one canonical socket peer. */
  ClientAddressResolver(const TrustedProxyPolicy* policy,
                        std::string direct_peer_address);

  /**
   * Resolves one request's strict logical X-Forwarded-For chain.
   *
   * Field lines are consumed in wire order as one comma-separated chain.
   * Untrusted peers and absent fields always resolve to the direct peer.
   * Malformed, oversized, or overlong chains from a trusted peer return
   * invalid_forwarded_for.
   */
  [[nodiscard]] ClientAddressResolution resolve(
      std::span<const std::string_view> forwarded_for_fields) const;

  /** Returns whether the connected peer matched the listener policy. */
  [[nodiscard]] bool direct_peer_is_trusted() const noexcept {
    return direct_peer_is_trusted_;
  }

  /** Returns the canonical address cached for the connected socket peer. */
  [[nodiscard]] std::string_view direct_peer_address() const noexcept {
    return direct_peer_address_;
  }

 private:
  const TrustedProxyPolicy* policy_{};
  std::string direct_peer_address_;
  bool direct_peer_is_trusted_{};
};

/** Returns whether a request header can assert proxy or client identity. */
[[nodiscard]] bool is_forwarded_identity_header(
    std::string_view name) noexcept;

}  // namespace bonvoyage::runtime
