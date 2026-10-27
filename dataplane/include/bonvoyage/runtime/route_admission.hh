#pragma once

#include <chrono>
#include <cstdint>
#include <optional>

namespace bonvoyage::runtime {

/** Immutable shard-local token-bucket settings for one route. */
struct RuntimeLocalRateLimit final {
  /** Maximum tokens retained after an idle period. */
  std::uint32_t capacity{};

  /** Whole request tokens restored per second. */
  std::uint32_t refill_tokens_per_second{};
};

/** Immutable route admission policy prepared from a validated snapshot. */
struct RuntimeRouteAdmissionPolicy final {
  /** Maximum active route requests per shard; zero disables this bound. */
  std::uint32_t max_concurrent_requests_per_shard{};

  /** Optional unkeyed token bucket owned by each shard. */
  std::optional<RuntimeLocalRateLimit> local_rate_limit;

  /** Returns whether this route needs mutable admission state. */
  [[nodiscard]] bool enabled() const noexcept {
    return max_concurrent_requests_per_shard != 0U ||
           local_rate_limit.has_value();
  }
};

/** Result of one shard-local route admission attempt. */
enum class RouteAdmission : std::uint8_t {
  admitted,
  rate_limited,
  concurrency_limited,
};

/**
 * Nonblocking concurrency gate and token bucket owned by one data-plane shard.
 *
 * A successful try_acquire() must be paired with release(). Rejections never
 * consume a token or increase the active request count.
 */
class ShardLocalRouteAdmission final {
 public:
  /** Monotonic clock used for deterministic refill accounting. */
  using Clock = std::chrono::steady_clock;

  /** Creates a full optional token bucket at the supplied time. */
  explicit ShardLocalRouteAdmission(
      RuntimeRouteAdmissionPolicy policy,
      Clock::time_point now = Clock::now());

  /** Attempts to admit one request without waiting or cross-shard access. */
  [[nodiscard]] RouteAdmission try_acquire(Clock::time_point now);

  /** Releases one previously admitted request. */
  void release();

  /** Returns the number of requests currently admitted on this shard. */
  [[nodiscard]] std::uint32_t active_requests() const noexcept {
    return active_requests_;
  }

  /** Returns whole available tokens, or zero when rate limiting is disabled. */
  [[nodiscard]] std::uint32_t available_tokens() const noexcept {
    return available_tokens_;
  }

 private:
  void refill(Clock::time_point now) noexcept;

  RuntimeRouteAdmissionPolicy policy_;
  std::uint32_t available_tokens_{};
  std::uint32_t active_requests_{};
  std::uint64_t refill_remainder_{};
  Clock::time_point last_refill_;
};

}  // namespace bonvoyage::runtime
