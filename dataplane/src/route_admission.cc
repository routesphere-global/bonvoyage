#include "bonvoyage/runtime/route_admission.hh"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <stdexcept>

namespace bonvoyage::runtime {
namespace {

constexpr std::uint64_t kNanosecondsPerSecond = 1'000'000'000ULL;

}  // namespace

ShardLocalRouteAdmission::ShardLocalRouteAdmission(
    RuntimeRouteAdmissionPolicy policy, Clock::time_point now)
    : policy_(policy), last_refill_(now) {
  if (!policy_.enabled()) {
    throw std::invalid_argument("route admission policy must enable a limit");
  }
  if (policy_.local_rate_limit.has_value()) {
    const auto& rate_limit = *policy_.local_rate_limit;
    if (rate_limit.capacity == 0U ||
        rate_limit.refill_tokens_per_second == 0U) {
      throw std::invalid_argument("route rate limits must be positive");
    }
    available_tokens_ = rate_limit.capacity;
  }
}

RouteAdmission ShardLocalRouteAdmission::try_acquire(
    Clock::time_point now) {
  refill(now);
  if (policy_.max_concurrent_requests_per_shard != 0U &&
      active_requests_ >= policy_.max_concurrent_requests_per_shard) {
    return RouteAdmission::concurrency_limited;
  }
  if (policy_.local_rate_limit.has_value() && available_tokens_ == 0U) {
    return RouteAdmission::rate_limited;
  }
  if (policy_.local_rate_limit.has_value()) {
    --available_tokens_;
  }
  ++active_requests_;
  return RouteAdmission::admitted;
}

void ShardLocalRouteAdmission::release() {
  if (active_requests_ == 0U) {
    throw std::logic_error("route admission release without admission");
  }
  --active_requests_;
}

void ShardLocalRouteAdmission::refill(Clock::time_point now) noexcept {
  if (!policy_.local_rate_limit.has_value() || now <= last_refill_) {
    return;
  }
  const auto& rate_limit = *policy_.local_rate_limit;
  if (available_tokens_ == rate_limit.capacity) {
    last_refill_ = now;
    refill_remainder_ = 0U;
    return;
  }

  const auto capacity_numerator =
      static_cast<std::uint64_t>(rate_limit.capacity) *
      kNanosecondsPerSecond;
  const auto maximum_refill_ns =
      (capacity_numerator + rate_limit.refill_tokens_per_second - 1U) /
      rate_limit.refill_tokens_per_second;
  const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                           now - last_refill_)
                           .count();
  const auto elapsed_ns = std::min(static_cast<std::uint64_t>(elapsed),
                                   maximum_refill_ns);
  const auto numerator =
      elapsed_ns * rate_limit.refill_tokens_per_second + refill_remainder_;
  const auto restored = numerator / kNanosecondsPerSecond;
  refill_remainder_ = numerator % kNanosecondsPerSecond;
  available_tokens_ = static_cast<std::uint32_t>(std::min<std::uint64_t>(
      rate_limit.capacity,
      static_cast<std::uint64_t>(available_tokens_) + restored));
  last_refill_ = now;
  if (available_tokens_ == rate_limit.capacity) {
    refill_remainder_ = 0U;
  }
}

}  // namespace bonvoyage::runtime
