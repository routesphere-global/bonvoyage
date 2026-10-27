#include "bonvoyage/runtime/endpoint_maintenance.hh"

#include <limits>
#include <stdexcept>

namespace bonvoyage::runtime {
namespace {

constexpr std::uint32_t kMaximumThreshold = 100U;

void increment_saturated(std::uint32_t& value) noexcept {
  if (value < std::numeric_limits<std::uint32_t>::max()) {
    ++value;
  }
}

}  // namespace

ActiveHealthTracker::ActiveHealthTracker(std::size_t endpoint_count,
                                         std::uint32_t healthy_threshold,
                                         std::uint32_t unhealthy_threshold)
    : healthy_threshold_(healthy_threshold),
      unhealthy_threshold_(unhealthy_threshold),
      endpoints_(endpoint_count) {
  if (endpoint_count == 0U) {
    throw std::invalid_argument(
        "active health tracker requires at least one endpoint");
  }
  if (healthy_threshold == 0U || healthy_threshold > kMaximumThreshold ||
      unhealthy_threshold == 0U ||
      unhealthy_threshold > kMaximumThreshold) {
    throw std::invalid_argument(
        "active health thresholds must be between 1 and 100");
  }
}

ActiveHealthDecision ActiveHealthTracker::record_probe(
    std::size_t endpoint_index, bool success) {
  if (endpoint_index >= endpoints_.size()) {
    throw std::out_of_range("active health endpoint index is out of range");
  }
  auto& endpoint = endpoints_[endpoint_index];
  if (endpoint.active_healthy) {
    endpoint.consecutive_successes = 0U;
    if (success) {
      endpoint.consecutive_failures = 0U;
      return {.active_healthy = true};
    }
    increment_saturated(endpoint.consecutive_failures);
    if (endpoint.consecutive_failures < unhealthy_threshold_) {
      return {.active_healthy = true};
    }
    endpoint.active_healthy = false;
    endpoint.consecutive_failures = 0U;
    return {.changed = true, .active_healthy = false};
  }

  endpoint.consecutive_failures = 0U;
  if (!success) {
    endpoint.consecutive_successes = 0U;
    return {.active_healthy = false};
  }
  increment_saturated(endpoint.consecutive_successes);
  if (endpoint.consecutive_successes < healthy_threshold_) {
    return {.active_healthy = false};
  }
  endpoint.active_healthy = true;
  endpoint.consecutive_successes = 0U;
  return {.changed = true, .active_healthy = true};
}

const ActiveHealthEndpointState& ActiveHealthTracker::state(
    std::size_t endpoint_index) const {
  if (endpoint_index >= endpoints_.size()) {
    throw std::out_of_range("active health endpoint index is out of range");
  }
  return endpoints_[endpoint_index];
}

}  // namespace bonvoyage::runtime
