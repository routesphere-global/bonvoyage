#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace bonvoyage::runtime {

/** Result of applying one active HTTP probe to an endpoint. */
struct ActiveHealthDecision final {
  /** True when the endpoint crossed a configured health threshold. */
  bool changed{false};

  /** Desired selector eligibility after the probe. */
  bool active_healthy{true};
};

/** Observable state for one coordinator-owned active-health endpoint. */
struct ActiveHealthEndpointState final {
  /** Current state derived from thresholded probe results. */
  bool active_healthy{true};

  /** Consecutive successes accumulated while unhealthy. */
  std::uint32_t consecutive_successes{};

  /** Consecutive failures accumulated while healthy. */
  std::uint32_t consecutive_failures{};
};

/**
 * Bounded active-health hysteresis owned by the maintenance coordinator.
 *
 * Endpoints begin healthy. Failures cross the unhealthy threshold only while
 * healthy, and successes cross the recovery threshold only while unhealthy.
 */
class ActiveHealthTracker final {
 public:
  /** Constructs state for a non-empty endpoint set and bounded thresholds. */
  ActiveHealthTracker(std::size_t endpoint_count,
                      std::uint32_t healthy_threshold,
                      std::uint32_t unhealthy_threshold);

  /** Applies one probe result and reports an optional state transition. */
  [[nodiscard]] ActiveHealthDecision record_probe(std::size_t endpoint_index,
                                                  bool success);

  /** Returns the current threshold state for one endpoint. */
  [[nodiscard]] const ActiveHealthEndpointState& state(
      std::size_t endpoint_index) const;

 private:
  std::uint32_t healthy_threshold_;
  std::uint32_t unhealthy_threshold_;
  std::vector<ActiveHealthEndpointState> endpoints_;
};

}  // namespace bonvoyage::runtime
