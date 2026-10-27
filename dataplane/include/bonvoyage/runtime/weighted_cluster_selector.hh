#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace bonvoyage::runtime {

/** One validated route-level cluster target and its relative traffic weight. */
struct RuntimeWeightedCluster final {
  /** Index into the immutable snapshot cluster table. */
  std::size_t cluster_index{};

  /** Relative share within this route's bounded weighted schedule. */
  std::uint32_t weight{1U};
};

/**
 * Allocation-free route-level cluster selector owned by one Seastar shard.
 *
 * Construction converts the validated targets into a smooth, exact schedule.
 * Request-time selection is one indexed read and one bounded cursor update.
 */
class ShardLocalWeightedClusterSelector final {
 public:
  /** Builds a smooth schedule for two through sixteen unique clusters. */
  explicit ShardLocalWeightedClusterSelector(
      std::span<const RuntimeWeightedCluster> targets);

  /** Selects the next cluster index without allocating or synchronizing. */
  [[nodiscard]] std::size_t select() noexcept;

  /** Returns the exact number of selections in one complete weight cycle. */
  [[nodiscard]] std::size_t schedule_size() const noexcept {
    return schedule_.size();
  }

 private:
  std::vector<std::size_t> schedule_;
  std::size_t cursor_{};
};

}  // namespace bonvoyage::runtime
