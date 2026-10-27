#include "bonvoyage/runtime/weighted_cluster_selector.hh"

#include <cstdint>
#include <stdexcept>
#include <unordered_set>
#include <vector>

namespace bonvoyage::runtime {
namespace {

constexpr std::size_t kMaximumWeightedClusters = 16U;
constexpr std::size_t kMaximumWeightedSchedule = 4096U;

}  // namespace

ShardLocalWeightedClusterSelector::ShardLocalWeightedClusterSelector(
    std::span<const RuntimeWeightedCluster> targets) {
  if (targets.size() < 2U || targets.size() > kMaximumWeightedClusters) {
    throw std::invalid_argument(
        "weighted route requires between 2 and 16 clusters");
  }

  std::unordered_set<std::size_t> cluster_indices;
  cluster_indices.reserve(targets.size());
  std::size_t total_weight = 0U;
  for (const auto& target : targets) {
    const auto weight = static_cast<std::size_t>(target.weight);
    if (!cluster_indices.emplace(target.cluster_index).second) {
      throw std::invalid_argument(
          "weighted route cluster indices must be unique");
    }
    if (weight == 0U || weight > kMaximumWeightedSchedule ||
        total_weight > kMaximumWeightedSchedule - weight) {
      throw std::invalid_argument(
          "weighted route total weight must be between 2 and 4096");
    }
    total_weight += weight;
  }

  schedule_.reserve(total_weight);
  std::vector<std::int64_t> current_weights(targets.size(), 0);
  const auto signed_total = static_cast<std::int64_t>(total_weight);
  for (std::size_t slot = 0U; slot < total_weight; ++slot) {
    std::size_t selected = 0U;
    for (std::size_t index = 0U; index < targets.size(); ++index) {
      current_weights[index] +=
          static_cast<std::int64_t>(targets[index].weight);
      if (current_weights[index] > current_weights[selected]) {
        selected = index;
      }
    }
    schedule_.push_back(targets[selected].cluster_index);
    current_weights[selected] -= signed_total;
  }
}

std::size_t ShardLocalWeightedClusterSelector::select() noexcept {
  const auto selected = schedule_[cursor_];
  cursor_ = (cursor_ + 1U) % schedule_.size();
  return selected;
}

}  // namespace bonvoyage::runtime
