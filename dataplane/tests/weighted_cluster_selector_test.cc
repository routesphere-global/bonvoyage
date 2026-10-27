#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <vector>

#include "bonvoyage/runtime/weighted_cluster_selector.hh"

namespace {

using bonvoyage::runtime::RuntimeWeightedCluster;
using bonvoyage::runtime::ShardLocalWeightedClusterSelector;

void require(bool condition, const char* message) {
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

template <typename Factory>
void require_invalid(Factory&& factory, const char* message) {
  try {
    factory();
  } catch (const std::invalid_argument&) {
    return;
  }
  require(false, message);
}

}  // namespace

int main() {
  {
    const std::vector<RuntimeWeightedCluster> targets{
        {7U, 9U}, {11U, 1U}};
    ShardLocalWeightedClusterSelector selector(targets);
    require(selector.schedule_size() == 10U,
            "weighted schedule did not retain its exact total");

    std::size_t stable = 0U;
    std::size_t canary = 0U;
    for (std::size_t request = 0U; request < 100U; ++request) {
      const auto selected = selector.select();
      stable += selected == 7U ? 1U : 0U;
      canary += selected == 11U ? 1U : 0U;
    }
    require(stable == 90U && canary == 10U,
            "90/10 route split was not exact across complete cycles");
  }

  {
    const std::vector<RuntimeWeightedCluster> targets{
        {3U, 2U}, {5U, 1U}};
    ShardLocalWeightedClusterSelector selector(targets);
    const auto first = selector.select();
    const auto second = selector.select();
    const auto third = selector.select();
    require(first == 3U && second == 5U && third == 3U,
            "smooth 2/1 schedule was not dispersed deterministically");
    require(selector.select() == first,
            "weighted schedule did not restart at its cycle boundary");
  }

  require_invalid(
      [] {
        const std::vector<RuntimeWeightedCluster> targets{{1U, 1U}};
        ShardLocalWeightedClusterSelector selector(targets);
      },
      "single-cluster weighted route was accepted");
  require_invalid(
      [] {
        const std::vector<RuntimeWeightedCluster> targets{
            {1U, 1U}, {1U, 1U}};
        ShardLocalWeightedClusterSelector selector(targets);
      },
      "duplicate weighted cluster index was accepted");
  require_invalid(
      [] {
        const std::vector<RuntimeWeightedCluster> targets{
            {1U, 0U}, {2U, 1U}};
        ShardLocalWeightedClusterSelector selector(targets);
      },
      "zero route weight was accepted");
  require_invalid(
      [] {
        const std::vector<RuntimeWeightedCluster> targets{
            {1U, 4096U}, {2U, 1U}};
        ShardLocalWeightedClusterSelector selector(targets);
      },
      "route weight total above 4096 was accepted");

  return 0;
}
