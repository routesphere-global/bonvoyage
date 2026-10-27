#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string_view>
#include <vector>

#include "bonvoyage/runtime/endpoint_selector.hh"

namespace {

using bonvoyage::runtime::EndpointCompletion;
using bonvoyage::runtime::RuntimeLoadBalancingPolicy;
using bonvoyage::runtime::ShardLocalEndpointSelector;

struct PolicyCase final {
  std::string_view name;
  RuntimeLoadBalancingPolicy policy;
};

std::uint64_t positive_argument(const char* value, const char* name) {
  std::uint64_t parsed = 0U;
  const auto text = std::string_view(value);
  const auto result =
      std::from_chars(text.data(), text.data() + text.size(), parsed);
  if (result.ec != std::errc{} || result.ptr != text.data() + text.size() ||
      parsed == 0U || parsed > 100000000U) {
    std::cerr << name << " must be between 1 and 100000000\n";
    std::exit(2);
  }
  return parsed;
}

std::size_t selected(ShardLocalEndpointSelector& selector,
                     ShardLocalEndpointSelector::TimePoint now) {
  const auto decision = selector.select(now);
  if (!decision.endpoint_index.has_value()) {
    std::cerr << "benchmark selector unexpectedly had no eligible endpoint\n";
    std::exit(2);
  }
  return *decision.endpoint_index;
}

void completed(ShardLocalEndpointSelector& selector, std::size_t endpoint,
               ShardLocalEndpointSelector::TimePoint now) {
  (void)selector.complete(endpoint, EndpointCompletion::success, now);
}

std::uint64_t run_immediate(RuntimeLoadBalancingPolicy policy,
                            std::size_t endpoint_count,
                            std::uint64_t iterations, std::uint64_t seed,
                            std::uint64_t& checksum) {
  const std::vector<std::uint32_t> weights(endpoint_count, 1U);
  ShardLocalEndpointSelector selector(policy, weights, std::nullopt, seed);
  const auto now = ShardLocalEndpointSelector::Clock::now();
  const auto started = std::chrono::steady_clock::now();
  for (std::uint64_t iteration = 0U; iteration < iterations; ++iteration) {
    const auto endpoint = selected(selector, now);
    checksum += endpoint + 1U;
    completed(selector, endpoint, now);
  }
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now() - started)
          .count());
}

std::uint64_t run_window(RuntimeLoadBalancingPolicy policy,
                         std::size_t endpoint_count,
                         std::uint64_t iterations, std::uint64_t seed,
                         std::uint64_t& checksum) {
  const std::vector<std::uint32_t> weights(endpoint_count, 1U);
  ShardLocalEndpointSelector selector(policy, weights, std::nullopt, seed);
  const auto now = ShardLocalEndpointSelector::Clock::now();
  constexpr std::size_t kWindow = 32U;
  std::array<std::size_t, kWindow> active{};
  for (auto& endpoint : active) {
    endpoint = selected(selector, now);
  }

  const auto started = std::chrono::steady_clock::now();
  for (std::uint64_t iteration = 0U; iteration < iterations; ++iteration) {
    const auto position = static_cast<std::size_t>(iteration % kWindow);
    completed(selector, active[position], now);
    active[position] = selected(selector, now);
    checksum += active[position] + 1U;
  }
  const auto elapsed = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now() - started)
          .count());
  for (const auto endpoint : active) {
    completed(selector, endpoint, now);
  }
  return elapsed;
}

}  // namespace

int main(int argc, char** argv) {
  const auto iterations =
      argc > 1 ? positive_argument(argv[1], "iterations") : 5000000U;
  const auto repetitions =
      argc > 2 ? positive_argument(argv[2], "repetitions") : 5U;
  constexpr std::array<std::size_t, 3> kEndpointCounts{2U, 8U, 64U};
  constexpr std::array<PolicyCase, 3> kPolicies{{
      {"round_robin", RuntimeLoadBalancingPolicy::round_robin},
      {"random", RuntimeLoadBalancingPolicy::random},
      {"least_request", RuntimeLoadBalancingPolicy::least_request},
  }};

  std::cout << "mode,policy,endpoint_count,repetition,iterations,elapsed_ns,ns_per_operation,checksum\n";
  for (std::uint64_t repetition = 1U; repetition <= repetitions;
       ++repetition) {
    for (const auto endpoint_count : kEndpointCounts) {
      for (const auto& policy : kPolicies) {
        for (const auto mode : {std::string_view("immediate"),
                                std::string_view("window_32")}) {
          std::uint64_t checksum = 0U;
          const auto seed = repetition * 131U + endpoint_count;
          const auto elapsed =
              mode == "immediate"
                  ? run_immediate(policy.policy, endpoint_count, iterations,
                                  seed, checksum)
                  : run_window(policy.policy, endpoint_count, iterations,
                               seed, checksum);
          const auto nanoseconds = static_cast<double>(elapsed) /
                                   static_cast<double>(iterations);
          std::cout << mode << ',' << policy.name << ',' << endpoint_count
                    << ',' << repetition << ',' << iterations << ','
                    << elapsed << ',' << nanoseconds << ',' << checksum
                    << '\n';
        }
      }
    }
  }
  return 0;
}
