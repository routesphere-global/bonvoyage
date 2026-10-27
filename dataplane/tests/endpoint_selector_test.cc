#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <vector>

#include "bonvoyage/runtime/endpoint_selector.hh"

namespace {

using bonvoyage::runtime::EndpointCompletion;
using bonvoyage::runtime::EndpointCircuitState;
using bonvoyage::runtime::EndpointSelectionRejection;
using bonvoyage::runtime::RuntimeLoadBalancingPolicy;
using bonvoyage::runtime::RuntimePassiveHealth;
using bonvoyage::runtime::ShardLocalEndpointSelector;

void require(bool condition, const char* message) {
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

std::size_t select(ShardLocalEndpointSelector& selector,
                   ShardLocalEndpointSelector::TimePoint now) {
  const auto decision = selector.select(now);
  require(decision.endpoint_index.has_value(), "expected an eligible endpoint");
  return *decision.endpoint_index;
}

void complete(ShardLocalEndpointSelector& selector, std::size_t endpoint,
              EndpointCompletion completion,
              ShardLocalEndpointSelector::TimePoint now) {
  (void)selector.complete(endpoint, completion, now);
}

}  // namespace

int main() {
  const auto start = ShardLocalEndpointSelector::Clock::now();

  {
    const std::vector<std::uint32_t> weights{2U, 1U};
    ShardLocalEndpointSelector selector(
        RuntimeLoadBalancingPolicy::round_robin, weights, std::nullopt, 1U);
    const auto first = select(selector, start);
    complete(selector, first, EndpointCompletion::success, start);
    const auto second = select(selector, start);
    complete(selector, second, EndpointCompletion::success, start);
    const auto third = select(selector, start);
    complete(selector, third, EndpointCompletion::success, start);
    require(first == 0U && second == 0U && third == 1U,
            "weighted round robin did not follow the prepared schedule");
  }

  {
    const std::vector<std::uint32_t> weights{1U, 1U};
    ShardLocalEndpointSelector selector(
        RuntimeLoadBalancingPolicy::least_request, weights, std::nullopt, 2U);
    const auto first = select(selector, start);
    const auto second = select(selector, start);
    require(first == 0U && second == 1U,
            "least request did not avoid the active endpoint");
    complete(selector, second, EndpointCompletion::success, start);
    const auto third = select(selector, start);
    require(third == 1U,
            "least request did not select the lower in-flight endpoint");
    complete(selector, third, EndpointCompletion::success, start);
    complete(selector, first, EndpointCompletion::success, start);
  }

  {
    const std::vector<std::uint32_t> weights{2U, 1U};
    ShardLocalEndpointSelector selector(
        RuntimeLoadBalancingPolicy::least_request, weights, std::nullopt, 3U);
    const auto first = select(selector, start);
    const auto second = select(selector, start);
    const auto third = select(selector, start);
    require(first == 0U && second == 1U && third == 0U,
            "weighted least request ignored normalized active load");
    complete(selector, third, EndpointCompletion::success, start);
    complete(selector, second, EndpointCompletion::success, start);
    complete(selector, first, EndpointCompletion::success, start);
  }

  {
    const std::vector<std::uint32_t> weights{2U, 1U};
    ShardLocalEndpointSelector selector(
        RuntimeLoadBalancingPolicy::random, weights, std::nullopt, 4U);
    std::size_t first_endpoint = 0U;
    constexpr std::size_t kSelections = 6000U;
    for (std::size_t request = 0U; request < kSelections; ++request) {
      const auto endpoint = select(selector, start);
      if (endpoint == 0U) {
        ++first_endpoint;
      }
      complete(selector, endpoint, EndpointCompletion::success, start);
    }
    require(first_endpoint > 3600U && first_endpoint < 4400U,
            "weighted random distribution escaped its deterministic bound");
  }

  {
    const std::vector<std::uint32_t> weights{1U, 1U};
    const RuntimePassiveHealth health{2U, 1000U, 50U};
    ShardLocalEndpointSelector selector(
        RuntimeLoadBalancingPolicy::round_robin, weights, health, 5U);

    auto endpoint = select(selector, start);
    require(endpoint == 0U, "unexpected first passive-health endpoint");
    complete(selector, endpoint, EndpointCompletion::passive_failure, start);
    endpoint = select(selector, start);
    complete(selector, endpoint, EndpointCompletion::success, start);
    endpoint = select(selector, start);
    require(endpoint == 0U, "unexpected second passive-health endpoint");
    const auto ejection = selector.complete(
        endpoint, EndpointCompletion::passive_failure, start);
    require(ejection.opened && selector.ejected_endpoints() == 1U,
            "failure threshold did not eject the endpoint");

    endpoint = select(selector, start);
    require(endpoint == 1U, "selection did not exclude an ejected endpoint");
    complete(selector, endpoint, EndpointCompletion::success, start);

    const auto after_expiry = selector.select(start + std::chrono::seconds(1));
    require(after_expiry.half_opened_endpoints == 1U &&
                after_expiry.endpoint_index.has_value(),
            "expired endpoint did not enter half-open state");
    const auto recovery = selector.complete(
        *after_expiry.endpoint_index, EndpointCompletion::success,
        start + std::chrono::seconds(1));
    require(recovery.closed && selector.ejected_endpoints() == 0U,
            "successful half-open probe did not close the circuit");
  }

  {
    const std::vector<std::uint32_t> weights{1U};
    const RuntimePassiveHealth health{2U, 1000U, 100U};
    ShardLocalEndpointSelector selector(
        RuntimeLoadBalancingPolicy::round_robin, weights, health, 6U);
    auto endpoint = select(selector, start);
    complete(selector, endpoint, EndpointCompletion::passive_failure, start);
    endpoint = select(selector, start);
    complete(selector, endpoint, EndpointCompletion::success, start);
    endpoint = select(selector, start);
    const auto after_reset = selector.complete(
        endpoint, EndpointCompletion::passive_failure, start);
    require(!after_reset.opened &&
                selector.state(endpoint).consecutive_failures == 1U,
            "success did not reset the passive failure streak");
    endpoint = select(selector, start);
    const auto ejection = selector.complete(
        endpoint, EndpointCompletion::passive_failure, start);
    require(ejection.opened,
            "reset passive failure streak did not reach its next threshold");
  }

  {
    const std::vector<std::uint32_t> weights{1U};
    const RuntimePassiveHealth health{2U, 1000U, 100U};
    ShardLocalEndpointSelector selector(
        RuntimeLoadBalancingPolicy::round_robin, weights, health, 7U);
    auto endpoint = select(selector, start);
    complete(selector, endpoint, EndpointCompletion::passive_failure, start);
    endpoint = select(selector, start);
    complete(selector, endpoint, EndpointCompletion::neutral, start);
    require(selector.state(endpoint).consecutive_failures == 1U,
            "neutral completion changed the passive failure streak");
    endpoint = select(selector, start);
    const auto ejection = selector.complete(
        endpoint, EndpointCompletion::passive_failure, start);
    require(ejection.opened,
            "neutral completion did not preserve the failure streak");
  }

  {
    const std::vector<std::uint32_t> weights{1U};
    ShardLocalEndpointSelector selector(
        RuntimeLoadBalancingPolicy::round_robin, weights, std::nullopt, 8U);
    for (std::size_t attempt = 0U; attempt < 3U; ++attempt) {
      const auto endpoint = select(selector, start);
      complete(selector, endpoint, EndpointCompletion::passive_failure, start);
    }
    require(selector.ejected_endpoints() == 0U,
            "disabled passive health ejected an endpoint");
  }

  {
    const std::vector<std::uint32_t> weights{1U};
    const RuntimePassiveHealth health{1U, 100U, 100U, 2U};
    ShardLocalEndpointSelector selector(
        RuntimeLoadBalancingPolicy::round_robin, weights, health, 15U);
    auto endpoint = select(selector, start);
    const auto opened = selector.complete(
        endpoint, EndpointCompletion::passive_failure, start);
    require(opened.opened && selector.open_circuits() == 1U,
            "single failure did not open the circuit");

    const auto blocked = selector.select(start + std::chrono::milliseconds(99));
    require(!blocked.endpoint_index.has_value() &&
                blocked.rejection ==
                    EndpointSelectionRejection::no_healthy_endpoint,
            "open circuit accepted traffic before its deadline");

    const auto first_probe =
        selector.select(start + std::chrono::milliseconds(100));
    require(first_probe.half_opened_endpoints == 1U &&
                first_probe.endpoint_index == 0U &&
                selector.state(0U).circuit_state ==
                    EndpointCircuitState::half_open,
            "expired circuit did not admit one half-open probe");
    const auto concurrent_probe =
        selector.select(start + std::chrono::milliseconds(100));
    require(!concurrent_probe.endpoint_index.has_value() &&
                concurrent_probe.rejection ==
                    EndpointSelectionRejection::half_open_probe_limit,
            "half-open circuit admitted concurrent probes");

    const auto first_success = selector.complete(
        *first_probe.endpoint_index, EndpointCompletion::success,
        start + std::chrono::milliseconds(100));
    require(!first_success.closed && selector.half_open_circuits() == 1U,
            "circuit closed before its recovery threshold");
    const auto second_probe =
        selector.select(start + std::chrono::milliseconds(100));
    const auto second_success = selector.complete(
        *second_probe.endpoint_index, EndpointCompletion::success,
        start + std::chrono::milliseconds(100));
    require(second_success.closed && selector.ejected_endpoints() == 0U &&
                selector.state(0U).circuit_state ==
                    EndpointCircuitState::closed,
            "recovery threshold did not close the circuit");
  }

  {
    const std::vector<std::uint32_t> weights{1U};
    const RuntimePassiveHealth health{1U, 100U, 100U, 1U};
    ShardLocalEndpointSelector selector(
        RuntimeLoadBalancingPolicy::round_robin, weights, health, 16U);
    auto endpoint = select(selector, start);
    require(selector
                .complete(endpoint, EndpointCompletion::passive_failure, start)
                .opened,
            "reopen test did not open its circuit");
    const auto probe = selector.select(start + std::chrono::milliseconds(100));
    const auto reopened = selector.complete(
        *probe.endpoint_index, EndpointCompletion::passive_failure,
        start + std::chrono::milliseconds(100));
    require(reopened.reopened && selector.open_circuits() == 1U &&
                selector.half_open_circuits() == 0U,
            "failed half-open probe did not reopen the circuit");
    require(!selector.select(start + std::chrono::milliseconds(199))
                 .endpoint_index.has_value(),
            "reopened circuit ignored its renewed deadline");
  }

  {
    const std::vector<std::uint32_t> weights{1U};
    ShardLocalEndpointSelector selector(
        RuntimeLoadBalancingPolicy::round_robin, weights, std::nullopt, 17U,
        1U);
    const auto endpoint = select(selector, start);
    const auto overloaded = selector.select(start);
    require(!overloaded.endpoint_index.has_value() &&
                overloaded.rejection ==
                    EndpointSelectionRejection::endpoint_concurrency_limit,
            "endpoint concurrency limit did not reject immediately");
    complete(selector, endpoint, EndpointCompletion::success, start);
    const auto recovered = select(selector, start);
    complete(selector, recovered, EndpointCompletion::success, start);
  }

  {
    const std::vector<std::uint32_t> weights{1U};
    const RuntimePassiveHealth health{1U, 100U, 100U, 1U};
    ShardLocalEndpointSelector selector(
        RuntimeLoadBalancingPolicy::round_robin, weights, health, 18U);
    auto endpoint = select(selector, start);
    require(selector
                .complete(endpoint, EndpointCompletion::passive_failure, start)
                .opened,
            "neutral probe test did not open its circuit");
    const auto probe = selector.select(start + std::chrono::milliseconds(100));
    const auto neutral = selector.complete(
        *probe.endpoint_index, EndpointCompletion::neutral,
        start + std::chrono::milliseconds(100));
    require(!neutral.closed && !neutral.reopened &&
                selector.state(0U).circuit_state ==
                    EndpointCircuitState::half_open &&
                !selector.state(0U).half_open_probe_active,
            "neutral half-open completion changed circuit state");
    const auto next_probe =
        selector.select(start + std::chrono::milliseconds(100));
    require(next_probe.endpoint_index == 0U,
            "neutral half-open completion did not release the probe");
    require(selector
                .complete(*next_probe.endpoint_index,
                          EndpointCompletion::success,
                          start + std::chrono::milliseconds(100))
                .closed,
            "probe after neutral completion did not close the circuit");
  }

  {
    const std::vector<std::uint32_t> weights{1U};
    const RuntimePassiveHealth health{1U, 100U, 100U, 1U};
    ShardLocalEndpointSelector selector(
        RuntimeLoadBalancingPolicy::round_robin, weights, health, 19U);
    auto endpoint = select(selector, start);
    require(selector
                .complete(endpoint, EndpointCompletion::passive_failure, start)
                .opened,
            "active-health recovery test did not open its circuit");
    require(selector.set_active_healthy(0U, false),
            "active-health recovery test did not exclude its endpoint");
    const auto blocked =
        selector.select(start + std::chrono::milliseconds(100));
    require(blocked.half_opened_endpoints == 0U &&
                !blocked.endpoint_index.has_value() &&
                selector.state(0U).circuit_state == EndpointCircuitState::open,
            "active-unhealthy endpoint entered half-open recovery");
    require(selector.set_active_healthy(0U, true),
            "active-health recovery test did not restore its endpoint");
    const auto probe = selector.select(start + std::chrono::milliseconds(100));
    require(probe.half_opened_endpoints == 1U && probe.endpoint_index == 0U,
            "active-health recovery did not permit a half-open probe");
    require(selector
                .complete(*probe.endpoint_index, EndpointCompletion::success,
                          start + std::chrono::milliseconds(100))
                .closed,
            "active-health-permitted probe did not close the circuit");
  }

  {
    const std::vector<std::uint32_t> weights{1U};
    const RuntimePassiveHealth health{1U, 100U, 100U, 1U};
    ShardLocalEndpointSelector selector(
        RuntimeLoadBalancingPolicy::round_robin, weights, health, 20U, 2U);
    const auto first = select(selector, start);
    const auto second = select(selector, start);
    require(selector
                .complete(first, EndpointCompletion::passive_failure, start)
                .opened,
            "in-flight recovery test did not open its circuit");
    const auto blocked =
        selector.select(start + std::chrono::milliseconds(100));
    require(blocked.half_opened_endpoints == 0U &&
                !blocked.endpoint_index.has_value() &&
                selector.state(0U).circuit_state == EndpointCircuitState::open,
            "open circuit entered half-open with an old active request");
    complete(selector, second, EndpointCompletion::success,
             start + std::chrono::milliseconds(100));
    const auto probe = selector.select(start + std::chrono::milliseconds(100));
    require(probe.half_opened_endpoints == 1U && probe.endpoint_index == 0U,
            "drained open circuit did not enter half-open recovery");
    require(selector
                .complete(*probe.endpoint_index, EndpointCompletion::success,
                          start + std::chrono::milliseconds(100))
                .closed,
            "drained circuit recovery probe did not close");
  }

  {
    const std::vector<std::uint32_t> weights{1U, 1U};
    const RuntimePassiveHealth health{1U, 1000U, 100U};
    ShardLocalEndpointSelector selector(
        RuntimeLoadBalancingPolicy::round_robin, weights, health, 9U);
    auto endpoint = select(selector, start);
    complete(selector, endpoint, EndpointCompletion::passive_failure, start);
    endpoint = select(selector, start);
    complete(selector, endpoint, EndpointCompletion::passive_failure, start);
    require(!selector.select(start).endpoint_index.has_value(),
            "an all-ejected cluster did not fail closed");
  }

  {
    const std::vector<std::uint32_t> weights{1U};
    const RuntimePassiveHealth health{1U, 1000U, 50U};
    ShardLocalEndpointSelector selector(
        RuntimeLoadBalancingPolicy::round_robin, weights, health, 10U);
    const auto endpoint = select(selector, start);
    complete(selector, endpoint, EndpointCompletion::passive_failure, start);
    require(selector.ejected_endpoints() == 0U,
            "floor-based ejection cap removed the only endpoint");
  }

  for (const auto policy : {RuntimeLoadBalancingPolicy::round_robin,
                            RuntimeLoadBalancingPolicy::least_request,
                            RuntimeLoadBalancingPolicy::random}) {
    const std::vector<std::uint32_t> weights{1U, 1U};
    ShardLocalEndpointSelector selector(policy, weights, std::nullopt, 11U);
    require(selector.set_active_healthy(0U, false),
            "active health transition was not applied");
    require(!selector.set_active_healthy(0U, false),
            "duplicate active health transition was not idempotent");
    require(selector.active_unhealthy_endpoints() == 1U,
            "active unhealthy endpoint count is incorrect");
    for (std::size_t attempt = 0U; attempt < 32U; ++attempt) {
      const auto endpoint = select(selector, start);
      require(endpoint == 1U,
              "selection returned an active-health-excluded endpoint");
      complete(selector, endpoint, EndpointCompletion::success, start);
    }
    require(selector.set_active_healthy(1U, false),
            "second active health transition was not applied");
    require(!selector.select(start).endpoint_index.has_value(),
            "all active-unhealthy endpoints did not fail closed");
    require(selector.set_active_healthy(0U, true),
            "active health recovery was not applied");
    const auto recovered = select(selector, start);
    require(recovered == 0U, "recovered endpoint did not become eligible");
    complete(selector, recovered, EndpointCompletion::success, start);
  }

  {
    bool rejected = false;
    try {
      const std::vector<std::uint32_t> weights{};
      (void)ShardLocalEndpointSelector(
          RuntimeLoadBalancingPolicy::round_robin, weights, std::nullopt, 12U);
    } catch (const std::invalid_argument&) {
      rejected = true;
    }
    require(rejected, "empty endpoint set was not rejected");
  }

  {
    bool rejected = false;
    try {
      const std::vector<std::uint32_t> weights{4097U};
      (void)ShardLocalEndpointSelector(
          RuntimeLoadBalancingPolicy::round_robin, weights, std::nullopt, 13U);
    } catch (const std::invalid_argument&) {
      rejected = true;
    }
    require(rejected, "oversized single endpoint weight was not rejected");
  }

  {
    bool rejected = false;
    try {
      const std::vector<std::uint32_t> weights{4096U, 1U};
      (void)ShardLocalEndpointSelector(
          RuntimeLoadBalancingPolicy::round_robin, weights, std::nullopt, 14U);
    } catch (const std::invalid_argument&) {
      rejected = true;
    }
    require(rejected, "oversized total endpoint weight was not rejected");
  }

  return 0;
}
