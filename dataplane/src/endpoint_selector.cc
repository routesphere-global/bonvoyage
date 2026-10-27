#include "bonvoyage/runtime/endpoint_selector.hh"

#include <limits>
#include <stdexcept>

namespace bonvoyage::runtime {
namespace {

constexpr std::size_t kMaximumWeightedSchedule = 4096U;
constexpr std::uint64_t kDefaultRandomSeed = 0x9e3779b97f4a7c15ULL;

bool has_lower_normalized_load(const EndpointSelectionState& candidate,
                               const EndpointSelectionState& current) {
  return static_cast<std::uint64_t>(candidate.active_requests) *
             static_cast<std::uint64_t>(current.weight) <
         static_cast<std::uint64_t>(current.active_requests) *
             static_cast<std::uint64_t>(candidate.weight);
}

bool has_equal_normalized_load(const EndpointSelectionState& candidate,
                               const EndpointSelectionState& current) {
  return static_cast<std::uint64_t>(candidate.active_requests) *
             static_cast<std::uint64_t>(current.weight) ==
         static_cast<std::uint64_t>(current.active_requests) *
             static_cast<std::uint64_t>(candidate.weight);
}

}  // namespace

ShardLocalEndpointSelector::ShardLocalEndpointSelector(
    RuntimeLoadBalancingPolicy policy,
    std::span<const std::uint32_t> endpoint_weights,
    std::optional<RuntimePassiveHealth> passive_health,
    std::uint64_t random_seed,
    std::uint32_t max_concurrent_requests_per_endpoint)
    : policy_(policy),
      passive_health_(passive_health),
      max_concurrent_requests_per_endpoint_(
          max_concurrent_requests_per_endpoint),
      random_state_(random_seed == 0U ? kDefaultRandomSeed : random_seed) {
  if (endpoint_weights.empty()) {
    throw std::invalid_argument("endpoint selector requires at least one endpoint");
  }
  if (passive_health_.has_value() &&
      (passive_health_->consecutive_failures == 0U ||
       passive_health_->consecutive_failures > 100U ||
       passive_health_->ejection_time_ms < 100U ||
       passive_health_->ejection_time_ms > 300000U ||
       passive_health_->max_ejection_percent == 0U ||
       passive_health_->max_ejection_percent > 100U ||
       passive_health_->consecutive_successes == 0U ||
       passive_health_->consecutive_successes > 100U)) {
    throw std::invalid_argument("passive health policy is outside its bounds");
  }
  if (max_concurrent_requests_per_endpoint_ == 0U) {
    throw std::invalid_argument(
        "endpoint concurrency limit must be greater than zero");
  }
  std::size_t total_weight = 0U;
  endpoints_.reserve(endpoint_weights.size());
  for (const auto weight : endpoint_weights) {
    const auto bounded_weight = static_cast<std::size_t>(weight);
    if (weight == 0U || bounded_weight > kMaximumWeightedSchedule ||
        total_weight > kMaximumWeightedSchedule -
                           bounded_weight) {
      throw std::invalid_argument(
          "endpoint selector total weight must be between 1 and 4096");
    }
    total_weight += bounded_weight;
    endpoints_.push_back(EndpointSelectionState{.weight = weight});
  }
  weighted_schedule_.reserve(total_weight);
  for (std::size_t endpoint = 0U; endpoint < endpoints_.size(); ++endpoint) {
    for (std::uint32_t count = 0U; count < endpoints_[endpoint].weight;
         ++count) {
      weighted_schedule_.push_back(endpoint);
    }
  }

  if (passive_health_.has_value()) {
    const auto endpoint_count = static_cast<std::uint64_t>(endpoints_.size());
    max_ejected_endpoints_ = static_cast<std::size_t>(
        endpoint_count * passive_health_->max_ejection_percent / 100U);
  }
}

EndpointSelectionDecision ShardLocalEndpointSelector::select(TimePoint now) {
  EndpointSelectionDecision decision;
  decision.half_opened_endpoints = advance_expired_circuits(now);
  switch (policy_) {
    case RuntimeLoadBalancingPolicy::round_robin:
      decision.endpoint_index = select_round_robin();
      break;
    case RuntimeLoadBalancingPolicy::least_request:
      decision.endpoint_index = select_least_request();
      break;
    case RuntimeLoadBalancingPolicy::random:
      decision.endpoint_index = select_random();
      break;
  }
  if (!decision.endpoint_index.has_value()) {
    decision.rejection = rejection_reason();
    return decision;
  }

  auto& endpoint = endpoints_[*decision.endpoint_index];
  if (!selectable(endpoint)) {
    throw std::logic_error("endpoint selector returned an ineligible endpoint");
  }
  if (endpoint.circuit_state == EndpointCircuitState::half_open) {
    endpoint.half_open_probe_active = true;
  }
  ++endpoint.active_requests;
  ++endpoint.selections_total;
  return decision;
}

EndpointCompletionDecision ShardLocalEndpointSelector::complete(
    std::size_t endpoint_index, EndpointCompletion completion, TimePoint now) {
  if (endpoint_index >= endpoints_.size()) {
    throw std::out_of_range("endpoint completion index is out of range");
  }
  auto& endpoint = endpoints_[endpoint_index];
  if (endpoint.active_requests == 0U) {
    throw std::logic_error("endpoint completion has no active request");
  }
  --endpoint.active_requests;

  if (completion == EndpointCompletion::passive_failure) {
    ++endpoint.passive_failures_total;
  }

  if (endpoint.circuit_state == EndpointCircuitState::open) {
    return {};
  }

  if (endpoint.circuit_state == EndpointCircuitState::half_open) {
    if (!endpoint.half_open_probe_active) {
      throw std::logic_error(
          "half-open endpoint completion has no active probe");
    }
    endpoint.half_open_probe_active = false;
    if (completion == EndpointCompletion::neutral) {
      return {};
    }
    if (completion == EndpointCompletion::success) {
      endpoint.consecutive_failures = 0U;
      if (endpoint.consecutive_successes <
          std::numeric_limits<std::uint32_t>::max()) {
        ++endpoint.consecutive_successes;
      }
      if (endpoint.consecutive_successes <
          passive_health_->consecutive_successes) {
        return {};
      }
      endpoint.circuit_state = EndpointCircuitState::closed;
      endpoint.consecutive_successes = 0U;
      ++endpoint.circuit_closes_total;
      --half_open_circuits_;
      return EndpointCompletionDecision{.closed = true};
    }

    endpoint.circuit_state = EndpointCircuitState::open;
    endpoint.circuit_open_until =
        now + std::chrono::milliseconds(passive_health_->ejection_time_ms);
    endpoint.consecutive_successes = 0U;
    endpoint.consecutive_failures = passive_health_->consecutive_failures;
    ++endpoint.ejections_total;
    ++endpoint.circuit_reopens_total;
    --half_open_circuits_;
    ++open_circuits_;
    return EndpointCompletionDecision{.reopened = true};
  }

  if (completion == EndpointCompletion::success) {
    endpoint.consecutive_failures = 0U;
    return {};
  }
  if (completion == EndpointCompletion::neutral) {
    return {};
  }

  if (endpoint.consecutive_failures <
      std::numeric_limits<std::uint32_t>::max()) {
    ++endpoint.consecutive_failures;
  }
  if (!passive_health_.has_value() ||
      endpoint.consecutive_failures <
          passive_health_->consecutive_failures ||
      ejected_endpoints() >= max_ejected_endpoints_) {
    return {};
  }

  endpoint.circuit_state = EndpointCircuitState::open;
  endpoint.circuit_open_until =
      now + std::chrono::milliseconds(passive_health_->ejection_time_ms);
  endpoint.consecutive_successes = 0U;
  ++endpoint.ejections_total;
  ++open_circuits_;
  return EndpointCompletionDecision{.opened = true};
}

const EndpointSelectionState& ShardLocalEndpointSelector::state(
    std::size_t endpoint_index) const {
  if (endpoint_index >= endpoints_.size()) {
    throw std::out_of_range("endpoint state index is out of range");
  }
  return endpoints_[endpoint_index];
}

bool ShardLocalEndpointSelector::set_active_healthy(
    std::size_t endpoint_index, bool active_healthy) {
  if (endpoint_index >= endpoints_.size()) {
    throw std::out_of_range("active health endpoint index is out of range");
  }
  auto& endpoint = endpoints_[endpoint_index];
  if (endpoint.active_healthy == active_healthy) {
    return false;
  }
  endpoint.active_healthy = active_healthy;
  if (active_healthy) {
    --active_unhealthy_endpoints_;
  } else {
    ++active_unhealthy_endpoints_;
  }
  return true;
}

std::size_t ShardLocalEndpointSelector::advance_expired_circuits(
    TimePoint now) {
  std::size_t half_opened = 0U;
  for (auto& endpoint : endpoints_) {
    if (endpoint.circuit_state != EndpointCircuitState::open ||
        now < endpoint.circuit_open_until || endpoint.active_requests != 0U ||
        !endpoint.active_healthy) {
      continue;
    }
    endpoint.circuit_state = EndpointCircuitState::half_open;
    endpoint.consecutive_failures = 0U;
    endpoint.consecutive_successes = 0U;
    endpoint.half_open_probe_active = false;
    ++endpoint.reactivations_total;
    --open_circuits_;
    ++half_open_circuits_;
    ++half_opened;
  }
  return half_opened;
}

bool ShardLocalEndpointSelector::selectable(
    const EndpointSelectionState& endpoint) const noexcept {
  if (!endpoint.active_healthy ||
      endpoint.active_requests >= max_concurrent_requests_per_endpoint_) {
    return false;
  }
  if (endpoint.circuit_state == EndpointCircuitState::open) {
    return false;
  }
  return endpoint.circuit_state == EndpointCircuitState::closed ||
         !endpoint.half_open_probe_active;
}

EndpointSelectionRejection ShardLocalEndpointSelector::rejection_reason()
    const noexcept {
  bool endpoint_concurrency_limited = false;
  bool half_open_probe_limited = false;
  for (const auto& endpoint : endpoints_) {
    if (!endpoint.active_healthy) {
      continue;
    }
    if (endpoint.circuit_state == EndpointCircuitState::closed &&
        endpoint.active_requests >= max_concurrent_requests_per_endpoint_) {
      endpoint_concurrency_limited = true;
    } else if (endpoint.circuit_state == EndpointCircuitState::half_open &&
               endpoint.half_open_probe_active) {
      half_open_probe_limited = true;
    }
  }
  if (endpoint_concurrency_limited) {
    return EndpointSelectionRejection::endpoint_concurrency_limit;
  }
  if (half_open_probe_limited) {
    return EndpointSelectionRejection::half_open_probe_limit;
  }
  return EndpointSelectionRejection::no_healthy_endpoint;
}

std::optional<std::size_t>
ShardLocalEndpointSelector::select_round_robin() {
  for (std::size_t offset = 0U; offset < weighted_schedule_.size(); ++offset) {
    const auto position =
        (schedule_cursor_ + offset) % weighted_schedule_.size();
    const auto endpoint = weighted_schedule_[position];
    if (!selectable(endpoints_[endpoint])) {
      continue;
    }
    schedule_cursor_ = (position + 1U) % weighted_schedule_.size();
    return endpoint;
  }
  return std::nullopt;
}

std::optional<std::size_t>
ShardLocalEndpointSelector::select_least_request() {
  std::optional<std::size_t> least;
  for (std::size_t endpoint = 0U; endpoint < endpoints_.size(); ++endpoint) {
    if (!selectable(endpoints_[endpoint])) {
      continue;
    }
    if (!least.has_value() ||
        has_lower_normalized_load(endpoints_[endpoint], endpoints_[*least])) {
      least = endpoint;
    }
  }
  if (!least.has_value()) {
    return std::nullopt;
  }

  for (std::size_t offset = 0U; offset < weighted_schedule_.size(); ++offset) {
    const auto position =
        (schedule_cursor_ + offset) % weighted_schedule_.size();
    const auto endpoint = weighted_schedule_[position];
    if (selectable(endpoints_[endpoint]) &&
        has_equal_normalized_load(endpoints_[endpoint], endpoints_[*least])) {
      schedule_cursor_ = (position + 1U) % weighted_schedule_.size();
      return endpoint;
    }
  }
  throw std::logic_error("least-request selector lost its eligible endpoint");
}

std::optional<std::size_t> ShardLocalEndpointSelector::select_random() {
  if (open_circuits_ == 0U && half_open_circuits_ == 0U &&
      active_unhealthy_endpoints_ == 0U) {
    const auto endpoint =
        weighted_schedule_[random_below(weighted_schedule_.size())];
    if (selectable(endpoints_[endpoint])) {
      return endpoint;
    }
  }
  std::uint64_t eligible_weight = 0U;
  for (const auto& endpoint : endpoints_) {
    if (selectable(endpoint)) {
      eligible_weight += endpoint.weight;
    }
  }
  if (eligible_weight == 0U) {
    return std::nullopt;
  }

  auto choice = random_below(eligible_weight);
  for (std::size_t endpoint = 0U; endpoint < endpoints_.size(); ++endpoint) {
    if (!selectable(endpoints_[endpoint])) {
      continue;
    }
    if (choice < endpoints_[endpoint].weight) {
      return endpoint;
    }
    choice -= endpoints_[endpoint].weight;
  }
  throw std::logic_error("weighted random selector exceeded eligible weight");
}

std::uint64_t ShardLocalEndpointSelector::next_random() noexcept {
  random_state_ += kDefaultRandomSeed;
  auto value = random_state_;
  value = (value ^ (value >> 30U)) * 0xbf58476d1ce4e5b9ULL;
  value = (value ^ (value >> 27U)) * 0x94d049bb133111ebULL;
  return value ^ (value >> 31U);
}

std::uint64_t ShardLocalEndpointSelector::random_below(
    std::uint64_t bound) noexcept {
  const auto maximum = std::numeric_limits<std::uint64_t>::max();
  const auto rejected_values = (maximum % bound + 1U) % bound;
  const auto largest_accepted = maximum - rejected_values;
  std::uint64_t value;
  do {
    value = next_random();
  } while (value > largest_accepted);
  return value % bound;
}

}  // namespace bonvoyage::runtime
