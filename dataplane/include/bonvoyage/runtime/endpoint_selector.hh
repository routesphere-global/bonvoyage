#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <vector>

namespace bonvoyage::runtime {

/** Shard-local endpoint-selection algorithm compiled from the snapshot. */
enum class RuntimeLoadBalancingPolicy {
  round_robin,   ///< Deterministic weighted round robin.
  least_request, ///< Weighted least in-flight requests with RR tie breaking.
  random         ///< Weighted pseudo-random selection.
};

/** Bounded passive transport-failure ejection policy. */
struct RuntimePassiveHealth final {
  /** Failures before an endpoint is considered for temporary ejection. */
  std::uint32_t consecutive_failures{5U};

  /** Ejection duration in milliseconds on this shard. */
  std::uint32_t ejection_time_ms{30000U};

  /** Maximum percentage of this cluster's endpoints ejected on one shard. */
  std::uint32_t max_ejection_percent{50U};

  /** Consecutive successful half-open probes required to close the circuit. */
  std::uint32_t consecutive_successes{1U};
};

/** Shard-local passive endpoint circuit state. */
enum class EndpointCircuitState {
  closed,   ///< Normal selection and passive failure accounting.
  open,     ///< New selections are excluded until the open interval expires.
  half_open ///< Exactly one recovery probe may be active.
};

/** Why no endpoint could be selected for an admitted cluster request. */
enum class EndpointSelectionRejection {
  none,                      ///< Selection succeeded.
  no_healthy_endpoint,       ///< Every endpoint is open or actively unhealthy.
  endpoint_concurrency_limit,  ///< Eligible endpoints reached their local limit.
  half_open_probe_limit      ///< A recovery probe is already active.
};

/** Completion class used by passive failure accounting. */
enum class EndpointCompletion {
  success,         ///< A valid upstream response head was received.
  passive_failure, ///< The attempt failed before a valid response head.
  neutral          ///< Caller cancellation or another non-endpoint failure.
};

/** One endpoint's shard-local, bounded balancing and health state. */
struct EndpointSelectionState final {
  /** Static endpoint weight compiled from the active snapshot. */
  std::uint32_t weight{1U};

  /** Requests selected for this endpoint that have not completed. */
  std::uint32_t active_requests{};

  /** Consecutive passive failures since the last success or reactivation. */
  std::uint32_t consecutive_failures{};

  /** Successful probes accumulated during the current half-open interval. */
  std::uint32_t consecutive_successes{};

  /** Total requests selected for this endpoint on this shard. */
  std::uint64_t selections_total{};

  /** Total passive failures attributed to this endpoint on this shard. */
  std::uint64_t passive_failures_total{};

  /** Total temporary ejections of this endpoint on this shard. */
  std::uint64_t ejections_total{};

  /** Total expiry-based reactivations of this endpoint on this shard. */
  std::uint64_t reactivations_total{};

  /** Total half-open circuits closed by successful probes on this shard. */
  std::uint64_t circuit_closes_total{};

  /** Total failed half-open probes that reopened this endpoint circuit. */
  std::uint64_t circuit_reopens_total{};

  /** Current passive circuit state. */
  EndpointCircuitState circuit_state{EndpointCircuitState::closed};

  /** True while the one permitted half-open recovery probe is active. */
  bool half_open_probe_active{false};

  /** Whether the latest published active-health state permits selection. */
  bool active_healthy{true};

  /** Monotonic time at which an open circuit may enter half-open state. */
  std::chrono::steady_clock::time_point circuit_open_until{};
};

/** Result of one endpoint selection and lazy ejection-expiry pass. */
struct EndpointSelectionDecision final {
  /** Selected endpoint index, or no value when every endpoint is excluded. */
  std::optional<std::size_t> endpoint_index;

  /** Count of expired open circuits moved to half-open during selection. */
  std::size_t half_opened_endpoints{};

  /** Failure class when endpoint_index has no value. */
  EndpointSelectionRejection rejection{
      EndpointSelectionRejection::none};
};

/** Result of completing one selected endpoint attempt. */
struct EndpointCompletionDecision final {
  /** True when a closed circuit newly opened. */
  bool opened{false};

  /** True when a failed half-open probe reopened the circuit. */
  bool reopened{false};

  /** True when successful half-open probes closed the circuit. */
  bool closed{false};
};

/**
 * Allocation-free request-time selector owned by exactly one Seastar shard.
 *
 * Construction prepares the bounded weighted schedule. Selection and
 * completion mutate only local counters and never synchronize across shards.
 */
class ShardLocalEndpointSelector final {
 public:
  /** Monotonic clock used for ejection deadlines. */
  using Clock = std::chrono::steady_clock;

  /** Monotonic timestamp accepted by selection and completion operations. */
  using TimePoint = Clock::time_point;

  /** Builds a selector from validated endpoint weights and optional health. */
  ShardLocalEndpointSelector(
      RuntimeLoadBalancingPolicy policy,
      std::span<const std::uint32_t> endpoint_weights,
      std::optional<RuntimePassiveHealth> passive_health,
      std::uint64_t random_seed,
      std::uint32_t max_concurrent_requests_per_endpoint =
          std::numeric_limits<std::uint32_t>::max());

  /** Selects and marks one eligible endpoint active, or returns no endpoint. */
  [[nodiscard]] EndpointSelectionDecision select(TimePoint now);

  /** Completes one active selection and updates passive health state. */
  [[nodiscard]] EndpointCompletionDecision complete(
      std::size_t endpoint_index, EndpointCompletion completion,
      TimePoint now);

  /** Exposes immutable state for diagnostics and bounded-cardinality metrics. */
  [[nodiscard]] const EndpointSelectionState& state(
      std::size_t endpoint_index) const;

  /** Applies an asynchronously published active-health state. */
  [[nodiscard]] bool set_active_healthy(std::size_t endpoint_index,
                                        bool active_healthy);

  /** Returns the number of endpoints excluded by active health. */
  [[nodiscard]] std::size_t active_unhealthy_endpoints() const noexcept {
    return active_unhealthy_endpoints_;
  }

  /** Number of endpoints currently excluded by passive health. */
  [[nodiscard]] std::size_t ejected_endpoints() const noexcept {
    return open_circuits_ + half_open_circuits_;
  }

  /** Number of endpoint circuits currently open on this shard. */
  [[nodiscard]] std::size_t open_circuits() const noexcept {
    return open_circuits_;
  }

  /** Number of endpoint circuits currently half-open on this shard. */
  [[nodiscard]] std::size_t half_open_circuits() const noexcept {
    return half_open_circuits_;
  }

 private:
  [[nodiscard]] std::size_t advance_expired_circuits(TimePoint now);
  [[nodiscard]] bool selectable(const EndpointSelectionState& endpoint) const
      noexcept;
  [[nodiscard]] EndpointSelectionRejection rejection_reason() const noexcept;
  [[nodiscard]] std::optional<std::size_t> select_round_robin();
  [[nodiscard]] std::optional<std::size_t> select_least_request();
  [[nodiscard]] std::optional<std::size_t> select_random();
  [[nodiscard]] std::uint64_t next_random() noexcept;
  [[nodiscard]] std::uint64_t random_below(std::uint64_t bound) noexcept;

  RuntimeLoadBalancingPolicy policy_;
  std::optional<RuntimePassiveHealth> passive_health_;
  std::vector<EndpointSelectionState> endpoints_;
  std::vector<std::size_t> weighted_schedule_;
  std::size_t schedule_cursor_{};
  std::size_t open_circuits_{};
  std::size_t half_open_circuits_{};
  std::size_t active_unhealthy_endpoints_{};
  std::size_t max_ejected_endpoints_{};
  std::uint32_t max_concurrent_requests_per_endpoint_;
  std::uint64_t random_state_;
};

}  // namespace bonvoyage::runtime
