#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace bonvoyage::runtime {

/** Immutable shard-local retry amplification bounds. */
struct RuntimeRetryBudget final {
  /** Maximum retry tokens retained after an idle period. */
  std::uint32_t capacity{100U};

  /** Retry tokens restored per second. */
  std::uint32_t refill_tokens_per_second{10U};

  /** Maximum retry attempts simultaneously active on one shard. */
  std::uint32_t max_concurrent_retries_per_shard{16U};
};

/** Immutable cluster retry policy prepared from a validated snapshot. */
struct RuntimeRetryPolicy final {
  /** Total original plus retry attempts allowed for one request. */
  std::uint32_t max_attempts{2U};

  /** Deadline for receiving a valid response head from one attempt. */
  std::uint32_t per_try_timeout_ms{1000U};

  /** Sorted idempotent request methods eligible for replay. */
  std::vector<std::string> retryable_methods{"GET", "HEAD", "OPTIONS"};

  /** Shard-local retry amplification bounds. */
  RuntimeRetryBudget budget;

  /** Returns whether the canonical request method is explicitly retryable. */
  [[nodiscard]] bool method_is_retryable(std::string_view method) const
      noexcept;
};

/** Monotonic request-attempt state used to prevent retry after commitment. */
enum class AttemptCommitState : std::uint8_t {
  not_started,
  request_started,
  response_head_received,
  downstream_handoff,
};

/** Failure classes considered by the bounded retry decision. */
enum class RetryFailureClass : std::uint8_t {
  transport,
  per_try_timeout,
  cancelled,
  invalid_response,
};

/** Observable reason that a failed attempt is retried or suppressed. */
enum class RetryDecision : std::uint8_t {
  retry,
  method_not_retryable,
  request_not_replayable,
  response_committed,
  failure_not_retryable,
  attempts_exhausted,
};

/** Evaluates retry safety without consuming a retry-budget token. */
[[nodiscard]] RetryDecision evaluate_retry(
    const RuntimeRetryPolicy& policy, std::string_view method,
    bool request_replayable, std::uint32_t attempts_started,
    AttemptCommitState commit_state, RetryFailureClass failure) noexcept;

/** Result of one shard-local retry-budget admission attempt. */
enum class RetryAdmission : std::uint8_t {
  admitted,
  token_exhausted,
  concurrency_limited,
};

/**
 * Token bucket and concurrent-retry circuit breaker owned by one shard.
 *
 * The original request never enters this controller. A successful admission
 * consumes one token and must be paired with release() when that retry attempt
 * finishes.
 */
class ShardLocalRetryBudget final {
 public:
  /** Monotonic clock used for deterministic token-refill accounting. */
  using Clock = std::chrono::steady_clock;

  /** Creates a full token bucket at the supplied deterministic time. */
  explicit ShardLocalRetryBudget(
      RuntimeRetryBudget config, Clock::time_point now = Clock::now());

  /** Attempts to admit one retry without waiting or cross-shard access. */
  [[nodiscard]] RetryAdmission try_acquire(Clock::time_point now);

  /** Releases one admitted retry from the concurrent circuit breaker. */
  void release();

  /** Current whole retry tokens, primarily for deterministic tests. */
  [[nodiscard]] std::uint32_t available_tokens() const noexcept {
    return available_tokens_;
  }

  /** Current admitted retries on this shard. */
  [[nodiscard]] std::uint32_t active_retries() const noexcept {
    return active_retries_;
  }

 private:
  void refill(Clock::time_point now) noexcept;

  RuntimeRetryBudget config_;
  std::uint32_t available_tokens_{};
  std::uint32_t active_retries_{};
  std::uint64_t refill_remainder_{};
  Clock::time_point last_refill_;
};

}  // namespace bonvoyage::runtime
