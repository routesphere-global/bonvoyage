#include "bonvoyage/runtime/retry_policy.hh"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <stdexcept>

namespace bonvoyage::runtime {
namespace {

constexpr std::uint64_t kNanosecondsPerSecond = 1'000'000'000ULL;

}  // namespace

bool RuntimeRetryPolicy::method_is_retryable(
    std::string_view method) const noexcept {
  return std::binary_search(retryable_methods.begin(),
                            retryable_methods.end(), method);
}

RetryDecision evaluate_retry(const RuntimeRetryPolicy& policy,
                             std::string_view method,
                             bool request_replayable,
                             std::uint32_t attempts_started,
                             AttemptCommitState commit_state,
                             RetryFailureClass failure) noexcept {
  if (!policy.method_is_retryable(method)) {
    return RetryDecision::method_not_retryable;
  }
  if (!request_replayable) {
    return RetryDecision::request_not_replayable;
  }
  if (commit_state == AttemptCommitState::response_head_received ||
      commit_state == AttemptCommitState::downstream_handoff) {
    return RetryDecision::response_committed;
  }
  if (failure != RetryFailureClass::transport &&
      failure != RetryFailureClass::per_try_timeout) {
    return RetryDecision::failure_not_retryable;
  }
  if (attempts_started >= policy.max_attempts) {
    return RetryDecision::attempts_exhausted;
  }
  return RetryDecision::retry;
}

ShardLocalRetryBudget::ShardLocalRetryBudget(RuntimeRetryBudget config,
                                             Clock::time_point now)
    : config_(config),
      available_tokens_(config.capacity),
      last_refill_(now) {
  if (config_.capacity == 0U || config_.refill_tokens_per_second == 0U ||
      config_.max_concurrent_retries_per_shard == 0U) {
    throw std::invalid_argument("retry budget limits must be positive");
  }
}

RetryAdmission ShardLocalRetryBudget::try_acquire(Clock::time_point now) {
  refill(now);
  if (active_retries_ >= config_.max_concurrent_retries_per_shard) {
    return RetryAdmission::concurrency_limited;
  }
  if (available_tokens_ == 0U) {
    return RetryAdmission::token_exhausted;
  }
  --available_tokens_;
  ++active_retries_;
  return RetryAdmission::admitted;
}

void ShardLocalRetryBudget::release() {
  if (active_retries_ == 0U) {
    throw std::logic_error("retry budget release without admission");
  }
  --active_retries_;
}

void ShardLocalRetryBudget::refill(Clock::time_point now) noexcept {
  if (now <= last_refill_) {
    return;
  }
  if (available_tokens_ == config_.capacity) {
    last_refill_ = now;
    refill_remainder_ = 0U;
    return;
  }

  const auto capacity_numerator =
      static_cast<std::uint64_t>(config_.capacity) * kNanosecondsPerSecond;
  const auto maximum_refill_ns =
      (capacity_numerator + config_.refill_tokens_per_second - 1U) /
      config_.refill_tokens_per_second;
  const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                           now - last_refill_)
                           .count();
  const auto elapsed_ns = std::min(
      static_cast<std::uint64_t>(elapsed), maximum_refill_ns);
  const auto numerator =
      elapsed_ns * config_.refill_tokens_per_second + refill_remainder_;
  const auto restored = numerator / kNanosecondsPerSecond;
  refill_remainder_ = numerator % kNanosecondsPerSecond;
  available_tokens_ = static_cast<std::uint32_t>(std::min<std::uint64_t>(
      config_.capacity,
      static_cast<std::uint64_t>(available_tokens_) + restored));
  last_refill_ = now;
  if (available_tokens_ == config_.capacity) {
    refill_remainder_ = 0U;
  }
}

}  // namespace bonvoyage::runtime
