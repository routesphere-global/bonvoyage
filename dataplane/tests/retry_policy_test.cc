#include "bonvoyage/runtime/retry_policy.hh"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

using bonvoyage::runtime::AttemptCommitState;
using bonvoyage::runtime::RetryAdmission;
using bonvoyage::runtime::RetryDecision;
using bonvoyage::runtime::RetryFailureClass;
using bonvoyage::runtime::RuntimeRetryBudget;
using bonvoyage::runtime::RuntimeRetryPolicy;
using bonvoyage::runtime::ShardLocalRetryBudget;

void require(bool condition, std::string_view message) {
  if (!condition) {
    throw std::runtime_error(std::string(message));
  }
}

void retry_decisions_are_commit_and_method_aware() {
  const RuntimeRetryPolicy policy{
      3U, 250U, {"GET", "HEAD", "OPTIONS"}, {2U, 1U, 1U}};
  require(bonvoyage::runtime::evaluate_retry(
              policy, "GET", true, 1U,
              AttemptCommitState::request_started,
              RetryFailureClass::transport) == RetryDecision::retry,
          "bodyless GET transport failure should retry before response head");
  require(bonvoyage::runtime::evaluate_retry(
              policy, "POST", true, 1U,
              AttemptCommitState::request_started,
              RetryFailureClass::transport) ==
              RetryDecision::method_not_retryable,
          "POST must not retry");
  require(bonvoyage::runtime::evaluate_retry(
              policy, "GET", false, 1U,
              AttemptCommitState::request_started,
              RetryFailureClass::transport) ==
              RetryDecision::request_not_replayable,
          "streamed request must not retry");
  require(bonvoyage::runtime::evaluate_retry(
              policy, "GET", true, 1U,
              AttemptCommitState::response_head_received,
              RetryFailureClass::transport) ==
              RetryDecision::response_committed,
          "response-head commitment must suppress retry");
  require(bonvoyage::runtime::evaluate_retry(
              policy, "GET", true, 1U,
              AttemptCommitState::request_started,
              RetryFailureClass::invalid_response) ==
              RetryDecision::failure_not_retryable,
          "invalid response framing must not retry");
  require(bonvoyage::runtime::evaluate_retry(
              policy, "GET", true, 3U,
              AttemptCommitState::request_started,
              RetryFailureClass::per_try_timeout) ==
              RetryDecision::attempts_exhausted,
          "maximum total attempts must be enforced");
}

void retry_budget_bounds_tokens_and_concurrency() {
  using namespace std::chrono_literals;
  const auto start = ShardLocalRetryBudget::Clock::time_point{};
  ShardLocalRetryBudget budget(RuntimeRetryBudget{2U, 2U, 1U}, start);

  require(budget.try_acquire(start) == RetryAdmission::admitted,
          "first retry should be admitted");
  require(budget.try_acquire(start) == RetryAdmission::concurrency_limited,
          "concurrent retry circuit breaker should reject without token loss");
  require(budget.available_tokens() == 1U,
          "concurrency rejection must not consume a token");
  budget.release();
  require(budget.try_acquire(start) == RetryAdmission::admitted,
          "second token should be admitted");
  budget.release();
  require(budget.try_acquire(start) == RetryAdmission::token_exhausted,
          "empty token bucket should fail without waiting");
  require(budget.try_acquire(start + 499ms) ==
              RetryAdmission::token_exhausted,
          "partial refill interval must not create a whole token");
  require(budget.try_acquire(start + 500ms) == RetryAdmission::admitted,
          "configured refill rate should restore one token");
  budget.release();
  require(budget.try_acquire(start + 10s) == RetryAdmission::admitted,
          "long idle period should refill to bounded capacity");
  budget.release();
  require(budget.available_tokens() == 1U,
          "idle refill must saturate at capacity before admission");
}

void invalid_budget_is_rejected() {
  bool rejected = false;
  try {
    (void)ShardLocalRetryBudget(RuntimeRetryBudget{0U, 1U, 1U});
  } catch (const std::invalid_argument&) {
    rejected = true;
  }
  require(rejected, "zero retry budget must be rejected");
}

}  // namespace

int main() {
  try {
    retry_decisions_are_commit_and_method_aware();
    retry_budget_bounds_tokens_and_concurrency();
    invalid_budget_is_rejected();
  } catch (const std::exception& error) {
    std::cerr << "retry policy test failed: " << error.what() << '\n';
    return EXIT_FAILURE;
  }
  std::cout << "retry policy tests passed\n";
  return EXIT_SUCCESS;
}
