#include "bonvoyage/runtime/route_admission.hh"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <stdexcept>

namespace {

using namespace std::chrono_literals;
using bonvoyage::runtime::RouteAdmission;
using bonvoyage::runtime::RuntimeLocalRateLimit;
using bonvoyage::runtime::RuntimeRouteAdmissionPolicy;
using bonvoyage::runtime::ShardLocalRouteAdmission;

void require(bool condition, const char* message) {
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

}  // namespace

int main() {
  const auto start = ShardLocalRouteAdmission::Clock::time_point{};

  ShardLocalRouteAdmission concurrency_only(
      RuntimeRouteAdmissionPolicy{2U, std::nullopt}, start);
  require(concurrency_only.try_acquire(start) == RouteAdmission::admitted,
          "first concurrent request was rejected");
  require(concurrency_only.try_acquire(start) == RouteAdmission::admitted,
          "second concurrent request was rejected");
  require(concurrency_only.try_acquire(start) ==
              RouteAdmission::concurrency_limited,
          "concurrency limit did not reject excess work");
  concurrency_only.release();
  require(concurrency_only.try_acquire(start) == RouteAdmission::admitted,
          "concurrency capacity did not recover");
  concurrency_only.release();
  concurrency_only.release();

  ShardLocalRouteAdmission rate_only(
      RuntimeRouteAdmissionPolicy{
          0U, RuntimeLocalRateLimit{2U, 2U}},
      start);
  require(rate_only.try_acquire(start) == RouteAdmission::admitted,
          "first rate token was rejected");
  rate_only.release();
  require(rate_only.try_acquire(start) == RouteAdmission::admitted,
          "second rate token was rejected");
  rate_only.release();
  require(rate_only.try_acquire(start) == RouteAdmission::rate_limited,
          "empty token bucket admitted a request");
  require(rate_only.try_acquire(start + 499ms) ==
              RouteAdmission::rate_limited,
          "fractional token admitted a request");
  require(rate_only.try_acquire(start + 500ms) == RouteAdmission::admitted,
          "whole token was not restored");
  rate_only.release();
  require(rate_only.try_acquire(start + 10s) == RouteAdmission::admitted,
          "idle refill did not restore the bucket");
  rate_only.release();
  require(rate_only.available_tokens() == 1U,
          "idle refill exceeded bucket capacity");

  ShardLocalRouteAdmission combined(
      RuntimeRouteAdmissionPolicy{
          1U, RuntimeLocalRateLimit{2U, 1U}},
      start);
  require(combined.try_acquire(start) == RouteAdmission::admitted,
          "combined policy rejected the first request");
  require(combined.try_acquire(start) ==
              RouteAdmission::concurrency_limited,
          "combined concurrency limit was not enforced first");
  require(combined.available_tokens() == 1U,
          "concurrency rejection consumed a rate token");
  combined.release();
  require(combined.try_acquire(start) == RouteAdmission::admitted,
          "combined policy did not admit remaining token");
  combined.release();
  require(combined.try_acquire(start) == RouteAdmission::rate_limited,
          "combined token bucket did not reject excess rate");

  bool invalid_disabled = false;
  try {
    (void)ShardLocalRouteAdmission(RuntimeRouteAdmissionPolicy{}, start);
  } catch (const std::invalid_argument&) {
    invalid_disabled = true;
  }
  require(invalid_disabled, "fully disabled admission state was accepted");

  bool invalid_rate = false;
  try {
    (void)ShardLocalRouteAdmission(
        RuntimeRouteAdmissionPolicy{
            0U, RuntimeLocalRateLimit{1U, 0U}},
        start);
  } catch (const std::invalid_argument&) {
    invalid_rate = true;
  }
  require(invalid_rate, "zero refill rate was accepted");

  bool invalid_release = false;
  try {
    concurrency_only.release();
  } catch (const std::logic_error&) {
    invalid_release = true;
  }
  require(invalid_release, "release without admission was accepted");

  return 0;
}
