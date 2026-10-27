#include <cstdlib>
#include <iostream>
#include <stdexcept>

#include "bonvoyage/runtime/endpoint_maintenance.hh"

namespace {

using bonvoyage::runtime::ActiveHealthTracker;

void require(bool condition, const char* message) {
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

}  // namespace

int main() {
  ActiveHealthTracker tracker(2U, 2U, 3U);
  require(tracker.state(0U).active_healthy,
          "endpoint did not start active healthy");

  require(!tracker.record_probe(0U, false).changed,
          "first failure changed active health");
  require(!tracker.record_probe(0U, false).changed,
          "second failure changed active health");
  const auto unhealthy = tracker.record_probe(0U, false);
  require(unhealthy.changed && !unhealthy.active_healthy &&
              !tracker.state(0U).active_healthy,
          "failure threshold did not mark the endpoint unhealthy");

  require(!tracker.record_probe(0U, true).changed,
          "first recovery success changed active health");
  require(!tracker.record_probe(0U, false).changed,
          "failure while unhealthy changed active health");
  require(!tracker.record_probe(0U, true).changed,
          "recovery streak was not reset by failure");
  const auto recovered = tracker.record_probe(0U, true);
  require(recovered.changed && recovered.active_healthy &&
              tracker.state(0U).active_healthy,
          "success threshold did not recover the endpoint");

  require(!tracker.record_probe(1U, true).changed &&
              tracker.state(1U).active_healthy,
          "success changed an already healthy endpoint");

  bool rejected = false;
  try {
    (void)ActiveHealthTracker(0U, 1U, 1U);
  } catch (const std::invalid_argument&) {
    rejected = true;
  }
  require(rejected, "empty active health tracker was accepted");

  rejected = false;
  try {
    (void)ActiveHealthTracker(1U, 0U, 1U);
  } catch (const std::invalid_argument&) {
    rejected = true;
  }
  require(rejected, "zero active health threshold was accepted");

  rejected = false;
  try {
    (void)tracker.record_probe(2U, true);
  } catch (const std::out_of_range&) {
    rejected = true;
  }
  require(rejected, "out-of-range active health endpoint was accepted");

  return 0;
}
