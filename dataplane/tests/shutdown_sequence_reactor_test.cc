#include "bonvoyage/runtime/shutdown_sequence.hh"

#include <algorithm>
#include <array>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <seastar/core/app-template.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/future.hh>

namespace {

using bonvoyage::runtime::ShutdownSequence;

constexpr std::array<std::string_view, 5U> kSteps{
    "admin-stop", "metrics-stop", "maintenance-stop", "gateway-stop",
    "logging-stop"};
unsigned assertions{};

void require(bool condition, const char* message) {
  ++assertions;
  if (!condition) {
    throw std::runtime_error(message);
  }
}

std::string exception_message(const ShutdownSequence& sequence) {
  try {
    sequence.rethrow_if_failed();
  } catch (const std::exception& error) {
    return error.what();
  }
  return {};
}

void attempt_step(ShutdownSequence& sequence,
                  std::vector<std::string_view>& observed,
                  std::size_t index,
                  std::size_t failed) {
  sequence.attempt([&] {
    observed.push_back(kSteps[index]);
    if (index == failed) {
      seastar::make_exception_future<>(
          std::runtime_error(std::string{kSteps[index]})).get();
    }
    seastar::make_ready_future<>().get();
  });
}

void test_single_failure_matrix() {
  for (std::size_t failed = 0U; failed < kSteps.size(); ++failed) {
    ShutdownSequence sequence;
    std::vector<std::string_view> observed;
    for (std::size_t index = 0U; index < kSteps.size(); ++index) {
      attempt_step(sequence, observed, index, failed);
    }
    require(sequence.failed(), "failed stop future was not preserved");
    require(observed.size() == kSteps.size(),
            "failed stop future skipped an owned stop step");
    require(std::equal(observed.begin(), observed.end(), kSteps.begin()),
            "shutdown order changed after a failed future");
    require(exception_message(sequence) == kSteps[failed],
            "shutdown did not preserve the injected failure");
  }
}

void test_clean_sequence() {
  ShutdownSequence sequence;
  std::vector<std::string_view> observed;
  for (std::size_t index = 0U; index < kSteps.size(); ++index) {
    sequence.attempt([&, index] {
      observed.push_back(kSteps[index]);
      seastar::make_ready_future<>().get();
    });
  }
  require(!sequence.failed(), "successful shutdown reported a failure");
  require(std::equal(observed.begin(), observed.end(), kSteps.begin()),
          "successful shutdown order changed");
  sequence.rethrow_if_failed();
}

void test_first_failure_and_reporting() {
  ShutdownSequence sequence{
      std::make_exception_ptr(std::runtime_error("runtime-first"))};
  std::vector<std::string_view> observed;
  for (std::size_t index = 0U; index < 4U; ++index) {
    sequence.attempt([&, index] {
      observed.push_back(kSteps[index]);
      if (index == 1U) {
        seastar::make_exception_future<>(
            std::runtime_error("metrics-second")).get();
      }
    });
  }
  require(sequence.failed(), "initial runtime failure was lost");
  sequence.attempt([&] {
    observed.push_back("failure-report");
    throw std::runtime_error("report-third");
  });
  sequence.attempt([&] {
    observed.push_back(kSteps.back());
    seastar::make_exception_future<>(
        std::runtime_error("logging-fourth")).get();
  });
  require(observed.size() == 6U,
          "reporting failure skipped logging teardown");
  require(observed[4] == "failure-report" && observed[5] == kSteps.back(),
          "failure reporting did not precede logging teardown");
  require(exception_message(sequence) == "runtime-first",
          "later failures replaced the original runtime failure");
}

void test_first_stop_failure_wins() {
  ShutdownSequence sequence;
  unsigned later_calls = 0U;
  sequence.attempt([] {
    seastar::make_exception_future<>(std::runtime_error("first-stop")).get();
  });
  sequence.attempt([] {
    seastar::make_exception_future<>(std::logic_error("second-stop")).get();
  });
  sequence.attempt([&later_calls] {
    ++later_calls;
    seastar::make_ready_future<>().get();
  });
  require(later_calls == 1U, "multiple failures skipped final cleanup");
  require(exception_message(sequence) == "first-stop",
          "later stop failure replaced the first stop failure");
}

seastar::future<> run() {
  test_clean_sequence();
  test_single_failure_matrix();
  test_first_failure_and_reporting();
  test_first_stop_failure_wins();
  std::cout << "{\"status\":\"passed\",\"groups\":[\"clean_order\","
               "\"stop_future_matrix\",\"failure_report_before_logging_stop\","
               "\"first_failure_preserved\"],\"assertions\":"
            << assertions << "}\n";
  co_return;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    seastar::app_template app;
    return app.run(argc, argv, &run);
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
