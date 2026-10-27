#pragma once

#include <exception>
#include <utility>

namespace bonvoyage::runtime {

/**
 * Preserve the first lifecycle failure while attempting every remaining stop.
 *
 * Callers must synchronously observe each asynchronous stop operation inside
 * the callback. This coordinator is used only during process teardown, never
 * on the request path.
 */
class ShutdownSequence final {
 public:
  /** Seed teardown with an earlier startup or runtime failure, if present. */
  explicit ShutdownSequence(std::exception_ptr first_failure = nullptr) noexcept
      : first_failure_(std::move(first_failure)) {}

  /** Run one stop step and retain its exception only when it is the first. */
  template <typename Stop>
  void attempt(Stop&& stop) noexcept {
    try {
      std::forward<Stop>(stop)();
    } catch (...) {
      preserve(std::current_exception());
    }
  }

  /** True when startup or any attempted shutdown step failed. */
  [[nodiscard]] bool failed() const noexcept {
    return first_failure_ != nullptr;
  }

  /** The preserved failure for bounded diagnostic reporting before teardown. */
  [[nodiscard]] const std::exception_ptr& failure() const noexcept {
    return first_failure_;
  }

  /** Rethrow the preserved first failure after all owned steps were attempted. */
  void rethrow_if_failed() const {
    if (first_failure_ != nullptr) {
      std::rethrow_exception(first_failure_);
    }
  }

 private:
  void preserve(std::exception_ptr failure) noexcept {
    if (first_failure_ == nullptr) {
      first_failure_ = std::move(failure);
    }
  }

  std::exception_ptr first_failure_;
};

}  // namespace bonvoyage::runtime
