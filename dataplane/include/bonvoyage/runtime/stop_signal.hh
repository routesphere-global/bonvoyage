#pragma once

#include <csignal>

#include <seastar/core/condition-variable.hh>
#include <seastar/core/future.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/signal.hh>

namespace bonvoyage::runtime {

/**
 * @brief Converts process termination signals into a Seastar future.
 *
 * A StopSignal instance must live on the shard where its handlers are
 * installed and must outlive the future returned by wait(). The first
 * SIGINT or SIGTERM broadcasts the stop condition; later signals are ignored.
 */
class StopSignal final {
 public:
  /** Installs one-shot process shutdown handlers on the current shard. */
  StopSignal() {
    seastar::handle_signal(SIGINT, [this] { signal(); });
    seastar::handle_signal(SIGTERM, [this] { signal(); });
  }

  /** Stop handlers are bound to this instance and cannot be copied. */
  StopSignal(const StopSignal&) = delete;

  /** Stop handlers are bound to this instance and cannot be copied. */
  StopSignal& operator=(const StopSignal&) = delete;

  /** Stop handlers are bound to this instance and cannot be moved. */
  StopSignal(StopSignal&&) = delete;

  /** Stop handlers are bound to this instance and cannot be moved. */
  StopSignal& operator=(StopSignal&&) = delete;

  /** Replaces installed handlers with no-op callbacks before destruction. */
  ~StopSignal() {
    // Seastar cannot unregister handlers, so detach them from this instance.
    seastar::handle_signal(SIGINT, [] {});
    seastar::handle_signal(SIGTERM, [] {});
  }

  /** @return A future resolved after SIGINT or SIGTERM is observed. */
  [[nodiscard]] seastar::future<> wait() {
    return condition_.wait([this] { return stopping_; });
  }

  /** @return True once shutdown has been requested. */
  [[nodiscard]] bool stopping() const noexcept { return stopping_; }

 private:
  void signal() noexcept {
    if (stopping_) {
      return;
    }

    stopping_ = true;
    condition_.broadcast();
  }

  bool stopping_{false};
  seastar::condition_variable condition_;
};

}  // namespace bonvoyage::runtime
