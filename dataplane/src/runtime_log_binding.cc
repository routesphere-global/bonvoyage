#include "bonvoyage/runtime/runtime_log_binding.hh"

#include <atomic>
#include <stdexcept>

namespace bonvoyage::runtime {
namespace {

// Trivial process/thread lifetime state remains valid after owner teardown.
thread_local RuntimeLogBinding* owner = nullptr;
constinit std::atomic<std::uint64_t> unbound_drops{0U};
static_assert(std::atomic<std::uint64_t>::is_always_lock_free);

}  // namespace

bool install_runtime_log_dispatcher() noexcept {
  static const seastar::custom_log_sink dispatcher{
      &RuntimeLogBinding::consume, nullptr, kRuntimeLogFormatLimit};
  return seastar::logger::install_custom_sink(&dispatcher);
}

std::uint64_t runtime_log_unbound_drops() noexcept {
  return unbound_drops.load(std::memory_order_relaxed);
}

RuntimeLogBinding::RuntimeLogBinding(RuntimeLogSink& sink) : sink_(sink) {
  if (owner != nullptr || sink.stats().active == 0U) {
    throw std::logic_error("runtime logger requires one active owner-thread sink");
  }
  owner = this;
}

RuntimeLogBinding::~RuntimeLogBinding() { detach(); }

bool RuntimeLogBinding::detach() noexcept {
  if (std::this_thread::get_id() != owner_thread_) {
    return false;
  }
  if (owner == this) {
    owner = nullptr;
  }
  return true;
}

void RuntimeLogBinding::consume(void*, seastar::log_level level,
                                std::string_view message,
                                seastar::log_record_status status) noexcept {
  if (owner == nullptr) {
    unbound_drops.fetch_add(1U, std::memory_order_relaxed);
    return;
  }
  auto& binding = *owner;
  ++binding.stats_.received;
  if (status == seastar::log_record_status::overflow) {
    ++binding.stats_.format_overflow_drops;
    return;
  }
  if (status != seastar::log_record_status::complete) {
    ++binding.stats_.format_error_drops;
    return;
  }
  RuntimeLogSeverity severity;
  // Seastar error is ordinal zero, not syslog emergency. Never cast ordinals.
  switch (level) {
    case seastar::log_level::error: severity = RuntimeLogSeverity::error; break;
    case seastar::log_level::warn: severity = RuntimeLogSeverity::warning; break;
    case seastar::log_level::info: severity = RuntimeLogSeverity::info; break;
    case seastar::log_level::debug:
    case seastar::log_level::trace: severity = RuntimeLogSeverity::debug; break;
    default:
      ++binding.stats_.invalid_severity_drops;
      return;
  }
  (void)binding.sink_.enqueue(severity, message);
}

}  // namespace bonvoyage::runtime
