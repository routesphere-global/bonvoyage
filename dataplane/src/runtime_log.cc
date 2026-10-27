#include "bonvoyage/runtime/runtime_log.hh"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <stdexcept>
#include <system_error>
#include <utility>

#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace bonvoyage::runtime {
namespace {

// Logging must not overwrite the error that its caller is trying to report.
struct PreserveErrno final {
  int saved{errno};
  ~PreserveErrno() { errno = saved; }
};

RuntimeLogOptions checked_options(RuntimeLogOptions options) {
  validate_runtime_log_options(options);
  return options;
}

bool valid_severity(RuntimeLogSeverity severity) noexcept {
  switch (severity) {
    case RuntimeLogSeverity::error:
    case RuntimeLogSeverity::warning:
    case RuntimeLogSeverity::info:
    case RuntimeLogSeverity::debug:
      return true;
  }
  return false;
}

RuntimeLogSendResult classify_error(int error) noexcept {
  if (error == EAGAIN || error == EWOULDBLOCK || error == ENOBUFS ||
      error == EINTR) {
    return RuntimeLogSendResult::would_block;
  }
  if (error == ENOENT || error == ECONNREFUSED || error == ENOTCONN ||
      error == EACCES || error == EMFILE || error == ENFILE || error == ENOMEM) {
    return RuntimeLogSendResult::unavailable;
  }
  return RuntimeLogSendResult::failed;
}

}  // namespace

void validate_runtime_log_options(const RuntimeLogOptions& options) {
  if (options.queue_capacity == 0U || options.queue_capacity > 4096U ||
      options.max_record_bytes < 128U || options.max_record_bytes > 2048U ||
      options.drain_batch == 0U || options.drain_batch > 256U) {
    throw std::invalid_argument("runtime-log queue, record or batch outside bounds");
  }
}

RuntimeLogSink::RuntimeLogSink(RuntimeLogOptions options)
    : options_(checked_options(options)),
      records_(options_.queue_capacity),
      process_id_(static_cast<std::uint64_t>(::getpid())) {
  stats_.queue_capacity = options_.queue_capacity;
}

bool RuntimeLogSink::enqueue(RuntimeLogSeverity severity,
                            std::string_view message) noexcept {
  ++stats_.records_attempted;
  if (stats_.active == 0U) {
    ++stats_.stopped_drops;
  } else if (!valid_severity(severity)) {
    ++stats_.invalid_severities;
  } else if (size_ == records_.size()) {
    ++stats_.queue_overflows;
  } else if (message.size() > options_.max_record_bytes) {
    ++stats_.oversized_records;
  } else {
    auto& record = records_[(head_ + size_) % records_.size()];
    std::size_t used = 0U;
    const auto append = [&](std::string_view text) {
      if (text.size() > options_.max_record_bytes - used) {
        return false;
      }
      std::memcpy(record.bytes.data() + used, text.data(), text.size());
      used += text.size();
      return true;
    };
    std::array<char, 32U> number{};
    const auto priority = 8U + static_cast<unsigned>(severity);  // LOG_USER facility.
    const auto priority_end = std::to_chars(number.data(), number.data() + number.size(), priority).ptr;
    bool fits = append("<") && append({number.data(), static_cast<std::size_t>(priority_end - number.data())}) &&
                append(">bonvoyage[");
    const auto pid_end = std::to_chars(number.data(), number.data() + number.size(), process_id_).ptr;
    fits = fits && append({number.data(), static_cast<std::size_t>(pid_end - number.data())}) && append("]: ");
    // Escape control bytes as data, including NUL/newline/ESC. Drop an oversized
    // record whole instead of truncating its UTF-8 bytes or silently losing text.
    constexpr char hex[] = "0123456789abcdef";
    for (const char character : message) {
      if (!fits) {
        break;
      }
      const auto byte = static_cast<unsigned char>(character);
      if (byte < 0x20U || byte == 0x7fU || byte == '\\') {
        const std::array<char, 4U> escaped{'\\', 'x', hex[byte >> 4U], hex[byte & 0x0fU]};
        fits = append({escaped.data(), escaped.size()});
      } else {
        fits = append({&character, 1U});
      }
    }
    if (fits) {
      record.size = used;
      ++size_;
      ++stats_.records_enqueued;
      stats_.queue_depth = size_;
      stats_.queue_high_water = std::max(stats_.queue_high_water, stats_.queue_depth);
      return true;
    }
    ++stats_.oversized_records;
  }
  ++stats_.records_dropped;
  return false;
}

void RuntimeLogSink::drain(RuntimeLogSender sender, void* context) noexcept {
  if (sender == nullptr || draining_) {
    return;
  }
  // Defend queue indices even if an adapter accidentally reenters drain/stop.
  draining_ = true;
  struct ResetDrain final {
    bool& value;
    ~ResetDrain() { value = false; }
  } reset{draining_};
  for (std::size_t attempt = 0U; size_ != 0U && attempt < options_.drain_batch; ++attempt) {
    const auto& record = records_[head_];
    ++stats_.send_attempts;
    const auto result = sender(context, {record.bytes.data(), record.size});
    stats_.sink_healthy = result == RuntimeLogSendResult::sent ? 1U : 0U;
    if (result == RuntimeLogSendResult::would_block) {
      ++stats_.would_block_events;
      return;
    }
    if (result == RuntimeLogSendResult::unavailable) {
      ++stats_.unavailable_events;
      return;
    }
    if (result == RuntimeLogSendResult::sent) {
      ++stats_.records_sent;
      stats_.bytes_sent += record.size;
    } else {
      ++stats_.send_failure_drops;
      ++stats_.records_dropped;
    }
    head_ = (head_ + 1U) % records_.size();
    --size_;
    stats_.queue_depth = size_;
  }
}

void RuntimeLogSink::stop(RuntimeLogSender sender, void* context) noexcept {
  if (stats_.active == 0U || draining_) {
    return;
  }
  stats_.active = 0U;
  drain(sender, context);
  stats_.shutdown_drops += size_;
  stats_.records_dropped += size_;
  size_ = 0U;
  stats_.queue_depth = 0U;
}

UnixRuntimeLogTransport::UnixRuntimeLogTransport(std::string path)
    : path_(std::move(path)) {
  sockaddr_un address{};
  if (path_.empty() || path_.front() != '/' || path_.size() >= sizeof(address.sun_path) ||
      std::any_of(path_.begin(), path_.end(), [](unsigned char byte) {
        return byte < 0x20U || byte == 0x7fU;
      })) {
    throw std::invalid_argument("runtime-log destination must be a bounded absolute local socket path");
  }
}

UnixRuntimeLogTransport::~UnixRuntimeLogTransport() {
  const PreserveErrno preserved;
  if (fd_ >= 0) {
    ::close(fd_);
  }
}

RuntimeLogSendResult UnixRuntimeLogTransport::try_send(std::string_view record) noexcept {
  const PreserveErrno preserved;
  if (record.empty() || record.size() > 2048U) {
    last_error_ = EMSGSIZE;
    return RuntimeLogSendResult::failed;
  }
  if (fd_ < 0) {
    fd_ = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd_ < 0) {
      last_error_ = errno;
      return classify_error(last_error_);
    }
  }
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  std::memcpy(address.sun_path, path_.c_str(), path_.size() + 1U);
  const auto size = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + path_.size() + 1U);
  const auto sent = ::sendto(fd_, record.data(), record.size(), MSG_DONTWAIT | MSG_NOSIGNAL,
                             reinterpret_cast<const sockaddr*>(&address), size);
  if (sent < 0) {
    last_error_ = errno;
    return classify_error(last_error_);
  }
  if (static_cast<std::size_t>(sent) != record.size()) {
    last_error_ = EIO;
    return RuntimeLogSendResult::failed;
  }
  last_error_ = 0;
  return RuntimeLogSendResult::sent;
}

RuntimeLogSendResult UnixRuntimeLogTransport::send(void* context,
                                                  std::string_view record) noexcept {
  if (context == nullptr) {
    return RuntimeLogSendResult::failed;
  }
  return static_cast<UnixRuntimeLogTransport*>(context)->try_send(record);
}

PipeRuntimeLogTransport::PipeRuntimeLogTransport(int source_fd) {
  const PreserveErrno preserved;
  fd_ = ::fcntl(source_fd, F_DUPFD_CLOEXEC, 0);
  if (fd_ < 0) {
    throw std::system_error(errno, std::generic_category(), "runtime-log pipe duplicate");
  }
  try {
    struct stat status{};
    if (::fstat(fd_, &status) < 0) {
      throw std::system_error(errno, std::generic_category(), "runtime-log pipe fstat");
    }
    if (!S_ISFIFO(status.st_mode)) {
      throw std::invalid_argument("runtime-log descriptor is not a pipe/FIFO");
    }
    const long atomic_limit = ::fpathconf(fd_, _PC_PIPE_BUF);
    if (atomic_limit < 0) {
      throw std::system_error(errno, std::generic_category(), "runtime-log pipe PIPE_BUF");
    }
    if (atomic_limit < 2049) {
      throw std::invalid_argument("runtime-log pipe PIPE_BUF is below 2049");
    }
    const int flags = ::fcntl(fd_, F_GETFL);
    if (flags < 0) {
      throw std::system_error(errno, std::generic_category(), "runtime-log pipe flags");
    }
    if ((flags & O_ACCMODE) == O_RDONLY) {
      throw std::invalid_argument("runtime-log pipe descriptor is not writable");
    }
    if (::fcntl(fd_, F_SETFL, flags | O_NONBLOCK) < 0) {
      throw std::system_error(errno, std::generic_category(), "runtime-log pipe nonblocking");
    }
  } catch (...) {
    ::close(fd_);
    fd_ = -1;
    throw;
  }
}

PipeRuntimeLogTransport::~PipeRuntimeLogTransport() {
  const PreserveErrno preserved;
  if (fd_ >= 0) {
    ::close(fd_);
  }
}

RuntimeLogSendResult PipeRuntimeLogTransport::try_send(std::string_view record) noexcept {
  const PreserveErrno preserved;
  if (record.empty() || record.size() > 2048U) {
    last_error_ = EMSGSIZE;
    return RuntimeLogSendResult::failed;
  }
  if (fd_ < 0) {
    last_error_ = EBADF;
    return RuntimeLogSendResult::unavailable;
  }
  const int flags = ::fcntl(fd_, F_GETFL);
  if (flags < 0) {
    last_error_ = errno;
    return last_error_ == EBADF ? RuntimeLogSendResult::unavailable
                               : RuntimeLogSendResult::failed;
  }
  if ((flags & O_NONBLOCK) == 0) {
    last_error_ = EOPNOTSUPP;
    return RuntimeLogSendResult::failed;
  }

  std::array<char, 2049U> line{};
  std::size_t payload_size = record.size();
  while (payload_size != 0U && record[payload_size - 1U] == '\n') {
    --payload_size;
  }
  std::memcpy(line.data(), record.data(), payload_size);
  line[payload_size] = '\n';
  const std::size_t line_size = payload_size + 1U;

  sigset_t blocked{};
  ::sigemptyset(&blocked);
  ::sigaddset(&blocked, SIGPIPE);
  sigset_t previous{};
  const int mask_error = ::pthread_sigmask(SIG_BLOCK, &blocked, &previous);
  if (mask_error != 0) {
    last_error_ = mask_error;
    return RuntimeLogSendResult::failed;
  }
  sigset_t pending{};
  if (::sigpending(&pending) < 0) {
    last_error_ = errno;
    ::pthread_sigmask(SIG_SETMASK, &previous, nullptr);
    return RuntimeLogSendResult::failed;
  }
  const bool had_pending = ::sigismember(&pending, SIGPIPE) == 1;
  const ssize_t written = ::write(fd_, line.data(), line_size);
  const int write_error = written < 0 ? errno : 0;
  if (write_error == EPIPE && !had_pending) {
    const timespec zero{};
    ::sigtimedwait(&blocked, nullptr, &zero);
  }
  ::pthread_sigmask(SIG_SETMASK, &previous, nullptr);

  if (written < 0) {
    last_error_ = write_error;
    if (write_error == EAGAIN || write_error == EWOULDBLOCK || write_error == EINTR) {
      return RuntimeLogSendResult::would_block;
    }
    if (write_error == EPIPE || write_error == EBADF) {
      return RuntimeLogSendResult::unavailable;
    }
    return RuntimeLogSendResult::failed;
  }
  if (static_cast<std::size_t>(written) != line_size) {
    last_error_ = EIO;
    return RuntimeLogSendResult::failed;
  }
  last_error_ = 0;
  return RuntimeLogSendResult::sent;
}

RuntimeLogSendResult PipeRuntimeLogTransport::send(void* context,
                                                  std::string_view record) noexcept {
  if (context == nullptr) {
    return RuntimeLogSendResult::failed;
  }
  return static_cast<PipeRuntimeLogTransport*>(context)->try_send(record);
}

}  // namespace bonvoyage::runtime
