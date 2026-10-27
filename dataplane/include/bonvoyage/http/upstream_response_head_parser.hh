#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <llhttp.h>

#include "bonvoyage/http/header_view.hh"

namespace bonvoyage::http {

/** Strict parser failure at the untrusted upstream HTTP/1 boundary. */
class UpstreamResponseHeadError final : public std::runtime_error {
 public:
  /** Constructs a stable parser rejection. */
  explicit UpstreamResponseHeadError(const std::string& message)
      : std::runtime_error(message) {}
};

/** Borrowed response metadata valid while the source head bytes remain alive. */
struct ParsedUpstreamResponseHead final {
  /** HTTP status code parsed from the status line. */
  std::uint16_t status{};

  /** Parsed HTTP major version. */
  std::uint8_t http_major{};

  /** Parsed HTTP minor version. */
  std::uint8_t http_minor{};

  /** Optional reason phrase borrowed from the input. */
  std::string_view reason;

  /** Ordered fields, including duplicates, borrowed from the input. */
  std::span<const HeaderView> headers;

  /** Bytes through the final CRLF terminating the response head. */
  std::size_t bytes_consumed{};

  /** Strict parser assessment of connection persistence. */
  bool keep_alive{false};
};

/**
 * Allocation-stable one-shot llhttp response-head parser.
 *
 * One parser is intended to be retained by a shard-local connection. Header
 * storage is reserved once and reused. Successful results borrow the supplied
 * contiguous bytes and must be consumed before that storage is released.
 */
class UpstreamResponseHeadParser final {
 public:
  /** Constructs a parser with explicit byte and field-count bounds. */
  UpstreamResponseHeadParser(std::size_t max_header_bytes,
                             std::size_t max_header_fields);

  /**
   * Parses a response head, returning no value when more bytes are required.
   *
   * The parser is deliberately strict: no llhttp leniency option is enabled.
   */
  [[nodiscard]] std::optional<ParsedUpstreamResponseHead> parse(
      std::string_view input);

 private:
  struct Slice final {
    const char* data{};
    std::size_t size{};
    bool started{false};
  };

  enum class CallbackError {
    none,
    noncontiguous_span,
    too_many_fields,
    incomplete_field,
    ambiguous_framing
  };

  static int on_status(llhttp_t* parser, const char* data,
                       std::size_t size) noexcept;
  static int on_header_field(llhttp_t* parser, const char* data,
                             std::size_t size) noexcept;
  static int on_header_value(llhttp_t* parser, const char* data,
                             std::size_t size) noexcept;
  static int on_header_value_complete(llhttp_t* parser) noexcept;
  static int on_headers_complete(llhttp_t* parser) noexcept;

  static UpstreamResponseHeadParser& owner(llhttp_t* parser) noexcept;
  int append(Slice& slice, const char* data, std::size_t size) noexcept;
  int reject(CallbackError error, const char* reason) noexcept;
  void reset() noexcept;
  [[nodiscard]] std::string_view view(const Slice& slice) const noexcept;

  std::size_t max_header_bytes_;
  std::size_t max_header_fields_;
  llhttp_settings_t settings_{};
  llhttp_t parser_{};
  Slice reason_;
  Slice field_name_;
  Slice field_value_;
  std::vector<HeaderView> headers_;
  CallbackError callback_error_{CallbackError::none};
  bool content_length_seen_{false};
  bool transfer_encoding_seen_{false};
  bool headers_complete_{false};
};

}  // namespace bonvoyage::http
