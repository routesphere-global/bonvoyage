#include "bonvoyage/http/upstream_response_head_parser.hh"

#include <algorithm>
#include <limits>
#include <string>

namespace bonvoyage::http {

namespace {

constexpr auto kNoncontiguousSpan =
    "llhttp returned a noncontiguous response-head span";
constexpr auto kTooManyFields =
    "upstream response contains too many header fields";
constexpr auto kIncompleteField =
    "upstream response contains an incomplete header field";
constexpr auto kAmbiguousFraming =
    "upstream response contains ambiguous framing headers";

bool ascii_case_equal(std::string_view left,
                      std::string_view right) noexcept {
  if (left.size() != right.size()) {
    return false;
  }
  for (std::size_t index = 0U; index < left.size(); ++index) {
    auto left_byte = static_cast<unsigned char>(left[index]);
    auto right_byte = static_cast<unsigned char>(right[index]);
    if (left_byte >= 'A' && left_byte <= 'Z') {
      left_byte = static_cast<unsigned char>(left_byte + ('a' - 'A'));
    }
    if (right_byte >= 'A' && right_byte <= 'Z') {
      right_byte = static_cast<unsigned char>(right_byte + ('a' - 'A'));
    }
    if (left_byte != right_byte) {
      return false;
    }
  }
  return true;
}

}  // namespace

UpstreamResponseHeadParser::UpstreamResponseHeadParser(
    std::size_t max_header_bytes, std::size_t max_header_fields)
    : max_header_bytes_(max_header_bytes),
      max_header_fields_(max_header_fields) {
  if (max_header_bytes_ == 0U) {
    throw std::invalid_argument("upstream response-head byte limit is zero");
  }
  if (max_header_fields_ == 0U) {
    throw std::invalid_argument("upstream response field-count limit is zero");
  }
  headers_.reserve(max_header_fields_);
  llhttp_settings_init(&settings_);
  settings_.on_status = &UpstreamResponseHeadParser::on_status;
  settings_.on_header_field = &UpstreamResponseHeadParser::on_header_field;
  settings_.on_header_value = &UpstreamResponseHeadParser::on_header_value;
  settings_.on_header_value_complete =
      &UpstreamResponseHeadParser::on_header_value_complete;
  settings_.on_headers_complete =
      &UpstreamResponseHeadParser::on_headers_complete;
  reset();
}

std::optional<ParsedUpstreamResponseHead>
UpstreamResponseHeadParser::parse(std::string_view input) {
  reset();
  const auto parse_bytes = std::min(input.size(), max_header_bytes_);
  const auto result = llhttp_execute(&parser_, input.data(), parse_bytes);
  if (result == HPE_OK && !headers_complete_) {
    if (input.size() >= max_header_bytes_) {
      throw UpstreamResponseHeadError(
          "upstream response head exceeds the configured byte limit");
    }
    return std::nullopt;
  }
  if (result != HPE_PAUSED || !headers_complete_) {
    const auto* reason = llhttp_get_error_reason(&parser_);
    const auto* name = llhttp_errno_name(result);
    std::string message{"invalid upstream HTTP/1 response head: "};
    message.append(name != nullptr ? name : "unknown parser error");
    if (reason != nullptr) {
      message.append(" (");
      message.append(reason);
      message.push_back(')');
    }
    throw UpstreamResponseHeadError(message);
  }

  const auto* error_position = llhttp_get_error_pos(&parser_);
  if (error_position == nullptr || error_position < input.data() ||
      error_position > input.data() + input.size()) {
    throw UpstreamResponseHeadError(
        "llhttp returned an invalid response-head boundary");
  }
  const auto consumed =
      static_cast<std::size_t>(error_position - input.data());
  if (consumed > max_header_bytes_) {
    throw UpstreamResponseHeadError(
        "upstream response head exceeds the configured byte limit");
  }
  const auto status = llhttp_get_status_code(&parser_);
  if (status < 100 || status > 999 ||
      status > static_cast<int>(std::numeric_limits<std::uint16_t>::max())) {
    throw UpstreamResponseHeadError("invalid upstream HTTP status code");
  }

  return ParsedUpstreamResponseHead{
      static_cast<std::uint16_t>(status),
      llhttp_get_http_major(&parser_),
      llhttp_get_http_minor(&parser_),
      view(reason_),
      std::span<const HeaderView>{headers_},
      consumed,
      llhttp_should_keep_alive(&parser_) != 0};
}

int UpstreamResponseHeadParser::on_status(
    llhttp_t* parser, const char* data, std::size_t size) noexcept {
  auto& self = owner(parser);
  return self.append(self.reason_, data, size);
}

int UpstreamResponseHeadParser::on_header_field(
    llhttp_t* parser, const char* data, std::size_t size) noexcept {
  auto& self = owner(parser);
  return self.append(self.field_name_, data, size);
}

int UpstreamResponseHeadParser::on_header_value(
    llhttp_t* parser, const char* data, std::size_t size) noexcept {
  auto& self = owner(parser);
  return self.append(self.field_value_, data, size);
}

int UpstreamResponseHeadParser::on_header_value_complete(
    llhttp_t* parser) noexcept {
  auto& self = owner(parser);
  if (!self.field_name_.started) {
    return self.reject(CallbackError::incomplete_field, kIncompleteField);
  }
  if (self.headers_.size() >= self.max_header_fields_) {
    return self.reject(CallbackError::too_many_fields, kTooManyFields);
  }
  const auto name = self.view(self.field_name_);
  const auto value = self.view(self.field_value_);
  if (ascii_case_equal(name, "Content-Length")) {
    if (self.content_length_seen_ || self.transfer_encoding_seen_ ||
        value.empty()) {
      return self.reject(CallbackError::ambiguous_framing,
                         kAmbiguousFraming);
    }
    self.content_length_seen_ = true;
  } else if (ascii_case_equal(name, "Transfer-Encoding")) {
    if (self.transfer_encoding_seen_ || self.content_length_seen_ ||
        value.empty()) {
      return self.reject(CallbackError::ambiguous_framing,
                         kAmbiguousFraming);
    }
    self.transfer_encoding_seen_ = true;
  }
  self.headers_.push_back(
      HeaderView{name, value});
  self.field_name_ = {};
  self.field_value_ = {};
  return HPE_OK;
}

int UpstreamResponseHeadParser::on_headers_complete(
    llhttp_t* parser) noexcept {
  auto& self = owner(parser);
  if (self.field_name_.started || self.field_value_.started) {
    return self.reject(CallbackError::incomplete_field, kIncompleteField);
  }
  self.headers_complete_ = true;
  return HPE_PAUSED;
}

UpstreamResponseHeadParser& UpstreamResponseHeadParser::owner(
    llhttp_t* parser) noexcept {
  return *static_cast<UpstreamResponseHeadParser*>(parser->data);
}

int UpstreamResponseHeadParser::append(
    Slice& slice, const char* data, std::size_t size) noexcept {
  if (size == 0U) {
    return HPE_OK;
  }
  if (!slice.started) {
    slice = Slice{data, size, true};
    return HPE_OK;
  }
  if (slice.data + slice.size != data) {
    return reject(CallbackError::noncontiguous_span, kNoncontiguousSpan);
  }
  slice.size += size;
  return HPE_OK;
}

int UpstreamResponseHeadParser::reject(
    CallbackError error, const char* reason) noexcept {
  callback_error_ = error;
  llhttp_set_error_reason(&parser_, reason);
  return HPE_USER;
}

void UpstreamResponseHeadParser::reset() noexcept {
  reason_ = {};
  field_name_ = {};
  field_value_ = {};
  headers_.clear();
  callback_error_ = CallbackError::none;
  content_length_seen_ = false;
  transfer_encoding_seen_ = false;
  headers_complete_ = false;
  llhttp_init(&parser_, HTTP_RESPONSE, &settings_);
  parser_.data = this;
}

std::string_view UpstreamResponseHeadParser::view(
    const Slice& slice) const noexcept {
  if (!slice.started) {
    return {};
  }
  return {slice.data, slice.size};
}

}  // namespace bonvoyage::http
