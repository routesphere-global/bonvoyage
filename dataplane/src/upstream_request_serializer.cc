#include "bonvoyage/http/upstream_request_serializer.hh"

#include <cstring>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string_view>

namespace bonvoyage::http {

namespace {

bool is_token_character(unsigned char character) noexcept {
  if ((character >= '0' && character <= '9') ||
      (character >= 'A' && character <= 'Z') ||
      (character >= 'a' && character <= 'z')) {
    return true;
  }
  constexpr std::string_view punctuation{"!#$%&'*+-.^_`|~"};
  return punctuation.find(static_cast<char>(character)) !=
         std::string_view::npos;
}

void validate_method(std::string_view method) {
  if (method.empty()) {
    throw std::invalid_argument("upstream request method is empty");
  }
  for (const auto character : method) {
    if (!is_token_character(static_cast<unsigned char>(character))) {
      throw std::invalid_argument(
          "upstream request method contains an invalid byte");
    }
  }
}

void validate_target(std::string_view target) {
  if (target.empty()) {
    throw std::invalid_argument("upstream request target is empty");
  }
  for (const auto character : target) {
    const auto byte = static_cast<unsigned char>(character);
    if (byte <= 0x20U || byte == 0x7fU) {
      throw std::invalid_argument(
          "upstream request target contains an invalid byte");
    }
  }
}

void validate_header(std::string_view name, std::string_view value) {
  if (name.empty()) {
    throw std::invalid_argument("upstream request header name is empty");
  }
  for (const auto character : name) {
    if (!is_token_character(static_cast<unsigned char>(character))) {
      throw std::invalid_argument(
          "upstream request header name contains an invalid byte");
    }
  }
  for (const auto character : value) {
    const auto byte = static_cast<unsigned char>(character);
    if ((byte < 0x20U && byte != '\t') || byte == 0x7fU) {
      throw std::invalid_argument(
          "upstream request header value contains an invalid byte");
    }
  }
}

void checked_add(std::size_t& total, std::size_t amount) {
  if (amount > std::numeric_limits<std::size_t>::max() - total) {
    throw std::length_error("upstream request head size overflow");
  }
  total += amount;
}

void append(char*& output, std::string_view value) noexcept {
  std::memcpy(output, value.data(), value.size());
  output += value.size();
}

}  // namespace

seastar::temporary_buffer<char> serialize_upstream_request_head(
    const seastar::http::request& request) {
  const std::string_view method{request._method.data(), request._method.size()};
  if (request._version != "1.1") {
    throw std::invalid_argument(
        "optimized upstream client requires HTTP/1.1 requests");
  }

  std::optional<seastar::sstring> formatted_target;
  std::string_view target{request._url.data(), request._url.size()};
  if (!request.query_parameters.empty()) {
    formatted_target.emplace(request.format_url());
    target = {formatted_target->data(), formatted_target->size()};
  }
  validate_method(method);
  validate_target(target);

  std::size_t size = 0U;
  checked_add(size, method.size());
  checked_add(size, 1U);
  checked_add(size, target.size());
  checked_add(size, 6U);
  checked_add(size, request._version.size());
  checked_add(size, 2U);
  for (const auto& [name_storage, value_storage] : request._headers) {
    const std::string_view name{name_storage.data(), name_storage.size()};
    const std::string_view value{value_storage.data(), value_storage.size()};
    validate_header(name, value);
    checked_add(size, name.size());
    checked_add(size, 2U);
    checked_add(size, value.size());
    checked_add(size, 2U);
  }
  checked_add(size, 2U);

  seastar::temporary_buffer<char> result(size);
  auto* output = result.get_write();
  append(output, method);
  append(output, " ");
  append(output, target);
  append(output, " HTTP/");
  append(output,
         {request._version.data(), request._version.size()});
  append(output, "\r\n");
  for (const auto& [name_storage, value_storage] : request._headers) {
    append(output, {name_storage.data(), name_storage.size()});
    append(output, ": ");
    append(output, {value_storage.data(), value_storage.size()});
    append(output, "\r\n");
  }
  append(output, "\r\n");
  return result;
}

}  // namespace bonvoyage::http
