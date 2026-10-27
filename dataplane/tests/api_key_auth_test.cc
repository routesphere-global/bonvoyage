#include "bonvoyage/runtime/api_key_auth.hh"

#include <array>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

using bonvoyage::runtime::ApiKeyCredentialSet;
using bonvoyage::runtime::ApiKeyPepper;

void require(bool condition, std::string_view message) {
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

template <typename Callback>
void require_invalid(Callback&& callback, std::string_view message) {
  try {
    callback();
  } catch (const std::invalid_argument&) {
    return;
  }
  require(false, message);
}

}  // namespace

int main() {
  ApiKeyPepper pepper{};
  for (std::size_t index = 0U; index < pepper.size(); ++index) {
    pepper[index] = static_cast<std::uint8_t>(index + 1U);
  }

  const auto credentials = ApiKeyCredentialSet::compile(
      "bv_live_AAAAAAAAAAAAAAAAAAAAAAAA\n"
      "bv_live_BBBBBBBBBBBBBBBBBBBBBBBB\r\n",
      pepper);
  require(credentials.size() == 2U, "credential count is incorrect");
  require(credentials.authorizes("bv_live_AAAAAAAAAAAAAAAAAAAAAAAA"),
          "first credential was rejected");
  require(credentials.authorizes("bv_live_BBBBBBBBBBBBBBBBBBBBBBBB"),
          "second credential was rejected");
  require(!credentials.authorizes("bv_live_CCCCCCCCCCCCCCCCCCCCCCCC"),
          "unknown credential was accepted");
  require(!credentials.authorizes("too-short"),
          "short credential was accepted");
  require(!credentials.authorizes(
              "bv_live_AAAAAAAAAAAAAAAAAAAAAAAA,bv_live_other"),
          "comma-joined credential was accepted");

  require_invalid(
      [&] { (void)ApiKeyCredentialSet::compile("", pepper); },
      "empty credential file was accepted");
  require_invalid(
      [&] {
        (void)ApiKeyCredentialSet::compile(
            "bv_live_AAAAAAAAAAAAAAAAAAAAAAAA\n\n", pepper);
      },
      "blank credential record was accepted");
  require_invalid(
      [&] {
        (void)ApiKeyCredentialSet::compile(
            "bv_live_AAAAAAAAAAAAAAAAAAAAAAAA\n"
            "bv_live_AAAAAAAAAAAAAAAAAAAAAAAA\n",
            pepper);
      },
      "duplicate credential was accepted");
  require_invalid(
      [&] {
        (void)ApiKeyCredentialSet::compile(
            "bv_live_AAAAAAAAAAAAAAAAAAAAAAAA with-space\n", pepper);
      },
      "credential containing whitespace was accepted");

  std::string too_many;
  for (std::size_t index = 0U; index < 65U; ++index) {
    too_many += "bv_static_" + std::to_string(100000U + index) +
                "_AAAAAAAAAAAAAAAA\n";
  }
  require_invalid(
      [&] { (void)ApiKeyCredentialSet::compile(too_many, pepper); },
      "credential-count bound was not enforced");

  std::string sensitive{"bv_live_sensitive_material_123456"};
  bonvoyage::runtime::secure_erase(sensitive);
  require(sensitive.empty(), "plaintext buffer was not cleared");
  std::array<char, 4U> sensitive_bytes{'k', 'e', 'y', '!'};
  bonvoyage::runtime::secure_erase(std::span<char>{sensitive_bytes});
  require(sensitive_bytes == std::array<char, 4U>{},
          "plaintext byte range was not erased");
  require(bonvoyage::runtime::generate_api_key_pepper() != ApiKeyPepper{},
          "generated pepper was all zero");
  return 0;
}
