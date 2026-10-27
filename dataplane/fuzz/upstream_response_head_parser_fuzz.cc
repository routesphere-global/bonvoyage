#include <cstddef>
#include <cstdint>
#include <string_view>

#include "bonvoyage/http/upstream_response_head_parser.hh"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
  static bonvoyage::http::UpstreamResponseHeadParser parser{32768U, 128U};
  const auto input = std::string_view{
      reinterpret_cast<const char*>(data), size};
  try {
    static_cast<void>(parser.parse(input));
  } catch (const bonvoyage::http::UpstreamResponseHeadError&) {
    // Protocol rejection is an expected result for arbitrary untrusted bytes.
  }
  return 0;
}
