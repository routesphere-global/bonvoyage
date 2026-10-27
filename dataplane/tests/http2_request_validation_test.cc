#include <cstdlib>
#include <iostream>
#include <string_view>
#include <vector>

#include "bonvoyage/http/http1_validation.hh"
#include "bonvoyage/http/http2_request_validation.hh"

namespace {

using bonvoyage::http::Http2Header;

void require(bool condition, const char* message) {
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

[[nodiscard]] std::vector<Http2Header> valid_headers() {
  return {{":method", "POST", false},
          {":scheme", "https", false},
          {":authority", "api.example.test", false},
          {":path", "/upload?part=1", false},
          {"content-type", "application/json", false},
          {"content-length", "2", false}};
}

template <typename Mutation>
void require_rejected(Mutation mutation, std::string_view expected_code,
                      const char* message) {
  auto headers = valid_headers();
  mutation(headers);
  try {
    (void)bonvoyage::http::validate_http2_request_headers(headers, false,
                                                          1024U);
  } catch (const bonvoyage::http::RequestError& error) {
    require(error.code() == expected_code, message);
    require(!error.close_connection(),
            "HTTP/2 request error incorrectly closed the connection");
    return;
  }
  require(false, message);
}

}  // namespace

int main() {
  const auto parsed = bonvoyage::http::validate_http2_request_headers(
      valid_headers(), false, 1024U);
  require(parsed.method == "POST" && parsed.scheme == "https",
          "HTTP/2 method or scheme changed");
  require(parsed.authority == "api.example.test" &&
              parsed.path == "/upload?part=1",
          "HTTP/2 authority or path changed");
  require(parsed.content_length == 2U,
          "HTTP/2 Content-Length was not prepared");

  require_rejected(
      [](auto& headers) {
        headers.push_back({":method", "GET", false});
      },
      "pseudo_header_order", "late HTTP/2 pseudo-header was accepted");
  require_rejected(
      [](auto& headers) { headers[1].value = "http"; }, "invalid_scheme",
      "insecure HTTP/2 scheme was accepted");
  require_rejected(
      [](auto& headers) {
        headers.push_back({"connection", "close", false});
      },
      "connection_header_forbidden",
      "connection-specific HTTP/2 header was accepted");
  require_rejected(
      [](auto& headers) { headers.back().value = "2048"; },
      "request_body_too_large", "oversized HTTP/2 body was accepted");
  require_rejected(
      [](auto& headers) {
        headers.push_back({"host", "other.example.test", false});
      },
      "host_authority_mismatch",
      "conflicting HTTP/2 Host and authority were accepted");
  require_rejected(
      [](auto& headers) { headers[2].value = "api.example.test:0"; },
      "invalid_authority", "zero-port HTTP/2 authority was accepted");
  require_rejected(
      [](auto& headers) { headers[2].value = "2001:db8::10"; },
      "invalid_authority", "unbracketed HTTP/2 IPv6 authority was accepted");
  require_rejected(
      [](auto& headers) { headers[2].value = "[1:2:3]"; },
      "invalid_authority", "malformed bracketed HTTP/2 IPv6 was accepted");
  require_rejected(
      [](auto& headers) { headers[2].value = "api..example.test"; },
      "invalid_authority", "malformed HTTP/2 DNS authority was accepted");
  require_rejected(
      [](auto& headers) { headers.push_back({"te", "gzip", false}); },
      "invalid_te_header", "invalid HTTP/2 TE value was accepted");

  bool ended_body_rejected = false;
  try {
    (void)bonvoyage::http::validate_http2_request_headers(
        valid_headers(), true, 1024U);
  } catch (const bonvoyage::http::RequestError& error) {
    ended_body_rejected = error.code() == "content_length_mismatch";
  }
  require(ended_body_rejected,
          "ended HTTP/2 stream with a body length was accepted");
  return 0;
}
