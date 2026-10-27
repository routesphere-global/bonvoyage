#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>

#include "bonvoyage/http/upstream_response_head_parser.hh"

namespace {

using bonvoyage::http::UpstreamResponseHeadError;
using bonvoyage::http::UpstreamResponseHeadParser;

void require(bool condition) {
  if (!condition) {
    throw std::runtime_error("upstream response-head parser test failed");
  }
}

void expect_rejected(std::string_view input) {
  UpstreamResponseHeadParser parser{4096U, 32U};
  bool rejected = false;
  try {
    static_cast<void>(parser.parse(input));
  } catch (const UpstreamResponseHeadError&) {
    rejected = true;
  }
  require(rejected);
}

void test_valid_response() {
  constexpr std::string_view input =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 5\r\n"
      "X-Test: alpha\r\n"
      "\r\n"
      "hello";
  UpstreamResponseHeadParser parser{4096U, 32U};
  const auto parsed = parser.parse(input);
  require(parsed.has_value());
  require(parsed->status == 200U);
  require(parsed->http_major == 1U);
  require(parsed->http_minor == 1U);
  require(parsed->reason == "OK");
  require(parsed->headers.size() == 2U);
  require(parsed->headers[0].name == "Content-Length");
  require(parsed->headers[0].value == "5");
  require(parsed->headers[1].name == "X-Test");
  require(parsed->headers[1].value == "alpha");
  require(parsed->bytes_consumed == input.size() - 5U);
  require(parsed->keep_alive);
}

void test_incomplete_response() {
  UpstreamResponseHeadParser parser{4096U, 32U};
  const auto parsed = parser.parse(
      "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n");
  require(!parsed.has_value());
}

void test_duplicates_are_preserved() {
  constexpr std::string_view input =
      "HTTP/1.1 200 OK\r\n"
      "Set-Cookie: a=1\r\n"
      "Set-Cookie: b=2\r\n"
      "Content-Length: 0\r\n"
      "\r\n";
  UpstreamResponseHeadParser parser{4096U, 32U};
  const auto parsed = parser.parse(input);
  require(parsed.has_value());
  require(parsed->headers.size() == 3U);
  require(parsed->headers[0].name == "Set-Cookie");
  require(parsed->headers[0].value == "a=1");
  require(parsed->headers[1].name == "Set-Cookie");
  require(parsed->headers[1].value == "b=2");
}

void test_informational_and_close() {
  UpstreamResponseHeadParser parser{4096U, 32U};
  const auto informational = parser.parse("HTTP/1.1 103 Early Hints\r\n\r\n");
  require(informational.has_value());
  require(informational->status == 103U);

  const auto closing = parser.parse(
      "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
  require(closing.has_value());
  require(!closing->keep_alive);
}

void test_explicit_bounds() {
  UpstreamResponseHeadParser field_bounded{4096U, 1U};
  bool fields_rejected = false;
  try {
    static_cast<void>(field_bounded.parse(
        "HTTP/1.1 200 OK\r\nX-A: 1\r\nX-B: 2\r\n\r\n"));
  } catch (const UpstreamResponseHeadError&) {
    fields_rejected = true;
  }
  require(fields_rejected);

  UpstreamResponseHeadParser byte_bounded{24U, 8U};
  bool bytes_rejected = false;
  try {
    static_cast<void>(byte_bounded.parse(
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"));
  } catch (const UpstreamResponseHeadError&) {
    bytes_rejected = true;
  }
  require(bytes_rejected);
}

void test_body_bytes_do_not_count_toward_head_limit() {
  constexpr std::string_view head =
      "HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n";
  std::string input{head};
  input.append(4096U, 'x');

  UpstreamResponseHeadParser parser{64U, 8U};
  const auto parsed = parser.parse(input);
  require(parsed.has_value());
  require(parsed->bytes_consumed == head.size());
}

void test_websocket_upgrade_preserves_immediate_bytes() {
  constexpr std::string_view head =
      "HTTP/1.1 101 Switching Protocols\r\n"
      "Connection: Upgrade\r\n"
      "Upgrade: websocket\r\n"
      "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
      "\r\n";
  std::string input{head};
  input.append("\x81\x05ready", 7U);

  UpstreamResponseHeadParser parser{4096U, 32U};
  const auto parsed = parser.parse(input);
  require(parsed.has_value());
  require(parsed->status == 101U);
  require(parsed->bytes_consumed == head.size());
}

void test_strict_rejections() {
  expect_rejected("HTTP/1.1 200 OK\nContent-Length: 0\n\n");
  expect_rejected("HTTP/1.1 200 OK\r\n Folded: value\r\n\r\n");
  expect_rejected("HTTP/1.1 200 OK\r\nBad Name: value\r\n\r\n");
  expect_rejected("HTTP/1.1 200 OK\r\nContent-Length : 0\r\n\r\n");
  expect_rejected(
      "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n");
  expect_rejected(
      "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n");
  expect_rejected(
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n");
  expect_rejected("HTTP/1.1 200 OK\r\nTransfer-Encoding:\r\n\r\n");
  expect_rejected("HTTP/1.1 20 OK\r\nContent-Length: 0\r\n\r\n");

  std::string nul_value{"HTTP/1.1 200 OK\r\nX-Test: value"};
  nul_value.push_back('\0');
  nul_value.append("suffix\r\n\r\n");
  expect_rejected(nul_value);
}

}  // namespace

int main() {
  test_valid_response();
  test_incomplete_response();
  test_duplicates_are_preserved();
  test_informational_and_close();
  test_explicit_bounds();
  test_body_bytes_do_not_count_toward_head_limit();
  test_websocket_upgrade_preserves_immediate_bytes();
  test_strict_rejections();
  return 0;
}
