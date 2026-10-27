#include <stdexcept>
#include <string>
#include <string_view>

#include <seastar/http/request.hh>

#include "bonvoyage/http/upstream_request_serializer.hh"

namespace {

void require(bool condition) {
  if (!condition) {
    throw std::runtime_error("upstream request serializer test failed");
  }
}

std::string serialize(const seastar::http::request& request) {
  const auto serialized =
      bonvoyage::http::serialize_upstream_request_head(request);
  return {serialized.get(), serialized.size()};
}

void test_complete_request_head() {
  auto request = seastar::http::request::make(
      "POST", "payments.internal", "/v1/transfers?currency=SGD");
  request._version = "1.1";
  request._headers["Connection"] = "keep-alive";
  request._headers["Content-Length"] = "7";
  request._headers["X-Request-Id"] = "payment-42";

  const auto serialized = serialize(request);
  require(serialized.starts_with(
      "POST /v1/transfers?currency=SGD HTTP/1.1\r\n"));
  require(serialized.ends_with("\r\n\r\n"));
  require(serialized.find("Host: payments.internal\r\n") !=
          std::string::npos);
  require(serialized.find("Content-Length: 7\r\n") != std::string::npos);
  require(serialized.find("X-Request-Id: payment-42\r\n") !=
          std::string::npos);
}

void test_query_parameter_formatting() {
  auto request = seastar::http::request::make("GET", "catalog", "/items");
  request._version = "1.1";
  request.query_parameters["page"] = "two words";
  const auto serialized = serialize(request);
  require(serialized.starts_with("GET /items?page=two%20words HTTP/1.1\r\n"));
}

void test_invalid_bytes_are_rejected() {
  auto request = seastar::http::request::make("GET", "catalog", "/items");
  request._version = "1.1";
  request._headers["X-Test"] = "safe\r\ninjected: true";
  bool rejected = false;
  try {
    static_cast<void>(serialize(request));
  } catch (const std::invalid_argument&) {
    rejected = true;
  }
  require(rejected);
}

}  // namespace

int main() {
  test_complete_request_head();
  test_query_parameter_formatting();
  test_invalid_bytes_are_rejected();
  return 0;
}
