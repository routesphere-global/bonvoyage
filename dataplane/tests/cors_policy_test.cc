#include "bonvoyage/runtime/cors_policy.hh"

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

using bonvoyage::runtime::CorsHeaderDecision;
using bonvoyage::runtime::CorsPolicy;

void require(bool condition, const char* message) {
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

template <typename Factory>
void require_invalid(Factory&& factory, const char* message) {
  try {
    factory();
  } catch (const std::invalid_argument&) {
    return;
  }
  require(false, message);
}

}  // namespace

int main() {
  const CorsPolicy exact(
      false,
      {"https://admin.example.com", "https://app.example.com:8443"},
      {"GET", "POST"}, {"authorization", "content-type", "x-request-id"},
      {"x-request-id", "x-trace-id"}, true, 600U);
  require(exact.allows_origin("https://admin.example.com"),
          "configured exact origin was rejected");
  require(exact.allows_origin("https://app.example.com:8443"),
          "configured non-default port was rejected");
  require(!exact.allows_origin("https://admin.example.com/"),
          "non-canonical trailing slash was accepted");
  require(!exact.allows_origin("https://other.example.com"),
          "unconfigured origin was accepted");
  std::optional<std::string_view> retained_origin;
  {
    std::string request_origin{"https://admin.example.com"};
    retained_origin = exact.response_origin(request_origin);
    require(retained_origin.has_value() &&
                *retained_origin == request_origin,
            "allowed response origin was not resolved");
    require(retained_origin->data() != request_origin.data(),
            "response origin borrowed request storage");
    request_origin.assign(request_origin.size(), 'x');
    require(*retained_origin == "https://admin.example.com",
            "request mutation changed the retained response origin");
  }
  require(*retained_origin == "https://admin.example.com",
          "response origin did not survive request destruction");
  require(!exact.response_origin("https://other.example.com").has_value(),
          "denied origin returned response storage");
  require(!exact.response_origin("https://admin.example.com/").has_value(),
          "non-canonical origin returned response storage");
  require(exact.response_origin("https://app.example.com:8443") ==
              std::optional<std::string_view>{"https://app.example.com:8443"},
          "second allowed origin returned the wrong policy entry");
  require(exact.allows_method("POST") && !exact.allows_method("PUT"),
          "method allowlist decision changed");
  require(exact.allows_request_headers(
              "Authorization, Content-Type, X-Request-Id") ==
              CorsHeaderDecision::allowed,
          "case-insensitive allowed request fields were rejected");
  require(exact.allows_request_headers("x-private") ==
              CorsHeaderDecision::denied,
          "unconfigured request field was accepted");
  require(exact.allows_request_headers("authorization,,content-type") ==
              CorsHeaderDecision::malformed,
          "malformed request-field list was accepted");
  require(exact.allow_credentials() && !exact.allow_any_origin(),
          "exact credential policy flags changed");
  require(exact.allowed_methods_value() == "GET, POST",
          "prepared allow-methods value changed");
  require(exact.allowed_headers_value() ==
              "authorization, content-type, x-request-id",
          "prepared allow-headers value changed");
  require(exact.exposed_headers_value() == "x-request-id, x-trace-id",
          "prepared expose-headers value changed");

  const CorsPolicy wildcard(true, {}, {"GET"}, {}, {}, false, 0U);
  require(wildcard.allows_origin("http://127.0.0.1:8080"),
          "wildcard did not allow a canonical origin");
  require(!wildcard.allows_origin("null"),
          "opaque null origin was accepted");
  require(wildcard.response_origin("http://127.0.0.1:8080") ==
              std::optional<std::string_view>{"*"},
          "wildcard response did not use the static star value");
  require(!wildcard.response_origin("null").has_value(),
          "wildcard response accepted an opaque origin");

  require(bonvoyage::runtime::is_canonical_cors_origin(
              "https://[2001:db8::1]:8443"),
          "canonical IPv6 origin was rejected");
  require(!bonvoyage::runtime::is_canonical_cors_origin(
              "https://EXAMPLE.com"),
          "uppercase non-canonical host was accepted");
  require(!bonvoyage::runtime::is_canonical_cors_origin(
              "https://example.com:443"),
          "explicit default port was accepted");
  require(bonvoyage::runtime::is_cors_response_header(
              "Access-Control-Allow-Origin"),
          "CORS response field was not recognized");
  require(!bonvoyage::runtime::is_cors_response_header("X-Request-Id"),
          "ordinary response field was classified as CORS");

  require_invalid(
      [] { (void)CorsPolicy(false, {}, {"GET"}, {}, {}, false, 600U); },
      "empty exact origin policy was accepted");
  require_invalid(
      [] {
        (void)CorsPolicy(true, {}, {"GET"}, {}, {}, true, 600U);
      },
      "credential wildcard policy was accepted");
  require_invalid(
      [] {
        (void)CorsPolicy(false, {"https://example.com"}, {"get"}, {}, {},
                         false, 600U);
      },
      "lowercase method was accepted");
  require_invalid(
      [] {
        (void)CorsPolicy(false, {"https://example.com"}, {"GET"},
                         {"X-Request-Id"}, {}, false, 600U);
      },
      "non-canonical header name was accepted");
  require_invalid(
      [] {
        (void)CorsPolicy(false, {"https://example.com"}, {"GET"},
                         {"origin"}, {}, false, 600U);
      },
      "protocol-owned request header was accepted");
  require_invalid(
      [] {
        (void)CorsPolicy(false, {"https://example.com"}, {"GET"}, {},
                         {"set-cookie"}, false, 600U);
      },
      "Set-Cookie exposure was accepted");

  return 0;
}
