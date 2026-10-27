#include "bonvoyage/runtime/request_content_policy.hh"

#include <cstdint>
#include <functional>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using bonvoyage::runtime::RequestContentPolicy;
using bonvoyage::runtime::RequestContentTypeDecision;

void require(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

void require_invalid(const std::function<void()>& action,
                     const std::string& message) {
  try {
    action();
  } catch (const std::invalid_argument&) {
    return;
  }
  throw std::runtime_error(message);
}

}  // namespace

int main() {
  try {
    const RequestContentPolicy policy(
        1024U, {"application/problem+json", "application/json"});
    require(policy.maximum_body_bytes() ==
                std::optional<std::uint64_t>{1024U},
            "body limit was not retained");
    require(policy.allowed_content_types() ==
                std::vector<std::string>({"application/json",
                                          "application/problem+json"}),
            "media types were not prepared deterministically");
    require(policy.accept_header_value() ==
                "application/json, application/problem+json",
            "Accept response-field value was not prepared deterministically");
    require(policy.evaluate_content_type("", false, false, false) ==
                RequestContentTypeDecision::allowed,
            "bodyless request unexpectedly required Content-Type");
    require(policy.evaluate_content_type("", false, false, true) ==
                RequestContentTypeDecision::required,
            "body-capable request did not require Content-Type");
    require(policy.evaluate_content_type(
                "Application/JSON; charset=utf-8", true, false, true) ==
                RequestContentTypeDecision::allowed,
            "case-insensitive media type with token parameter was rejected");
    require(policy.evaluate_content_type(
                "application/json; profile=\"tenant\\\"-a\"", true, false,
                true) == RequestContentTypeDecision::allowed,
            "valid quoted media-type parameter was rejected");
    require(policy.evaluate_content_type("text/plain", true, false, true) ==
                RequestContentTypeDecision::unsupported,
            "unconfigured media type was accepted");
    require(policy.evaluate_content_type("application/json", true, true,
                                         true) ==
                RequestContentTypeDecision::malformed,
            "repeated Content-Type was accepted");
    require(policy.evaluate_content_type(std::string(1025U, 'a'), true, false,
                                         true) ==
                RequestContentTypeDecision::too_large,
            "oversized Content-Type was accepted");
    for (const auto& malformed :
         {"application", "application/", "application/json;",
          "application/json; charset", "application/json; charset=",
          "application/json; charset=\"unterminated", "application /json",
          "application/json, text/plain"}) {
      require(policy.evaluate_content_type(malformed, true, false, true) ==
                  RequestContentTypeDecision::malformed,
              std::string("malformed media type was accepted: ") + malformed);
    }
    std::string too_many_parameters = "application/json";
    for (std::size_t index = 0U; index < 17U; ++index) {
      too_many_parameters += "; p" + std::to_string(index) + "=x";
    }
    require(policy.evaluate_content_type(too_many_parameters, true, false,
                                         true) ==
                RequestContentTypeDecision::malformed,
            "media type with too many parameters was accepted");

    const RequestContentPolicy size_only(16U, {});
    require(size_only.evaluate_content_type("not a media type", true, true,
                                            true) ==
                RequestContentTypeDecision::allowed,
            "size-only policy inspected Content-Type");

    require_invalid([] { RequestContentPolicy({}, {}); },
                    "empty request-content policy was accepted");
    require_invalid([] { RequestContentPolicy(0U, {}); },
                    "zero body limit was accepted");
    require_invalid(
        [] { RequestContentPolicy({}, {"Application/JSON"}); },
        "non-canonical uppercase media type was accepted");
    require_invalid(
        [] { RequestContentPolicy({}, {"application/*"}); },
        "wildcard media type was accepted");
    require_invalid(
        [] { RequestContentPolicy({}, {"application/json; charset=utf-8"}); },
        "parameterized configured media type was accepted");
    require_invalid(
        [] { RequestContentPolicy({}, {"application/json", "application/json"}); },
        "duplicate media type was accepted");
    require_invalid(
        [] {
          std::vector<std::string> values(17U, "application/json");
          RequestContentPolicy policy({}, std::move(values));
        },
        "oversized media-type list was accepted");

    std::cout << "request content policy tests passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
