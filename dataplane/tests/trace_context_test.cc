#include "bonvoyage/runtime/trace_context.hh"

#include <array>
#include <cstdlib>
#include <iostream>
#include <string>

namespace {

void require(bool condition, const char* message) {
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

void test_parsing() {
  constexpr std::string_view valid =
      "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-03";
  const auto parsed = bonvoyage::runtime::parse_traceparent(valid);
  require(parsed.has_value(), "valid traceparent was rejected");
  require(parsed->flags == 0x03U, "supported trace flags were not retained");
  require(bonvoyage::runtime::format_traceparent(
              parsed->trace_id, parsed->parent_id, parsed->flags) == valid,
          "traceparent did not round-trip canonically");

  require(!bonvoyage::runtime::parse_traceparent(
               "00-4BF92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
               .has_value(),
          "uppercase trace ID was accepted");
  require(!bonvoyage::runtime::parse_traceparent(
               "00-00000000000000000000000000000000-00f067aa0ba902b7-01")
               .has_value(),
          "all-zero trace ID was accepted");
  require(!bonvoyage::runtime::parse_traceparent(
               "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01")
               .has_value(),
          "all-zero parent ID was accepted");
  require(!bonvoyage::runtime::parse_traceparent(
               "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
               .has_value(),
          "forbidden version ff was accepted");
  require(!bonvoyage::runtime::parse_traceparent(
               "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01,00")
               .has_value(),
          "comma-joined traceparent was accepted");
  require(bonvoyage::runtime::parse_traceparent(
              "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-ff-extra")
              .has_value(),
          "syntactically valid future-version prefix was rejected");
}

void test_header_ownership() {
  require(bonvoyage::runtime::is_trace_propagation_header("traceparent"),
          "traceparent ownership was missing");
  require(bonvoyage::runtime::is_trace_propagation_header("TraceState"),
          "tracestate ownership was not case insensitive");
  require(bonvoyage::runtime::is_trace_propagation_header("BAGGAGE"),
          "baggage ownership was not case insensitive");
  require(!bonvoyage::runtime::is_trace_propagation_header("x-request-id"),
          "unrelated header entered the tracing boundary");
}

void test_generator() {
  bonvoyage::runtime::TraceIdGenerator generator(
      std::array<std::uint64_t, 4U>{1U, 2U, 3U, 4U});
  const auto first_trace = generator.next_trace_id();
  const auto second_trace = generator.next_trace_id();
  const auto span = generator.next_span_id();
  require(first_trace != second_trace,
          "deterministic generator repeated a trace ID");
  require(first_trace != bonvoyage::runtime::TraceId{},
          "generator returned an all-zero trace ID");
  require(span != bonvoyage::runtime::SpanId{},
          "generator returned an all-zero span ID");
}

}  // namespace

int main() {
  test_parsing();
  test_header_ownership();
  test_generator();
  return 0;
}
