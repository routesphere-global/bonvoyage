#include "bonvoyage/runtime/access_log.hh"

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

using bonvoyage::runtime::AccessLogAction;
using bonvoyage::runtime::AccessLogCompletion;
using bonvoyage::runtime::AccessLogMethod;
using bonvoyage::runtime::AccessLogOptions;
using bonvoyage::runtime::AccessLogProtocol;
using bonvoyage::runtime::AccessLogRecord;
using bonvoyage::runtime::BoundedAccessLogQueue;

void require(bool condition, const char* message) {
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

void expect_invalid(const AccessLogOptions& options) {
  bool rejected = false;
  try {
    bonvoyage::runtime::validate_access_log_options(options);
  } catch (const std::invalid_argument&) {
    rejected = true;
  }
  require(rejected, "invalid access-log options were accepted");
}

void test_options() {
  bonvoyage::runtime::validate_access_log_options(AccessLogOptions{});

  auto options = AccessLogOptions{};
  options.queue_capacity = 0U;
  expect_invalid(options);
  options = AccessLogOptions{};
  options.max_file_bytes = 1024U;
  expect_invalid(options);
  options = AccessLogOptions{};
  options.flush_interval_ms = 1U;
  expect_invalid(options);
  options = AccessLogOptions{};
  options.sample_every = 0U;
  expect_invalid(options);
  options = AccessLogOptions{};
  options.directory = "bad\npath";
  expect_invalid(options);
}

void test_method_classification() {
  using bonvoyage::runtime::classify_access_log_method;
  require(classify_access_log_method("GET") == AccessLogMethod::get,
          "GET method classification failed");
  require(classify_access_log_method("POST") == AccessLogMethod::post,
          "POST method classification failed");
  require(classify_access_log_method("CUSTOM") == AccessLogMethod::other,
          "custom method was not bounded to OTHER");
  require(classify_access_log_method("get") == AccessLogMethod::other,
          "lowercase method was not bounded to OTHER");
}

void test_queue() {
  BoundedAccessLogQueue queue(2U);
  AccessLogRecord first;
  first.status = 200U;
  AccessLogRecord second;
  second.status = 503U;
  require(queue.push(first), "first access record was not admitted");
  require(queue.push(second), "second access record was not admitted");
  require(!queue.push(first), "overflow did not use drop-newest policy");
  require(queue.size() == 2U, "queue depth changed after overflow");
  require(queue.pop().status == 200U, "queue lost FIFO order");
  require(queue.pop().status == 503U, "queue lost second FIFO record");
  require(queue.empty(), "queue was not empty after draining");
  require(queue.push(first), "queue did not admit after draining");
  require(queue.clear() == 1U, "queue clear count was incorrect");
  require(queue.empty(), "queue was not empty after clear");
}

void test_format() {
  const auto record = AccessLogRecord{
      .timestamp_unix_microseconds = 1720000000000000U,
      .snapshot_generation = 41U,
      .duration_microseconds = 975U,
      .request_body_bytes = 12U,
      .response_body_bytes = 48U,
      .shard = 1U,
      .status = 200U,
      .listener = "public-http2",
      .route = "tenant-a-api",
      .cluster = "tenant-a-stable",
      .protocol = AccessLogProtocol::grpc,
      .method = AccessLogMethod::post,
      .action = AccessLogAction::proxy,
      .completion = AccessLogCompletion::complete,
  };
  const auto line = bonvoyage::runtime::format_access_log_record(record);
  require(line.ends_with("}\n"), "access record was not JSON Lines framed");
  require(line.find("\"schema\":\"bonvoyage.access.v1\"") !=
              std::string::npos,
          "access schema identity was missing");
  require(line.find("\"route\":\"tenant-a-api\"") !=
              std::string::npos,
          "access route identity was missing");
  require(line.find("\"protocol\":\"grpc\"") != std::string::npos,
          "access protocol class was missing");
  require(line.find("\"request_body_bytes\":12") != std::string::npos,
          "access request byte count was missing");
  require(line.find("request_path") == std::string::npos,
          "access record exposed a request path");
  require(line.find("client") == std::string::npos,
          "access record exposed client identity");

  auto missing = record;
  missing.route = {};
  missing.cluster = {};
  const auto missing_line =
      bonvoyage::runtime::format_access_log_record(missing);
  require(missing_line.find("\"route\":null") != std::string::npos,
          "missing route was not encoded as null");
  require(missing_line.find("\"cluster\":null") != std::string::npos,
          "missing cluster was not encoded as null");
}

}  // namespace

int main() {
  test_options();
  test_method_classification();
  test_queue();
  test_format();
  return 0;
}
