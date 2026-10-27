cmake_minimum_required(VERSION 3.28)

project(
  bonvoyage_dataplane
  VERSION 0.2.0
  DESCRIPTION "RouteSphere BonVoyage Seastar dataplane"
  LANGUAGES CXX
)

include(CTest)

option(BONVOYAGE_WARNINGS_AS_ERRORS "Treat BonVoyage compiler warnings as errors" ON)
option(BONVOYAGE_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(BONVOYAGE_BUILD_DOCUMENTATION "Build Doxygen API documentation" OFF)
option(BONVOYAGE_RUN_RUNTIME_TESTS "Run tests that initialize the Seastar reactor" ON)

# Seastar exports ABI-affecting debug macros for the Sanitize configuration.
# RelWithDebInfo against sanitizer Seastar can link incompatible gate layouts.
if(BONVOYAGE_ENABLE_SANITIZERS AND NOT CMAKE_BUILD_TYPE STREQUAL "Sanitize")
  message(FATAL_ERROR
    "BONVOYAGE_ENABLE_SANITIZERS requires CMAKE_BUILD_TYPE=Sanitize "
    "and a matching Seastar sanitize build"
  )
endif()
if(CMAKE_BUILD_TYPE STREQUAL "Sanitize" AND NOT CMAKE_CXX_FLAGS_SANITIZE)
  set(CMAKE_CXX_FLAGS_SANITIZE "-O2 -g -DNDEBUG" CACHE STRING
    "Optimization and debug information for the sanitizer configuration" FORCE)
endif()
set(
  BONVOYAGE_UPSTREAM_HTTP1_CLIENT
  "seastar-reference"
  CACHE STRING
  "Private build-time upstream HTTP/1 client selection"
)
set_property(
  CACHE BONVOYAGE_UPSTREAM_HTTP1_CLIENT
  PROPERTY STRINGS "seastar-reference" "llhttp-candidate"
)

if(NOT BONVOYAGE_UPSTREAM_HTTP1_CLIENT STREQUAL "seastar-reference" AND
   NOT BONVOYAGE_UPSTREAM_HTTP1_CLIENT STREQUAL "llhttp-candidate")
  message(FATAL_ERROR
    "Unsupported BONVOYAGE_UPSTREAM_HTTP1_CLIENT: "
    "${BONVOYAGE_UPSTREAM_HTTP1_CLIENT}"
  )
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Seastar REQUIRED)
get_target_property(BONVOYAGE_CARES_LIBRARY c-ares::cares IMPORTED_LOCATION)
if(NOT BONVOYAGE_CARES_LIBRARY STREQUAL "/opt/c-ares/lib/libcares.a")
  message(FATAL_ERROR "Seastar must use BonVoyage's pinned static c-ares library")
endif()
find_package(Protobuf REQUIRED)
find_package(nghttp2 1.70.0 EXACT CONFIG REQUIRED)
find_package(llhttp 9.4.3 EXACT CONFIG REQUIRED)
find_package(re2 CONFIG REQUIRED)
find_path(BONVOYAGE_LIBJWT_INCLUDE_DIR jwt.h REQUIRED)
find_file(
  BONVOYAGE_LIBJWT_LIBRARY
  NAMES libjwt.a
  PATHS /opt/libjwt/lib
  NO_DEFAULT_PATH
  REQUIRED
)
find_file(
  BONVOYAGE_JANSSON_LIBRARY
  NAMES libjansson.so.4
  PATHS /usr/lib /lib
  PATH_SUFFIXES ${CMAKE_LIBRARY_ARCHITECTURE}
  NO_DEFAULT_PATH
  REQUIRED
)
find_file(
  BONVOYAGE_OPENSSL_CRYPTO_LIBRARY
  NAMES libcrypto.so.3
  PATHS /usr/lib /lib
  PATH_SUFFIXES ${CMAKE_LIBRARY_ARCHITECTURE}
  NO_DEFAULT_PATH
  REQUIRED
)
find_path(BONVOYAGE_GNUTLS_INCLUDE_DIR gnutls/crypto.h REQUIRED)
find_library(BONVOYAGE_GNUTLS_LIBRARY NAMES gnutls REQUIRED)

set(
  BONVOYAGE_PROTO_ROOT
  "${CMAKE_CURRENT_SOURCE_DIR}/../api/proto"
  CACHE PATH
  "Root directory of the BonVoyage Protobuf module"
)

set(BONVOYAGE_PROTO_FILES
  "${BONVOYAGE_PROTO_ROOT}/bonvoyage/v1/config.proto"
  "${BONVOYAGE_PROTO_ROOT}/bonvoyage/v1/discovery.proto"
)

foreach(proto_file IN LISTS BONVOYAGE_PROTO_FILES)
  if(NOT EXISTS "${proto_file}")
    message(FATAL_ERROR "Required BonVoyage contract is missing: ${proto_file}")
  endif()
endforeach()

set(BONVOYAGE_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
set(BONVOYAGE_PROTO_GENERATED_SOURCES
  "${BONVOYAGE_GENERATED_DIR}/bonvoyage/v1/config.pb.cc"
  "${BONVOYAGE_GENERATED_DIR}/bonvoyage/v1/discovery.pb.cc"
)
set(BONVOYAGE_PROTO_GENERATED_HEADERS
  "${BONVOYAGE_GENERATED_DIR}/bonvoyage/v1/config.pb.h"
  "${BONVOYAGE_GENERATED_DIR}/bonvoyage/v1/discovery.pb.h"
)

add_custom_command(
  OUTPUT
    ${BONVOYAGE_PROTO_GENERATED_SOURCES}
    ${BONVOYAGE_PROTO_GENERATED_HEADERS}
  COMMAND "${CMAKE_COMMAND}" -E make_directory
    "${BONVOYAGE_GENERATED_DIR}/bonvoyage/v1"
  COMMAND "${Protobuf_PROTOC_EXECUTABLE}"
    "--cpp_out=${BONVOYAGE_GENERATED_DIR}"
    "--proto_path=${BONVOYAGE_PROTO_ROOT}"
    ${BONVOYAGE_PROTO_FILES}
  DEPENDS ${BONVOYAGE_PROTO_FILES}
  COMMENT "Generating BonVoyage C++ Protobuf contracts"
  VERBATIM
)

add_library(bonvoyage-api-contracts STATIC
  ${BONVOYAGE_PROTO_GENERATED_SOURCES}
  ${BONVOYAGE_PROTO_GENERATED_HEADERS}
)
target_include_directories(
  bonvoyage-api-contracts
  SYSTEM PUBLIC "${BONVOYAGE_GENERATED_DIR}"
)
target_link_libraries(bonvoyage-api-contracts PUBLIC protobuf::libprotobuf)

set(
  BONVOYAGE_OTEL_PROTO_ROOT
  "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/opentelemetry-proto"
  CACHE PATH
  "Root directory of the pinned OpenTelemetry Proto module"
)
set(BONVOYAGE_OTEL_PROTO_FILES
  "${BONVOYAGE_OTEL_PROTO_ROOT}/opentelemetry/proto/common/v1/common.proto"
  "${BONVOYAGE_OTEL_PROTO_ROOT}/opentelemetry/proto/resource/v1/resource.proto"
  "${BONVOYAGE_OTEL_PROTO_ROOT}/opentelemetry/proto/trace/v1/trace.proto"
  "${BONVOYAGE_OTEL_PROTO_ROOT}/opentelemetry/proto/collector/trace/v1/trace_service.proto"
)
foreach(proto_file IN LISTS BONVOYAGE_OTEL_PROTO_FILES)
  if(NOT EXISTS "${proto_file}")
    message(FATAL_ERROR "Required OpenTelemetry contract is missing: ${proto_file}")
  endif()
endforeach()

set(BONVOYAGE_OTEL_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated-otel")
set(BONVOYAGE_OTEL_GENERATED_SOURCES
  "${BONVOYAGE_OTEL_GENERATED_DIR}/opentelemetry/proto/common/v1/common.pb.cc"
  "${BONVOYAGE_OTEL_GENERATED_DIR}/opentelemetry/proto/resource/v1/resource.pb.cc"
  "${BONVOYAGE_OTEL_GENERATED_DIR}/opentelemetry/proto/trace/v1/trace.pb.cc"
  "${BONVOYAGE_OTEL_GENERATED_DIR}/opentelemetry/proto/collector/trace/v1/trace_service.pb.cc"
)
set(BONVOYAGE_OTEL_GENERATED_HEADERS
  "${BONVOYAGE_OTEL_GENERATED_DIR}/opentelemetry/proto/common/v1/common.pb.h"
  "${BONVOYAGE_OTEL_GENERATED_DIR}/opentelemetry/proto/resource/v1/resource.pb.h"
  "${BONVOYAGE_OTEL_GENERATED_DIR}/opentelemetry/proto/trace/v1/trace.pb.h"
  "${BONVOYAGE_OTEL_GENERATED_DIR}/opentelemetry/proto/collector/trace/v1/trace_service.pb.h"
)
add_custom_command(
  OUTPUT
    ${BONVOYAGE_OTEL_GENERATED_SOURCES}
    ${BONVOYAGE_OTEL_GENERATED_HEADERS}
  COMMAND "${CMAKE_COMMAND}" -E make_directory
    "${BONVOYAGE_OTEL_GENERATED_DIR}"
  COMMAND "${Protobuf_PROTOC_EXECUTABLE}"
    "--cpp_out=${BONVOYAGE_OTEL_GENERATED_DIR}"
    "--proto_path=${BONVOYAGE_OTEL_PROTO_ROOT}"
    ${BONVOYAGE_OTEL_PROTO_FILES}
  DEPENDS ${BONVOYAGE_OTEL_PROTO_FILES}
  COMMENT "Generating pinned OpenTelemetry trace contracts"
  VERBATIM
)
add_library(bonvoyage-otlp-contracts STATIC
  ${BONVOYAGE_OTEL_GENERATED_SOURCES}
  ${BONVOYAGE_OTEL_GENERATED_HEADERS}
)
target_include_directories(
  bonvoyage-otlp-contracts
  SYSTEM PUBLIC "${BONVOYAGE_OTEL_GENERATED_DIR}"
)
target_link_libraries(bonvoyage-otlp-contracts PUBLIC protobuf::libprotobuf)

add_library(
  bonvoyage-http-validation STATIC
  src/http1_validation.cc
  src/websocket_protocol.cc
)
target_include_directories(bonvoyage-http-validation PUBLIC include)
target_include_directories(
  bonvoyage-http-validation SYSTEM PUBLIC ${BONVOYAGE_GNUTLS_INCLUDE_DIR}
)
target_link_libraries(
  bonvoyage-http-validation PUBLIC
  Seastar::seastar
  ${BONVOYAGE_GNUTLS_LIBRARY}
)
target_compile_options(bonvoyage-http-validation PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-http-validation PRIVATE -Werror)
endif()

add_library(bonvoyage-endpoint-selector STATIC src/endpoint_selector.cc)
target_include_directories(bonvoyage-endpoint-selector PUBLIC include)
target_compile_options(bonvoyage-endpoint-selector PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-endpoint-selector PRIVATE -Werror)
endif()

add_library(
  bonvoyage-weighted-cluster-selector STATIC
  src/weighted_cluster_selector.cc
)
target_include_directories(
  bonvoyage-weighted-cluster-selector PUBLIC include
)
target_compile_options(bonvoyage-weighted-cluster-selector PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(
    bonvoyage-weighted-cluster-selector PRIVATE -Werror
  )
endif()

add_library(bonvoyage-endpoint-maintenance STATIC src/endpoint_maintenance.cc)
target_include_directories(bonvoyage-endpoint-maintenance PUBLIC include)
target_compile_options(bonvoyage-endpoint-maintenance PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-endpoint-maintenance PRIVATE -Werror)
endif()

add_library(bonvoyage-retry-policy STATIC src/retry_policy.cc)
target_include_directories(bonvoyage-retry-policy PUBLIC include)
target_compile_options(bonvoyage-retry-policy PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-retry-policy PRIVATE -Werror)
endif()

add_library(bonvoyage-route-admission STATIC src/route_admission.cc)
target_include_directories(bonvoyage-route-admission PUBLIC include)
target_compile_options(bonvoyage-route-admission PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-route-admission PRIVATE -Werror)
endif()

add_library(bonvoyage-client-identity STATIC src/client_identity.cc)
target_include_directories(bonvoyage-client-identity PUBLIC include)
target_compile_options(bonvoyage-client-identity PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-client-identity PRIVATE -Werror)
endif()

add_library(bonvoyage-cors-policy STATIC src/cors_policy.cc)
target_include_directories(bonvoyage-cors-policy PUBLIC include)
target_compile_options(bonvoyage-cors-policy PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-cors-policy PRIVATE -Werror)
endif()

add_library(
  bonvoyage-request-content-policy STATIC
  src/request_content_policy.cc
)
target_include_directories(bonvoyage-request-content-policy PUBLIC include)
target_compile_options(bonvoyage-request-content-policy PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-request-content-policy PRIVATE -Werror)
endif()

add_library(
  bonvoyage-header-transformations STATIC
  src/header_transformations.cc
)
target_include_directories(bonvoyage-header-transformations PUBLIC include)
target_compile_options(bonvoyage-header-transformations PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-header-transformations PRIVATE -Werror)
endif()

add_library(bonvoyage-route-rewrite STATIC src/route_rewrite.cc)
target_include_directories(bonvoyage-route-rewrite PUBLIC include)
target_compile_options(bonvoyage-route-rewrite PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-route-rewrite PRIVATE -Werror)
endif()

add_library(bonvoyage-api-key-auth STATIC src/api_key_auth.cc)
target_include_directories(bonvoyage-api-key-auth PUBLIC include)
target_include_directories(
  bonvoyage-api-key-auth SYSTEM PUBLIC ${BONVOYAGE_GNUTLS_INCLUDE_DIR}
)
target_link_libraries(
  bonvoyage-api-key-auth PUBLIC ${BONVOYAGE_GNUTLS_LIBRARY}
)
target_compile_options(bonvoyage-api-key-auth PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-api-key-auth PRIVATE -Werror)
endif()

add_library(bonvoyage-jwt-auth STATIC src/jwt_auth.cc)
target_include_directories(bonvoyage-jwt-auth PUBLIC include)
target_include_directories(
  bonvoyage-jwt-auth SYSTEM PRIVATE ${BONVOYAGE_LIBJWT_INCLUDE_DIR}
)
target_link_libraries(
  bonvoyage-jwt-auth PUBLIC
    ${BONVOYAGE_LIBJWT_LIBRARY}
    ${BONVOYAGE_JANSSON_LIBRARY}
    ${BONVOYAGE_OPENSSL_CRYPTO_LIBRARY}
)
target_compile_options(bonvoyage-jwt-auth PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-jwt-auth PRIVATE -Werror)
endif()

add_library(
  bonvoyage-upstream-response-head STATIC
  src/upstream_response_head_parser.cc
)
target_include_directories(bonvoyage-upstream-response-head PUBLIC include)
target_link_libraries(
  bonvoyage-upstream-response-head
  PUBLIC llhttp::llhttp_static
)
target_compile_options(bonvoyage-upstream-response-head PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-upstream-response-head PRIVATE -Werror)
endif()

add_library(
  bonvoyage-upstream-request STATIC
  src/upstream_request_serializer.cc
)
target_include_directories(bonvoyage-upstream-request PUBLIC include)
target_link_libraries(bonvoyage-upstream-request PUBLIC Seastar::seastar)
target_compile_options(bonvoyage-upstream-request PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-upstream-request PRIVATE -Werror)
endif()

add_library(
  bonvoyage-upstream-http1 STATIC
  src/upstream_http1_client.cc
)
target_include_directories(bonvoyage-upstream-http1 PUBLIC include)
target_link_libraries(bonvoyage-upstream-http1 PUBLIC Seastar::seastar)
if(BONVOYAGE_UPSTREAM_HTTP1_CLIENT STREQUAL "seastar-reference")
  target_compile_definitions(
    bonvoyage-upstream-http1
    PUBLIC BONVOYAGE_UPSTREAM_HTTP1_CLIENT_SEASTAR_REFERENCE=1
  )
else()
  target_sources(
    bonvoyage-upstream-http1
    PRIVATE src/llhttp_upstream_http1_client.cc
  )
  target_link_libraries(
    bonvoyage-upstream-http1
    PUBLIC
      bonvoyage-http-validation
      bonvoyage-upstream-request
      bonvoyage-upstream-response-head
  )
  target_compile_definitions(
    bonvoyage-upstream-http1
    PUBLIC BONVOYAGE_UPSTREAM_HTTP1_CLIENT_LLHTTP_CANDIDATE=1
  )
endif()
target_compile_options(bonvoyage-upstream-http1 PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-upstream-http1 PRIVATE -Werror)
endif()

add_library(bonvoyage-http2 STATIC
  src/grpc_protocol.cc
  src/http2_client_session.cc
  src/http2_request_validation.cc
  src/http2_session.cc
)
target_include_directories(bonvoyage-http2 PUBLIC include)
target_link_libraries(
  bonvoyage-http2
  PUBLIC nghttp2::nghttp2_static
  PUBLIC bonvoyage-http-validation
)
target_compile_options(bonvoyage-http2 PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-http2 PRIVATE -Werror)
endif()

add_library(
  bonvoyage-upstream-http2 STATIC
  src/upstream_http2_client.cc
)
target_include_directories(bonvoyage-upstream-http2 PUBLIC include)
target_link_libraries(
  bonvoyage-upstream-http2
  PUBLIC
    bonvoyage-http2
    Seastar::seastar
)
target_compile_options(bonvoyage-upstream-http2 PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-upstream-http2 PRIVATE -Werror)
endif()

add_library(bonvoyage-runtime-log STATIC src/runtime_log.cc)
target_include_directories(bonvoyage-runtime-log PUBLIC include)
target_compile_options(bonvoyage-runtime-log PRIVATE
  -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-runtime-log PRIVATE -Werror)
endif()

add_library(bonvoyage-runtime-log-binding STATIC src/runtime_log_binding.cc)
target_include_directories(bonvoyage-runtime-log-binding PUBLIC include)
target_link_libraries(bonvoyage-runtime-log-binding
  PUBLIC bonvoyage-runtime-log Seastar::seastar)
target_compile_options(bonvoyage-runtime-log-binding PRIVATE
  -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-runtime-log-binding PRIVATE -Werror)
endif()
if(BONVOYAGE_ENABLE_SANITIZERS)
  target_compile_options(bonvoyage-runtime-log-binding PRIVATE
    -fno-omit-frame-pointer -fno-sanitize-recover=undefined -fsanitize=address,undefined)
  target_link_options(bonvoyage-runtime-log-binding PUBLIC -fsanitize=address,undefined)
endif()
if(BONVOYAGE_ENABLE_SANITIZERS)
  target_compile_options(bonvoyage-runtime-log PRIVATE
    -fno-omit-frame-pointer -fno-sanitize-recover=undefined -fsanitize=address,undefined)
  target_link_options(bonvoyage-runtime-log PUBLIC -fsanitize=address,undefined)
endif()

add_library(bonvoyage-runtime-log-service STATIC src/runtime_log_service.cc)
target_include_directories(bonvoyage-runtime-log-service PUBLIC include)
target_link_libraries(bonvoyage-runtime-log-service
  PUBLIC bonvoyage-runtime-log-binding Seastar::seastar)
target_compile_options(bonvoyage-runtime-log-service PRIVATE
  -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-runtime-log-service PRIVATE -Werror)
endif()
if(BONVOYAGE_ENABLE_SANITIZERS)
  target_compile_options(bonvoyage-runtime-log-service PRIVATE
    -fno-omit-frame-pointer -fno-sanitize-recover=undefined -fsanitize=address,undefined)
  target_link_options(bonvoyage-runtime-log-service PUBLIC -fsanitize=address,undefined)
endif()

add_library(bonvoyage-access-log STATIC src/access_log.cc)
target_include_directories(bonvoyage-access-log PUBLIC include)
target_link_libraries(bonvoyage-access-log PUBLIC Seastar::seastar)
target_compile_options(bonvoyage-access-log PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-access-log PRIVATE -Werror)
endif()

add_library(bonvoyage-trace-context STATIC src/trace_context.cc)
target_include_directories(bonvoyage-trace-context PUBLIC include)
target_include_directories(
  bonvoyage-trace-context SYSTEM PUBLIC ${BONVOYAGE_GNUTLS_INCLUDE_DIR}
)
target_link_libraries(
  bonvoyage-trace-context PUBLIC ${BONVOYAGE_GNUTLS_LIBRARY}
)
target_compile_options(bonvoyage-trace-context PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-trace-context PRIVATE -Werror)
endif()

add_library(bonvoyage-trace-exporter STATIC src/trace_exporter.cc)
target_include_directories(bonvoyage-trace-exporter PUBLIC include)
target_link_libraries(
  bonvoyage-trace-exporter
  PUBLIC
    bonvoyage-access-log
    bonvoyage-otlp-contracts
    bonvoyage-trace-context
    bonvoyage-upstream-http1
    Seastar::seastar
)
target_compile_options(bonvoyage-trace-exporter PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-trace-exporter PRIVATE -Werror)
endif()

add_library(bonvoyage-runtime-snapshot STATIC src/runtime_snapshot.cc)
target_include_directories(bonvoyage-runtime-snapshot PUBLIC include)
target_link_libraries(
  bonvoyage-runtime-snapshot
  PUBLIC
    bonvoyage-api-contracts
    bonvoyage-client-identity
    bonvoyage-cors-policy
    bonvoyage-header-transformations
    bonvoyage-request-content-policy
    re2::re2
)
target_compile_options(bonvoyage-runtime-snapshot PRIVATE
  -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-runtime-snapshot PRIVATE -Werror)
endif()

add_library(
  bonvoyage-snapshot-preparation STATIC
  src/snapshot_preparation.cc
)
target_include_directories(bonvoyage-snapshot-preparation PUBLIC include)
target_include_directories(
  bonvoyage-snapshot-preparation SYSTEM PUBLIC ${BONVOYAGE_GNUTLS_INCLUDE_DIR}
)
target_link_libraries(
  bonvoyage-snapshot-preparation
  PUBLIC
    bonvoyage-api-contracts
    bonvoyage-runtime-snapshot
    ${BONVOYAGE_GNUTLS_LIBRARY}
)
target_compile_options(bonvoyage-snapshot-preparation PRIVATE
  -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-snapshot-preparation PRIVATE -Werror)
endif()

add_library(
  bonvoyage-snapshot-preparation-coordinator STATIC
  src/snapshot_preparation_coordinator.cc
)
target_include_directories(
  bonvoyage-snapshot-preparation-coordinator PUBLIC include
)
target_link_libraries(
  bonvoyage-snapshot-preparation-coordinator
  PUBLIC bonvoyage-snapshot-preparation Seastar::seastar
)
target_compile_options(bonvoyage-snapshot-preparation-coordinator PRIVATE
  -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(
    bonvoyage-snapshot-preparation-coordinator PRIVATE -Werror
  )
endif()

add_library(
  bonvoyage-discovery-protocol STATIC
  src/discovery_protocol.cc
)
target_include_directories(bonvoyage-discovery-protocol PUBLIC include)
target_link_libraries(
  bonvoyage-discovery-protocol
  PUBLIC bonvoyage-snapshot-preparation-coordinator
)
target_compile_options(bonvoyage-discovery-protocol PRIVATE
  -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-discovery-protocol PRIVATE -Werror)
endif()

add_library(
  bonvoyage-live-snapshot-coordinator STATIC
  src/live_snapshot_coordinator.cc
)
target_include_directories(
  bonvoyage-live-snapshot-coordinator PUBLIC include
)
target_link_libraries(
  bonvoyage-live-snapshot-coordinator
  PUBLIC bonvoyage-snapshot-preparation-coordinator Seastar::seastar
)
target_compile_options(bonvoyage-live-snapshot-coordinator PRIVATE
  -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(
    bonvoyage-live-snapshot-coordinator PRIVATE -Werror
  )
endif()

add_library(
  bonvoyage-discovery-client STATIC
  src/discovery_client.cc
)
target_include_directories(bonvoyage-discovery-client PUBLIC include)
target_link_libraries(
  bonvoyage-discovery-client
  PUBLIC
    bonvoyage-discovery-protocol
    bonvoyage-upstream-http2
    Seastar::seastar
)
target_compile_options(bonvoyage-discovery-client PRIVATE
  -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-discovery-client PRIVATE -Werror)
endif()

foreach(preparation_target IN ITEMS
    bonvoyage-runtime-snapshot
    bonvoyage-snapshot-preparation
    bonvoyage-snapshot-preparation-coordinator
    bonvoyage-discovery-protocol
    bonvoyage-live-snapshot-coordinator
    bonvoyage-discovery-client)
  if(BONVOYAGE_ENABLE_SANITIZERS)
    target_compile_options(${preparation_target} PRIVATE
      -fno-omit-frame-pointer
      -fno-sanitize-recover=undefined
      -fsanitize=address,undefined
    )
    target_link_options(${preparation_target} PUBLIC
      -fno-omit-frame-pointer
      -fsanitize=address,undefined
    )
  endif()
endforeach()

add_executable(bonvoyage-dataplane
  src/gateway.cc
  src/main.cc
)

target_include_directories(bonvoyage-dataplane PRIVATE include)
target_link_libraries(
  bonvoyage-dataplane
  PRIVATE
    bonvoyage-access-log
    bonvoyage-runtime-log-service
    bonvoyage-api-contracts
    bonvoyage-api-key-auth
    bonvoyage-client-identity
    bonvoyage-cors-policy
    bonvoyage-discovery-client
    bonvoyage-endpoint-maintenance
    bonvoyage-endpoint-selector
    bonvoyage-http-validation
    bonvoyage-http2
    bonvoyage-header-transformations
    bonvoyage-jwt-auth
    bonvoyage-request-content-policy
    bonvoyage-retry-policy
    bonvoyage-route-admission
    bonvoyage-route-rewrite
    bonvoyage-runtime-snapshot
    bonvoyage-live-snapshot-coordinator
    bonvoyage-snapshot-preparation
    bonvoyage-trace-exporter
    bonvoyage-upstream-http1
    bonvoyage-upstream-http2
    bonvoyage-upstream-request
    bonvoyage-upstream-response-head
    bonvoyage-weighted-cluster-selector
    re2::re2
    Seastar::seastar
)

target_compile_options(bonvoyage-dataplane PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
)

if(BONVOYAGE_WARNINGS_AS_ERRORS)
  target_compile_options(bonvoyage-dataplane PRIVATE -Werror)
endif()

# GCC 13 misdiagnoses fmt 9's inlined bigint buffer growth in this translation
# unit. Keep the system-header diagnostic visible while authored warnings and
# every other warning remain fatal; clang-tidy and sanitizers stay independent.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND
   CMAKE_CXX_COMPILER_VERSION VERSION_LESS 14)
  target_compile_options(bonvoyage-dataplane PRIVATE
    -Wno-error=array-bounds
  )
endif()

if(BONVOYAGE_ENABLE_SANITIZERS)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    message(FATAL_ERROR "Sanitizers require Clang or GCC")
  endif()

  target_compile_options(bonvoyage-dataplane PRIVATE
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined
    -fsanitize=address,undefined
  )
  target_link_options(bonvoyage-dataplane PRIVATE
    -fno-omit-frame-pointer
    -fsanitize=address,undefined
  )
  target_compile_options(bonvoyage-api-contracts PRIVATE
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined
    -fsanitize=address,undefined
  )
  target_compile_options(bonvoyage-otlp-contracts PRIVATE
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined
    -fsanitize=address,undefined
  )
  target_compile_options(bonvoyage-access-log PRIVATE
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined
    -fsanitize=address,undefined
  )
  target_link_options(bonvoyage-access-log PRIVATE
    -fno-omit-frame-pointer
    -fsanitize=address,undefined
  )
  target_compile_options(bonvoyage-trace-context PRIVATE
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined
    -fsanitize=address,undefined
  )
  target_link_options(bonvoyage-trace-context PRIVATE
    -fno-omit-frame-pointer
    -fsanitize=address,undefined
  )
  target_compile_options(bonvoyage-trace-exporter PRIVATE
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined
    -fsanitize=address,undefined
  )
  target_link_options(bonvoyage-trace-exporter PRIVATE
    -fno-omit-frame-pointer
    -fsanitize=address,undefined
  )
  target_compile_options(bonvoyage-http2 PRIVATE
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined
    -fsanitize=address,undefined
  )
  target_compile_options(bonvoyage-upstream-http2 PRIVATE
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined
    -fsanitize=address,undefined
  )
  target_compile_options(bonvoyage-http-validation PRIVATE
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined
    -fsanitize=address,undefined
  )
  target_compile_options(bonvoyage-endpoint-selector PRIVATE
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined
    -fsanitize=address,undefined
  )
  target_link_options(bonvoyage-endpoint-selector PRIVATE
    -fno-omit-frame-pointer
    -fsanitize=address,undefined
  )
  target_compile_options(bonvoyage-endpoint-maintenance PRIVATE
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined
    -fsanitize=address,undefined
  )
  target_link_options(bonvoyage-endpoint-maintenance PRIVATE
    -fno-omit-frame-pointer
    -fsanitize=address,undefined
  )
  target_compile_options(bonvoyage-retry-policy PRIVATE
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined
    -fsanitize=address,undefined
  )
  target_link_options(bonvoyage-retry-policy PRIVATE
    -fno-omit-frame-pointer
    -fsanitize=address,undefined
  )
  target_compile_options(bonvoyage-route-admission PRIVATE
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined
    -fsanitize=address,undefined
  )
  target_link_options(bonvoyage-route-admission PRIVATE
    -fno-omit-frame-pointer
    -fsanitize=address,undefined
  )
  target_compile_options(bonvoyage-client-identity PRIVATE
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined
    -fsanitize=address,undefined
  )
  target_link_options(bonvoyage-client-identity PRIVATE
    -fno-omit-frame-pointer
    -fsanitize=address,undefined
  )
  target_compile_options(bonvoyage-cors-policy PRIVATE
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined
    -fsanitize=address,undefined
  )
  target_link_options(bonvoyage-cors-policy PRIVATE
    -fno-omit-frame-pointer
    -fsanitize=address,undefined
  )
  target_compile_options(bonvoyage-request-content-policy PRIVATE
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined
    -fsanitize=address,undefined
  )
  target_link_options(bonvoyage-request-content-policy PRIVATE
    -fno-omit-frame-pointer
    -fsanitize=address,undefined
  )
  target_compile_options(bonvoyage-header-transformations PRIVATE
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined
    -fsanitize=address,undefined
  )
  target_link_options(bonvoyage-header-transformations PRIVATE
    -fno-omit-frame-pointer
    -fsanitize=address,undefined
  )
  target_compile_options(bonvoyage-route-rewrite PRIVATE
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined
    -fsanitize=address,undefined
  )
  target_link_options(bonvoyage-route-rewrite PRIVATE
    -fno-omit-frame-pointer
    -fsanitize=address,undefined
  )
  target_compile_options(bonvoyage-api-key-auth PRIVATE
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined
    -fsanitize=address,undefined
  )
  target_link_options(bonvoyage-api-key-auth PRIVATE
    -fno-omit-frame-pointer
    -fsanitize=address,undefined
  )
  target_compile_options(bonvoyage-jwt-auth PRIVATE
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined
    -fsanitize=address,undefined
  )
  target_link_options(bonvoyage-jwt-auth PRIVATE
    -fno-omit-frame-pointer
    -fsanitize=address,undefined
  )
  target_compile_options(bonvoyage-upstream-http1 PRIVATE
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined
    -fsanitize=address,undefined
  )
  target_compile_options(bonvoyage-upstream-request PRIVATE
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined
    -fsanitize=address,undefined
  )
  target_compile_options(bonvoyage-upstream-response-head PRIVATE
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined
    -fsanitize=address,undefined
  )
endif()

install(TARGETS bonvoyage-dataplane RUNTIME DESTINATION bin)

if(BUILD_TESTING)
  find_package(Threads REQUIRED)
  add_executable(bonvoyage-runtime-log-test tests/runtime_log_test.cc)
  target_link_libraries(bonvoyage-runtime-log-test PRIVATE bonvoyage-runtime-log Threads::Threads)
  target_compile_options(bonvoyage-runtime-log-test PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Werror)
  if(BONVOYAGE_ENABLE_SANITIZERS)
    target_compile_options(bonvoyage-runtime-log-test PRIVATE
      -fno-omit-frame-pointer -fno-sanitize-recover=undefined -fsanitize=address,undefined)
  endif()
  add_test(NAME bonvoyage-runtime-log COMMAND bonvoyage-runtime-log-test)
  set_tests_properties(bonvoyage-runtime-log PROPERTIES TIMEOUT 20)

  add_executable(bonvoyage-runtime-log-binding-test
    tests/runtime_log_binding_test.cc)
  target_link_libraries(bonvoyage-runtime-log-binding-test
    PRIVATE bonvoyage-runtime-log-binding Threads::Threads)
  target_compile_options(bonvoyage-runtime-log-binding-test PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Werror)
  if(BONVOYAGE_ENABLE_SANITIZERS)
    target_compile_options(bonvoyage-runtime-log-binding-test PRIVATE
      -fno-omit-frame-pointer -fno-sanitize-recover=undefined -fsanitize=address,undefined)
  endif()
  add_test(NAME bonvoyage-runtime-log-binding
    COMMAND bonvoyage-runtime-log-binding-test)
  set_tests_properties(bonvoyage-runtime-log-binding PROPERTIES TIMEOUT 25)

  add_executable(bonvoyage-runtime-log-binding-reactor-test
    tests/runtime_log_binding_reactor_test.cc)
  target_link_libraries(bonvoyage-runtime-log-binding-reactor-test
    PRIVATE bonvoyage-runtime-log-binding)
  target_compile_options(bonvoyage-runtime-log-binding-reactor-test PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Werror)
  if(BONVOYAGE_ENABLE_SANITIZERS)
    target_compile_options(bonvoyage-runtime-log-binding-reactor-test PRIVATE
      -fno-omit-frame-pointer -fno-sanitize-recover=undefined -fsanitize=address,undefined)
  endif()
  add_test(NAME bonvoyage-runtime-log-binding-reactor
    COMMAND bonvoyage-runtime-log-binding-reactor-test
      --smp 2 --memory 512M --overprovisioned)
  set_tests_properties(bonvoyage-runtime-log-binding-reactor
    PROPERTIES TIMEOUT 25)

  add_executable(bonvoyage-runtime-log-service-reactor-test
    tests/runtime_log_service_reactor_test.cc)
  target_link_libraries(bonvoyage-runtime-log-service-reactor-test
    PRIVATE bonvoyage-runtime-log-service)
  target_compile_options(bonvoyage-runtime-log-service-reactor-test PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Werror)
  if(BONVOYAGE_ENABLE_SANITIZERS)
    target_compile_options(bonvoyage-runtime-log-service-reactor-test PRIVATE
      -fno-omit-frame-pointer -fno-sanitize-recover=undefined -fsanitize=address,undefined)
  endif()
  add_test(NAME bonvoyage-runtime-log-service-reactor
    COMMAND bonvoyage-runtime-log-service-reactor-test
      --smp 1 --memory 256M --overprovisioned)
  set_tests_properties(bonvoyage-runtime-log-service-reactor
    PROPERTIES TIMEOUT 25)

  add_executable(bonvoyage-shutdown-sequence-reactor-test
    tests/shutdown_sequence_reactor_test.cc)
  target_include_directories(bonvoyage-shutdown-sequence-reactor-test
    PRIVATE include)
  target_link_libraries(bonvoyage-shutdown-sequence-reactor-test
    PRIVATE Seastar::seastar)
  target_compile_options(bonvoyage-shutdown-sequence-reactor-test PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Werror)
  if(BONVOYAGE_ENABLE_SANITIZERS)
    target_compile_options(bonvoyage-shutdown-sequence-reactor-test PRIVATE
      -fno-omit-frame-pointer -fno-sanitize-recover=undefined -fsanitize=address,undefined)
  endif()
  add_test(NAME bonvoyage-shutdown-sequence-reactor
    COMMAND bonvoyage-shutdown-sequence-reactor-test
      --smp 1 --memory 128M --overprovisioned)
  set_tests_properties(bonvoyage-shutdown-sequence-reactor
    PROPERTIES TIMEOUT 20)

  add_executable(bonvoyage-dns-dependency-test tests/dns_dependency_test.cc)
  target_link_libraries(bonvoyage-dns-dependency-test PRIVATE c-ares::cares)
  target_compile_options(bonvoyage-dns-dependency-test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  if(BONVOYAGE_ENABLE_SANITIZERS)
    target_compile_options(bonvoyage-dns-dependency-test PRIVATE
      -fno-omit-frame-pointer -fno-sanitize-recover=undefined -fsanitize=address,undefined)
    target_link_options(bonvoyage-dns-dependency-test PRIVATE -fsanitize=address,undefined)
  endif()
  add_test(NAME bonvoyage-dns-dependency COMMAND bonvoyage-dns-dependency-test)
  set_tests_properties(bonvoyage-dns-dependency PROPERTIES TIMEOUT 5)

  if(BONVOYAGE_RUN_RUNTIME_TESTS)
    add_executable(bonvoyage-dns-resolver-runtime-test tests/dns_resolver_runtime_test.cc)
    target_link_libraries(bonvoyage-dns-resolver-runtime-test PRIVATE Seastar::seastar)
    target_compile_options(bonvoyage-dns-resolver-runtime-test PRIVATE
      -Wall -Wextra -Wpedantic -Werror)
    if(BONVOYAGE_ENABLE_SANITIZERS)
      target_compile_options(bonvoyage-dns-resolver-runtime-test PRIVATE
        -fno-omit-frame-pointer -fno-sanitize-recover=undefined -fsanitize=address,undefined)
      target_link_options(bonvoyage-dns-resolver-runtime-test PRIVATE
        -fno-omit-frame-pointer -fsanitize=address,undefined)
    endif()
    add_test(NAME bonvoyage-dns-resolver-runtime
      COMMAND bonvoyage-dns-resolver-runtime-test
        --smp 1 --memory 256M --overprovisioned)
    set_tests_properties(bonvoyage-dns-resolver-runtime PROPERTIES TIMEOUT 20)
    add_test(
      NAME bonvoyage-dataplane-version
      COMMAND bonvoyage-dataplane
        --version
        --smp 1
        --memory 256M
        --overprovisioned
    )
    set_tests_properties(bonvoyage-dataplane-version PROPERTIES
      PASS_REGULAR_EXPRESSION "RouteSphere BonVoyage dataplane 0.2.0"
      TIMEOUT 20
    )
  endif()

  add_executable(bonvoyage-contracts-smoke tests/contracts_smoke.cc)
  target_link_libraries(
    bonvoyage-contracts-smoke
    PRIVATE bonvoyage-api-contracts
  )
  target_compile_options(bonvoyage-contracts-smoke PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
  )
  if(BONVOYAGE_WARNINGS_AS_ERRORS)
    target_compile_options(bonvoyage-contracts-smoke PRIVATE -Werror)
  endif()
  if(BONVOYAGE_ENABLE_SANITIZERS)
    target_compile_options(bonvoyage-contracts-smoke PRIVATE
      -fno-omit-frame-pointer
      -fno-sanitize-recover=undefined
      -fsanitize=address,undefined
    )
    target_link_options(bonvoyage-contracts-smoke PRIVATE
      -fno-omit-frame-pointer
      -fsanitize=address,undefined
    )
  endif()

  add_test(NAME bonvoyage-contracts-smoke COMMAND bonvoyage-contracts-smoke)
  set_tests_properties(bonvoyage-contracts-smoke PROPERTIES TIMEOUT 20)

  add_executable(
    bonvoyage-runtime-snapshot-test
    tests/runtime_snapshot_test.cc
  )
  add_executable(
    bonvoyage-snapshot-preparation-test
    tests/snapshot_preparation_test.cc
  )
  add_executable(
    bonvoyage-snapshot-preparation-reactor-test
    tests/snapshot_preparation_reactor_test.cc
  )
  add_executable(
    bonvoyage-snapshot-activation-test
    tests/snapshot_activation_test.cc
  )
  add_executable(
    bonvoyage-snapshot-activation-reactor-test
    tests/snapshot_activation_reactor_test.cc
  )
  add_executable(
    bonvoyage-discovery-protocol-test
    tests/discovery_protocol_test.cc
  )
  add_executable(
    bonvoyage-discovery-client-test
    tests/discovery_client_test.cc
  )
  add_executable(
    bonvoyage-live-snapshot-coordinator-reactor-test
    tests/live_snapshot_coordinator_reactor_test.cc
  )
  add_executable(
    bonvoyage-access-log-test
    tests/access_log_test.cc
  )
  add_executable(
    bonvoyage-access-log-runtime-test
    tests/access_log_runtime_test.cc
  )
  add_executable(
    bonvoyage-trace-context-test
    tests/trace_context_test.cc
  )
  add_executable(
    bonvoyage-trace-exporter-runtime-test
    tests/trace_exporter_runtime_test.cc
  )
  add_executable(
    bonvoyage-listener-lifecycle-test
    tests/listener_lifecycle_test.cc
  )
  target_link_libraries(
    bonvoyage-listener-lifecycle-test
    PRIVATE Seastar::seastar
  )
  add_executable(
    bonvoyage-endpoint-selector-test
    tests/endpoint_selector_test.cc
  )
  add_executable(
    bonvoyage-weighted-cluster-selector-test
    tests/weighted_cluster_selector_test.cc
  )
  add_executable(
    bonvoyage-endpoint-maintenance-test
    tests/endpoint_maintenance_test.cc
  )
  add_executable(
    bonvoyage-retry-policy-test
    tests/retry_policy_test.cc
  )
  add_executable(
    bonvoyage-route-admission-test
    tests/route_admission_test.cc
  )
  add_executable(
    bonvoyage-client-identity-test
    tests/client_identity_test.cc
  )
  add_executable(
    bonvoyage-source-ip-policy-test
    tests/source_ip_policy_test.cc
  )
  add_executable(
    bonvoyage-cors-policy-test
    tests/cors_policy_test.cc
  )
  add_executable(
    bonvoyage-request-content-policy-test
    tests/request_content_policy_test.cc
  )
  add_executable(
    bonvoyage-header-transformations-test
    tests/header_transformations_test.cc
  )
  add_executable(
    bonvoyage-route-rewrite-test
    tests/route_rewrite_test.cc
  )
  add_executable(
    bonvoyage-api-key-auth-test
    tests/api_key_auth_test.cc
  )
  add_executable(
    bonvoyage-jwt-auth-test
    tests/jwt_auth_test.cc
  )
  add_executable(
    bonvoyage-endpoint-selector-benchmark
    benchmarks/endpoint_selector_benchmark.cc
  )
  target_link_libraries(
    bonvoyage-access-log-test
    PRIVATE bonvoyage-access-log
  )
  target_link_libraries(
    bonvoyage-access-log-runtime-test
    PRIVATE bonvoyage-access-log
  )
  target_link_libraries(
    bonvoyage-trace-context-test
    PRIVATE bonvoyage-trace-context
  )
  target_link_libraries(
    bonvoyage-trace-exporter-runtime-test
    PRIVATE bonvoyage-trace-exporter
  )
  target_link_libraries(
    bonvoyage-endpoint-selector-test
    PRIVATE bonvoyage-endpoint-selector
  )
  target_link_libraries(
    bonvoyage-weighted-cluster-selector-test
    PRIVATE bonvoyage-weighted-cluster-selector
  )
  target_link_libraries(
    bonvoyage-endpoint-maintenance-test
    PRIVATE bonvoyage-endpoint-maintenance
  )
  target_link_libraries(
    bonvoyage-retry-policy-test
    PRIVATE bonvoyage-retry-policy
  )
  target_link_libraries(
    bonvoyage-route-admission-test
    PRIVATE bonvoyage-route-admission
  )
  target_link_libraries(
    bonvoyage-client-identity-test
    PRIVATE bonvoyage-client-identity
  )
  target_link_libraries(
    bonvoyage-source-ip-policy-test
    PRIVATE bonvoyage-client-identity
  )
  target_link_libraries(
    bonvoyage-cors-policy-test
    PRIVATE bonvoyage-cors-policy
  )
  target_link_libraries(
    bonvoyage-request-content-policy-test
    PRIVATE bonvoyage-request-content-policy
  )
  target_link_libraries(
    bonvoyage-header-transformations-test
    PRIVATE bonvoyage-header-transformations
  )
  target_link_libraries(
    bonvoyage-route-rewrite-test
    PRIVATE bonvoyage-route-rewrite
  )
  target_link_libraries(
    bonvoyage-api-key-auth-test
    PRIVATE bonvoyage-api-key-auth
  )
  target_include_directories(
    bonvoyage-jwt-auth-test SYSTEM PRIVATE ${BONVOYAGE_LIBJWT_INCLUDE_DIR}
  )
  target_link_libraries(
    bonvoyage-jwt-auth-test
    PRIVATE bonvoyage-jwt-auth
  )
  target_link_libraries(
    bonvoyage-endpoint-selector-benchmark
    PRIVATE bonvoyage-endpoint-selector
  )
  target_include_directories(bonvoyage-runtime-snapshot-test PRIVATE include)
  target_link_libraries(
    bonvoyage-runtime-snapshot-test
    PRIVATE bonvoyage-runtime-snapshot
  )
  target_link_libraries(
    bonvoyage-snapshot-preparation-test
    PRIVATE bonvoyage-snapshot-preparation
  )
  target_link_libraries(
    bonvoyage-snapshot-preparation-reactor-test
    PRIVATE bonvoyage-snapshot-preparation-coordinator
  )
  target_link_libraries(
    bonvoyage-snapshot-activation-test
    PRIVATE bonvoyage-snapshot-preparation
  )
  target_link_libraries(
    bonvoyage-snapshot-activation-reactor-test
    PRIVATE bonvoyage-snapshot-preparation-coordinator
  )
  target_link_libraries(
    bonvoyage-discovery-protocol-test
    PRIVATE bonvoyage-discovery-protocol
  )
  target_link_libraries(
    bonvoyage-discovery-client-test
    PRIVATE bonvoyage-discovery-client
  )
  target_link_libraries(
    bonvoyage-live-snapshot-coordinator-reactor-test
    PRIVATE bonvoyage-live-snapshot-coordinator
  )

  add_executable(
    bonvoyage-http1-validation-test
    tests/http1_validation_test.cc
  )
  target_link_libraries(
    bonvoyage-http1-validation-test
    PRIVATE bonvoyage-http-validation
  )

  add_executable(
    bonvoyage-websocket-protocol-test
    tests/websocket_protocol_test.cc
  )
  target_link_libraries(
    bonvoyage-websocket-protocol-test
    PRIVATE bonvoyage-http-validation
  )

  add_executable(bonvoyage-http2-session-test tests/http2_session_test.cc)
  target_link_libraries(
    bonvoyage-http2-session-test
    PRIVATE bonvoyage-http2
  )

  add_executable(bonvoyage-grpc-protocol-test tests/grpc_protocol_test.cc)
  target_link_libraries(
    bonvoyage-grpc-protocol-test
    PRIVATE bonvoyage-http2
  )

  add_executable(
    bonvoyage-http2-client-session-test
    tests/http2_client_session_test.cc
  )
  target_link_libraries(
    bonvoyage-http2-client-session-test
    PRIVATE bonvoyage-http2
  )

  add_executable(
    bonvoyage-http2-request-validation-test
    tests/http2_request_validation_test.cc
  )

  add_executable(
    bonvoyage-upstream-http1-client-test
    tests/upstream_http1_client_test.cc
  )
  add_executable(
    bonvoyage-upstream-response-head-test
    tests/upstream_response_head_parser_test.cc
  )
  add_executable(
    bonvoyage-upstream-request-test
    tests/upstream_request_serializer_test.cc
  )
  target_link_libraries(
    bonvoyage-upstream-response-head-test
    PRIVATE bonvoyage-upstream-response-head
  )
  target_link_libraries(
    bonvoyage-upstream-http1-client-test
    PRIVATE bonvoyage-upstream-http1
  )
  target_link_libraries(
    bonvoyage-upstream-request-test
    PRIVATE bonvoyage-upstream-request
  )
  target_link_libraries(
    bonvoyage-http2-request-validation-test
    PRIVATE bonvoyage-http2
  )

  foreach(test_target IN ITEMS
      bonvoyage-access-log-test
      bonvoyage-access-log-runtime-test
      bonvoyage-trace-context-test
      bonvoyage-trace-exporter-runtime-test
      bonvoyage-listener-lifecycle-test
      bonvoyage-runtime-snapshot-test
      bonvoyage-snapshot-preparation-test
      bonvoyage-snapshot-preparation-reactor-test
      bonvoyage-snapshot-activation-test
      bonvoyage-snapshot-activation-reactor-test
      bonvoyage-discovery-protocol-test
      bonvoyage-discovery-client-test
      bonvoyage-live-snapshot-coordinator-reactor-test
      bonvoyage-endpoint-maintenance-test
      bonvoyage-endpoint-selector-test
      bonvoyage-weighted-cluster-selector-test
      bonvoyage-retry-policy-test
      bonvoyage-route-admission-test
      bonvoyage-client-identity-test
      bonvoyage-source-ip-policy-test
      bonvoyage-cors-policy-test
      bonvoyage-request-content-policy-test
      bonvoyage-header-transformations-test
      bonvoyage-route-rewrite-test
      bonvoyage-api-key-auth-test
      bonvoyage-jwt-auth-test
      bonvoyage-endpoint-selector-benchmark
      bonvoyage-http1-validation-test
      bonvoyage-websocket-protocol-test
      bonvoyage-grpc-protocol-test
      bonvoyage-http2-request-validation-test
      bonvoyage-http2-client-session-test
      bonvoyage-http2-session-test
      bonvoyage-upstream-http1-client-test
      bonvoyage-upstream-request-test
      bonvoyage-upstream-response-head-test)
    target_compile_options(${test_target} PRIVATE
      -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
    )
    if(BONVOYAGE_WARNINGS_AS_ERRORS)
      target_compile_options(${test_target} PRIVATE -Werror)
    endif()
    if(BONVOYAGE_ENABLE_SANITIZERS)
      target_compile_options(${test_target} PRIVATE
        -fno-omit-frame-pointer
        -fno-sanitize-recover=undefined
        -fsanitize=address,undefined
      )
      target_link_options(${test_target} PRIVATE
        -fno-omit-frame-pointer -fsanitize=address,undefined
      )
    endif()
  endforeach()

  add_test(NAME bonvoyage-access-log COMMAND bonvoyage-access-log-test)
  add_test(NAME bonvoyage-trace-context COMMAND bonvoyage-trace-context-test)
  if(BONVOYAGE_RUN_RUNTIME_TESTS)
    add_test(
      NAME bonvoyage-access-log-runtime
      COMMAND bonvoyage-access-log-runtime-test
        --smp 1
        --memory 256M
        --overprovisioned
    )
    set_tests_properties(bonvoyage-access-log-runtime PROPERTIES TIMEOUT 20)
    add_test(
      NAME bonvoyage-trace-exporter-runtime
      COMMAND bonvoyage-trace-exporter-runtime-test
        --smp 1
        --memory 256M
        --overprovisioned
    )
    set_tests_properties(
      bonvoyage-trace-exporter-runtime PROPERTIES TIMEOUT 20
    )
    add_test(
      NAME bonvoyage-listener-lifecycle
      COMMAND bonvoyage-listener-lifecycle-test
        --smp 1
        --memory 256M
        --overprovisioned
    )
    set_tests_properties(bonvoyage-listener-lifecycle PROPERTIES TIMEOUT 20)
  endif()
  add_test(NAME bonvoyage-runtime-snapshot COMMAND bonvoyage-runtime-snapshot-test)
  add_test(
    NAME bonvoyage-snapshot-preparation
    COMMAND bonvoyage-snapshot-preparation-test
  )
  if(BONVOYAGE_RUN_RUNTIME_TESTS)
    add_test(
      NAME bonvoyage-snapshot-preparation-reactor
      COMMAND bonvoyage-snapshot-preparation-reactor-test
        --smp 2
        --memory 512M
        --overprovisioned
    )
    set_tests_properties(
      bonvoyage-snapshot-preparation-reactor PROPERTIES TIMEOUT 30
    )
    add_test(
      NAME bonvoyage-snapshot-activation-reactor
      COMMAND bonvoyage-snapshot-activation-reactor-test
        --smp 2
        --memory 512M
        --overprovisioned
    )
    set_tests_properties(
      bonvoyage-snapshot-activation-reactor PROPERTIES TIMEOUT 30
    )
    add_test(
      NAME bonvoyage-live-snapshot-coordinator-reactor
      COMMAND bonvoyage-live-snapshot-coordinator-reactor-test
        --smp 2
        --memory 512M
        --overprovisioned
    )
    set_tests_properties(
      bonvoyage-live-snapshot-coordinator-reactor PROPERTIES TIMEOUT 30
    )
  endif()
  add_test(
    NAME bonvoyage-snapshot-activation
    COMMAND bonvoyage-snapshot-activation-test
  )
  add_test(
    NAME bonvoyage-discovery-protocol
    COMMAND bonvoyage-discovery-protocol-test
  )
  add_test(
    NAME bonvoyage-discovery-client
    COMMAND bonvoyage-discovery-client-test
  )
  add_test(
    NAME bonvoyage-endpoint-maintenance
    COMMAND bonvoyage-endpoint-maintenance-test
  )
  add_test(NAME bonvoyage-endpoint-selector COMMAND bonvoyage-endpoint-selector-test)
  add_test(
    NAME bonvoyage-weighted-cluster-selector
    COMMAND bonvoyage-weighted-cluster-selector-test
  )
  add_test(NAME bonvoyage-retry-policy COMMAND bonvoyage-retry-policy-test)
  add_test(NAME bonvoyage-route-admission COMMAND bonvoyage-route-admission-test)
  add_test(NAME bonvoyage-client-identity COMMAND bonvoyage-client-identity-test)
  add_test(NAME bonvoyage-source-ip-policy COMMAND bonvoyage-source-ip-policy-test)
  add_test(NAME bonvoyage-cors-policy COMMAND bonvoyage-cors-policy-test)
  add_test(
    NAME bonvoyage-request-content-policy
    COMMAND bonvoyage-request-content-policy-test
  )
  add_test(
    NAME bonvoyage-header-transformations
    COMMAND bonvoyage-header-transformations-test
  )
  add_test(NAME bonvoyage-route-rewrite COMMAND bonvoyage-route-rewrite-test)
  add_test(NAME bonvoyage-api-key-auth COMMAND bonvoyage-api-key-auth-test)
  add_test(NAME bonvoyage-jwt-auth COMMAND bonvoyage-jwt-auth-test)
  add_test(NAME bonvoyage-http1-validation COMMAND bonvoyage-http1-validation-test)
  add_test(
    NAME bonvoyage-websocket-protocol
    COMMAND bonvoyage-websocket-protocol-test
  )
  add_test(NAME bonvoyage-grpc-protocol COMMAND bonvoyage-grpc-protocol-test)
  add_test(
    NAME bonvoyage-http2-request-validation
    COMMAND bonvoyage-http2-request-validation-test
  )
  add_test(NAME bonvoyage-http2-session COMMAND bonvoyage-http2-session-test)
  add_test(
    NAME bonvoyage-http2-client-session
    COMMAND bonvoyage-http2-client-session-test
  )
  add_test(
    NAME bonvoyage-upstream-http1-client
    COMMAND bonvoyage-upstream-http1-client-test
  )
  add_test(
    NAME bonvoyage-upstream-response-head
    COMMAND bonvoyage-upstream-response-head-test
  )
  add_test(
    NAME bonvoyage-upstream-request
    COMMAND bonvoyage-upstream-request-test
  )
  set_tests_properties(
    bonvoyage-access-log
    bonvoyage-trace-context
    bonvoyage-runtime-snapshot
    bonvoyage-snapshot-preparation
    bonvoyage-snapshot-activation
    bonvoyage-discovery-protocol
    bonvoyage-discovery-client
    bonvoyage-endpoint-maintenance
    bonvoyage-endpoint-selector
    bonvoyage-retry-policy
    bonvoyage-route-admission
    bonvoyage-client-identity
    bonvoyage-source-ip-policy
    bonvoyage-cors-policy
    bonvoyage-request-content-policy
    bonvoyage-header-transformations
    bonvoyage-route-rewrite
    bonvoyage-api-key-auth
    bonvoyage-jwt-auth
    bonvoyage-http1-validation
    bonvoyage-websocket-protocol
    bonvoyage-grpc-protocol
    bonvoyage-http2-request-validation
    bonvoyage-http2-client-session
    bonvoyage-http2-session
    bonvoyage-upstream-http1-client
    bonvoyage-upstream-request
    bonvoyage-upstream-response-head
    PROPERTIES TIMEOUT 20
  )
endif()

if(BONVOYAGE_BUILD_DOCUMENTATION)
  find_package(Doxygen REQUIRED)
  set(DOXYGEN_INPUT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
  set(DOXYGEN_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/doxygen")
  configure_file(Doxyfile.in Doxyfile @ONLY)
  add_custom_target(dataplane-docs
    COMMAND "${DOXYGEN_EXECUTABLE}" "${CMAKE_CURRENT_BINARY_DIR}/Doxyfile"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    COMMENT "Generating BonVoyage dataplane API documentation"
    VERBATIM
  )
endif()
