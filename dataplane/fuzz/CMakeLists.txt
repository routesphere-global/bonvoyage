cmake_minimum_required(VERSION 3.28)

project(
  bonvoyage_http2_fuzz
  DESCRIPTION "Sanitizer-backed BonVoyage HTTP/2 protocol-engine fuzzer"
  LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR "BonVoyage libFuzzer targets require Clang")
endif()

find_package(nghttp2 1.70.0 EXACT CONFIG REQUIRED)
find_package(llhttp 9.4.3 EXACT CONFIG REQUIRED)

set(BONVOYAGE_FUZZ_WARNINGS
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
  -Werror
)
set(BONVOYAGE_FUZZ_SANITIZERS
  -fno-omit-frame-pointer
  -fno-sanitize-recover=undefined
  -fsanitize=fuzzer-no-link,address,undefined
)

# Keep this target transport-neutral: the parser/session engine does not use
# Seastar, so fuzzing it must not inherit the reactor's compiler or allocator.
add_library(bonvoyage-http2-fuzz-subject STATIC
  ../src/http2_session.cc
)
target_include_directories(bonvoyage-http2-fuzz-subject PUBLIC ../include)
target_link_libraries(
  bonvoyage-http2-fuzz-subject
  PUBLIC nghttp2::nghttp2_static
)
target_compile_options(
  bonvoyage-http2-fuzz-subject
  PRIVATE ${BONVOYAGE_FUZZ_WARNINGS} ${BONVOYAGE_FUZZ_SANITIZERS}
)

add_executable(
  bonvoyage-http2-session-fuzz
  http2_session_fuzz.cc
)
target_link_libraries(
  bonvoyage-http2-session-fuzz
  PRIVATE bonvoyage-http2-fuzz-subject
)
target_compile_options(
  bonvoyage-http2-session-fuzz
  PRIVATE ${BONVOYAGE_FUZZ_WARNINGS} ${BONVOYAGE_FUZZ_SANITIZERS}
)
target_link_options(bonvoyage-http2-session-fuzz PRIVATE
  -fno-omit-frame-pointer
  -fno-sanitize-recover=undefined
  -fsanitize=fuzzer,address,undefined
)

add_library(bonvoyage-http2-client-fuzz-subject STATIC
  ../src/http2_client_session.cc
)
target_include_directories(
  bonvoyage-http2-client-fuzz-subject PUBLIC ../include
)
target_link_libraries(
  bonvoyage-http2-client-fuzz-subject
  PUBLIC bonvoyage-http2-fuzz-subject nghttp2::nghttp2_static
)
target_compile_options(
  bonvoyage-http2-client-fuzz-subject
  PRIVATE ${BONVOYAGE_FUZZ_WARNINGS} ${BONVOYAGE_FUZZ_SANITIZERS}
)

add_executable(
  bonvoyage-http2-client-session-fuzz
  http2_client_session_fuzz.cc
)
target_link_libraries(
  bonvoyage-http2-client-session-fuzz
  PRIVATE bonvoyage-http2-client-fuzz-subject
)
target_compile_options(
  bonvoyage-http2-client-session-fuzz
  PRIVATE ${BONVOYAGE_FUZZ_WARNINGS} ${BONVOYAGE_FUZZ_SANITIZERS}
)
target_link_options(bonvoyage-http2-client-session-fuzz PRIVATE
  -fno-omit-frame-pointer
  -fno-sanitize-recover=undefined
  -fsanitize=fuzzer,address,undefined
)

add_library(bonvoyage-upstream-response-head-fuzz-subject STATIC
  ../src/upstream_response_head_parser.cc
)
target_include_directories(
  bonvoyage-upstream-response-head-fuzz-subject PUBLIC ../include
)
target_link_libraries(
  bonvoyage-upstream-response-head-fuzz-subject
  PUBLIC llhttp::llhttp_static
)
target_compile_options(
  bonvoyage-upstream-response-head-fuzz-subject
  PRIVATE ${BONVOYAGE_FUZZ_WARNINGS} ${BONVOYAGE_FUZZ_SANITIZERS}
)

add_executable(
  bonvoyage-upstream-response-head-fuzz
  upstream_response_head_parser_fuzz.cc
)
target_link_libraries(
  bonvoyage-upstream-response-head-fuzz
  PRIVATE bonvoyage-upstream-response-head-fuzz-subject
)
target_compile_options(
  bonvoyage-upstream-response-head-fuzz
  PRIVATE ${BONVOYAGE_FUZZ_WARNINGS} ${BONVOYAGE_FUZZ_SANITIZERS}
)
target_link_options(bonvoyage-upstream-response-head-fuzz PRIVATE
  -fno-omit-frame-pointer
  -fno-sanitize-recover=undefined
  -fsanitize=fuzzer,address,undefined
)
