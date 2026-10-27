#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <seastar/http/request.hh>

#include "bonvoyage/http/http1_validation.hh"

namespace {

seastar::http::request request() {
  auto value = seastar::http::request::make("POST", "example.test", "/v1");
  value._version = "1.1";
  return value;
}

void require(bool condition, const char* message) {
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

template <typename Mutation>
void require_status(Mutation mutation, std::uint16_t expected) {
  auto value = request();
  mutation(value);
  try {
    (void)bonvoyage::http::validate_request(value, 1024U);
  } catch (const bonvoyage::http::RequestError& error) {
    require(error.status_code() == expected, "unexpected rejection status");
    return;
  }
  require(false, "invalid request was accepted");
}

template <typename Callable>
void require_response_rejection(Callable callable) {
  try {
    (void)callable();
  } catch (const std::runtime_error&) {
    return;
  }
  require(false, "invalid upstream response framing was accepted");
}

char ascii_lower(char value) {
  return value >= 'A' && value <= 'Z'
             ? static_cast<char>(value + ('a' - 'A'))
             : value;
}

std::string lowercase_ascii(std::string_view value) {
  std::string result(value);
  std::transform(result.begin(), result.end(), result.begin(), ascii_lower);
  return result;
}

std::string alternate_case(std::string_view value, std::size_t offset) {
  std::string result(value);
  for (std::size_t index = 0U; index < result.size(); ++index) {
    const auto byte = static_cast<unsigned char>(result[index]);
    if (byte >= 'a' && byte <= 'z' && (index + offset) % 2U == 0U) {
      result[index] = static_cast<char>(
          std::toupper(static_cast<unsigned char>(result[index])));
    }
  }
  return result;
}

bonvoyage::http::RequestHeaderLookupResult reference_header_lookup(
    const seastar::http::request& value,
    std::string_view lowercase_name) noexcept {
  bonvoyage::http::RequestHeaderLookupResult result;
  for (const auto& [name, field_value] : value._headers) {
    if (!bonvoyage::http::ascii_case_equal(name, lowercase_name)) {
      continue;
    }
    if (result.present) {
      result.repeated = true;
      continue;
    }
    result.value = field_value;
    result.present = true;
  }
  return result;
}

void require_lookup_equal(
    const bonvoyage::http::RequestHeaderLookupResult& actual,
    const bonvoyage::http::RequestHeaderLookupResult& expected,
    const char* message) {
  require(actual.value == expected.value &&
              actual.present == expected.present &&
              actual.repeated == expected.repeated,
          message);
}

void test_selected_http1_headers() {
  using Selected = bonvoyage::http::SelectedHttp1Headers;
  using Member = bonvoyage::http::RequestHeaderLookupResult Selected::*;
  struct SelectionCase final {
    std::string_view name;
    Member member;
  };
  constexpr std::array<SelectionCase, 14U> selections{{
      {"host", &Selected::host},
      {"connection", &Selected::connection},
      {"upgrade", &Selected::upgrade},
      {"expect", &Selected::expect},
      {"content-length", &Selected::content_length},
      {"transfer-encoding", &Selected::transfer_encoding},
      {"sec-websocket-version", &Selected::websocket_version},
      {"sec-websocket-key", &Selected::websocket_key},
      {"sec-websocket-protocol", &Selected::websocket_protocol},
      {"sec-websocket-extensions", &Selected::websocket_extensions},
      {"origin", &Selected::origin},
      {"access-control-request-method", &Selected::cors_method},
      {"access-control-request-headers", &Selected::cors_headers},
      {"x-forwarded-for", &Selected::forwarded_for},
  }};

  for (std::size_t case_offset = 0U; case_offset < 2U; ++case_offset) {
    auto value = request();
    value._headers.clear();
    for (std::size_t index = 0U; index < selections.size(); ++index) {
      const auto name = alternate_case(selections[index].name,
                                       index + case_offset);
      const auto field_value = "selected-" + std::to_string(index);
      value._headers[seastar::sstring(name)] =
          seastar::sstring(field_value);
    }
    value._headers["x-ignored-field"] = "ignored";
    value._headers["export"] = "same-length-decoy";
    value._headers.emplace("ORIGIN", "duplicate-if-supported");

    const auto actual = bonvoyage::http::select_http1_headers(value);
    for (const auto& selection : selections) {
      require_lookup_equal(
          actual.*(selection.member),
          reference_header_lookup(value, selection.name),
          "single-scan HTTP/1 selector diverged from reference lookup");
    }
  }

  auto value = request();
  value._headers.clear();
  const auto selected = bonvoyage::http::select_http1_headers(value);
  for (const auto& selection : selections) {
    require_lookup_equal(
        selected.*(selection.member),
        reference_header_lookup(value, selection.name),
        "missing HTTP/1 field diverged from reference lookup");
  }
}

struct ValidationOutcome final {
  bool accepted{false};
  bonvoyage::http::BodyKind kind{bonvoyage::http::BodyKind::none};
  std::uint64_t content_length{};
  std::uint16_t status{};
  std::string code;
};

ValidationOutcome validate_with_reference_lookup(
    const seastar::http::request& value) {
  try {
    const auto framing = bonvoyage::http::validate_request(value, 1024U);
    return ValidationOutcome{true, framing.kind, framing.content_length, 0U,
                             {}};
  } catch (const bonvoyage::http::RequestError& error) {
    return ValidationOutcome{false, bonvoyage::http::BodyKind::none, 0U,
                             error.status_code(), error.code()};
  }
}

ValidationOutcome validate_with_selected_headers(
    const seastar::http::request& value) {
  const auto selected = bonvoyage::http::select_http1_headers(value);
  try {
    const auto framing = bonvoyage::http::validate_request(
        value,
        bonvoyage::http::RequestFramingHeaders{
            selected.host.value, selected.upgrade.value,
            selected.expect.value, selected.content_length.value,
            selected.transfer_encoding.value},
        1024U);
    return ValidationOutcome{true, framing.kind, framing.content_length, 0U,
                             {}};
  } catch (const bonvoyage::http::RequestError& error) {
    return ValidationOutcome{false, bonvoyage::http::BodyKind::none, 0U,
                             error.status_code(), error.code()};
  }
}

template <typename Mutation>
void require_selector_validation_equivalence(Mutation mutation) {
  auto value = request();
  mutation(value);
  const auto expected = validate_with_reference_lookup(value);
  const auto actual = validate_with_selected_headers(value);
  require(actual.accepted == expected.accepted &&
              actual.kind == expected.kind &&
              actual.content_length == expected.content_length &&
              actual.status == expected.status &&
              actual.code == expected.code,
          "selected HTTP/1 fields changed framing validation behavior");
}

void test_selector_validation_equivalence() {
  require_selector_validation_equivalence([](auto&) {});
  require_selector_validation_equivalence([](auto& value) {
    value._headers["cOnTeNt-LeNgTh"] = "12";
  });
  require_selector_validation_equivalence([](auto& value) {
    value._headers["TrAnSfEr-EnCoDiNg"] = "ChUnKeD";
  });
  require_selector_validation_equivalence([](auto& value) {
    value._headers["Content-Length"] = "1";
    value._headers["Transfer-Encoding"] = "chunked";
  });
  require_selector_validation_equivalence([](auto& value) {
    value._headers["Content-Length"] = "1,1";
  });
  require_selector_validation_equivalence([](auto& value) {
    value._headers["Content-Length"] = "1025";
  });
  require_selector_validation_equivalence([](auto& value) {
    value._headers.erase("Host");
  });
  require_selector_validation_equivalence([](auto& value) {
    value._headers["Host"] = "bad host";
  });
  require_selector_validation_equivalence([](auto& value) {
    value._headers["Upgrade"] = "h2c";
  });
  require_selector_validation_equivalence([](auto& value) {
    value._headers["Expect"] = "100-continue";
  });
  require_selector_validation_equivalence([](auto& value) {
    value._url = "http://example.test/";
  });
}

struct ConstantHash final {
  std::size_t operator()(const seastar::sstring&) const noexcept { return 0U; }
};

void test_seastar_header_hash_contract() {
  const seastar::internal::case_insensitive_cmp compare;
  const seastar::internal::case_insensitive_hash hash;
  constexpr std::string_view token_characters =
      "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz";

  for (const auto left_character : token_characters) {
    for (const auto right_character : token_characters) {
      const std::string left(1U, left_character);
      const std::string right(1U, right_character);
      const seastar::sstring left_value(left);
      const seastar::sstring right_value(right);
      const auto expected = bonvoyage::http::ascii_case_equal(left, right);
      require(compare(left_value, right_value) == expected,
              "Seastar comparator changed valid token-byte semantics");
      if (expected) {
        require(hash(left_value) == hash(right_value),
                "equal valid token bytes produced different hashes");
      }
    }
  }

  constexpr std::string_view permutation_base = "abcdefghijkl";
  for (std::uint32_t mask = 0U;
       mask < (1U << permutation_base.size()); ++mask) {
    std::string candidate(permutation_base);
    for (std::size_t index = 0U; index < candidate.size(); ++index) {
      if ((mask & (1U << index)) != 0U) {
        candidate[index] = static_cast<char>(
            std::toupper(static_cast<unsigned char>(candidate[index])));
      }
    }
    const seastar::sstring candidate_value(candidate);
    const seastar::sstring base_value(permutation_base);
    require(compare(candidate_value, base_value),
            "Seastar comparator rejected a case permutation");
    require(hash(candidate_value) == hash(base_value),
            "case permutation produced a different Seastar hash");
  }

  constexpr std::array<std::size_t, 7U> lengths{
      0U, 1U, 15U, 63U, 255U, 1024U, 32768U};
  for (const auto length : lengths) {
    std::string mixed(length, 'a');
    for (std::size_t index = 0U; index < mixed.size(); ++index) {
      mixed[index] = index % 3U == 0U ? 'X' :
                     index % 3U == 1U ? '-' : '7';
    }
    const auto folded = lowercase_ascii(mixed);
    const seastar::sstring mixed_value(mixed);
    const seastar::sstring folded_value(folded);
    require(compare(mixed_value, folded_value),
            "Seastar comparator rejected a bounded long header name");
    require(hash(mixed_value) == hash(folded_value),
            "bounded long header name produced a different folded hash");
  }

  std::unordered_map<seastar::sstring, std::size_t,
                     seastar::internal::case_insensitive_hash,
                     seastar::internal::case_insensitive_cmp>
      headers;
  for (std::size_t index = 0U; index < 512U; ++index) {
    headers.emplace(seastar::sstring("X-BonVoyage-Header-" +
                                     std::to_string(index)),
                    index);
  }
  for (std::size_t index = 0U; index < 512U; ++index) {
    const auto found = headers.find(seastar::sstring(
        "x-bonvoyage-header-" + std::to_string(index)));
    require(found != headers.end() && found->second == index,
            "mixed-case lookup failed in the generated header corpus");
  }

  std::unordered_map<seastar::sstring, std::size_t, ConstantHash,
                     seastar::internal::case_insensitive_cmp>
      collision_stress;
  for (std::size_t index = 0U; index < 128U; ++index) {
    collision_stress.emplace(seastar::sstring(
                                 "X-Collision-Stress-" +
                                 std::to_string(index)),
                             index);
  }
  for (std::size_t index = 0U; index < 128U; ++index) {
    const auto found = collision_stress.find(seastar::sstring(
        "x-collision-stress-" + std::to_string(index)));
    require(found != collision_stress.end() && found->second == index,
            "case-insensitive equality failed under forced collisions");
  }
}

seastar::temporary_buffer<char> serialize_scoped_response_headers() {
  const std::vector<std::pair<std::string, std::string>> owners{
      {"Content-Type", "text/plain"}, {"X-Owned", "scoped"}};
  const std::array<bonvoyage::http::HeaderView, 2U> views{
      bonvoyage::http::HeaderView{owners[0].first, owners[0].second},
      bonvoyage::http::HeaderView{owners[1].first, owners[1].second}};
  return bonvoyage::http::serialize_response_head_buffer(
      200U, "OK", views, false);
}

}  // namespace

int main() {
  test_seastar_header_hash_contract();
  test_selected_http1_headers();
  test_selector_validation_equivalence();

  auto value = request();
  value._headers["Content-Length"] = "12";
  const auto framing = bonvoyage::http::validate_request(value, 1024U);
  require(framing.kind == bonvoyage::http::BodyKind::content_length &&
              framing.content_length == 12U,
          "valid content length was not prepared");
  const bonvoyage::http::RequestFramingHeaders selected_framing_headers{
      "example.test", "", "", "12", ""};
  const auto selected_framing = bonvoyage::http::validate_request(
      value, selected_framing_headers, 1024U);
  require(selected_framing.kind ==
              bonvoyage::http::BodyKind::content_length &&
              selected_framing.content_length == 12U,
          "borrowed request framing fields were not validated");

  require_status(
      [](auto& candidate) {
        candidate._headers["Content-Length"] = "1";
        candidate._headers["Transfer-Encoding"] = "chunked";
      },
      400U);
  require_status(
      [](auto& candidate) { candidate._headers["Content-Length"] = "1,1"; },
      400U);
  require_status(
      [](auto& candidate) { candidate._headers["Content-Length"] = "1025"; },
      413U);
  require_status(
      [](auto& candidate) { candidate._headers.erase("Host"); }, 400U);
  require_status(
      [](auto& candidate) { candidate._headers["Host"] = "bad host"; },
      400U);
  require_status(
      [](auto& candidate) { candidate._headers["Host"] = "example.test:0"; },
      400U);
  require_status(
      [](auto& candidate) { candidate._headers["Host"] = "2001:db8::1"; },
      400U);
  require_status(
      [](auto& candidate) { candidate._headers["Host"] = "[1:2:3]"; },
      400U);
  value = request();
  value._headers["Connection"] = "keep-alive, Upgrade";
  value._headers["Upgrade"] = "websocket";
  require(bonvoyage::http::validate_request(value, 1024U).kind ==
              bonvoyage::http::BodyKind::none,
          "WebSocket candidate was rejected before route policy validation");
  require_status(
      [](auto& candidate) { candidate._headers["Upgrade"] = "h2c"; },
      426U);
  require_status(
      [](auto& candidate) { candidate._url = "http://example.test/"; }, 400U);

  value = request();
  value._headers["Host"] = "[2001:db8::1]:8080";
  require(bonvoyage::http::validate_request(value, 1024U).kind ==
              bonvoyage::http::BodyKind::none,
          "valid bracketed IPv6 Host was rejected");

  require(bonvoyage::http::ascii_case_equal("Content-Length",
                                             "content-length"),
          "ASCII case-insensitive comparison failed");
  require(!bonvoyage::http::ascii_case_equal("x-internal", "x-intern"),
          "ASCII token comparison accepted a prefix");
  require(bonvoyage::http::is_event_stream_content_type(
              "text/event-stream"),
          "canonical SSE content type was not recognized");
  require(bonvoyage::http::is_event_stream_content_type(
              " Text/Event-Stream ; charset=utf-8\t"),
          "parameterized mixed-case SSE content type was not recognized");
  require(!bonvoyage::http::is_event_stream_content_type(""),
          "empty content type was recognized as SSE");
  require(!bonvoyage::http::is_event_stream_content_type(
              "text/event-streaming"),
          "SSE content-type prefix was accepted");
  require(!bonvoyage::http::is_event_stream_content_type(
              "text/event-stream+json"),
          "SSE content-type suffix was accepted");
  require(bonvoyage::http::connection_has_token(
              " keep-alive,\tX-Internal ,, close ", "x-internal"),
          "Connection-nominated mixed-case token was not found");
  require(!bonvoyage::http::connection_has_token(
              "keep-alive, X-Internal", "x-intern"),
          "Connection token matching accepted a prefix");
  const bonvoyage::http::ConnectionTokenSet nominated_headers(
      " keep-alive, X-Internal, x-debug, X-Internal ");
  require(nominated_headers.contains("x-internal"),
          "parsed Connection nominations lost mixed-case tokens");
  require(!nominated_headers.contains("x-intern"),
          "parsed Connection nominations accepted a prefix");
  constexpr std::array<std::string_view, 8U> fixed_hop_headers{
      "Connection", "Keep-Alive", "Proxy-Authenticate",
      "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding",
      "Upgrade"};
  for (const auto header : fixed_hop_headers) {
    require(bonvoyage::http::is_hop_by_hop_header(header, ""),
            "fixed mixed-case hop-by-hop name was not identified");
  }
  require(bonvoyage::http::is_hop_by_hop_header(
              "X-Internal", nominated_headers),
          "Connection-nominated header was not identified");
  require(!bonvoyage::http::is_hop_by_hop_header(
              "X-External", nominated_headers),
          "end-to-end header was classified as hop-by-hop");
  require(!bonvoyage::http::is_hop_by_hop_header("Content-Length", ""),
          "Content-Length must remain a separately handled framing field");
  require(!bonvoyage::http::connection_has_token(", ,\t,", "close"),
          "empty Connection elements produced a token match");
  require(bonvoyage::http::trim_ows_view(" \tvalue\t ") == "value",
          "optional whitespace view was not trimmed");

  const seastar::sstring mixed_case_header = "X-BonVoyage-Trace";
  const seastar::sstring lower_case_header = "x-bonvoyage-trace";
  require(seastar::internal::case_insensitive_cmp()(
              mixed_case_header, lower_case_header),
          "Seastar header comparison lost ASCII case folding");
  require(seastar::internal::case_insensitive_hash()(mixed_case_header) ==
              seastar::internal::case_insensitive_hash()(lower_case_header),
          "equal Seastar header names produced different hashes");
  value = request();
  value._headers[mixed_case_header] = "present";
  require(value._headers.find(lower_case_header) != value._headers.end(),
          "mixed-case Seastar header lookup failed");

  const auto fixed_response =
      bonvoyage::http::validate_response_framing("GET", 200U, " 12 ", "");
  require(fixed_response.kind ==
              bonvoyage::http::ResponseBodyKind::content_length &&
              fixed_response.content_length == 12U,
          "valid upstream Content-Length was not prepared");
  const auto chunked_response =
      bonvoyage::http::validate_response_framing("GET", 200U, "", "Chunked");
  require(chunked_response.kind == bonvoyage::http::ResponseBodyKind::chunked &&
              !chunked_response.content_length.has_value(),
          "case-insensitive upstream chunked framing was rejected");
  const auto close_delimited =
      bonvoyage::http::validate_response_framing("GET", 200U, "", "");
  require(close_delimited.kind ==
              bonvoyage::http::ResponseBodyKind::close_delimited,
          "close-delimited upstream response was not classified");
  const auto head_response =
      bonvoyage::http::validate_response_framing("HEAD", 200U, "25", "");
  require(head_response.kind == bonvoyage::http::ResponseBodyKind::none &&
              head_response.content_length == 25U,
          "HEAD representation length was not preserved");
  require(bonvoyage::http::validate_response_framing("GET", 304U, "25", "")
              .kind == bonvoyage::http::ResponseBodyKind::none,
          "304 response framing was not classified as bodyless");
  require(!bonvoyage::http::response_allows_body("GET", 205U),
          "205 response was incorrectly allowed to carry content");
  const auto reset_content_response =
      bonvoyage::http::validate_response_framing("GET", 205U, "0", "");
  require(reset_content_response.kind ==
              bonvoyage::http::ResponseBodyKind::none &&
              reset_content_response.content_length == 0U,
          "valid zero-length 205 response framing was rejected");
  require_response_rejection([] {
    return bonvoyage::http::validate_response_framing(
        "GET", 200U, "1", "chunked");
  });
  require_response_rejection([] {
    return bonvoyage::http::validate_response_framing(
        "GET", 200U, "", "gzip, chunked");
  });
  require_response_rejection([] {
    return bonvoyage::http::validate_response_framing(
        "GET", 200U, "1, 1", "");
  });
  require_response_rejection([] {
    return bonvoyage::http::validate_response_framing(
        "GET", 204U, "1", "");
  });
  require_response_rejection([] {
    return bonvoyage::http::validate_response_framing(
        "GET", 205U, "1", "");
  });
  require_response_rejection([] {
    return bonvoyage::http::validate_response_framing(
        "GET", 205U, "", "chunked");
  });
  require_response_rejection([] {
    return bonvoyage::http::validate_response_framing(
        "HEAD", 200U, "", "chunked");
  });

  const std::vector<std::pair<std::string, std::string>> response_headers{
      {"Content-Type", "text/plain"}, {"Content-Length", "2"}};
  require(bonvoyage::http::serialize_response_head(
              200U, "OK", response_headers, false) ==
              "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
              "Content-Length: 2\r\nConnection: keep-alive\r\n\r\n",
          "keep-alive response head serialization changed");
  require(bonvoyage::http::serialize_response_head(
              503U, "Service Unavailable",
              std::vector<std::pair<std::string, std::string>>{}, true) ==
              "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n",
          "close response head serialization changed");

  constexpr std::array<bonvoyage::http::HeaderView, 2U> response_header_views{
      bonvoyage::http::HeaderView{"Content-Type", "text/plain"},
      bonvoyage::http::HeaderView{"Content-Length", "2"}};
  require(bonvoyage::http::serialize_response_head_views(
              200U, "OK", response_header_views, false) ==
              "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
              "Content-Length: 2\r\nConnection: keep-alive\r\n\r\n",
          "borrowed response head serialization changed");
  const auto response_head_buffer =
      bonvoyage::http::serialize_response_head_buffer(
          200U, "OK", response_header_views, false);
  require(std::string_view(response_head_buffer.get(),
                           response_head_buffer.size()) ==
              "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
              "Content-Length: 2\r\nConnection: keep-alive\r\n\r\n",
          "movable response head serialization changed");
  const auto scoped_response_head = serialize_scoped_response_headers();
  require(std::string_view(scoped_response_head.get(),
                           scoped_response_head.size()) ==
              "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
              "X-Owned: scoped\r\nConnection: keep-alive\r\n\r\n",
          "serialized response buffer retained borrowed owner storage");
  return 0;
}
