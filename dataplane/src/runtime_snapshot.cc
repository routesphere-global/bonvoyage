#include "bonvoyage/runtime/runtime_snapshot.hh"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <limits>
#include <stdexcept>
#include <unordered_set>

#include <re2/re2.h>

#include "bonvoyage/version.hh"

namespace bonvoyage::runtime {
namespace {

constexpr std::size_t kMaximumFixedResponseBytes = 1024U * 1024U;
constexpr std::size_t kMaximumRedirectLocationBytes = 8U * 1024U;
constexpr std::uint32_t kMaximumRouteWeight = 4096U;
constexpr std::uint32_t kMaximumConnectionsPerShard = 1000000U;
constexpr std::uint32_t kMaximumPendingRequestsPerShard = 1000000U;
constexpr std::uint32_t kMaximumConcurrentRequestsPerEndpoint = 2000000U;
constexpr std::uint32_t kMaximumHttp2StreamsPerConnection = 1000U;
constexpr std::uint32_t kMaximumPassiveFailureCount = 100U;
constexpr std::uint32_t kMaximumPassiveSuccessCount = 100U;
constexpr std::uint32_t kMaximumPassiveEjectionTimeMs = 300000U;
constexpr std::uint32_t kMaximumActiveHealthIntervalMs = 300000U;
constexpr std::uint32_t kMaximumActiveHealthTimeoutMs = 10000U;
constexpr std::uint32_t kMaximumActiveHealthThreshold = 100U;
constexpr std::uint32_t kMaximumDnsRefreshIntervalMs = 3600000U;
constexpr std::uint32_t kMaximumDnsResolveTimeoutMs = 10000U;
constexpr std::uint32_t kMaximumRetryAttempts = 5U;
constexpr std::uint32_t kMaximumRetryBudget = 1000000U;
constexpr std::uint32_t kMaximumRouteConcurrency = 2000000U;
constexpr std::uint32_t kMaximumRouteRateLimit = 1000000U;
constexpr std::size_t kMaximumRetryMethods = 5U;
constexpr std::size_t kMaximumRouteMethods = 16U;
constexpr std::size_t kMaximumRoutePredicates = 16U;
constexpr std::size_t kMaximumRouteMethodBytes = 32U;
constexpr std::size_t kMaximumRoutePathBytes = 4U * 1024U;
constexpr std::size_t kMaximumSafeRegexBytes = 1024U;
constexpr std::size_t kSafeRegexMemoryBytes = 256U * 1024U;
constexpr std::size_t kMaximumHeaderNameBytes = 128U;
constexpr std::size_t kMaximumHeaderMutationValueBytes = 4U * 1024U;
constexpr std::size_t kMaximumHeaderMutationsPerDirection = 16U;
constexpr std::size_t kMaximumHeaderMutationBytesPerDirection = 16U * 1024U;
constexpr std::size_t kMaximumWeightedClustersPerRoute = 16U;
constexpr std::uint32_t kMaximumWeightedClusterTotal = 4096U;
constexpr std::size_t kMaximumQueryNameBytes = 256U;
constexpr std::size_t kMaximumPredicateValueBytes = 4U * 1024U;
constexpr std::size_t kMaximumJwtIssuerBytes = 1024U;
constexpr std::size_t kMaximumJwtAudienceBytes = 256U;
constexpr std::size_t kMaximumJwtTypeBytes = 64U;
constexpr std::size_t kMaximumJwtAlgorithms = 3U;
constexpr std::uint32_t kMaximumJwtClockSkewSeconds = 300U;
constexpr std::uint32_t kMaximumJwtLifetimeSeconds = 86400U;
constexpr std::size_t kMaximumJwtPolicyEntries = 16U;
constexpr std::size_t kMaximumJwtScopeBytes = 128U;
constexpr std::size_t kMaximumJwtClaimNameBytes = 64U;
constexpr std::size_t kMaximumJwtClaimValueBytes = 256U;

[[noreturn]] void invalid(const std::string& field, const std::string& reason) {
  throw std::invalid_argument(field + ": " + reason);
}

std::string lower_ascii(std::string_view value) {
  std::string result(value);
  std::transform(result.begin(), result.end(), result.begin(), [](char c) {
    return static_cast<char>(
        std::tolower(static_cast<unsigned char>(c)));
  });
  return result;
}

bool contains_ctl(std::string_view value) {
  return std::any_of(value.begin(), value.end(), [](char c) {
    const auto byte = static_cast<unsigned char>(c);
    return byte < 0x20U || byte == 0x7fU;
  });
}

bool valid_http_token(std::string_view value) {
  if (value.empty()) {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [](char character) {
    const auto alphanumeric =
        (character >= '0' && character <= '9') ||
        (character >= 'A' && character <= 'Z') ||
        (character >= 'a' && character <= 'z');
    if (alphanumeric) {
      return true;
    }
    switch (character) {
      case '!':
      case '#':
      case '$':
      case '%':
      case '&':
      case '\'':
      case '*':
      case '+':
      case '-':
      case '.':
      case '^':
      case '_':
      case '`':
      case '|':
      case '~':
        return true;
      default:
        return false;
    }
  });
}

bool reserved_api_key_header(std::string_view value) noexcept {
  return value == "cf-connecting-ip" || value == "client-ip" ||
         value == "connection" || value == "content-length" ||
         value == "forwarded" || value == "host" ||
         value == "proxy-connection" || value == "te" ||
         value == "trailer" || value == "transfer-encoding" ||
         value == "true-client-ip" || value == "upgrade" ||
         value == "x-real-ip" || value.starts_with("x-forwarded-");
}

bool canonical_method(std::string_view value) {
  return valid_http_token(value) && value.size() <= kMaximumRouteMethodBytes &&
         std::none_of(value.begin(), value.end(), [](char character) {
           return character >= 'a' && character <= 'z';
         });
}

bool idempotent_retry_method(std::string_view value) noexcept {
  return value == "DELETE" || value == "GET" || value == "HEAD" ||
         value == "OPTIONS" || value == "PUT";
}

int hex_value(char character) noexcept {
  if (character >= '0' && character <= '9') {
    return character - '0';
  }
  if (character >= 'a' && character <= 'f') {
    return character - 'a' + 10;
  }
  if (character >= 'A' && character <= 'F') {
    return character - 'A' + 10;
  }
  return -1;
}

bool decoded_component_equal(std::string_view encoded,
                             std::string_view expected) noexcept {
  std::size_t expected_offset = 0U;
  for (std::size_t offset = 0U; offset < encoded.size(); ++offset) {
    unsigned char decoded = static_cast<unsigned char>(encoded[offset]);
    if (encoded[offset] == '%') {
      if (offset + 2U >= encoded.size()) {
        return false;
      }
      const auto high = hex_value(encoded[offset + 1U]);
      const auto low = hex_value(encoded[offset + 2U]);
      if (high < 0 || low < 0) {
        return false;
      }
      decoded = static_cast<unsigned char>((high << 4U) | low);
      offset += 2U;
    }
    if (expected_offset >= expected.size() ||
        decoded != static_cast<unsigned char>(expected[expected_offset])) {
      return false;
    }
    ++expected_offset;
  }
  return expected_offset == expected.size();
}

bool query_predicate_matches(const RuntimeQueryParameterMatch& predicate,
                             std::string_view query) noexcept {
  bool present = false;
  while (!query.empty()) {
    const auto separator = query.find('&');
    const auto component = query.substr(0U, separator);
    const auto equals = component.find('=');
    const auto name = component.substr(0U, equals);
    const auto value = equals == std::string_view::npos
                           ? std::string_view{}
                           : component.substr(equals + 1U);
    if (decoded_component_equal(name, predicate.name)) {
      present = true;
      if (predicate.exact.has_value() &&
          decoded_component_equal(value, *predicate.exact)) {
        return true;
      }
    }
    if (separator == std::string_view::npos) {
      break;
    }
    query.remove_prefix(separator + 1U);
  }
  if (predicate.exact.has_value()) {
    return false;
  }
  return present == predicate.present;
}

void append_signature(std::string& signature, char kind,
                      std::string_view value) {
  signature.push_back(kind);
  signature.append(std::to_string(value.size()));
  signature.push_back(':');
  signature.append(value);
  signature.push_back(';');
}

std::string route_signature(const RuntimeRoute& route) {
  std::string signature;
  append_signature(signature, route.exact_path
                                  ? 'E'
                                  : route.safe_regex != nullptr ? 'R' : 'P',
                   route.path);
  for (const auto& method : route.methods) {
    append_signature(signature, 'M', method);
  }
  for (const auto& header : route.headers) {
    append_signature(signature, 'H', header.name);
    if (header.exact.has_value()) {
      append_signature(signature, '=', *header.exact);
    } else {
      append_signature(signature, '?', header.present ? "1" : "0");
    }
  }
  for (const auto& query : route.query_parameters) {
    append_signature(signature, 'Q', query.name);
    if (query.exact.has_value()) {
      append_signature(signature, '=', *query.exact);
    } else {
      append_signature(signature, '?', query.present ? "1" : "0");
    }
  }
  return signature;
}

std::string route_path_signature(const RuntimeRoute& route) {
  std::string signature;
  char kind = 'P';
  if (route.exact_path) {
    kind = 'E';
  } else if (route.safe_regex != nullptr) {
    kind = 'R';
  }
  append_signature(signature, kind, route.path);
  return signature;
}

bool route_is_unconditional(const RuntimeRoute& route) {
  return route.methods.empty() && route.headers.empty() &&
         route.query_parameters.empty();
}

bool valid_name(std::string_view value) {
  if (value.empty() || value.size() > 128U) {
    return false;
  }
  const auto alnum = [](char character) {
    return (character >= 'a' && character <= 'z') ||
           (character >= 'A' && character <= 'Z') ||
           (character >= '0' && character <= '9');
  };
  if (!alnum(value.front())) {
    return false;
  }
  return std::all_of(value.begin() + 1, value.end(), [alnum](char character) {
    return alnum(character) || character == '.' || character == '_' ||
           character == '-';
  });
}

bool valid_secret_reference(std::string_view value) {
  return valid_name(value) && value != "." && value != "..";
}

bool visible_ascii(std::string_view value, bool allow_space) noexcept {
  return !value.empty() &&
         std::all_of(value.begin(), value.end(), [allow_space](char character) {
           const auto byte = static_cast<unsigned char>(character);
           return byte >= (allow_space ? 0x20U : 0x21U) && byte <= 0x7eU;
         });
}

bool trimmed_visible_text(std::string_view value) noexcept {
  return !value.empty() && !contains_ctl(value) &&
         static_cast<unsigned char>(value.front()) > 0x20U &&
         static_cast<unsigned char>(value.back()) > 0x20U;
}

bool protocol_owned_header(std::string_view name) noexcept {
  return name == "connection" || name == "content-length" || name == "host" ||
         name == "keep-alive" || name == "proxy-connection" || name == "te" ||
         name == "trailer" || name == "transfer-encoding" ||
         name == "upgrade" || name == "sec-websocket-accept" ||
         name == "sec-websocket-extensions" ||
         name == "sec-websocket-key" ||
         name == "sec-websocket-protocol" ||
         name == "sec-websocket-version" || name == "traceparent" ||
         name == "tracestate" || name == "baggage";
}

bool forwarding_identity_header(std::string_view name) noexcept {
  return name == "cf-connecting-ip" || name == "client-ip" ||
         name == "forwarded" || name == "true-client-ip" ||
         name == "x-real-ip" || name.starts_with("x-forwarded-");
}

bool cors_owned_header(std::string_view name) noexcept {
  return name == "origin" || name.starts_with("access-control-");
}

bool credential_bearing_header(std::string_view name) noexcept {
  return name == "authorization" || name == "cookie" ||
         name == "proxy-authorization" || name == "set-cookie" ||
         name == "set-cookie2";
}

template <typename ConfiguredMutations>
std::vector<HeaderMutation> compile_header_mutations(
    const ConfiguredMutations& configured, const std::string& field,
    bool request_direction,
    std::optional<std::string_view> api_key_header = std::nullopt) {
  if (configured.size() >
      static_cast<int>(kMaximumHeaderMutationsPerDirection)) {
    invalid(field, "must not contain more than 16 mutations");
  }

  std::vector<HeaderMutation> result;
  result.reserve(static_cast<std::size_t>(configured.size()));
  std::unordered_set<std::string> names;
  std::size_t configured_bytes = 0U;
  for (int index = 0; index < configured.size(); ++index) {
    const auto& item = configured.Get(index);
    const auto item_field = field + "[" + std::to_string(index) + "]";
    const auto name = lower_ascii(item.name());
    if (name != item.name() || name.size() > kMaximumHeaderNameBytes ||
        !valid_http_token(name)) {
      invalid(item_field + ".name",
              "must be a canonical lowercase HTTP field-name no longer than 128 bytes");
    }
    if (!names.emplace(name).second) {
      invalid(item_field + ".name", "must not repeat a field name");
    }
    if (protocol_owned_header(name) || forwarding_identity_header(name) ||
        cors_owned_header(name)) {
      invalid(item_field + ".name",
              "is owned by HTTP framing, tracing, forwarding identity, or CORS policy");
    }

    HeaderMutation mutation;
    mutation.name = name;
    switch (item.operation()) {
      case bonvoyage::v1::HEADER_MUTATION_OPERATION_SET:
        mutation.operation = HeaderMutationOperation::set;
        break;
      case bonvoyage::v1::HEADER_MUTATION_OPERATION_APPEND:
        mutation.operation = HeaderMutationOperation::append;
        break;
      case bonvoyage::v1::HEADER_MUTATION_OPERATION_REMOVE:
        mutation.operation = HeaderMutationOperation::remove;
        break;
      case bonvoyage::v1::HEADER_MUTATION_OPERATION_UNSPECIFIED:
      default:
        invalid(item_field + ".operation",
                "must be set, append, or remove");
    }

    if (mutation.operation == HeaderMutationOperation::remove) {
      if (!item.value().empty()) {
        invalid(item_field + ".value", "must be empty for remove");
      }
    } else {
      if (item.value().size() > kMaximumHeaderMutationValueBytes ||
          !visible_ascii(item.value(), true) ||
          static_cast<unsigned char>(item.value().front()) <= 0x20U ||
          static_cast<unsigned char>(item.value().back()) <= 0x20U) {
        invalid(item_field + ".value",
                "must contain 1 to 4096 trimmed visible ASCII bytes");
      }
      if (credential_bearing_header(name) ||
          (request_direction && api_key_header == name)) {
        invalid(item_field + ".name",
                "credential-bearing fields may only be removed");
      }
      mutation.value = item.value();
    }

    if (configured_bytes >
        kMaximumHeaderMutationBytesPerDirection - name.size() ||
        item.value().size() > kMaximumHeaderMutationBytesPerDirection -
                                  configured_bytes - name.size()) {
      invalid(field, "configured names and values must not exceed 16384 bytes");
    }
    configured_bytes += name.size() + item.value().size();
    result.push_back(std::move(mutation));
  }
  std::sort(result.begin(), result.end(),
            [](const HeaderMutation& left, const HeaderMutation& right) {
              return left.name < right.name;
            });
  return result;
}

bool valid_https_issuer(std::string_view value) noexcept {
  constexpr std::string_view prefix{"https://"};
  if (value.size() <= prefix.size() ||
      value.size() > kMaximumJwtIssuerBytes || !visible_ascii(value, false)) {
    return false;
  }
  for (std::size_t index = 0U; index < prefix.size(); ++index) {
    if (static_cast<char>(std::tolower(
            static_cast<unsigned char>(value[index]))) != prefix[index]) {
      return false;
    }
  }
  const auto authority = value.substr(prefix.size());
  const auto end = authority.find_first_of("/?#");
  const auto host = authority.substr(0U, end);
  return !host.empty() && host.find('@') == std::string_view::npos;
}

bool reserved_jwt_claim(std::string_view value) noexcept {
  return value == "iss" || value == "sub" || value == "aud" ||
         value == "exp" || value == "nbf" || value == "iat" ||
         value == "scope";
}

bool is_ipv4_literal(std::string_view value) {
  std::size_t components = 0U;
  while (!value.empty()) {
    const auto separator = value.find('.');
    const auto part = value.substr(0U, separator);
    std::uint32_t octet = 0U;
    const auto [position, error] =
        std::from_chars(part.data(), part.data() + part.size(), octet, 10);
    if (part.empty() || error != std::errc{} ||
        position != part.data() + part.size() || octet > 255U) {
      return false;
    }
    ++components;
    if (separator == std::string_view::npos) {
      break;
    }
    value.remove_prefix(separator + 1U);
  }
  return components == 4U;
}

bool is_ipv6_literal(std::string_view value) {
  std::array<unsigned char, 16U> address{};
  const std::string text(value);
  return inet_pton(AF_INET6, text.c_str(), address.data()) == 1;
}

bool is_ip_literal(std::string_view value) {
  return is_ipv4_literal(value) || is_ipv6_literal(value);
}

std::optional<std::string> canonical_ip_literal(std::string_view value) {
  const std::string text(value);
  std::array<unsigned char, 16U> address{};
  std::array<char, INET6_ADDRSTRLEN> rendered{};
  if (inet_pton(AF_INET, text.c_str(), address.data()) == 1) {
    if (inet_ntop(AF_INET, address.data(), rendered.data(), rendered.size()) ==
        nullptr) {
      return std::nullopt;
    }
    return std::string(rendered.data());
  }
  if (inet_pton(AF_INET6, text.c_str(), address.data()) == 1) {
    if (inet_ntop(AF_INET6, address.data(), rendered.data(), rendered.size()) ==
        nullptr) {
      return std::nullopt;
    }
    return lower_ascii(rendered.data());
  }
  return std::nullopt;
}

bool valid_redirect_component(std::string_view value, bool path) noexcept {
  if (path && (value.empty() || value.front() != '/' ||
               value.starts_with("//") ||
               value.size() > kMaximumRoutePathBytes)) {
    return false;
  }
  if (!path && value.size() > kMaximumRoutePathBytes) {
    return false;
  }
  constexpr std::string_view punctuation{"-._~!$&'()*+,;=:@/"};
  for (std::size_t index = 0U; index < value.size(); ++index) {
    const auto character = value[index];
    if (character == '%') {
      if (index + 2U >= value.size() || hex_value(value[index + 1U]) < 0 ||
          hex_value(value[index + 2U]) < 0) {
        return false;
      }
      index += 2U;
      continue;
    }
    const auto alphanumeric =
        (character >= 'a' && character <= 'z') ||
        (character >= 'A' && character <= 'Z') ||
        (character >= '0' && character <= '9');
    if (!alphanumeric && punctuation.find(character) == std::string_view::npos &&
        (path || character != '?')) {
      return false;
    }
  }
  return true;
}

bool redirect_status(std::uint32_t status) noexcept {
  return status == 301U || status == 302U || status == 303U ||
         status == 307U || status == 308U;
}

bool valid_tls_server_name(std::string_view value) {
  if (value.empty() || value.size() > 253U || value.back() == '.' ||
      contains_ctl(value) || is_ipv4_literal(value)) {
    return false;
  }
  const auto alnum = [](char character) {
    return (character >= 'a' && character <= 'z') ||
           (character >= 'A' && character <= 'Z') ||
           (character >= '0' && character <= '9');
  };
  while (!value.empty()) {
    const auto separator = value.find('.');
    const auto label = value.substr(0U, separator);
    if (label.empty() || label.size() > 63U || !alnum(label.front()) ||
        !alnum(label.back()) ||
        !std::all_of(label.begin(), label.end(), [alnum](char character) {
          return alnum(character) || character == '-';
        })) {
      return false;
    }
    if (separator == std::string_view::npos) {
      break;
    }
    value.remove_prefix(separator + 1U);
  }
  return true;
}

bool valid_endpoint_address(std::string_view value) {
  return is_ip_literal(value) || valid_tls_server_name(value);
}

bool valid_health_check_path(std::string_view value) {
  return !value.empty() && value.front() == '/' &&
         value.size() <= kMaximumRoutePathBytes && !contains_ctl(value) &&
         value.find(' ') == std::string_view::npos &&
         value.find('#') == std::string_view::npos;
}

std::string normalize_domain(std::string_view value) {
  auto result = lower_ascii(value);
  if (result.size() > 1U && result.back() == '.') {
    result.pop_back();
  }
  return result;
}

std::string normalize_host(std::string_view value) {
  auto host = value;
  if (!host.empty() && host.front() == '[') {
    const auto closing = host.find(']');
    if (closing != std::string_view::npos) {
      host = host.substr(0U, closing + 1U);
    }
  } else {
    const auto colon = host.rfind(':');
    if (colon != std::string_view::npos && host.find(':') == colon) {
      host = host.substr(0U, colon);
    }
  }
  return normalize_domain(host);
}

bool domain_matches(std::string_view pattern, std::string_view host) {
  if (pattern == "*") {
    return true;
  }
  if (pattern.starts_with("*.")) {
    const auto suffix = pattern.substr(1U);
    return host.size() > suffix.size() && host.ends_with(suffix);
  }
  return pattern == host;
}

std::array<std::uint32_t, 3U> parse_version(std::string_view value,
                                            const std::string& field) {
  std::array<std::uint32_t, 3U> version{};
  for (std::size_t component = 0U; component < version.size(); ++component) {
    const auto separator = value.find('.');
    const auto part = value.substr(0U, separator);
    if (part.empty()) {
      invalid(field, "must be a major.minor.patch version");
    }
    const auto [position, error] = std::from_chars(
        part.data(), part.data() + part.size(), version[component], 10);
    if (error != std::errc{} || position != part.data() + part.size()) {
      invalid(field, "must be a major.minor.patch version");
    }
    if (component + 1U == version.size()) {
      if (separator != std::string_view::npos) {
        invalid(field, "must be a major.minor.patch version");
      }
    } else {
      if (separator == std::string_view::npos) {
        invalid(field, "must be a major.minor.patch version");
      }
      value.remove_prefix(separator + 1U);
    }
  }
  return version;
}

bool route_predicates_match(const RuntimeRoute& route,
                            const RequestView& request,
                            bool cors_preflight) {
  if (cors_preflight && !route.cors.has_value()) {
    return false;
  }
  if (!route.methods.empty() &&
      std::find(route.methods.begin(), route.methods.end(), request.method) ==
          route.methods.end()) {
    return false;
  }
  for (const auto& predicate : route.headers) {
    if (cors_preflight) {
      return false;
    }
    if (request.header_lookup == nullptr) {
      return false;
    }
    const auto found =
        request.header_lookup(request.header_context, predicate.name);
    if (predicate.exact.has_value()) {
      if (!found.present || found.repeated || found.value != *predicate.exact) {
        return false;
      }
    } else if (found.present != predicate.present) {
      return false;
    }
  }
  for (const auto& predicate : route.query_parameters) {
    if (!query_predicate_matches(predicate, request.query)) {
      return false;
    }
  }
  return true;
}

template <typename Map>
void require_unique(Map& values, const std::string& value,
                    const std::string& field) {
  if (!values.emplace(value).second) {
    invalid(field, "duplicate value '" + value + "'");
  }
}

}  // namespace

RuntimeSnapshot RuntimeSnapshot::decode(std::string_view bytes) {
  bonvoyage::v1::Snapshot snapshot;
  if (!snapshot.ParseFromArray(bytes.data(), static_cast<int>(bytes.size()))) {
    invalid("snapshot", "invalid protobuf payload");
  }
  return compile(snapshot);
}

void RuntimeSnapshot::validate_live_gateway_capabilities() const {
  // Every protocol accepted by snapshot compilation has a live gateway path.
}

RuntimeSnapshot RuntimeSnapshot::compile(
    const bonvoyage::v1::Snapshot& snapshot) {
  RuntimeSnapshot result;
  if (snapshot.schema_version() != 1U) {
    invalid("snapshot.schema_version", "only version 1 is supported");
  }
  if (!valid_name(snapshot.snapshot_id())) {
    invalid("snapshot.snapshot_id", "must be a valid BonVoyage name");
  }
  if (snapshot.generation() == 0U) {
    invalid("snapshot.generation", "must be greater than zero");
  }
  result.snapshot_id_ = snapshot.snapshot_id();
  result.generation_ = snapshot.generation();
  if (!snapshot.minimum_dataplane_version().empty() &&
      parse_version(snapshot.minimum_dataplane_version(),
                    "snapshot.minimum_dataplane_version") >
          parse_version(bonvoyage::kDataplaneVersion, "dataplane.version")) {
    invalid("snapshot.minimum_dataplane_version",
            "requires a newer BonVoyage dataplane");
  }

  const auto& configured_limits = snapshot.runtime_limits();
  if (configured_limits.max_downstream_connections_per_shard() != 0U) {
    result.limits_.max_downstream_connections_per_shard =
        configured_limits.max_downstream_connections_per_shard();
  }
  if (configured_limits.max_request_header_bytes() != 0U) {
    result.limits_.max_request_header_bytes =
        configured_limits.max_request_header_bytes();
  }
  if (configured_limits.max_request_body_bytes() != 0U) {
    result.limits_.max_request_body_bytes =
        configured_limits.max_request_body_bytes();
  }
  if (configured_limits.max_upstream_chunk_metadata_bytes() != 0U) {
    result.limits_.max_upstream_chunk_metadata_bytes =
        configured_limits.max_upstream_chunk_metadata_bytes();
  }
  if (configured_limits.max_upstream_response_header_bytes() != 0U) {
    result.limits_.max_upstream_response_header_bytes =
        configured_limits.max_upstream_response_header_bytes();
  }
  if (configured_limits.request_timeout_ms() != 0U) {
    result.limits_.request_timeout_ms =
        configured_limits.request_timeout_ms();
  }
  if (configured_limits.downstream_idle_timeout_ms() != 0U) {
    result.limits_.downstream_idle_timeout_ms =
        configured_limits.downstream_idle_timeout_ms();
  }
  if (result.limits_.max_request_header_bytes < 1024U ||
      result.limits_.max_request_header_bytes > 1024U * 1024U) {
    invalid("runtime_limits.max_request_header_bytes",
            "must be between 1024 and 1048576");
  }
  if (result.limits_.max_downstream_connections_per_shard == 0U ||
      result.limits_.max_downstream_connections_per_shard >
          kMaximumConnectionsPerShard) {
    invalid("runtime_limits.max_downstream_connections_per_shard",
            "must be between 1 and 1000000");
  }
  if (result.limits_.max_request_body_bytes > 1024ULL * 1024ULL * 1024ULL) {
    invalid("runtime_limits.max_request_body_bytes",
            "must not exceed 1 GiB in Phase 1");
  }
  if (result.limits_.max_upstream_chunk_metadata_bytes < 1024U ||
      result.limits_.max_upstream_chunk_metadata_bytes > 1024U * 1024U) {
    invalid("runtime_limits.max_upstream_chunk_metadata_bytes",
            "must be between 1024 and 1048576");
  }
  if (result.limits_.max_upstream_response_header_bytes < 1024U ||
      result.limits_.max_upstream_response_header_bytes > 1024U * 1024U) {
    invalid("runtime_limits.max_upstream_response_header_bytes",
            "must be between 1024 and 1048576");
  }
  if (result.limits_.request_timeout_ms > 300000U ||
      result.limits_.downstream_idle_timeout_ms > 3600000U) {
    invalid("runtime_limits", "timeout exceeds the Phase 1 safety limit");
  }

  std::unordered_map<std::string, std::size_t> cluster_indices;
  std::unordered_set<std::string> cluster_names;
  result.clusters_.reserve(static_cast<std::size_t>(snapshot.clusters_size()));
  for (int cluster_number = 0; cluster_number < snapshot.clusters_size();
       ++cluster_number) {
    const auto& configured = snapshot.clusters(cluster_number);
    const auto field = "clusters[" + std::to_string(cluster_number) + "]";
    if (!valid_name(configured.name())) {
      invalid(field + ".name", "must be a valid BonVoyage name");
    }
    require_unique(cluster_names, configured.name(), field + ".name");
    RuntimeLoadBalancingPolicy load_balancing_policy;
    switch (configured.load_balancing_policy()) {
      case bonvoyage::v1::LOAD_BALANCING_POLICY_ROUND_ROBIN:
        load_balancing_policy = RuntimeLoadBalancingPolicy::round_robin;
        break;
      case bonvoyage::v1::LOAD_BALANCING_POLICY_LEAST_REQUEST:
        load_balancing_policy = RuntimeLoadBalancingPolicy::least_request;
        break;
      case bonvoyage::v1::LOAD_BALANCING_POLICY_RANDOM:
        load_balancing_policy = RuntimeLoadBalancingPolicy::random;
        break;
      case bonvoyage::v1::LOAD_BALANCING_POLICY_UNSPECIFIED:
      default:
        invalid(field + ".load_balancing_policy",
                "must be round_robin, least_request, or random");
    }
    if (configured.endpoints().empty()) {
      invalid(field + ".endpoints", "must contain at least one endpoint");
    }
    if (configured.endpoints_size() >
        static_cast<int>(kMaximumRouteWeight)) {
      invalid(field + ".endpoints", "must not contain more than 4096 endpoints");
    }

    RuntimeCluster cluster;
    cluster.name = configured.name();
    cluster.load_balancing_policy = load_balancing_policy;
    if (configured.protocol() == bonvoyage::v1::PROTOCOL_UNSPECIFIED ||
        configured.protocol() == bonvoyage::v1::PROTOCOL_HTTP1) {
      cluster.protocol = RuntimeUpstreamProtocol::http1;
    } else if (configured.protocol() == bonvoyage::v1::PROTOCOL_HTTP2) {
      cluster.protocol = RuntimeUpstreamProtocol::http2;
    } else {
      invalid(field + ".protocol", "must be HTTP/1 or TLS HTTP/2");
    }
    if (configured.connect_timeout_ms() != 0U) {
      cluster.connect_timeout_ms = configured.connect_timeout_ms();
    }
    if (configured.max_connections_per_shard() != 0U) {
      cluster.max_connections_per_shard =
          configured.max_connections_per_shard();
    }
    if (configured.max_pending_requests_per_shard() != 0U) {
      cluster.max_pending_requests_per_shard =
          configured.max_pending_requests_per_shard();
    }
    const auto cluster_admission_limit =
        static_cast<std::uint64_t>(cluster.max_connections_per_shard) +
        static_cast<std::uint64_t>(cluster.max_pending_requests_per_shard);
    cluster.max_concurrent_requests_per_endpoint =
        configured.max_concurrent_requests_per_endpoint() == 0U
            ? static_cast<std::uint32_t>(cluster_admission_limit)
            : configured.max_concurrent_requests_per_endpoint();
    if (configured.max_http2_streams_per_connection() != 0U) {
      if (cluster.protocol != RuntimeUpstreamProtocol::http2) {
        invalid(field + ".max_http2_streams_per_connection",
                "is only valid when protocol is HTTP/2");
      }
      cluster.max_http2_streams_per_connection =
          configured.max_http2_streams_per_connection();
    }
    if (cluster.connect_timeout_ms > 60000U) {
      invalid(field + ".connect_timeout_ms", "must not exceed 60000");
    }
    if (cluster.max_connections_per_shard <
        static_cast<std::uint32_t>(configured.endpoints_size())) {
      invalid(field + ".max_connections_per_shard",
              "must be at least the endpoint count");
    }
    if (cluster.max_connections_per_shard > kMaximumConnectionsPerShard ||
        cluster.max_pending_requests_per_shard >
            kMaximumPendingRequestsPerShard) {
      invalid(field, "connection and pending limits must not exceed 1000000");
    }
    if (cluster.max_concurrent_requests_per_endpoint == 0U ||
        cluster.max_concurrent_requests_per_endpoint >
            kMaximumConcurrentRequestsPerEndpoint ||
        static_cast<std::uint64_t>(
            cluster.max_concurrent_requests_per_endpoint) >
            cluster_admission_limit) {
      invalid(field + ".max_concurrent_requests_per_endpoint",
              "must be between 1 and the cluster connection-plus-pending admission limit");
    }
    if (cluster.max_http2_streams_per_connection == 0U ||
        cluster.max_http2_streams_per_connection >
            kMaximumHttp2StreamsPerConnection) {
      invalid(field + ".max_http2_streams_per_connection",
              "must be between 1 and 1000");
    }
    if (cluster.protocol == RuntimeUpstreamProtocol::http2 &&
        !configured.has_upstream_tls()) {
      invalid(field + ".protocol",
              "HTTP/2 requires upstream TLS and explicit h2 ALPN");
    }
    if (configured.has_upstream_tls()) {
      const auto& tls = configured.upstream_tls();
      if (!valid_tls_server_name(tls.server_name())) {
        invalid(field + ".upstream_tls.server_name",
                "must be a DNS hostname, not a wildcard or IP address");
      }
      if (!valid_secret_reference(tls.trust_bundle_secret())) {
        invalid(field + ".upstream_tls.trust_bundle_secret",
                "must be a safe secret filename");
      }
      const auto has_certificate = !tls.certificate_chain_secret().empty();
      const auto has_private_key = !tls.private_key_secret().empty();
      if (has_certificate != has_private_key) {
        invalid(field + ".upstream_tls",
                "certificate_chain_secret and private_key_secret must be configured together");
      }
      if (has_certificate &&
          !valid_secret_reference(tls.certificate_chain_secret())) {
        invalid(field + ".upstream_tls.certificate_chain_secret",
                "must be a safe secret filename");
      }
      if (has_private_key &&
          !valid_secret_reference(tls.private_key_secret())) {
        invalid(field + ".upstream_tls.private_key_secret",
                "must be a safe secret filename");
      }
      cluster.upstream_tls = RuntimeUpstreamTls{
          lower_ascii(tls.server_name()), tls.trust_bundle_secret(),
          has_certificate
              ? std::optional<std::string>(tls.certificate_chain_secret())
              : std::nullopt,
          has_private_key
              ? std::optional<std::string>(tls.private_key_secret())
              : std::nullopt};
    }
    if (configured.has_passive_health()) {
      const auto& health = configured.passive_health();
      const auto failures = health.consecutive_failures() == 0U
                                ? 5U
                                : health.consecutive_failures();
      const auto ejection_time = health.ejection_time_ms() == 0U
                                     ? 30000U
                                     : health.ejection_time_ms();
      const auto max_ejection = health.max_ejection_percent() == 0U
                                    ? 50U
                                    : health.max_ejection_percent();
      const auto successes = health.consecutive_successes() == 0U
                                 ? 1U
                                 : health.consecutive_successes();
      if (failures > kMaximumPassiveFailureCount) {
        invalid(field + ".passive_health.consecutive_failures",
                "must be between 1 and 100");
      }
      if (ejection_time < 100U ||
          ejection_time > kMaximumPassiveEjectionTimeMs) {
        invalid(field + ".passive_health.ejection_time_ms",
                "must be between 100 and 300000");
      }
      if (max_ejection > 100U) {
        invalid(field + ".passive_health.max_ejection_percent",
                "must be between 1 and 100");
      }
      if (successes > kMaximumPassiveSuccessCount) {
        invalid(field + ".passive_health.consecutive_successes",
                "must be between 1 and 100");
      }
      cluster.passive_health = RuntimePassiveHealth{
          failures, ejection_time, max_ejection, successes};
    }
    if (configured.has_active_health()) {
      const auto& health = configured.active_health();
      const auto path = health.path().empty() ? std::string("/healthz")
                                              : health.path();
      const auto interval = health.interval_ms() == 0U
                                ? 5000U
                                : health.interval_ms();
      const auto timeout = health.timeout_ms() == 0U
                               ? 1000U
                               : health.timeout_ms();
      const auto healthy_threshold = health.healthy_threshold() == 0U
                                         ? 2U
                                         : health.healthy_threshold();
      const auto unhealthy_threshold = health.unhealthy_threshold() == 0U
                                           ? 3U
                                           : health.unhealthy_threshold();
      const auto status_minimum = health.expected_status_min() == 0U
                                      ? 200U
                                      : health.expected_status_min();
      const auto status_maximum = health.expected_status_max() == 0U
                                      ? 399U
                                      : health.expected_status_max();
      if (!valid_health_check_path(path)) {
        invalid(field + ".active_health.path",
                "must be an absolute origin-form path of at most 4096 bytes without spaces, fragments, or controls");
      }
      if (interval < 1000U || interval > kMaximumActiveHealthIntervalMs) {
        invalid(field + ".active_health.interval_ms",
                "must be between 1000 and 300000");
      }
      if (timeout < 100U || timeout > kMaximumActiveHealthTimeoutMs ||
          timeout > interval) {
        invalid(field + ".active_health.timeout_ms",
                "must be between 100 and 10000 and not exceed interval_ms");
      }
      if (healthy_threshold > kMaximumActiveHealthThreshold ||
          unhealthy_threshold > kMaximumActiveHealthThreshold) {
        invalid(field + ".active_health",
                "healthy and unhealthy thresholds must be between 1 and 100");
      }
      if (status_minimum < 200U || status_maximum > 599U ||
          status_minimum > status_maximum) {
        invalid(field + ".active_health",
                "expected status range must be ordered between 200 and 599");
      }
      if (!health.host().empty() &&
          !valid_endpoint_address(health.host())) {
        invalid(field + ".active_health.host",
                "must be an IP address or DNS hostname without a port");
      }
      cluster.active_health = RuntimeActiveHealth{
          path,
          interval,
          timeout,
          healthy_threshold,
          unhealthy_threshold,
          static_cast<std::uint16_t>(status_minimum),
          static_cast<std::uint16_t>(status_maximum),
          health.host().empty()
              ? std::nullopt
              : std::optional<std::string>(lower_ascii(health.host()))};
    }
    if (configured.has_dns_refresh()) {
      const auto& dns = configured.dns_refresh();
      const auto interval = dns.refresh_interval_ms() == 0U
                                ? 30000U
                                : dns.refresh_interval_ms();
      const auto timeout = dns.resolve_timeout_ms() == 0U
                               ? 1000U
                               : dns.resolve_timeout_ms();
      if (interval < 1000U || interval > kMaximumDnsRefreshIntervalMs) {
        invalid(field + ".dns_refresh.refresh_interval_ms",
                "must be between 1000 and 3600000");
      }
      if (timeout < 100U || timeout > kMaximumDnsResolveTimeoutMs ||
          timeout > interval) {
        invalid(field + ".dns_refresh.resolve_timeout_ms",
                "must be between 100 and 10000 and not exceed refresh_interval_ms");
      }
      cluster.dns_refresh = RuntimeDnsRefresh{interval, timeout};
    }
    if (configured.has_retry()) {
      const auto& retry = configured.retry();
      const auto max_attempts =
          retry.max_attempts() == 0U ? 2U : retry.max_attempts();
      const auto per_try_timeout = retry.per_try_timeout_ms() == 0U
                                       ? 1000U
                                       : retry.per_try_timeout_ms();
      if (max_attempts < 2U || max_attempts > kMaximumRetryAttempts) {
        invalid(field + ".retry.max_attempts", "must be between 2 and 5");
      }
      if (per_try_timeout < 10U || per_try_timeout > 60000U ||
          per_try_timeout > result.limits_.request_timeout_ms) {
        invalid(field + ".retry.per_try_timeout_ms",
                "must be between 10 and 60000 and not exceed the request timeout");
      }

      std::vector<std::string> retryable_methods;
      if (retry.retryable_methods().empty()) {
        retryable_methods = {"GET", "HEAD", "OPTIONS"};
      } else {
        if (retry.retryable_methods_size() >
            static_cast<int>(kMaximumRetryMethods)) {
          invalid(field + ".retry.retryable_methods",
                  "must not contain more than 5 methods");
        }
        std::unordered_set<std::string> seen_methods;
        retryable_methods.reserve(static_cast<std::size_t>(
            retry.retryable_methods_size()));
        for (int method_number = 0;
             method_number < retry.retryable_methods_size();
             ++method_number) {
          const auto& method = retry.retryable_methods(method_number);
          const auto method_field = field + ".retry.retryable_methods[" +
                                    std::to_string(method_number) + "]";
          if (!canonical_method(method) || !idempotent_retry_method(method)) {
            invalid(method_field,
                    "must be DELETE, GET, HEAD, OPTIONS, or PUT");
          }
          require_unique(seen_methods, method, method_field);
          retryable_methods.push_back(method);
        }
        std::sort(retryable_methods.begin(), retryable_methods.end());
      }

      const auto& budget = retry.budget();
      const auto capacity =
          budget.capacity() == 0U ? 100U : budget.capacity();
      const auto refill = budget.refill_tokens_per_second() == 0U
                              ? 10U
                              : budget.refill_tokens_per_second();
      const auto concurrent =
          budget.max_concurrent_retries_per_shard() == 0U
              ? 16U
              : budget.max_concurrent_retries_per_shard();
      if (capacity > kMaximumRetryBudget || refill > kMaximumRetryBudget ||
          concurrent > kMaximumRetryBudget) {
        invalid(field + ".retry.budget",
                "capacity, refill rate, and concurrent retries must be between 1 and 1000000");
      }
      cluster.retry = RuntimeRetryPolicy{
          max_attempts,
          per_try_timeout,
          std::move(retryable_methods),
          RuntimeRetryBudget{capacity, refill, concurrent}};
    }

    std::unordered_set<std::string> endpoint_names;
    std::uint64_t total_weight = 0U;
    std::size_t dns_endpoint_count = 0U;
    cluster.endpoints.reserve(
        static_cast<std::size_t>(configured.endpoints_size()));
    for (int endpoint_number = 0;
         endpoint_number < configured.endpoints_size(); ++endpoint_number) {
      const auto& endpoint = configured.endpoints(endpoint_number);
      const auto endpoint_field =
          field + ".endpoints[" + std::to_string(endpoint_number) + "]";
      if (!valid_name(endpoint.name()) ||
          !valid_endpoint_address(endpoint.address())) {
        invalid(endpoint_field,
                "name must be valid and address must be an IP address or DNS hostname without a port");
      }
      require_unique(endpoint_names, endpoint.name(), endpoint_field + ".name");
      if (endpoint.port() == 0U || endpoint.port() > 65535U) {
        invalid(endpoint_field + ".port", "must be between 1 and 65535");
      }
      const auto weight = endpoint.weight() == 0U ? 1U : endpoint.weight();
      if (!is_ip_literal(endpoint.address())) {
        ++dns_endpoint_count;
      }
      total_weight += weight;
      if (total_weight > kMaximumRouteWeight) {
        invalid(field + ".endpoints", "total weight must not exceed 4096");
      }
      cluster.endpoints.push_back(RuntimeEndpoint{
          endpoint.name(), endpoint.address(),
          static_cast<std::uint16_t>(endpoint.port()), weight,
          !is_ip_literal(endpoint.address())});
    }
    if (cluster.dns_refresh.has_value() && dns_endpoint_count == 0U) {
      invalid(field + ".dns_refresh",
              "requires at least one DNS hostname endpoint");
    }
    cluster_indices.emplace(cluster.name, result.clusters_.size());
    result.clusters_.push_back(std::move(cluster));
  }

  std::unordered_map<std::string, std::size_t> virtual_host_indices;
  std::unordered_set<std::string> virtual_host_names;
  result.virtual_hosts_.reserve(
      static_cast<std::size_t>(snapshot.virtual_hosts_size()));
  for (int host_number = 0; host_number < snapshot.virtual_hosts_size();
       ++host_number) {
    const auto& configured = snapshot.virtual_hosts(host_number);
    const auto field =
        "virtual_hosts[" + std::to_string(host_number) + "]";
    if (!valid_name(configured.name())) {
      invalid(field + ".name", "must be a valid BonVoyage name");
    }
    require_unique(virtual_host_names, configured.name(), field + ".name");
    if (configured.domains().empty() || configured.routes().empty()) {
      invalid(field, "domains and routes must not be empty");
    }

    RuntimeVirtualHost virtual_host;
    virtual_host.name = configured.name();
    virtual_host.prefix_trie.emplace_back();
    std::unordered_set<std::string> domains;
    for (const auto& raw_domain : configured.domains()) {
      const auto domain = normalize_domain(raw_domain);
      if (domain.empty() || contains_ctl(domain) ||
          (domain.find('*') != std::string::npos &&
           !(domain == "*" || domain.starts_with("*.")))) {
        invalid(field + ".domains", "invalid domain '" + raw_domain + "'");
      }
      require_unique(domains, domain, field + ".domains");
      virtual_host.domains.push_back(domain);
    }

    std::unordered_set<std::string> route_names;
    std::unordered_set<std::string> route_bindings;
    std::unordered_set<std::string> unconditional_path_bindings;
    virtual_host.routes.reserve(
        static_cast<std::size_t>(configured.routes_size()));
    for (int route_number = 0; route_number < configured.routes_size();
         ++route_number) {
      const auto& configured_route = configured.routes(route_number);
      const auto route_field =
          field + ".routes[" + std::to_string(route_number) + "]";
      if (!valid_name(configured_route.name())) {
        invalid(route_field + ".name", "must be a valid BonVoyage name");
      }
      require_unique(route_names, configured_route.name(),
                     route_field + ".name");

      RuntimeRoute route;
      route.name = configured_route.name();
      const auto route_concurrency =
          configured_route.max_concurrent_requests_per_shard();
      if (route_concurrency > kMaximumRouteConcurrency) {
        invalid(route_field + ".max_concurrent_requests_per_shard",
                "must not exceed 2000000");
      }
      route.admission.max_concurrent_requests_per_shard = route_concurrency;
      if (configured_route.has_local_rate_limit()) {
        const auto& configured_limit = configured_route.local_rate_limit();
        if (configured_limit.capacity() == 0U ||
            configured_limit.refill_tokens_per_second() == 0U) {
          invalid(route_field + ".local_rate_limit",
                  "capacity and refill_tokens_per_second must be positive");
        }
        if (configured_limit.capacity() > kMaximumRouteRateLimit ||
            configured_limit.refill_tokens_per_second() >
                kMaximumRouteRateLimit) {
          invalid(route_field + ".local_rate_limit",
                  "capacity and refill_tokens_per_second must not exceed 1000000");
        }
        route.admission.local_rate_limit = RuntimeLocalRateLimit{
            configured_limit.capacity(),
            configured_limit.refill_tokens_per_second()};
      }
      if (configured_route.has_api_key_auth()) {
        const auto& configured_auth = configured_route.api_key_auth();
        const auto header_name = lower_ascii(configured_auth.header_name());
        if (header_name.empty() ||
            header_name.size() > kMaximumHeaderNameBytes ||
            !valid_http_token(header_name)) {
          invalid(route_field + ".api_key_auth.header_name",
                  "must be an HTTP field-name no longer than 128 bytes");
        }
        if (!valid_secret_reference(configured_auth.credentials_secret())) {
          invalid(route_field + ".api_key_auth.credentials_secret",
                  "must be a safe secret filename");
        }
        route.api_key_auth = RuntimeApiKeyAuth{
            header_name, configured_auth.credentials_secret()};
      }
      if (configured_route.has_jwt_auth()) {
        if (configured_route.has_api_key_auth()) {
          invalid(route_field, "api_key_auth and jwt_auth are mutually exclusive");
        }
        const auto& configured_auth = configured_route.jwt_auth();
        if (!valid_secret_reference(configured_auth.jwks_secret())) {
          invalid(route_field + ".jwt_auth.jwks_secret",
                  "must be a safe secret filename");
        }
        if (!valid_https_issuer(configured_auth.issuer())) {
          invalid(route_field + ".jwt_auth.issuer",
                  "must be an HTTPS URI-like value no longer than 1024 bytes");
        }
        if (configured_auth.audience().size() > kMaximumJwtAudienceBytes ||
            !trimmed_visible_text(configured_auth.audience())) {
          invalid(route_field + ".jwt_auth.audience",
                  "must contain between 1 and 256 bytes of trimmed visible text");
        }
        if (configured_auth.required_type().size() > kMaximumJwtTypeBytes ||
            !valid_http_token(configured_auth.required_type())) {
          invalid(route_field + ".jwt_auth.required_type",
                  "must be an HTTP token no longer than 64 bytes");
        }
        if (configured_auth.algorithms_size() == 0 ||
            configured_auth.algorithms_size() >
                static_cast<int>(kMaximumJwtAlgorithms)) {
          invalid(route_field + ".jwt_auth.algorithms",
                  "must contain between 1 and 3 algorithms");
        }
        RuntimeJwtAuth auth;
        auth.jwks_secret = configured_auth.jwks_secret();
        auth.issuer = configured_auth.issuer();
        auth.audience = configured_auth.audience();
        auth.required_type = configured_auth.required_type();
        std::unordered_set<int> algorithms;
        for (const auto configured_algorithm : configured_auth.algorithms()) {
          if (!algorithms.emplace(static_cast<int>(configured_algorithm)).second) {
            invalid(route_field + ".jwt_auth.algorithms",
                    "must not contain duplicate algorithms");
          }
          switch (configured_algorithm) {
            case bonvoyage::v1::JWT_ALGORITHM_RS256:
              auth.algorithms.push_back(JwtAlgorithm::rs256);
              break;
            case bonvoyage::v1::JWT_ALGORITHM_PS256:
              auth.algorithms.push_back(JwtAlgorithm::ps256);
              break;
            case bonvoyage::v1::JWT_ALGORITHM_ES256:
              auth.algorithms.push_back(JwtAlgorithm::es256);
              break;
            case bonvoyage::v1::JWT_ALGORITHM_UNSPECIFIED:
            default:
              invalid(route_field + ".jwt_auth.algorithms",
                      "contains an unsupported algorithm");
          }
        }
        if (configured_auth.clock_skew_seconds() >
            kMaximumJwtClockSkewSeconds) {
          invalid(route_field + ".jwt_auth.clock_skew_seconds",
                  "must not exceed 300");
        }
        if (configured_auth.max_token_lifetime_seconds() == 0U ||
            configured_auth.max_token_lifetime_seconds() >
                kMaximumJwtLifetimeSeconds) {
          invalid(route_field + ".jwt_auth.max_token_lifetime_seconds",
                  "must be between 1 and 86400");
        }
        auth.clock_skew_seconds = configured_auth.clock_skew_seconds();
        auth.max_token_lifetime_seconds =
            configured_auth.max_token_lifetime_seconds();
        if (configured_auth.required_scopes_size() >
            static_cast<int>(kMaximumJwtPolicyEntries)) {
          invalid(route_field + ".jwt_auth.required_scopes",
                  "must not contain more than 16 entries");
        }
        std::unordered_set<std::string> scopes;
        for (const auto& scope : configured_auth.required_scopes()) {
          if (scope.size() > kMaximumJwtScopeBytes ||
              !visible_ascii(scope, false) || !scopes.emplace(scope).second) {
            invalid(route_field + ".jwt_auth.required_scopes",
                    "must contain unique visible ASCII values no longer than 128 bytes");
          }
          auth.required_scopes.push_back(scope);
        }
        if (configured_auth.required_claims_size() >
            static_cast<int>(kMaximumJwtPolicyEntries)) {
          invalid(route_field + ".jwt_auth.required_claims",
                  "must not contain more than 16 entries");
        }
        std::unordered_set<std::string> claims;
        for (const auto& claim : configured_auth.required_claims()) {
          if (claim.name().size() > kMaximumJwtClaimNameBytes ||
              !valid_http_token(claim.name()) ||
              reserved_jwt_claim(claim.name()) ||
              !claims.emplace(claim.name()).second) {
            invalid(route_field + ".jwt_auth.required_claims",
                    "must use unique, non-reserved HTTP-token claim names no longer than 64 bytes");
          }
          if (claim.exact().size() > kMaximumJwtClaimValueBytes ||
              !visible_ascii(claim.exact(), true) ||
              static_cast<unsigned char>(claim.exact().front()) <= 0x20U ||
              static_cast<unsigned char>(claim.exact().back()) <= 0x20U) {
            invalid(route_field + ".jwt_auth.required_claims",
                    "exact values must contain 1 to 256 trimmed visible ASCII bytes");
          }
          auth.required_claims.push_back(
              JwtClaimRequirement{claim.name(), claim.exact()});
        }
        if (!configured_auth.has_verification_rate_limit()) {
          invalid(route_field + ".jwt_auth.verification_rate_limit",
                  "is required");
        }
        const auto& verification_limit =
            configured_auth.verification_rate_limit();
        if (verification_limit.capacity() == 0U ||
            verification_limit.refill_tokens_per_second() == 0U ||
            verification_limit.capacity() > kMaximumRouteRateLimit ||
            verification_limit.refill_tokens_per_second() >
                kMaximumRouteRateLimit) {
          invalid(route_field + ".jwt_auth.verification_rate_limit",
                  "capacity and refill_tokens_per_second must be between 1 and 1000000");
        }
        auth.verification_rate_limit = RuntimeLocalRateLimit{
            verification_limit.capacity(),
            verification_limit.refill_tokens_per_second()};
        route.jwt_auth = std::move(auth);
      }
      if (configured_route.has_source_ip_policy()) {
        const auto& configured_policy = configured_route.source_ip_policy();
        const auto allow_count = static_cast<std::size_t>(
            configured_policy.allow_cidrs_size());
        const auto deny_count = static_cast<std::size_t>(
            configured_policy.deny_cidrs_size());
        if (allow_count + deny_count == 0U ||
            allow_count + deny_count > kMaximumSourceIpCidrs) {
          invalid(route_field + ".source_ip_policy",
                  "must contain between 1 and 64 total CIDRs");
        }
        std::vector<std::string> allow_cidrs(
            configured_policy.allow_cidrs().begin(),
            configured_policy.allow_cidrs().end());
        std::vector<std::string> deny_cidrs(
            configured_policy.deny_cidrs().begin(),
            configured_policy.deny_cidrs().end());
        try {
          route.source_ip_policy.emplace(allow_cidrs, deny_cidrs);
        } catch (const std::invalid_argument& error) {
          invalid(route_field + ".source_ip_policy", error.what());
        }
      }
      switch (configured_route.match().path_match_case()) {
        case bonvoyage::v1::RouteMatch::kPathExact:
          route.path = configured_route.match().path_exact();
          route.exact_path = true;
          break;
        case bonvoyage::v1::RouteMatch::kPathPrefix:
          route.path = configured_route.match().path_prefix();
          break;
        case bonvoyage::v1::RouteMatch::kSafeRegex: {
          route.path = configured_route.match().safe_regex();
          if (route.path.empty() || route.path.size() > kMaximumSafeRegexBytes ||
              contains_ctl(route.path)) {
            invalid(route_field + ".match.safe_regex",
                    "must contain between 1 and 1024 bytes without controls");
          }
          re2::RE2::Options options;
          options.set_log_errors(false);
          options.set_max_mem(kSafeRegexMemoryBytes);
          options.set_never_capture(true);
          auto expression = std::make_shared<re2::RE2>(route.path, options);
          if (!expression->ok()) {
            invalid(route_field + ".match.safe_regex",
                    "invalid RE2 expression: " + expression->error());
          }
          route.safe_regex = std::move(expression);
          break;
        }
        case bonvoyage::v1::RouteMatch::PATH_MATCH_NOT_SET:
          invalid(route_field + ".match", "path match is required");
      }
      if (route.safe_regex == nullptr &&
          (route.path.empty() || route.path.front() != '/' ||
           route.path.size() > kMaximumRoutePathBytes ||
           contains_ctl(route.path))) {
        invalid(route_field + ".match",
                "path must start with '/', stay within 4096 bytes, and contain no controls");
      }

      if (configured_route.match().methods_size() >
          static_cast<int>(kMaximumRouteMethods)) {
        invalid(route_field + ".match.methods",
                "must not contain more than 16 methods");
      }
      std::unordered_set<std::string> methods;
      for (const auto& method : configured_route.match().methods()) {
        if (!canonical_method(method)) {
          invalid(route_field + ".match.methods",
                  "methods must be uppercase HTTP tokens no longer than 32 bytes");
        }
        require_unique(methods, method, route_field + ".match.methods");
        route.methods.push_back(method);
      }
      std::sort(route.methods.begin(), route.methods.end());

      if (configured_route.match().headers_size() >
          static_cast<int>(kMaximumRoutePredicates)) {
        invalid(route_field + ".match.headers",
                "must not contain more than 16 predicates");
      }
      std::unordered_set<std::string> header_names;
      for (int header_number = 0;
           header_number < configured_route.match().headers_size();
           ++header_number) {
        const auto& configured_header =
            configured_route.match().headers(header_number);
        const auto header_field = route_field + ".match.headers[" +
                                  std::to_string(header_number) + "]";
        const auto name = lower_ascii(configured_header.name());
        if (name.empty() || name.size() > kMaximumHeaderNameBytes ||
            !valid_http_token(name)) {
          invalid(header_field + ".name",
                  "must be an HTTP field-name no longer than 128 bytes");
        }
        require_unique(header_names, name, header_field + ".name");
        RuntimeHeaderMatch header;
        header.name = name;
        switch (configured_header.value_match_case()) {
          case bonvoyage::v1::HeaderMatch::kExact:
            if (configured_header.exact().size() >
                    kMaximumPredicateValueBytes ||
                contains_ctl(configured_header.exact())) {
              invalid(header_field + ".exact",
                      "must not exceed 4096 bytes or contain controls");
            }
            header.exact = configured_header.exact();
            break;
          case bonvoyage::v1::HeaderMatch::kPresent:
            header.present = configured_header.present();
            break;
          case bonvoyage::v1::HeaderMatch::VALUE_MATCH_NOT_SET:
            invalid(header_field,
                    "exactly one of exact or present is required");
        }
        route.headers.push_back(std::move(header));
      }
      std::sort(route.headers.begin(), route.headers.end(),
                [](const RuntimeHeaderMatch& left,
                   const RuntimeHeaderMatch& right) {
                  return left.name < right.name;
                });
      if (route.api_key_auth.has_value()) {
        if (reserved_api_key_header(route.api_key_auth->header_name)) {
          invalid(route_field + ".api_key_auth.header_name",
                  "must not use a hop-by-hop or forwarding identity field");
        }
        if (std::any_of(route.headers.begin(), route.headers.end(),
                        [&route](const RuntimeHeaderMatch& predicate) {
                          return predicate.name ==
                                 route.api_key_auth->header_name;
                        })) {
          invalid(route_field + ".api_key_auth.header_name",
                  "must not duplicate a route header predicate");
        }
      }
      if (route.jwt_auth.has_value() &&
          std::any_of(route.headers.begin(), route.headers.end(),
                      [](const RuntimeHeaderMatch& predicate) {
                        return predicate.name == "authorization";
                      })) {
        invalid(route_field + ".jwt_auth",
                "must not duplicate an Authorization route predicate");
      }
      if (configured_route.has_cors()) {
        if (!route.headers.empty()) {
          invalid(route_field + ".cors",
                  "routes with CORS cannot use ordinary header match predicates");
        }
        const auto& configured_cors = configured_route.cors();
        if (!route.methods.empty()) {
          for (const auto& method : configured_cors.allowed_methods()) {
            if (std::find(route.methods.begin(), route.methods.end(), method) ==
                route.methods.end()) {
              invalid(route_field + ".cors.allowed_methods",
                      "method '" + method +
                          "' is not accepted by the route matcher");
            }
          }
        }
        try {
          route.cors.emplace(
              configured_cors.allow_any_origin(),
              std::vector<std::string>(
                  configured_cors.allowed_origins().begin(),
                  configured_cors.allowed_origins().end()),
              std::vector<std::string>(
                  configured_cors.allowed_methods().begin(),
                  configured_cors.allowed_methods().end()),
              std::vector<std::string>(
                  configured_cors.allowed_headers().begin(),
                  configured_cors.allowed_headers().end()),
              std::vector<std::string>(
                  configured_cors.exposed_headers().begin(),
                  configured_cors.exposed_headers().end()),
              configured_cors.allow_credentials(),
              configured_cors.max_age_seconds());
        } catch (const std::invalid_argument& error) {
          invalid(route_field + ".cors", error.what());
        }
      }
      if (configured_route.has_request_content()) {
        const auto& configured_content = configured_route.request_content();
        std::optional<std::uint64_t> maximum_body_bytes;
        if (configured_content.max_body_bytes() != 0U) {
          if (configured_content.max_body_bytes() >
              result.limits_.max_request_body_bytes) {
            invalid(route_field + ".request_content.max_body_bytes",
                    "must not exceed runtime_limits.max_request_body_bytes");
          }
          maximum_body_bytes = configured_content.max_body_bytes();
        }
        try {
          route.request_content.emplace(
              maximum_body_bytes,
              std::vector<std::string>(
                  configured_content.allowed_content_types().begin(),
                  configured_content.allowed_content_types().end()));
        } catch (const std::invalid_argument& error) {
          invalid(route_field + ".request_content", error.what());
        }
        if (std::any_of(route.headers.begin(), route.headers.end(),
                        [](const RuntimeHeaderMatch& predicate) {
                          return predicate.name == "content-type";
                        })) {
          invalid(route_field + ".request_content",
                  "must not duplicate a Content-Type route predicate");
        }
        if (route.api_key_auth.has_value() &&
            route.api_key_auth->header_name == "content-type") {
          invalid(route_field + ".request_content",
                  "Content-Type cannot carry an API key");
        }
      }

      if (configured_route.match().query_parameters_size() >
          static_cast<int>(kMaximumRoutePredicates)) {
        invalid(route_field + ".match.query_parameters",
                "must not contain more than 16 predicates");
      }
      std::unordered_set<std::string> query_names;
      for (int query_number = 0;
           query_number < configured_route.match().query_parameters_size();
           ++query_number) {
        const auto& configured_query =
            configured_route.match().query_parameters(query_number);
        const auto query_field = route_field + ".match.query_parameters[" +
                                 std::to_string(query_number) + "]";
        if (configured_query.name().empty() ||
            configured_query.name().size() > kMaximumQueryNameBytes ||
            contains_ctl(configured_query.name())) {
          invalid(query_field + ".name",
                  "must contain between 1 and 256 bytes without controls");
        }
        require_unique(query_names, configured_query.name(),
                       query_field + ".name");
        RuntimeQueryParameterMatch query;
        query.name = configured_query.name();
        switch (configured_query.value_match_case()) {
          case bonvoyage::v1::QueryParameterMatch::kExact:
            if (configured_query.exact().size() >
                    kMaximumPredicateValueBytes ||
                contains_ctl(configured_query.exact())) {
              invalid(query_field + ".exact",
                      "must not exceed 4096 bytes or contain controls");
            }
            query.exact = configured_query.exact();
            break;
          case bonvoyage::v1::QueryParameterMatch::kPresent:
            query.present = configured_query.present();
            break;
          case bonvoyage::v1::QueryParameterMatch::VALUE_MATCH_NOT_SET:
            invalid(query_field,
                    "exactly one of exact or present is required");
        }
        route.query_parameters.push_back(std::move(query));
      }
      std::sort(route.query_parameters.begin(), route.query_parameters.end(),
                [](const RuntimeQueryParameterMatch& left,
                   const RuntimeQueryParameterMatch& right) {
                  return left.name < right.name;
                });

      require_unique(route_bindings, route_signature(route),
                     route_field + ".match");

      const auto path_signature = route_path_signature(route);
      if (unconditional_path_bindings.contains(path_signature)) {
        invalid(route_field + ".match",
                "unreachable because an earlier route with the same path "
                "matcher has no predicates");
      }
      if (route_is_unconditional(route)) {
        unconditional_path_bindings.emplace(path_signature);
      }

      const bool has_cluster = !configured_route.cluster_name().empty();
      const bool has_weighted_clusters =
          configured_route.weighted_clusters_size() != 0;
      const bool has_fixed = configured_route.has_fixed_response();
      const bool has_redirect = configured_route.has_redirect();
      if (static_cast<unsigned int>(has_cluster) +
              static_cast<unsigned int>(has_weighted_clusters) +
              static_cast<unsigned int>(has_fixed) +
              static_cast<unsigned int>(has_redirect) !=
          1U) {
        invalid(route_field,
                "exactly one of cluster_name, weighted_clusters, fixed_response, or redirect is required");
      }
      const bool has_proxy_action = has_cluster || has_weighted_clusters;
      std::vector<RuntimeWeightedCluster> weighted_clusters;
      if (has_cluster) {
        const auto cluster = cluster_indices.find(configured_route.cluster_name());
        if (cluster == cluster_indices.end()) {
          invalid(route_field + ".cluster_name",
                  "unknown cluster '" + configured_route.cluster_name() + "'");
        }
        route.cluster_index = cluster->second;
      } else if (has_weighted_clusters) {
        const auto target_count = static_cast<std::size_t>(
            configured_route.weighted_clusters_size());
        if (target_count < 2U ||
            target_count > kMaximumWeightedClustersPerRoute) {
          invalid(route_field + ".weighted_clusters",
                  "must contain between 2 and 16 entries");
        }
        weighted_clusters.reserve(target_count);
        std::unordered_set<std::size_t> seen_clusters;
        std::uint32_t total_weight = 0U;
        for (int target_number = 0;
             target_number < configured_route.weighted_clusters_size();
             ++target_number) {
          const auto& configured_target =
              configured_route.weighted_clusters(target_number);
          const auto target_field =
              route_field + ".weighted_clusters[" +
              std::to_string(target_number) + "]";
          const auto cluster =
              cluster_indices.find(configured_target.cluster_name());
          if (cluster == cluster_indices.end()) {
            invalid(target_field + ".cluster_name",
                    "unknown cluster '" + configured_target.cluster_name() +
                        "'");
          }
          if (!seen_clusters.emplace(cluster->second).second) {
            invalid(target_field + ".cluster_name",
                    "cluster must be unique within the route");
          }
          const auto weight = configured_target.weight();
          if (weight == 0U || weight > kMaximumWeightedClusterTotal) {
            invalid(target_field + ".weight",
                    "must be between 1 and 4096");
          }
          if (total_weight > kMaximumWeightedClusterTotal - weight) {
            invalid(route_field + ".weighted_clusters",
                    "total weight must not exceed 4096");
          }
          total_weight += weight;
          weighted_clusters.push_back(
              RuntimeWeightedCluster{cluster->second, weight});
        }
      } else if (has_fixed) {
        const auto& fixed = configured_route.fixed_response();
        if (fixed.status_code() < 200U || fixed.status_code() > 599U) {
          invalid(route_field + ".fixed_response.status_code",
                  "must be between 200 and 599");
        }
        if (fixed.body().size() > kMaximumFixedResponseBytes) {
          invalid(route_field + ".fixed_response.body",
                  "must not exceed 1 MiB");
        }
        if (contains_ctl(fixed.content_type())) {
          invalid(route_field + ".fixed_response.content_type",
                  "must not contain control characters");
        }
        route.fixed_response = RuntimeFixedResponse{
            static_cast<std::uint16_t>(fixed.status_code()), fixed.body(),
            fixed.content_type().empty() ? "text/plain"
                                         : fixed.content_type()};
      } else {
        const auto& configured_redirect = configured_route.redirect();
        if (!redirect_status(configured_redirect.status_code())) {
          invalid(route_field + ".redirect.status_code",
                  "must be one of 301, 302, 303, 307, or 308");
        }
        if (!valid_redirect_component(configured_redirect.path(), true)) {
          invalid(route_field + ".redirect.path",
                  "must be a bounded RFC 3986 path starting with one '/'");
        }
        if (!valid_redirect_component(configured_redirect.query(), false)) {
          invalid(route_field + ".redirect.query",
                  "must be a bounded RFC 3986 query without a leading '?'");
        }
        if (configured_redirect.query().starts_with('?')) {
          invalid(route_field + ".redirect.query",
                  "must not start with '?'");
        }

        const bool has_scheme = !configured_redirect.scheme().empty();
        const bool has_host = !configured_redirect.host().empty();
        if (has_scheme != has_host) {
          invalid(route_field + ".redirect",
                  "scheme and host must be configured together");
        }
        if (!has_scheme && configured_redirect.port() != 0U) {
          invalid(route_field + ".redirect.port",
                  "requires scheme and host");
        }
        if (configured_redirect.port() > 65535U) {
          invalid(route_field + ".redirect.port",
                  "must be between 1 and 65535");
        }

        std::string authority;
        if (has_scheme) {
          if (configured_redirect.scheme() != "http" &&
              configured_redirect.scheme() != "https") {
            invalid(route_field + ".redirect.scheme",
                    "must be exactly http or https");
          }
          auto host = std::string_view(configured_redirect.host());
          bool bracketed = false;
          if (host.starts_with('[') || host.ends_with(']')) {
            if (!host.starts_with('[') || !host.ends_with(']')) {
              invalid(route_field + ".redirect.host",
                      "contains mismatched IPv6 brackets");
            }
            bracketed = true;
            host.remove_prefix(1U);
            host.remove_suffix(1U);
          }
          const auto canonical_ip = canonical_ip_literal(host);
          if (canonical_ip.has_value()) {
            if (*canonical_ip != host) {
              invalid(route_field + ".redirect.host",
                      "IP literal must be canonical");
            }
            const bool ipv6 = canonical_ip->find(':') != std::string::npos;
            if (bracketed != ipv6) {
              invalid(route_field + ".redirect.host",
                      ipv6 ? "IPv6 literal must be bracketed"
                           : "IPv4 literal must not be bracketed");
            }
            authority = configured_redirect.host();
          } else {
            if (bracketed || lower_ascii(host) != host ||
                !valid_tls_server_name(host)) {
              invalid(route_field + ".redirect.host",
                      "must be a canonical lowercase DNS name or numeric IP literal");
            }
            authority = configured_redirect.host();
          }
          if (configured_redirect.port() != 0U) {
            authority.push_back(':');
            authority.append(std::to_string(configured_redirect.port()));
          }
        }

        std::string location;
        location.reserve(configured_redirect.scheme().size() + authority.size() +
                         configured_redirect.path().size() +
                         configured_redirect.query().size() + 4U);
        if (has_scheme) {
          location.append(configured_redirect.scheme());
          location.append("://");
          location.append(authority);
        }
        location.append(configured_redirect.path());
        if (!configured_redirect.query().empty()) {
          location.push_back('?');
          location.append(configured_redirect.query());
        }
        if (location.size() > kMaximumRedirectLocationBytes) {
          invalid(route_field + ".redirect",
                  "prepared Location must not exceed 8192 bytes");
        }
        route.redirect = RuntimeRedirectResponse{
            static_cast<std::uint16_t>(configured_redirect.status_code()),
            std::move(location)};
      }

      if (configured_route.has_websocket()) {
        if (!has_proxy_action) {
          invalid(route_field + ".websocket",
                  "is supported only on reverse-proxy routes");
        }
        if (route.admission.max_concurrent_requests_per_shard == 0U) {
          invalid(route_field + ".max_concurrent_requests_per_shard",
                  "is required for a bounded WebSocket route");
        }
        const auto idle_timeout =
            configured_route.websocket().idle_timeout_ms();
        if (idle_timeout < 1000U || idle_timeout > 3600000U) {
          invalid(route_field + ".websocket.idle_timeout_ms",
                  "must be between 1000 and 3600000");
        }
        if (!route.methods.empty() &&
            !std::binary_search(route.methods.begin(), route.methods.end(),
                                "GET")) {
          invalid(route_field + ".match.methods",
                  "a WebSocket route must permit GET");
        }
        const auto require_http1_cluster =
            [&result, &route_field](std::size_t cluster_index) {
              if (result.clusters_[cluster_index].protocol !=
                  RuntimeUpstreamProtocol::http1) {
                invalid(route_field + ".websocket",
                        "every selected cluster must use HTTP/1");
              }
            };
        if (route.cluster_index.has_value()) {
          require_http1_cluster(*route.cluster_index);
        }
        for (const auto& target : weighted_clusters) {
          require_http1_cluster(target.cluster_index);
        }
        route.websocket = RuntimeWebSocketPolicy{idle_timeout};
      }

      if (configured_route.has_header_transformations()) {
        if (!has_proxy_action) {
          invalid(route_field + ".header_transformations",
                  "is supported only on reverse-proxy routes");
        }
        const auto& configured = configured_route.header_transformations();
        if (configured.request().empty() && configured.response().empty()) {
          invalid(route_field + ".header_transformations",
                  "must contain at least one request or response mutation");
        }
        const auto api_key_header =
            route.api_key_auth.has_value()
                ? std::optional<std::string_view>{
                      route.api_key_auth->header_name}
                : std::nullopt;
        auto request_mutations = compile_header_mutations(
            configured.request(),
            route_field + ".header_transformations.request", true,
            api_key_header);
        auto response_mutations = compile_header_mutations(
            configured.response(),
            route_field + ".header_transformations.response", false);
        route.header_transformations = HeaderTransformations{
            std::move(request_mutations), std::move(response_mutations)};
      }

      if (configured_route.has_rewrite()) {
        if (!has_proxy_action) {
          invalid(route_field + ".rewrite",
                  "is supported only on reverse-proxy routes");
        }
        const auto& configured = configured_route.rewrite();
        const bool has_host = !configured.host().empty();
        const bool has_path = configured.path_rewrite_case() !=
                              bonvoyage::v1::RouteRewrite::
                                  PATH_REWRITE_NOT_SET;
        if (!has_host && !has_path) {
          invalid(route_field + ".rewrite",
                  "must contain a host or path rewrite");
        }
        if (!has_host && configured.port() != 0U) {
          invalid(route_field + ".rewrite.port", "requires host");
        }
        if (configured.port() > 65535U) {
          invalid(route_field + ".rewrite.port",
                  "must be between 1 and 65535");
        }

        RouteRewrite rewrite;
        if (has_host) {
          auto host = std::string_view(configured.host());
          bool bracketed = false;
          if (host.starts_with('[') || host.ends_with(']')) {
            if (!host.starts_with('[') || !host.ends_with(']')) {
              invalid(route_field + ".rewrite.host",
                      "contains mismatched IPv6 brackets");
            }
            bracketed = true;
            host.remove_prefix(1U);
            host.remove_suffix(1U);
          }
          const auto canonical_ip = canonical_ip_literal(host);
          if (canonical_ip.has_value()) {
            if (*canonical_ip != host) {
              invalid(route_field + ".rewrite.host",
                      "IP literal must be canonical");
            }
            const bool ipv6 = canonical_ip->find(':') != std::string::npos;
            if (bracketed != ipv6) {
              invalid(route_field + ".rewrite.host",
                      ipv6 ? "IPv6 literal must be bracketed"
                           : "IPv4 literal must not be bracketed");
            }
          } else if (bracketed || lower_ascii(host) != host ||
                     !valid_tls_server_name(host)) {
            invalid(route_field + ".rewrite.host",
                    "must be a canonical lowercase DNS name or numeric IP literal");
          }

          std::string authority = configured.host();
          if (configured.port() != 0U) {
            authority.push_back(':');
            authority.append(std::to_string(configured.port()));
          }
          rewrite.authority = std::move(authority);
        }

        if (has_path) {
          const bool prefix_rewrite =
              configured.path_rewrite_case() ==
              bonvoyage::v1::RouteRewrite::kPathPrefix;
          const auto& replacement = prefix_rewrite
                                        ? configured.path_prefix()
                                        : configured.path();
          if (!valid_redirect_component(replacement, true)) {
            invalid(route_field +
                        (prefix_rewrite ? ".rewrite.path_prefix"
                                        : ".rewrite.path"),
                    "must be a bounded RFC 3986 path starting with one '/'");
          }
          if (replacement.size() >
              result.limits_.max_request_header_bytes) {
            invalid(route_field +
                        (prefix_rewrite ? ".rewrite.path_prefix"
                                        : ".rewrite.path"),
                    "must not exceed runtime_limits.max_request_header_bytes");
          }
          if (prefix_rewrite) {
            if (route.exact_path || route.safe_regex != nullptr) {
              invalid(route_field + ".rewrite.path_prefix",
                      "requires a path_prefix route match");
            }
            if (route.path.ends_with('/') != replacement.ends_with('/')) {
              invalid(route_field + ".rewrite.path_prefix",
                      "must preserve the matched prefix trailing-slash form");
            }
          }
          rewrite.path = PathRewrite{
              prefix_rewrite ? PathRewriteOperation::replace_prefix
                             : PathRewriteOperation::replace,
              replacement};
        }
        route.rewrite = std::move(rewrite);
      }

      route.runtime_index = result.route_admission_policies_.size();
      result.route_admission_policies_.push_back(route.admission);
      result.route_api_key_policies_.push_back(route.api_key_auth);
      result.route_jwt_policies_.push_back(route.jwt_auth);
      result.route_weighted_clusters_.push_back(
          std::move(weighted_clusters));
      const auto route_index = virtual_host.routes.size();
      virtual_host.routes.push_back(std::move(route));
      const auto& prepared_route = virtual_host.routes.back();
      if (prepared_route.exact_path) {
        virtual_host.exact_routes[prepared_route.path].push_back(route_index);
      } else if (prepared_route.safe_regex != nullptr) {
        virtual_host.regex_routes.push_back(route_index);
      } else {
        std::size_t node = 0U;
        for (const auto character : prepared_route.path) {
          const auto new_child_index = virtual_host.prefix_trie.size();
          auto [child, inserted] =
              virtual_host.prefix_trie[node].children.emplace(
                  character, new_child_index);
          const auto child_index = child->second;
          if (inserted) {
            virtual_host.prefix_trie.emplace_back();
          }
          node = child_index;
        }
        virtual_host.prefix_trie[node].routes.push_back(route_index);
      }
    }
    virtual_host_indices.emplace(virtual_host.name,
                                 result.virtual_hosts_.size());
    result.virtual_hosts_.push_back(std::move(virtual_host));
  }

  if (snapshot.listeners().empty()) {
    invalid("listeners", "must contain at least one listener");
  }
  std::unordered_set<std::string> listener_names;
  std::unordered_set<std::string> listener_bindings;
  result.listeners_.reserve(
      static_cast<std::size_t>(snapshot.listeners_size()));
  for (int listener_number = 0; listener_number < snapshot.listeners_size();
       ++listener_number) {
    const auto& configured = snapshot.listeners(listener_number);
    const auto field = "listeners[" + std::to_string(listener_number) + "]";
    if (!valid_name(configured.name()) || configured.address().empty()) {
      invalid(field, "name must be valid and address must not be empty");
    }
    require_unique(listener_names, configured.name(), field + ".name");
    if (configured.port() == 0U || configured.port() > 65535U) {
      invalid(field + ".port", "must be between 1 and 65535");
    }
    RuntimeProtocol protocol;
    if (configured.protocol() == bonvoyage::v1::PROTOCOL_HTTP1) {
      protocol = RuntimeProtocol::http1;
    } else if (configured.protocol() == bonvoyage::v1::PROTOCOL_HTTP2) {
      if (!configured.has_downstream_tls()) {
        invalid(field + ".protocol",
                "HTTP/2 requires downstream TLS and explicit h2 ALPN");
      }
      protocol = RuntimeProtocol::http2;
    } else {
      invalid(field + ".protocol", "must be HTTP/1 or TLS HTTP/2");
    }
    require_unique(listener_bindings,
                   lower_ascii(configured.address()) + ":" +
                       std::to_string(configured.port()),
                   field + ".binding");
    RuntimeListener listener;
    listener.name = configured.name();
    listener.address = configured.address();
    listener.port = static_cast<std::uint16_t>(configured.port());
    listener.protocol = protocol;
    if (configured.has_downstream_tls()) {
      const auto& tls = configured.downstream_tls();
      if (!valid_secret_reference(tls.certificate_chain_secret())) {
        invalid(field + ".downstream_tls.certificate_chain_secret",
                "must be a safe secret filename");
      }
      if (!valid_secret_reference(tls.private_key_secret())) {
        invalid(field + ".downstream_tls.private_key_secret",
                "must be a safe secret filename");
      }
      const auto has_trust_bundle = !tls.trust_bundle_secret().empty();
      if (has_trust_bundle &&
          !valid_secret_reference(tls.trust_bundle_secret())) {
        invalid(field + ".downstream_tls.trust_bundle_secret",
                "must be a safe secret filename");
      }
      if (tls.require_client_certificate() != has_trust_bundle) {
        invalid(field + ".downstream_tls",
                "require_client_certificate and trust_bundle_secret must be configured together");
      }
      listener.downstream_tls = RuntimeDownstreamTls{
          tls.certificate_chain_secret(), tls.private_key_secret(),
          has_trust_bundle
              ? std::optional<std::string>(tls.trust_bundle_secret())
              : std::nullopt,
          tls.require_client_certificate()};
    }
    if (configured.has_trusted_proxy()) {
      const auto& trusted = configured.trusted_proxy().trusted_cidrs();
      if (trusted.empty() ||
          static_cast<std::size_t>(trusted.size()) >
              kMaximumTrustedProxyCidrs) {
        invalid(field + ".trusted_proxy.trusted_cidrs",
                "must contain between 1 and 64 entries");
      }
      std::vector<std::string> cidrs;
      cidrs.reserve(static_cast<std::size_t>(trusted.size()));
      for (const auto& cidr : trusted) {
        cidrs.push_back(cidr);
      }
      try {
        listener.trusted_proxy.emplace(cidrs);
      } catch (const std::invalid_argument& error) {
        invalid(field + ".trusted_proxy.trusted_cidrs", error.what());
      }
    }
    std::unordered_set<std::string> listener_domains;
    for (const auto& virtual_host_name : configured.virtual_host_names()) {
      const auto found = virtual_host_indices.find(virtual_host_name);
      if (found == virtual_host_indices.end()) {
        invalid(field + ".virtual_host_names",
                "unknown virtual host '" + virtual_host_name + "'");
      }
      listener.virtual_host_indices.push_back(found->second);
      if (protocol == RuntimeProtocol::http2) {
        const auto& virtual_host = result.virtual_hosts_[found->second];
        if (std::any_of(
                virtual_host.routes.begin(), virtual_host.routes.end(),
                [](const RuntimeRoute& route) {
                  return route.websocket.has_value();
                })) {
          invalid(field + ".protocol",
                  "WebSocket routes require an HTTP/1 listener");
        }
      }
      for (const auto& domain : result.virtual_hosts_[found->second].domains) {
        require_unique(listener_domains, domain, field + ".domains");
      }
    }
    if (listener.virtual_host_indices.empty()) {
      invalid(field + ".virtual_host_names", "must not be empty");
    }
    result.listeners_.push_back(std::move(listener));
  }

  return result;
}

const RuntimeSnapshot::RuntimeVirtualHost* RuntimeSnapshot::find_virtual_host(
    const RuntimeListener& listener, std::string_view raw_host) const {
  const auto host = normalize_host(raw_host);
  const RuntimeVirtualHost* wildcard = nullptr;
  std::size_t wildcard_length = 0U;
  const RuntimeVirtualHost* fallback = nullptr;
  for (const auto index : listener.virtual_host_indices) {
    const auto& candidate = virtual_hosts_[index];
    for (const auto& domain : candidate.domains) {
      if (domain == host) {
        return &candidate;
      }
      if (domain == "*") {
        fallback = &candidate;
      } else if (domain.starts_with("*.") && domain_matches(domain, host) &&
                 domain.size() > wildcard_length) {
        wildcard = &candidate;
        wildcard_length = domain.size();
      }
    }
  }
  return wildcard != nullptr ? wildcard : fallback;
}

const RuntimeRoute* RuntimeSnapshot::find_route(
    const RuntimeVirtualHost& virtual_host,
    const RequestView& request, bool cors_preflight) const {
  if (const auto exact = virtual_host.exact_routes.find(request.path);
      exact != virtual_host.exact_routes.end()) {
    for (const auto route_index : exact->second) {
      const auto& route = virtual_host.routes[route_index];
      if (route_predicates_match(route, request, cors_preflight)) {
        return &route;
      }
    }
  }

  const RuntimeRoute* best = nullptr;
  const RuntimeRoute* fallback = nullptr;
  std::size_t node = 0U;
  for (const auto character : request.path) {
    const auto child = virtual_host.prefix_trie[node].children.find(character);
    if (child == virtual_host.prefix_trie[node].children.end()) {
      break;
    }
    node = child->second;
    for (const auto route_index : virtual_host.prefix_trie[node].routes) {
      const auto& route = virtual_host.routes[route_index];
      if (route_predicates_match(route, request, cors_preflight)) {
        if (route.path == "/") {
          fallback = &route;
        } else {
          best = &route;
        }
        break;
      }
    }
  }
  if (best != nullptr) {
    return best;
  }
  for (const auto route_index : virtual_host.regex_routes) {
    const auto& route = virtual_host.routes[route_index];
    if (route_predicates_match(route, request, cors_preflight) &&
        re2::RE2::FullMatch(request.path, *route.safe_regex)) {
      return &route;
    }
  }
  return fallback;
}

RouteMatch RuntimeSnapshot::match(std::size_t listener_index,
                                  const RequestView& request) const {
  if (listener_index >= listeners_.size()) {
    return {};
  }
  const auto* virtual_host =
      find_virtual_host(listeners_[listener_index], request.host);
  if (virtual_host == nullptr) {
    return {};
  }
  const auto* route = find_route(*virtual_host, request, false);
  if (route == nullptr) {
    return {};
  }
  return RouteMatch{route,
                    route->cluster_index.has_value()
                        ? &clusters_[*route->cluster_index]
                        : nullptr};
}

RouteMatch RuntimeSnapshot::match_cors_preflight(
    std::size_t listener_index, const RequestView& request) const {
  if (listener_index >= listeners_.size()) {
    return {};
  }
  const auto* virtual_host =
      find_virtual_host(listeners_[listener_index], request.host);
  if (virtual_host == nullptr) {
    return {};
  }
  const auto* route = find_route(*virtual_host, request, true);
  if (route == nullptr) {
    return {};
  }
  return RouteMatch{route,
                    route->cluster_index.has_value()
                        ? &clusters_[*route->cluster_index]
                        : nullptr};
}

bool RuntimeSnapshot::listener_accepts_server_name(
    std::size_t listener_index, std::string_view server_name) const {
  if (listener_index >= listeners_.size() || server_name.empty() ||
      server_name.size() > 253U || contains_ctl(server_name) ||
      server_name.find_first_of("/*[]:") != std::string_view::npos) {
    return false;
  }
  return find_virtual_host(listeners_[listener_index], server_name) != nullptr;
}

bool RuntimeSnapshot::authority_matches_server_name(
    std::string_view authority, std::string_view server_name) {
  if (authority.empty() || server_name.empty()) {
    return false;
  }
  return normalize_host(authority) == normalize_domain(server_name);
}

}  // namespace bonvoyage::runtime
