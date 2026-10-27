#include "bonvoyage/runtime/jwt_auth.hh"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <limits>
#include <optional>
#include <stdexcept>
#include <unordered_set>
#include <utility>

#include <jwt.h>

namespace bonvoyage::runtime {
namespace {

constexpr std::size_t kMaximumJwtKeys = 16U;
constexpr std::size_t kMaximumJwtKidBytes = 128U;
constexpr std::size_t kMaximumJwtHeaderSegmentBytes = 2U * 1024U;
constexpr std::size_t kMaximumJwtPayloadSegmentBytes = 6U * 1024U;
constexpr std::size_t kMaximumJwtSignatureSegmentBytes = 2U * 1024U;
constexpr std::size_t kMaximumJwtSubjectBytes = 256U;
constexpr std::size_t kMaximumJwtScopeClaimBytes = 2U * 1024U;
constexpr std::size_t kMaximumJwtScopes = 64U;
constexpr std::size_t kMaximumJwtClaimValueBytes = 256U;
constexpr std::string_view kBearerPrefix{"Bearer "};

bool visible_ascii(std::string_view value) noexcept {
  return std::all_of(value.begin(), value.end(), [](const char character) {
    const auto byte = static_cast<unsigned char>(character);
    return byte >= 0x21U && byte <= 0x7eU;
  });
}

bool base64url_segment(std::string_view value) noexcept {
  return !value.empty() &&
         std::all_of(value.begin(), value.end(), [](const char character) {
           const auto byte = static_cast<unsigned char>(character);
           return (byte >= static_cast<unsigned char>('A') &&
                   byte <= static_cast<unsigned char>('Z')) ||
                  (byte >= static_cast<unsigned char>('a') &&
                   byte <= static_cast<unsigned char>('z')) ||
                  (byte >= static_cast<unsigned char>('0') &&
                   byte <= static_cast<unsigned char>('9')) ||
                  character == '-' || character == '_';
         });
}

bool bearer_prefix(std::string_view value) noexcept {
  if (value.size() < kBearerPrefix.size()) {
    return false;
  }
  for (std::size_t index = 0U; index < 6U; ++index) {
    const auto actual = static_cast<unsigned char>(value[index]);
    const auto expected = static_cast<unsigned char>(kBearerPrefix[index]);
    if (std::tolower(actual) != std::tolower(expected)) {
      return false;
    }
  }
  return value[6U] == ' ';
}

std::optional<std::string_view> compact_token(
    std::string_view authorization) noexcept {
  if (!bearer_prefix(authorization) ||
      authorization.size() <= kBearerPrefix.size() ||
      authorization.size() > kBearerPrefix.size() + kMaximumJwtBytes) {
    return std::nullopt;
  }
  const auto token = authorization.substr(kBearerPrefix.size());
  const auto first_dot = token.find('.');
  if (first_dot == std::string_view::npos) {
    return std::nullopt;
  }
  const auto second_dot = token.find('.', first_dot + 1U);
  if (second_dot == std::string_view::npos ||
      token.find('.', second_dot + 1U) != std::string_view::npos) {
    return std::nullopt;
  }
  const auto header = token.substr(0U, first_dot);
  const auto payload = token.substr(first_dot + 1U, second_dot - first_dot - 1U);
  const auto signature = token.substr(second_dot + 1U);
  if (header.size() > kMaximumJwtHeaderSegmentBytes ||
      payload.size() > kMaximumJwtPayloadSegmentBytes ||
      signature.size() > kMaximumJwtSignatureSegmentBytes ||
      !base64url_segment(header) || !base64url_segment(payload) ||
      !base64url_segment(signature)) {
    return std::nullopt;
  }
  return token;
}

jwt_alg_t native_algorithm(const JwtAlgorithm algorithm) noexcept {
  switch (algorithm) {
    case JwtAlgorithm::rs256:
      return JWT_ALG_RS256;
    case JwtAlgorithm::ps256:
      return JWT_ALG_PS256;
    case JwtAlgorithm::es256:
      return JWT_ALG_ES256;
  }
  return JWT_ALG_INVAL;
}

bool supported_key_algorithm(const jwt_alg_t algorithm) noexcept {
  return algorithm == JWT_ALG_RS256 || algorithm == JWT_ALG_PS256 ||
         algorithm == JWT_ALG_ES256;
}

bool compatible_key_type(const jwt_alg_t algorithm,
                         const jwk_key_type_t type) noexcept {
  if (algorithm == JWT_ALG_ES256) {
    return type == JWK_KEY_TYPE_EC;
  }
  return (algorithm == JWT_ALG_RS256 || algorithm == JWT_ALG_PS256) &&
         type == JWK_KEY_TYPE_RSA;
}

bool valid_key_bits(const jwt_alg_t algorithm, const int bits) noexcept {
  if (algorithm == JWT_ALG_ES256) {
    return bits == 256;
  }
  return bits >= 2048 && bits <= 8192;
}

bool header_is_absent(jwt_t* token, const char* name) noexcept {
  jwt_value_t value{};
  value.type = JWT_VALUE_JSON;
  value.name = name;
  const auto result = jwt_header_get(token, &value);
  if (result == JWT_VALUE_ERR_NONE) {
    std::free(value.json_val);
    return false;
  }
  return result == JWT_VALUE_ERR_NOEXIST;
}

bool get_header_string(jwt_t* token, const char* name,
                       const char*& result) noexcept {
  jwt_value_t value{};
  value.type = JWT_VALUE_STR;
  value.name = name;
  if (jwt_header_get(token, &value) != JWT_VALUE_ERR_NONE ||
      value.str_val == nullptr) {
    return false;
  }
  result = value.str_val;
  return true;
}

bool get_claim_string(jwt_t* token, const char* name,
                      const char*& result) noexcept {
  jwt_value_t value{};
  value.type = JWT_VALUE_STR;
  value.name = name;
  if (jwt_claim_get(token, &value) != JWT_VALUE_ERR_NONE ||
      value.str_val == nullptr) {
    return false;
  }
  result = value.str_val;
  return true;
}

bool get_claim_integer(jwt_t* token, const char* name,
                       jwt_long_t& result) noexcept {
  jwt_value_t value{};
  value.type = JWT_VALUE_INT;
  value.name = name;
  if (jwt_claim_get(token, &value) != JWT_VALUE_ERR_NONE) {
    return false;
  }
  result = value.int_val;
  return true;
}

bool valid_scope_character(const char character) noexcept {
  const auto byte = static_cast<unsigned char>(character);
  return byte == 0x21U || (byte >= 0x23U && byte <= 0x5bU) ||
         (byte >= 0x5dU && byte <= 0x7eU);
}

bool has_required_scopes(std::string_view scope_claim,
                         const std::vector<std::string>& required) noexcept {
  if (scope_claim.empty() || scope_claim.size() > kMaximumJwtScopeClaimBytes) {
    return false;
  }
  std::array<std::string_view, kMaximumJwtScopes> scopes{};
  std::size_t scope_count = 0U;
  std::size_t begin = 0U;
  while (begin < scope_claim.size()) {
    if (scope_count == scopes.size()) {
      return false;
    }
    const auto end = scope_claim.find(' ', begin);
    const auto scope = scope_claim.substr(
        begin, end == std::string_view::npos ? std::string_view::npos
                                             : end - begin);
    if (scope.empty() ||
        !std::all_of(scope.begin(), scope.end(), valid_scope_character)) {
      return false;
    }
    scopes[scope_count++] = scope;
    if (end == std::string_view::npos) {
      break;
    }
    begin = end + 1U;
  }
  const auto end = scopes.begin() + static_cast<std::ptrdiff_t>(scope_count);
  return std::all_of(required.begin(), required.end(), [&](const auto& wanted) {
    return std::find(scopes.begin(), end, std::string_view(wanted)) != end;
  });
}

}  // namespace

struct JwtKeySet::Impl final {
  explicit Impl(jwk_set_t* value) noexcept : value(value) {}
  ~Impl() { jwks_free(value); }

  jwk_set_t* value;
};

JwtKeySet::JwtKeySet(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

JwtKeySet::~JwtKeySet() = default;

std::shared_ptr<const JwtKeySet> JwtKeySet::compile(std::string_view jwks) {
  if (jwks.empty() || jwks.size() > kMaximumJwtJwksBytes) {
    throw std::invalid_argument(
        "JWT JWKS must contain between 1 byte and 64 KiB");
  }
  auto* parsed = jwks_create_strn(jwks.data(), jwks.size());
  if (parsed == nullptr) {
    throw std::invalid_argument("JWT JWKS could not be parsed");
  }
  auto impl = std::make_unique<Impl>(parsed);
  if (jwks_error_any(parsed) != 0) {
    throw std::invalid_argument("JWT JWKS contains an invalid key");
  }
  const auto count = jwks_item_count(parsed);
  if (count == 0U || count > kMaximumJwtKeys) {
    throw std::invalid_argument("JWT JWKS must contain between 1 and 16 keys");
  }

  std::unordered_set<std::string> kids;
  for (std::size_t index = 0U; index < count; ++index) {
    const auto* key = jwks_item_get(parsed, index);
    if (key == nullptr || jwks_item_error(key) != 0 ||
        jwks_item_is_private(key) != 0) {
      throw std::invalid_argument(
          "JWT JWKS must contain valid public keys only");
    }
    const auto* kid_value = jwks_item_kid(key);
    const std::string_view kid = kid_value == nullptr
                                     ? std::string_view{}
                                     : std::string_view(kid_value);
    if (kid.empty() || kid.size() > kMaximumJwtKidBytes ||
        !visible_ascii(kid) || !kids.emplace(kid).second) {
      throw std::invalid_argument(
          "JWT JWKS key IDs must be unique visible ASCII values no longer than 128 bytes");
    }
    const auto algorithm = jwks_item_alg(key);
    if (!supported_key_algorithm(algorithm) ||
        !compatible_key_type(algorithm, jwks_item_kty(key)) ||
        !valid_key_bits(algorithm, jwks_item_key_bits(key))) {
      throw std::invalid_argument(
          "JWT JWKS keys must explicitly bind supported algorithms to safe key sizes");
    }
    if (jwks_item_use(key) != JWK_PUB_KEY_USE_SIG) {
      throw std::invalid_argument(
          "JWT JWKS keys must explicitly declare use=sig");
    }
    const auto operations = jwks_item_key_ops(key);
    if (operations != JWK_KEY_OP_VERIFY) {
      throw std::invalid_argument(
          "JWT JWKS keys must explicitly declare key_ops=[verify]");
    }
  }
  return std::shared_ptr<const JwtKeySet>(new JwtKeySet(std::move(impl)));
}

struct JwtValidator::Impl final {
  Impl(std::shared_ptr<const JwtKeySet> key_set, JwtValidationPolicy value)
      : keys(std::move(key_set)), policy(std::move(value)) {}

  ~Impl() { jwt_checker_free(checker); }

  static int validate_token(jwt_t* token, jwt_config_t* config) noexcept {
    auto* self = static_cast<Impl*>(config->ctx);
    if (self == nullptr || !header_is_absent(token, "jku") ||
        !header_is_absent(token, "x5u") ||
        !header_is_absent(token, "jwk")) {
      return 1;
    }

    const char* kid = nullptr;
    if (!get_header_string(token, "kid", kid) || kid[0] == '\0' ||
        std::strlen(kid) > kMaximumJwtKidBytes) {
      return 1;
    }
    auto* key = jwks_find_bykid(self->keys->impl_->value, kid);
    if (key == nullptr) {
      return 1;
    }
    config->key = key;

    const char* subject = nullptr;
    if (!get_claim_string(token, "sub", subject)) {
      return 1;
    }
    const std::string_view subject_view(subject);
    if (subject_view.empty() || subject_view.size() > kMaximumJwtSubjectBytes ||
        !visible_ascii(subject_view)) {
      return 1;
    }

    jwt_long_t issued_at{};
    jwt_long_t expires_at{};
    if (!get_claim_integer(token, "iat", issued_at) ||
        !get_claim_integer(token, "exp", expires_at) || issued_at < 0 ||
        expires_at < issued_at) {
      return 1;
    }
    const auto now = static_cast<jwt_long_t>(std::time(nullptr));
    const auto skew = static_cast<jwt_long_t>(self->policy.clock_skew_seconds);
    if (issued_at > now + skew ||
        expires_at - issued_at >
            static_cast<jwt_long_t>(
                self->policy.max_token_lifetime_seconds)) {
      return 1;
    }

    if (!self->policy.required_scopes.empty()) {
      const char* scopes = nullptr;
      if (!get_claim_string(token, "scope", scopes) ||
          !has_required_scopes(scopes, self->policy.required_scopes)) {
        self->authorized = false;
      }
    }
    for (const auto& required : self->policy.required_claims) {
      const char* actual = nullptr;
      if (!get_claim_string(token, required.name.c_str(), actual) ||
          std::strlen(actual) > kMaximumJwtClaimValueBytes ||
          required.exact != actual) {
        self->authorized = false;
      }
    }
    return 0;
  }

  std::shared_ptr<const JwtKeySet> keys;
  JwtValidationPolicy policy;
  jwt_checker_t* checker{nullptr};
  std::string token_buffer;
  bool authorized{true};
};

JwtValidator::JwtValidator(std::shared_ptr<const JwtKeySet> keys,
                           JwtValidationPolicy policy)
    : impl_(std::make_unique<Impl>(std::move(keys), std::move(policy))) {
  if (impl_->keys == nullptr || impl_->policy.issuer.empty() ||
      impl_->policy.audience.empty() || impl_->policy.required_type.empty() ||
      impl_->policy.algorithms.empty() ||
      impl_->policy.max_token_lifetime_seconds == 0U) {
    throw std::invalid_argument("JWT validation policy is incomplete");
  }
  impl_->checker = jwt_checker_new();
  if (impl_->checker == nullptr) {
    throw std::runtime_error("JWT checker allocation failed");
  }
  impl_->token_buffer.reserve(kMaximumJwtBytes);

  std::vector<jwt_alg_t> algorithms;
  algorithms.reserve(impl_->policy.algorithms.size());
  for (const auto algorithm : impl_->policy.algorithms) {
    const auto native = native_algorithm(algorithm);
    if (native == JWT_ALG_INVAL) {
      throw std::invalid_argument("JWT policy contains an unsupported algorithm");
    }
    algorithms.push_back(native);
  }
  std::array<const char*, 5U> required_claims{
      "iss", "aud", "exp", "iat", "sub"};
  const auto skew = static_cast<std::time_t>(
      impl_->policy.clock_skew_seconds);
  if (jwt_checker_setkeyring(impl_->checker, impl_->keys->impl_->value,
                             JWT_VERIFY_POLICY_ANY) != 0 ||
      jwt_checker_setalgs(impl_->checker, algorithms.data(),
                          algorithms.size()) != 0 ||
      jwt_checker_expect_typ(impl_->checker,
                             impl_->policy.required_type.c_str()) != 0 ||
      jwt_checker_require(impl_->checker, required_claims.data(),
                          static_cast<unsigned int>(required_claims.size())) !=
          0 ||
      jwt_checker_claim_set(impl_->checker, JWT_CLAIM_ISS,
                            impl_->policy.issuer.c_str()) != 0 ||
      jwt_checker_claim_set(impl_->checker, JWT_CLAIM_AUD,
                            impl_->policy.audience.c_str()) != 0 ||
      jwt_checker_time_leeway(impl_->checker, JWT_CLAIM_EXP, skew) != 0 ||
      jwt_checker_time_leeway(impl_->checker, JWT_CLAIM_NBF, skew) != 0 ||
      jwt_checker_setcb(impl_->checker, &Impl::validate_token, impl_.get()) !=
          0) {
    throw std::invalid_argument("JWT checker preparation failed");
  }
}

JwtValidator::~JwtValidator() = default;

JwtAuthorizationResult JwtValidator::authorize_bearer(
    const std::string_view authorization) noexcept {
  const auto token = compact_token(authorization);
  if (!token.has_value()) {
    return JwtAuthorizationResult::invalid_token;
  }
  try {
    impl_->token_buffer.assign(token->data(), token->size());
  } catch (...) {
    return JwtAuthorizationResult::invalid_token;
  }
  impl_->authorized = true;
  jwt_checker_error_clear(impl_->checker);
  if (jwt_checker_verify(impl_->checker, impl_->token_buffer.c_str()) != 0) {
    return JwtAuthorizationResult::invalid_token;
  }
  return impl_->authorized ? JwtAuthorizationResult::authorized
                           : JwtAuthorizationResult::insufficient_scope;
}

}  // namespace bonvoyage::runtime
