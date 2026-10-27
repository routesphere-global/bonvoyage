#include "bonvoyage/runtime/jwt_auth.hh"

#include <cstdlib>
#include <ctime>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <jwt.h>

namespace {

using bonvoyage::runtime::JwtAlgorithm;
using bonvoyage::runtime::JwtAuthorizationResult;
using bonvoyage::runtime::JwtClaimRequirement;
using bonvoyage::runtime::JwtKeySet;
using bonvoyage::runtime::JwtValidationPolicy;
using bonvoyage::runtime::JwtValidator;

void require(const bool condition, std::string_view message) {
  if (!condition) {
    throw std::runtime_error(std::string(message));
  }
}

std::string prepare_verification_jwks(std::string jwks) {
  const auto keys_member = jwks.find("\"keys\"");
  const auto array_start = jwks.find('[', keys_member);
  const auto key_start = jwks.find('{', array_start);
  require(keys_member != std::string::npos &&
              array_start != std::string::npos &&
              key_start != std::string::npos,
          "unexpected JWKS serialization");
  const auto signing_operation = jwks.find("\"sign\"", key_start);
  require(signing_operation != std::string::npos,
          "generated key is missing its signing operation");
  jwks.replace(signing_operation, std::string_view("\"sign\"").size(),
               "\"verify\"");
  if (jwks.find("\"use\"", key_start) == std::string::npos) {
    jwks.insert(key_start + 1U, "\n      \"use\": \"sig\",");
  }
  return jwks;
}

class KeyRing final {
 public:
  explicit KeyRing(const jwt_alg_t algorithm,
                   const jwk_key_type_t key_type = JWK_KEY_TYPE_RSA,
                   const char* parameter = "2048")
      : value_(jwks_create_generate(key_type, parameter, algorithm,
                                    JWK_KEY_GEN_KID)) {
    require(value_ != nullptr && jwks_error_any(value_) == 0,
            "ephemeral RSA key generation failed");
  }

  ~KeyRing() { jwks_free(value_); }
  KeyRing(const KeyRing&) = delete;
  KeyRing& operator=(const KeyRing&) = delete;

  [[nodiscard]] jwk_set_t* get() const noexcept { return value_; }
  [[nodiscard]] const jwk_item_t* key() const noexcept {
    return jwks_item_get(value_, 0U);
  }
  [[nodiscard]] std::string kid() const {
    const auto* value = jwks_item_kid(key());
    require(value != nullptr, "generated key is missing kid");
    return value;
  }

  [[nodiscard]] std::string public_jwks() const {
    auto* exported = jwks_export(value_, 0);
    require(exported != nullptr, "public JWKS export failed");
    std::string result(exported);
    std::free(exported);
    return prepare_verification_jwks(std::move(result));
  }

  [[nodiscard]] std::string private_jwks() const {
    auto* exported = jwks_export(value_, 1);
    require(exported != nullptr, "private JWKS export failed");
    std::string result(exported);
    std::free(exported);
    return prepare_verification_jwks(std::move(result));
  }

 private:
  jwk_set_t* value_;
};

struct TokenContext final {
  std::string kid;
  std::string type{"at+jwt"};
  std::string issuer{"https://issuer.example.test"};
  std::string audience{"payments-api"};
  std::string subject{"service-account-17"};
  std::string scope{"payments:read payments:write"};
  std::string tenant{"tenant-a"};
  std::string remote_jku;
  jwt_long_t issued_at{};
  jwt_long_t expires_at{};
  jwt_long_t not_before{};
  bool include_scope{true};
  bool include_tenant{true};
  bool include_not_before{false};
};

int set_header_string(jwt_t* token, const char* name,
                      const char* value) noexcept {
  jwt_value_t field{};
  field.type = JWT_VALUE_STR;
  field.name = name;
  field.str_val = value;
  field.replace = 1;
  return jwt_header_set(token, &field) == JWT_VALUE_ERR_NONE ? 0 : 1;
}

int set_claim_string(jwt_t* token, const char* name,
                     const char* value) noexcept {
  jwt_value_t field{};
  field.type = JWT_VALUE_STR;
  field.name = name;
  field.str_val = value;
  field.replace = 1;
  return jwt_claim_set(token, &field) == JWT_VALUE_ERR_NONE ? 0 : 1;
}

int set_claim_integer(jwt_t* token, const char* name,
                      const jwt_long_t value) noexcept {
  jwt_value_t field{};
  field.type = JWT_VALUE_INT;
  field.name = name;
  field.int_val = value;
  field.replace = 1;
  return jwt_claim_set(token, &field) == JWT_VALUE_ERR_NONE ? 0 : 1;
}

int populate_token(jwt_t* token, jwt_config_t* configuration) noexcept {
  const auto& context = *static_cast<const TokenContext*>(configuration->ctx);
  if (set_header_string(token, "kid", context.kid.c_str()) != 0 ||
      set_header_string(token, "typ", context.type.c_str()) != 0 ||
      set_claim_string(token, "iss", context.issuer.c_str()) != 0 ||
      set_claim_string(token, "aud", context.audience.c_str()) != 0 ||
      set_claim_string(token, "sub", context.subject.c_str()) != 0 ||
      set_claim_integer(token, "iat", context.issued_at) != 0 ||
      set_claim_integer(token, "exp", context.expires_at) != 0) {
    return 1;
  }
  if (context.include_not_before &&
      set_claim_integer(token, "nbf", context.not_before) != 0) {
    return 1;
  }
  if (context.include_scope &&
      set_claim_string(token, "scope", context.scope.c_str()) != 0) {
    return 1;
  }
  if (context.include_tenant &&
      set_claim_string(token, "tenant", context.tenant.c_str()) != 0) {
    return 1;
  }
  if (!context.remote_jku.empty() &&
      set_header_string(token, "jku", context.remote_jku.c_str()) != 0) {
    return 1;
  }
  return 0;
}

std::string make_token(const KeyRing& keys, const jwt_alg_t algorithm,
                       TokenContext context) {
  auto* builder = jwt_builder_new();
  require(builder != nullptr, "JWT builder allocation failed");
  const auto cleanup = std::unique_ptr<jwt_builder_t,
                                       decltype(&jwt_builder_free)>(
      builder, &jwt_builder_free);
  require(jwt_builder_setkey(builder, algorithm, keys.key()) == 0,
          "JWT signing key setup failed");
  require(jwt_builder_setcb(builder, &populate_token, &context) == 0,
          "JWT builder callback setup failed");
  auto* generated = jwt_builder_generate(builder);
  require(generated != nullptr, "JWT generation failed");
  std::string result(generated);
  std::free(generated);
  return result;
}

JwtValidationPolicy policy() {
  return JwtValidationPolicy{
      .issuer = "https://issuer.example.test",
      .audience = "payments-api",
      .required_type = "at+jwt",
      .algorithms = {JwtAlgorithm::rs256},
      .clock_skew_seconds = 5U,
      .max_token_lifetime_seconds = 300U,
      .required_scopes = {"payments:read"},
      .required_claims = {JwtClaimRequirement{"tenant", "tenant-a"}},
  };
}

std::string authorization(std::string_view token) {
  return "Bearer " + std::string(token);
}

void expect_invalid_jwks(std::string_view jwks, std::string_view message) {
  bool rejected = false;
  try {
    (void)JwtKeySet::compile(jwks);
  } catch (const std::invalid_argument&) {
    rejected = true;
  }
  require(rejected, message);
}

}  // namespace

int main() {
  try {
    KeyRing rs256_keys(JWT_ALG_RS256);
    const auto public_jwks = rs256_keys.public_jwks();
    const auto keys = JwtKeySet::compile(public_jwks);
    JwtValidator validator(keys, policy());

    const auto now = static_cast<jwt_long_t>(std::time(nullptr));
    TokenContext valid{
        .kid = rs256_keys.kid(),
        .remote_jku = "",
        .issued_at = now - 1,
        .expires_at = now + 120,
    };
    const auto valid_token = make_token(rs256_keys, JWT_ALG_RS256, valid);
    require(validator.authorize_bearer(authorization(valid_token)) ==
                JwtAuthorizationResult::authorized,
            "valid token was rejected");

    KeyRing ps256_keys(JWT_ALG_PS256);
    auto ps_policy = policy();
    ps_policy.algorithms = {JwtAlgorithm::ps256};
    JwtValidator ps_validator(JwtKeySet::compile(ps256_keys.public_jwks()),
                              std::move(ps_policy));
    auto ps_valid = valid;
    ps_valid.kid = ps256_keys.kid();
    require(ps_validator.authorize_bearer(authorization(make_token(
                ps256_keys, JWT_ALG_PS256, ps_valid))) ==
                JwtAuthorizationResult::authorized,
            "valid PS256 token was rejected");

    KeyRing es256_keys(JWT_ALG_ES256, JWK_KEY_TYPE_EC, "P-256");
    auto es_policy = policy();
    es_policy.algorithms = {JwtAlgorithm::es256};
    JwtValidator es_validator(JwtKeySet::compile(es256_keys.public_jwks()),
                              std::move(es_policy));
    auto es_valid = valid;
    es_valid.kid = es256_keys.kid();
    require(es_validator.authorize_bearer(authorization(make_token(
                es256_keys, JWT_ALG_ES256, es_valid))) ==
                JwtAuthorizationResult::authorized,
            "valid ES256 token was rejected");
    require(validator.authorize_bearer("Basic abc") ==
                JwtAuthorizationResult::invalid_token,
            "wrong authorization scheme was accepted");
    require(validator.authorize_bearer("Bearer a.b") ==
                JwtAuthorizationResult::invalid_token,
            "malformed compact token was accepted");

    auto altered = valid_token;
    const auto signature_separator = altered.rfind('.');
    require(signature_separator != std::string::npos &&
                signature_separator + 1U < altered.size(),
            "generated token is missing its signature segment");
    auto& signature_character = altered[signature_separator + 1U];
    signature_character = signature_character == 'A' ? 'B' : 'A';
    require(validator.authorize_bearer(authorization(altered)) ==
                JwtAuthorizationResult::invalid_token,
            "altered signature was accepted");

    auto wrong_issuer = valid;
    wrong_issuer.issuer = "https://other.example.test";
    require(validator.authorize_bearer(authorization(make_token(
                rs256_keys, JWT_ALG_RS256, wrong_issuer))) ==
                JwtAuthorizationResult::invalid_token,
            "wrong issuer was accepted");
    auto wrong_audience = valid;
    wrong_audience.audience = "other-api";
    require(validator.authorize_bearer(authorization(make_token(
                rs256_keys, JWT_ALG_RS256, wrong_audience))) ==
                JwtAuthorizationResult::invalid_token,
            "wrong audience was accepted");
    auto wrong_type = valid;
    wrong_type.type = "JWT";
    require(validator.authorize_bearer(authorization(make_token(
                rs256_keys, JWT_ALG_RS256, wrong_type))) ==
                JwtAuthorizationResult::invalid_token,
            "wrong token type was accepted");

    auto expired = valid;
    expired.issued_at = now - 120;
    expired.expires_at = now - 10;
    require(validator.authorize_bearer(authorization(make_token(
                rs256_keys, JWT_ALG_RS256, expired))) ==
                JwtAuthorizationResult::invalid_token,
            "expired token was accepted");
    auto future = valid;
    future.issued_at = now + 30;
    future.expires_at = now + 60;
    require(validator.authorize_bearer(authorization(make_token(
                rs256_keys, JWT_ALG_RS256, future))) ==
                JwtAuthorizationResult::invalid_token,
            "future-issued token was accepted");
    auto excessive_lifetime = valid;
    excessive_lifetime.expires_at = excessive_lifetime.issued_at + 301;
    require(validator.authorize_bearer(authorization(make_token(
                rs256_keys, JWT_ALG_RS256, excessive_lifetime))) ==
                JwtAuthorizationResult::invalid_token,
            "excessive token lifetime was accepted");

    auto missing_scope = valid;
    missing_scope.include_scope = false;
    require(validator.authorize_bearer(authorization(make_token(
                rs256_keys, JWT_ALG_RS256, missing_scope))) ==
                JwtAuthorizationResult::insufficient_scope,
            "missing scope did not produce an authorization rejection");
    auto wrong_claim = valid;
    wrong_claim.tenant = "tenant-b";
    require(validator.authorize_bearer(authorization(make_token(
                rs256_keys, JWT_ALG_RS256, wrong_claim))) ==
                JwtAuthorizationResult::insufficient_scope,
            "wrong route claim did not produce an authorization rejection");

    auto remote_key = valid;
    remote_key.remote_jku = "https://attacker.example.test/jwks.json";
    require(validator.authorize_bearer(authorization(make_token(
                rs256_keys, JWT_ALG_RS256, remote_key))) ==
                JwtAuthorizationResult::invalid_token,
            "token-controlled remote key URL was accepted");
    auto unknown_key = valid;
    unknown_key.kid = "unknown-key";
    require(validator.authorize_bearer(authorization(make_token(
                rs256_keys, JWT_ALG_RS256, unknown_key))) ==
                JwtAuthorizationResult::invalid_token,
            "unknown key ID was accepted");

    auto ps256 = valid;
    ps256.kid = ps256_keys.kid();
    require(validator.authorize_bearer(authorization(make_token(
                ps256_keys, JWT_ALG_PS256, ps256))) ==
                JwtAuthorizationResult::invalid_token,
            "algorithm outside the route allowlist was accepted");

    expect_invalid_jwks({}, "empty JWKS was accepted");
    expect_invalid_jwks(rs256_keys.private_jwks(),
                        "private JWKS material was accepted");
    auto missing_purpose = public_jwks;
    const auto purpose = missing_purpose.find("\"use\": \"sig\",");
    require(purpose != std::string::npos,
            "test JWKS signing purpose is missing");
    missing_purpose.erase(
        purpose, std::string_view("\"use\": \"sig\",").size());
    expect_invalid_jwks(missing_purpose,
                        "JWKS without explicit verification purpose was accepted");

    auto signing_only = public_jwks;
    const auto verify_operation = signing_only.find("\"verify\"");
    require(verify_operation != std::string::npos,
            "test JWKS verification operation is missing");
    signing_only.replace(verify_operation,
                         std::string_view("\"verify\"").size(), "\"sign\"");
    expect_invalid_jwks(signing_only,
                        "JWKS with signing-only key operations was accepted");

    auto duplicate_member = public_jwks;
    const auto keys_member = duplicate_member.find("\"keys\"");
    const auto member_array = duplicate_member.find('[', keys_member);
    const auto member_key = duplicate_member.find('{', member_array);
    require(member_key != std::string::npos,
            "test JWKS key object is malformed");
    duplicate_member.insert(member_key + 1U,
                            "\n      \"use\": \"sig\",");
    expect_invalid_jwks(duplicate_member,
                        "JWKS with a duplicate object member was accepted");

    auto embedded_nul = public_jwks;
    const auto key_id = rs256_keys.kid();
    const auto key_id_position = embedded_nul.find(key_id);
    require(key_id_position != std::string::npos,
            "test JWKS key ID is missing");
    embedded_nul.insert(key_id_position + key_id.size(), "\\u0000suffix");
    expect_invalid_jwks(embedded_nul,
                        "JWKS with an embedded-NUL key ID was accepted");

    const auto array_begin = public_jwks.find('[');
    const auto array_end = public_jwks.rfind(']');
    require(array_begin != std::string::npos && array_end > array_begin,
            "test JWKS array is malformed");
    const auto key_json = public_jwks.substr(
        array_begin + 1U, array_end - array_begin - 1U);
    const auto duplicate = "{\"keys\":[" + key_json + "," + key_json + "]}";
    expect_invalid_jwks(duplicate, "duplicate JWKS key ID was accepted");

    std::cout << "jwt auth tests passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "jwt auth test failure: " << error.what() << '\n';
    return 1;
  }
}
