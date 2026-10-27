#!/usr/bin/env python3
"""Generate ephemeral JWT smoke-test keys and tokens without retaining secrets."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import subprocess
import time
from pathlib import Path


ISSUER = "https://issuer.example.test"
AUDIENCE = "payments-api"


def base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def compact_json(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("ascii")


def sign_serialized(private_key: Path, header: bytes, claims: bytes) -> str:
    signing_input = b".".join((base64url(header).encode("ascii"),
                               base64url(claims).encode("ascii")))
    signature = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(private_key)],
        input=signing_input,
        check=True,
        capture_output=True,
    ).stdout
    return signing_input.decode("ascii") + "." + base64url(signature)


def sign(private_key: Path, header: dict[str, object], claims: dict[str, object]) -> str:
    return sign_serialized(private_key, compact_json(header), compact_json(claims))


def token(private_key: Path, kid: str, claims: dict[str, object],
          **extra_header: object) -> str:
    header: dict[str, object] = {"alg": "RS256", "kid": kid, "typ": "at+jwt"}
    header.update(extra_header)
    return sign(private_key, header, claims)


def regular_private_file(path: Path, label: str) -> None:
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or
            metadata.st_nlink != 1):
        raise RuntimeError(f"{label} must be a regular non-symlink file")
    if metadata.st_mode & 0o077:
        raise RuntimeError(f"{label} permissions must not grant group or other access")


def public_jwks(private_key: Path) -> tuple[str, dict[str, object], bytes]:
    modulus_line = subprocess.run(
        ["openssl", "rsa", "-in", str(private_key), "-noout", "-modulus"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    prefix = "Modulus="
    if not modulus_line.startswith(prefix):
        raise RuntimeError("OpenSSL returned an unexpected RSA modulus")
    modulus = bytes.fromhex(modulus_line[len(prefix):])
    exponent = b"\x01\x00\x01"
    thumbprint_input = {
        "e": base64url(exponent),
        "kty": "RSA",
        "n": base64url(modulus),
    }
    kid = base64url(hashlib.sha256(compact_json(thumbprint_input)).digest())
    jwk = {
        **thumbprint_input,
        "alg": "RS256",
        "key_ops": ["verify"],
        "kid": kid,
        "use": "sig",
    }
    return kid, jwk, compact_json({"keys": [jwk]}) + b"\n"


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_directory", type=Path)
    parser.add_argument("--lifetime-seconds", type=int, default=120)
    parser.add_argument("--reuse-key-directory", type=Path)
    result = parser.parse_args()
    if not 60 <= result.lifetime_seconds <= 300:
        parser.error("JWT lifetime must be between 60 and 300 seconds")
    return result


def main() -> int:
    args = arguments()
    lifetime_seconds = args.lifetime_seconds
    output = args.output_directory.resolve()
    output.mkdir(parents=True, exist_ok=True)
    output.chmod(0o700)
    if args.reuse_key_directory is None:
        private_key = output / "jwt-private.pem"
        if private_key.exists():
            raise RuntimeError("refusing to replace an existing JWT private key")
        subprocess.run(
            [
                "openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                "rsa_keygen_bits:2048", "-out", str(private_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        private_key.chmod(0o600)
        expected_jwks = None
    else:
        reuse = args.reuse_key_directory.resolve()
        if not reuse.is_dir() or reuse.is_symlink():
            raise RuntimeError("JWT reuse directory must be a real directory")
        private_key = reuse / "jwt-private.pem"
        source_jwks = reuse / "phase3-jwks.json"
        regular_private_file(private_key, "JWT private key")
        regular_private_file(source_jwks, "JWT JWKS")
        expected_jwks = source_jwks.read_bytes()

    regular_private_file(private_key, "JWT private key")
    kid, jwk, jwks_bytes = public_jwks(private_key)
    if expected_jwks is not None and expected_jwks != jwks_bytes:
        raise RuntimeError("reused JWT private key differs from its frozen JWKS")
    jwks_path = output / "phase3-jwks.json"
    jwks_path.write_bytes(jwks_bytes)
    jwks_path.chmod(0o600)

    now = int(time.time())
    issued_at = now - 1
    base_claims: dict[str, object] = {
        "aud": AUDIENCE,
        "exp": issued_at + lifetime_seconds,
        "iat": issued_at,
        "iss": ISSUER,
        "scope": "payments:read payments:write",
        "sub": "service-account-17",
        "tenant": "tenant-a",
    }

    def changed(**values: object) -> dict[str, object]:
        result = dict(base_claims)
        result.update(values)
        return result

    missing_scope = dict(base_claims)
    del missing_scope["scope"]
    tokens = {
        "valid": token(private_key, kid, base_claims),
        "wrong_issuer": token(
            private_key, kid, changed(iss="https://other.example.test")
        ),
        "wrong_audience": token(private_key, kid, changed(aud="other-api")),
        "wrong_type": sign(
            private_key,
            {"alg": "RS256", "kid": kid, "typ": "JWT"},
            base_claims,
        ),
        "expired": token(
            private_key, kid, changed(iat=now - 120, exp=now - 10)
        ),
        "future_iat": token(
            private_key, kid, changed(iat=now + 60, exp=now + 120)
        ),
        "future_nbf": token(private_key, kid, changed(nbf=now + 60)),
        "excessive_lifetime": token(
            private_key, kid, changed(iat=now - 1, exp=now + 600)
        ),
        "missing_scope": token(private_key, kid, missing_scope),
        "wrong_scope": token(private_key, kid, changed(scope="profile:read")),
        "wrong_claim": token(private_key, kid, changed(tenant="tenant-b")),
        "unknown_kid": token(private_key, "unknown-key", base_claims),
        "remote_jku": token(
            private_key,
            kid,
            base_claims,
            jku="https://attacker.example.test/jwks.json",
        ),
        "remote_x5u": token(
            private_key,
            kid,
            base_claims,
            x5u="https://attacker.example.test/certificate.pem",
        ),
        "embedded_jwk": token(private_key, kid, base_claims, jwk=jwk),
        "embedded_nul": token(
            private_key, kid, changed(scope="payments:read\0evil")
        ),
    }
    altered = tokens["valid"]
    signing_input, signature = altered.rsplit(".", 1)
    signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    tokens["bad_signature"] = signing_input + "." + signature
    header_json = compact_json(
        {"alg": "RS256", "kid": kid, "typ": "at+jwt"}
    )
    duplicate_header = header_json.replace(
        b'"alg":"RS256"', b'"alg":"RS256","alg":"none"', 1
    )
    payload_json = compact_json(base_claims)
    duplicate_payload = payload_json.replace(
        b'"iss":"https://issuer.example.test"',
        b'"iss":"https://issuer.example.test","iss":"https://attacker.example.test"',
        1,
    )
    tokens["duplicate_header"] = sign_serialized(
        private_key, duplicate_header, payload_json
    )
    tokens["duplicate_payload"] = sign_serialized(
        private_key, header_json, duplicate_payload
    )
    tokens["none_algorithm"] = ".".join(
        (
            base64url(compact_json({"alg": "none", "kid": kid, "typ": "at+jwt"})),
            base64url(compact_json(base_claims)),
            "AA",
        )
    )
    tokens_path = output / "jwt-tokens.json"
    tokens_path.write_text(
        json.dumps(tokens, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="ascii",
    )
    tokens_path.chmod(0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
