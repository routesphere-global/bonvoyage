package identity

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"path"
	"strings"
	"unicode/utf8"
)

const (
	maxNodeIDBytes   = 128
	maxAudienceBytes = 256
	maxReasonBytes   = 1024
)

func validateIdentifier(name, value string) error {
	if len(value) == 0 || len(value) > maxNodeIDBytes {
		return fmt.Errorf("%s must contain 1-%d bytes: %w", name, maxNodeIDBytes, ErrInvalid)
	}
	for index, char := range value {
		valid := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' ||
			char >= '0' && char <= '9' || char == '.' || char == '_' || char == ':' || char == '-'
		if !valid || index == 0 && (char == '.' || char == ':' || char == '-') {
			return fmt.Errorf("%s contains an unsupported character: %w", name, ErrInvalid)
		}
	}
	return nil
}

func validateText(name, value string, maxBytes int, required bool) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8: %w", name, ErrInvalid)
	}
	if required && strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is empty: %w", name, ErrInvalid)
	}
	if len(value) > maxBytes {
		return fmt.Errorf("%s exceeds %d bytes: %w", name, maxBytes, ErrInvalid)
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return fmt.Errorf("%s contains a control character: %w", name, ErrInvalid)
		}
	}
	return nil
}

func validateTrustDomain(value string) error {
	if len(value) == 0 || len(value) > 255 || value != strings.ToLower(value) ||
		strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return fmt.Errorf("invalid SPIFFE trust domain: %w", ErrInvalid)
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("invalid SPIFFE trust domain: %w", ErrInvalid)
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
				return fmt.Errorf("invalid SPIFFE trust domain: %w", ErrInvalid)
			}
		}
	}
	return nil
}

func validateNodePathPrefix(value string) error {
	if len(value) < 3 || len(value) > 256 || !strings.HasPrefix(value, "/") ||
		!strings.HasSuffix(value, "/") || strings.Contains(value, "//") || path.Clean(value) != strings.TrimSuffix(value, "/") {
		return fmt.Errorf("node path prefix must be one clean absolute directory path: %w", ErrInvalid)
	}
	parsed, err := url.Parse("spiffe://example.test" + value + "node")
	if err != nil || parsed.EscapedPath() != value+"node" {
		return fmt.Errorf("node path prefix is not URI-safe: %w", ErrInvalid)
	}
	return nil
}

func validateFingerprint(name, value string) error {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+sha256.Size*2 {
		return fmt.Errorf("%s is not a canonical SHA-256 fingerprint: %w", name, ErrInvalid)
	}
	digest := strings.TrimPrefix(value, "sha256:")
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != sha256.Size || digest != strings.ToLower(digest) {
		return fmt.Errorf("%s is not a canonical SHA-256 fingerprint: %w", name, ErrInvalid)
	}
	return nil
}

func validateGenerationID(value string) error {
	if !strings.HasPrefix(value, "gen_") {
		return fmt.Errorf("generation ID is not canonical: %w", ErrInvalid)
	}
	randomPart := strings.TrimPrefix(value, "gen_")
	decoded, err := base64.RawURLEncoding.DecodeString(randomPart)
	if err != nil || len(decoded) != 16 || base64.RawURLEncoding.EncodeToString(decoded) != randomPart {
		return fmt.Errorf("generation ID is not canonical: %w", ErrInvalid)
	}
	return nil
}

func validateSerial(value string) error {
	if value == "" || value == "0" || len(value) > 32 || value != strings.ToLower(value) ||
		value[0] == '0' && len(value) > 1 {
		return fmt.Errorf("serial is not canonical: %w", ErrInvalid)
	}
	decoded, err := hex.DecodeString(padHex(value))
	if err != nil || len(decoded) == 0 || len(decoded) > 16 {
		return fmt.Errorf("serial is not canonical: %w", ErrInvalid)
	}
	return nil
}

func padHex(value string) string {
	if len(value)%2 == 0 {
		return value
	}
	return "0" + value
}

func fingerprint(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func contextError(ctx interface{ Err() error }) error {
	if ctx == nil {
		return fmt.Errorf("context is nil: %w", ErrInvalid)
	}
	return ctx.Err()
}
