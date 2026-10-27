package nodecredentials

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"time"

	bonvoyagev1 "github.com/routesphere-global/bonvoyage/api/gen/go/bonvoyage/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	maxCertificateChainBytes = 1 << 20
	maxTrustBundleBytes      = 1 << 20
	maxPrivateKeyBytes       = 64 << 10
	maxCertificateCount      = 8
	maxNodeIDBytes           = 128
)

var (
	oidKeyUsage             = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidSubjectKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidSubjectAltName       = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidBasicConstraints     = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidAuthorityKeyID       = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtendedKeyUsage     = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// Validate converts an untrusted server response into one immutable candidate
// only after all identity, trust, time, metadata, and key-binding checks pass.
func Validate(
	bundle *bonvoyagev1.NodeCredentialBundle,
	options ValidationOptions,
) (*ValidatedGeneration, error) {
	if bundle == nil {
		return nil, fmt.Errorf("credential bundle is nil: %w", ErrInvalid)
	}
	if len(bundle.ProtoReflect().GetUnknown()) != 0 {
		return nil, fmt.Errorf("credential bundle contains unknown fields: %w", ErrInvalid)
	}
	if err := validateIdentifier("node ID", options.ExpectedNodeID); err != nil {
		return nil, err
	}
	if err := validateTrustDomain(options.TrustDomain); err != nil {
		return nil, err
	}
	if err := validateNodePathPrefix(options.NodePathPrefix); err != nil {
		return nil, err
	}
	if options.MaxServerClockSkew < 0 || options.MaxServerClockSkew > MaximumServerClockSkew {
		return nil, fmt.Errorf("server clock skew must be between zero and %s: %w", MaximumServerClockSkew, ErrInvalid)
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	now := clock().UTC()
	if now.IsZero() {
		return nil, fmt.Errorf("local clock returned zero time: %w", ErrInvalid)
	}
	if err := validateIdentifier("credential generation", bundle.GetCredentialGeneration()); err != nil {
		return nil, err
	}

	privateKey, privateKeyPEM, err := parsePrivateKey(options.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	chain, certificatePEM, err := parseCertificatePEM(
		"certificate chain", bundle.GetCertificateChainPem(), maxCertificateChainBytes, 2, maxCertificateCount,
	)
	if err != nil {
		return nil, err
	}
	trust, trustBundlePEM, err := parseCertificatePEM(
		"trust bundle", bundle.GetTrustBundlePem(), maxTrustBundleBytes, 1, maxCertificateCount,
	)
	if err != nil {
		return nil, err
	}
	leaf := chain[0]
	issuer := chain[1]
	if err := validateLeafProfile(leaf, options.ExpectedNodeID, options.TrustDomain, options.NodePathPrefix); err != nil {
		return nil, err
	}
	leafPublicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || leafPublicKey.Curve != elliptic.P256() || !leafPublicKey.Equal(&privateKey.PublicKey) {
		return nil, fmt.Errorf("node certificate does not match the local ECDSA P-256 key: %w", ErrInvalid)
	}
	if err := validateChain(chain, trust, now); err != nil {
		return nil, err
	}

	certificateDigest := sha256.Sum256(leaf.Raw)
	if !bytes.Equal(bundle.GetCertificateSha256(), certificateDigest[:]) {
		return nil, fmt.Errorf("certificate SHA-256 does not match the leaf certificate: %w", ErrInvalid)
	}
	issuerDigest := sha256.Sum256(issuer.Raw)
	if !bytes.Equal(bundle.GetIssuerSha256(), issuerDigest[:]) {
		return nil, fmt.Errorf("issuer SHA-256 does not match the immediate issuer: %w", ErrInvalid)
	}
	serial := strings.ToLower(leaf.SerialNumber.Text(16))
	if bundle.GetSerialNumber() != serial || !canonicalHex(bundle.GetSerialNumber()) {
		return nil, fmt.Errorf("serial number does not exactly match the leaf certificate: %w", ErrInvalid)
	}
	notBefore, err := exactTimestamp("not_before", bundle.GetNotBefore(), leaf.NotBefore)
	if err != nil {
		return nil, err
	}
	notAfter, err := exactTimestamp("not_after", bundle.GetNotAfter(), leaf.NotAfter)
	if err != nil {
		return nil, err
	}
	if now.Before(notBefore) {
		return nil, fmt.Errorf("node certificate is not yet valid: %w", ErrInvalid)
	}
	if !now.Before(notAfter) {
		return nil, fmt.Errorf("node certificate is expired: %w", ErrInvalid)
	}
	expectedRenewAfter := notBefore.Add(notAfter.Sub(notBefore) * 2 / 3).UTC()
	renewAfter, err := exactTimestamp("renew_after", bundle.GetRenewAfter(), expectedRenewAfter)
	if err != nil {
		return nil, err
	}
	serverTime, err := checkedTimestamp("server_time", bundle.GetServerTime())
	if err != nil {
		return nil, err
	}
	if clockDistance(now, serverTime) > options.MaxServerClockSkew {
		return nil, fmt.Errorf("server clock differs from the local clock by more than %s: %w", options.MaxServerClockSkew, ErrInvalid)
	}

	spiffeID := leaf.URIs[0].String()
	generation := bundle.GetCredentialGeneration()
	base := filepath.ToSlash(filepath.Join("generations", generation))
	chainDigest := sha256.Sum256(certificatePEM)
	trustDigest := sha256.Sum256(trustBundlePEM)
	manifest := Manifest{
		SchemaVersion:          manifestSchemaVersion,
		CredentialGeneration:   generation,
		NodeID:                 options.ExpectedNodeID,
		TrustDomain:            options.TrustDomain,
		NodePathPrefix:         options.NodePathPrefix,
		SPIFFEID:               spiffeID,
		CertificateSHA256:      hex.EncodeToString(certificateDigest[:]),
		IssuerSHA256:           hex.EncodeToString(issuerDigest[:]),
		CertificateChainSHA256: hex.EncodeToString(chainDigest[:]),
		TrustBundleSHA256:      hex.EncodeToString(trustDigest[:]),
		SerialNumber:           serial,
		NotBefore:              notBefore,
		NotAfter:               notAfter,
		RenewAfter:             renewAfter,
		ServerTime:             serverTime,
		CertificatePath:        base + "/node.pem",
		TrustBundlePath:        base + "/ca.pem",
		PrivateKeyPath:         base + "/node-key.pem",
	}
	return &ValidatedGeneration{
		manifest:       manifest,
		certificatePEM: append([]byte(nil), certificatePEM...),
		trustBundlePEM: append([]byte(nil), trustBundlePEM...),
		privateKeyPEM:  append([]byte(nil), privateKeyPEM...),
	}, nil
}

func validateLeafProfile(leaf *x509.Certificate, nodeID, trustDomain, nodePathPrefix string) error {
	if leaf == nil || leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		len(leaf.UnknownExtKeyUsage) != 0 || len(leaf.UnhandledCriticalExtensions) != 0 ||
		len(leaf.DNSNames) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.IPAddresses) != 0 ||
		len(leaf.URIs) != 1 {
		return fmt.Errorf("node certificate violates the required client leaf profile: %w", ErrInvalid)
	}
	expected := (&url.URL{Scheme: "spiffe", Host: trustDomain, Path: nodePathPrefix + nodeID}).String()
	identity := leaf.URIs[0]
	if identity == nil || identity.String() != expected || identity.Scheme != "spiffe" ||
		identity.Host != trustDomain || identity.Path != nodePathPrefix+nodeID || identity.User != nil ||
		identity.RawQuery != "" || identity.Fragment != "" || identity.Opaque != "" {
		return fmt.Errorf("node certificate does not contain the exact expected SPIFFE ID: %w", ErrInvalid)
	}
	if err := validateLeafExtensions(leaf, expected); err != nil {
		return err
	}
	return nil
}

func validateLeafExtensions(leaf *x509.Certificate, expectedSPIFFEID string) error {
	allowed := []asn1.ObjectIdentifier{
		oidKeyUsage, oidSubjectKeyIdentifier, oidSubjectAltName,
		oidBasicConstraints, oidAuthorityKeyID, oidExtendedKeyUsage,
	}
	seen := make(map[string]struct{}, len(leaf.Extensions))
	var san []byte
	for index := range leaf.Extensions {
		extension := leaf.Extensions[index]
		key := extension.Id.String()
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("node certificate contains duplicate extension %s: %w", key, ErrInvalid)
		}
		seen[key] = struct{}{}
		known := false
		for _, oid := range allowed {
			known = known || extension.Id.Equal(oid)
		}
		if !known {
			return fmt.Errorf("node certificate contains unsupported extension %s: %w", key, ErrInvalid)
		}
		if extension.Id.Equal(oidSubjectAltName) {
			san = extension.Value
		}
	}
	if san == nil {
		return fmt.Errorf("node certificate has no subjectAltName extension: %w", ErrInvalid)
	}
	var names asn1.RawValue
	rest, err := asn1.Unmarshal(san, &names)
	if err != nil || len(rest) != 0 || names.Class != asn1.ClassUniversal || names.Tag != asn1.TagSequence || !names.IsCompound {
		return fmt.Errorf("node certificate subjectAltName is malformed: %w", ErrInvalid)
	}
	contents := names.Bytes
	count := 0
	for len(contents) != 0 {
		var name asn1.RawValue
		contents, err = asn1.Unmarshal(contents, &name)
		if err != nil {
			return fmt.Errorf("node certificate subjectAltName entry is malformed: %w", ErrInvalid)
		}
		count++
		if name.Class != asn1.ClassContextSpecific || name.Tag != 6 || name.IsCompound || string(name.Bytes) != expectedSPIFFEID {
			return fmt.Errorf("node certificate contains a non-matching SAN entry: %w", ErrInvalid)
		}
	}
	if count != 1 {
		return fmt.Errorf("node certificate must contain exactly one URI SAN: %w", ErrInvalid)
	}
	return nil
}

func validateChain(chain, trust []*x509.Certificate, now time.Time) error {
	seenChain := make(map[string]struct{}, len(chain))
	for index, certificate := range chain {
		digest := sha256.Sum256(certificate.Raw)
		key := string(digest[:])
		if _, duplicate := seenChain[key]; duplicate {
			return fmt.Errorf("certificate chain contains duplicate material: %w", ErrInvalid)
		}
		seenChain[key] = struct{}{}
		if len(certificate.UnhandledCriticalExtensions) != 0 {
			return fmt.Errorf("certificate chain member %d has an unsupported critical extension: %w", index, ErrInvalid)
		}
		if index > 0 && (!certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0) {
			return fmt.Errorf("certificate chain member %d is not a signing CA: %w", index, ErrInvalid)
		}
	}
	if err := chain[0].CheckSignatureFrom(chain[1]); err != nil {
		return fmt.Errorf("leaf is not signed by the claimed immediate issuer: %w: %v", ErrInvalid, err)
	}

	roots := x509.NewCertPool()
	seenTrust := make(map[string]struct{}, len(trust))
	for index, certificate := range trust {
		digest := sha256.Sum256(certificate.Raw)
		key := string(digest[:])
		if _, duplicate := seenTrust[key]; duplicate {
			return fmt.Errorf("trust bundle contains duplicate material: %w", ErrInvalid)
		}
		seenTrust[key] = struct{}{}
		if !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0 ||
			len(certificate.UnhandledCriticalExtensions) != 0 || certificate.CheckSignatureFrom(certificate) != nil {
			return fmt.Errorf("trust bundle member %d is not a self-signed root CA: %w", index, ErrInvalid)
		}
		roots.AddCert(certificate)
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range chain[1:] {
		intermediates.AddCert(certificate)
	}
	verified, err := chain[0].Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return fmt.Errorf("verify node certificate chain: %w: %v", ErrInvalid, err)
	}
	for _, candidate := range verified {
		if presentedCertificateChainMatches(candidate, chain) {
			return nil
		}
	}
	return fmt.Errorf("certificate response contains unused or reordered chain material: %w", ErrInvalid)
}

func presentedCertificateChainMatches(verified, presented []*x509.Certificate) bool {
	if len(verified) != len(presented) && len(verified) != len(presented)+1 {
		return false
	}
	for index := range presented {
		if !bytes.Equal(verified[index].Raw, presented[index].Raw) {
			return false
		}
	}
	return true
}

func parsePrivateKey(data []byte) (*ecdsa.PrivateKey, []byte, error) {
	if len(data) == 0 || len(data) > maxPrivateKeyBytes {
		return nil, nil, fmt.Errorf("private key must contain 1-%d bytes: %w", maxPrivateKeyBytes, ErrInvalid)
	}
	blocks, err := strictPEM(data, "PRIVATE KEY")
	if err != nil || len(blocks) != 1 {
		return nil, nil, fmt.Errorf("private key must contain exactly one PKCS#8 block: %w", joinInvalid(err))
	}
	parsed, err := x509.ParsePKCS8PrivateKey(blocks[0].Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse PKCS#8 private key: %w: %v", ErrInvalid, err)
	}
	privateKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || privateKey.Curve != elliptic.P256() || privateKey.D == nil ||
		!privateKey.Curve.IsOnCurve(privateKey.X, privateKey.Y) {
		return nil, nil, fmt.Errorf("private key must be ECDSA P-256: %w", ErrInvalid)
	}
	canonicalDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("canonicalize private key: %w", err)
	}
	canonical := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: canonicalDER})
	return privateKey, canonical, nil
}

func parseCertificatePEM(name string, data []byte, maxBytes, minimum, maximum int) (
	[]*x509.Certificate,
	[]byte,
	error,
) {
	if len(data) == 0 || len(data) > maxBytes {
		return nil, nil, fmt.Errorf("%s must contain 1-%d bytes: %w", name, maxBytes, ErrInvalid)
	}
	blocks, err := strictPEM(data, "CERTIFICATE")
	if err != nil || len(blocks) < minimum || len(blocks) > maximum {
		return nil, nil, fmt.Errorf("%s must contain %d-%d certificates: %w", name, minimum, maximum, joinInvalid(err))
	}
	certificates := make([]*x509.Certificate, 0, len(blocks))
	canonical := make([]byte, 0, len(data))
	for index, block := range blocks {
		certificate, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil, nil, fmt.Errorf("parse %s certificate %d: %w: %v", name, index, ErrInvalid, parseErr)
		}
		certificates = append(certificates, certificate)
		canonical = append(canonical, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})...)
	}
	return certificates, canonical, nil
}

func strictPEM(data []byte, allowedType string) ([]*pem.Block, error) {
	remaining := bytes.TrimSpace(data)
	var blocks []*pem.Block
	for len(remaining) != 0 {
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN ")) {
			return nil, fmt.Errorf("PEM contains non-PEM material: %w", ErrInvalid)
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != allowedType || len(block.Headers) != 0 {
			return nil, fmt.Errorf("PEM contains an unsupported or malformed block: %w", ErrInvalid)
		}
		blocks = append(blocks, block)
		remaining = bytes.TrimSpace(rest)
	}
	if len(blocks) == 0 {
		return nil, fmt.Errorf("PEM contains no blocks: %w", ErrInvalid)
	}
	return blocks, nil
}

func checkedTimestamp(name string, value *timestamppb.Timestamp) (time.Time, error) {
	if value == nil {
		return time.Time{}, fmt.Errorf("%s is missing: %w", name, ErrInvalid)
	}
	if err := value.CheckValid(); err != nil {
		return time.Time{}, fmt.Errorf("%s is invalid: %w: %v", name, ErrInvalid, err)
	}
	return value.AsTime().UTC(), nil
}

func exactTimestamp(name string, value *timestamppb.Timestamp, expected time.Time) (time.Time, error) {
	actual, err := checkedTimestamp(name, value)
	if err != nil {
		return time.Time{}, err
	}
	expected = expected.UTC()
	if !actual.Equal(expected) {
		return time.Time{}, fmt.Errorf("%s does not exactly match the certificate: %w", name, ErrInvalid)
	}
	return actual, nil
}

func clockDistance(left, right time.Time) time.Duration {
	if left.After(right) {
		return left.Sub(right)
	}
	return right.Sub(left)
}

func canonicalHex(value string) bool {
	if value == "" || value != strings.ToLower(value) || len(value) > 40 || len(value) > 1 && value[0] == '0' {
		return false
	}
	_, err := hex.DecodeString(padHex(value))
	return err == nil
}

func padHex(value string) string {
	if len(value)%2 == 0 {
		return value
	}
	return "0" + value
}

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
		!strings.HasSuffix(value, "/") || strings.Contains(value, "//") ||
		path.Clean(value) != strings.TrimSuffix(value, "/") {
		return fmt.Errorf("node path prefix must be one clean absolute directory path: %w", ErrInvalid)
	}
	parsed, err := url.Parse("spiffe://example.test" + value + "node")
	if err != nil || parsed.EscapedPath() != value+"node" {
		return fmt.Errorf("node path prefix is not URI-safe: %w", ErrInvalid)
	}
	return nil
}

func joinInvalid(err error) error {
	if err != nil {
		return err
	}
	return ErrInvalid
}
