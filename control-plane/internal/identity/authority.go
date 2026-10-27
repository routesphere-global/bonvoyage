package identity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	maxCertificateFileBytes = 1 << 20
	maxCSRBytes             = 64 << 10
	minimumLeafLifetime     = 5 * time.Minute
	maximumBackdate         = 5 * time.Minute
)

// Authority owns the in-memory issuing signer and immutable trust policy. Its
// private key is never exposed through the public API or repository records.
type Authority struct {
	mu                  sync.Mutex
	certificate         *x509.Certificate
	privateKey          *ecdsa.PrivateKey
	trustBundlePEM      string
	trustDomain         string
	nodePathPrefix      string
	issuerFingerprint   string
	clock               func() time.Time
	random              io.Reader
	defaultLeafLifetime time.Duration
	maximumLeafLifetime time.Duration
	backdate            time.Duration
}

// LoadAuthority validates and loads one operator-managed ECDSA P-256 issuing
// CA and its trust bundle. Operator files are never copied into repository
// state; only public certificate material is emitted in credential bundles.
func LoadAuthority(options AuthorityOptions) (*Authority, error) {
	if err := validateTrustDomain(options.TrustDomain); err != nil {
		return nil, err
	}
	if err := validateNodePathPrefix(options.NodePathPrefix); err != nil {
		return nil, err
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	randomReader := options.Random
	if randomReader == nil {
		randomReader = rand.Reader
	}
	defaultLifetime := options.DefaultLeafLifetime
	if defaultLifetime == 0 {
		defaultLifetime = DefaultLeafLifetime
	}
	maximumLifetime := options.MaximumLeafLifetime
	if maximumLifetime == 0 {
		maximumLifetime = MaximumLeafLifetime
	}
	if maximumLifetime < minimumLeafLifetime || maximumLifetime > MaximumLeafLifetime ||
		defaultLifetime < minimumLeafLifetime || defaultLifetime > maximumLifetime {
		return nil, fmt.Errorf("invalid leaf certificate lifetime policy: %w", ErrInvalid)
	}
	backdate := options.Backdate
	if backdate < 0 || backdate > maximumBackdate {
		return nil, fmt.Errorf("certificate backdate must be between zero and %s: %w", maximumBackdate, ErrInvalid)
	}
	loadTime := clock().UTC()

	certificateBytes, err := readOperatorFile(options.CertificatePath, maxCertificateFileBytes, false)
	if err != nil {
		return nil, fmt.Errorf("load issuing CA certificate: %w", err)
	}
	certificateBlocks, err := strictPEMBlocks(certificateBytes, "CERTIFICATE")
	if err != nil || len(certificateBlocks) != 1 {
		return nil, fmt.Errorf("issuing CA file must contain exactly one certificate: %w", joinInvalid(err))
	}
	certificate, err := x509.ParseCertificate(certificateBlocks[0].Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse issuing CA certificate: %w: %w", ErrInvalid, err)
	}
	if err := validateIssuingCertificate(certificate, loadTime); err != nil {
		return nil, err
	}

	keyBytes, err := readOperatorFile(options.PrivateKeyPath, maxCertificateFileBytes, true)
	if err != nil {
		return nil, fmt.Errorf("load issuing CA private key: %w", err)
	}
	defer clear(keyBytes)
	privateKey, err := parseECDSAPrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}
	publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || !publicKey.Equal(&privateKey.PublicKey) {
		return nil, fmt.Errorf("issuing CA certificate and private key do not match: %w", ErrInvalid)
	}

	trustBytes, err := readOperatorFile(options.TrustBundlePath, maxCertificateFileBytes, false)
	if err != nil {
		return nil, fmt.Errorf("load trust bundle: %w", err)
	}
	trustBlocks, err := strictPEMBlocks(trustBytes, "CERTIFICATE")
	if err != nil || len(trustBlocks) == 0 {
		return nil, fmt.Errorf("trust bundle must contain certificates only: %w", joinInvalid(err))
	}
	trustCertificates := make([]*x509.Certificate, 0, len(trustBlocks))
	canonicalTrust := &strings.Builder{}
	seen := make(map[string]struct{}, len(trustBlocks))
	roots := x509.NewCertPool()
	for _, block := range trustBlocks {
		trusted, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("parse trust bundle certificate: %w: %w", ErrInvalid, parseErr)
		}
		digest := fingerprint(trusted.Raw)
		if _, duplicate := seen[digest]; duplicate {
			return nil, fmt.Errorf("trust bundle contains duplicate certificate %s: %w", digest, ErrInvalid)
		}
		if err := validateTrustCertificate(trusted, loadTime); err != nil {
			return nil, err
		}
		seen[digest] = struct{}{}
		trustCertificates = append(trustCertificates, trusted)
		roots.AddCert(trusted)
		canonicalTrust.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: trusted.Raw}))
	}
	if _, err := certificate.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: loadTime,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("issuing CA is not anchored by the trust bundle: %w: %v", ErrInvalid, err)
	}

	return &Authority{
		certificate:         certificate,
		privateKey:          privateKey,
		trustBundlePEM:      canonicalTrust.String(),
		trustDomain:         options.TrustDomain,
		nodePathPrefix:      options.NodePathPrefix,
		issuerFingerprint:   fingerprint(certificate.Raw),
		clock:               clock,
		random:              randomReader,
		defaultLeafLifetime: defaultLifetime,
		maximumLeafLifetime: maximumLifetime,
		backdate:            backdate,
	}, nil
}

// IssuerFingerprint returns the canonical SHA-256 identity of the loaded CA.
func (authority *Authority) IssuerFingerprint() string {
	if authority == nil {
		return ""
	}
	return authority.issuerFingerprint
}

// TrustBundlePEM returns the canonical public trust bundle used for issuance.
func (authority *Authority) TrustBundlePEM() string {
	if authority == nil {
		return ""
	}
	return authority.trustBundlePEM
}

// Issue signs one strictly validated CSR and returns public credential
// material. It does not persist or activate the result.
func (authority *Authority) Issue(ctx context.Context, request IssueRequest) (CredentialBundle, error) {
	if authority == nil {
		return CredentialBundle{}, fmt.Errorf("authority is nil: %w", ErrInvalid)
	}
	if err := contextError(ctx); err != nil {
		return CredentialBundle{}, err
	}
	if err := validateIdentifier("node ID", request.NodeID); err != nil {
		return CredentialBundle{}, err
	}
	if len(request.CSRDER) == 0 || len(request.CSRDER) > maxCSRBytes {
		return CredentialBundle{}, fmt.Errorf("CSR must contain 1-%d DER bytes: %w", maxCSRBytes, ErrInvalid)
	}
	if bytes.Contains(request.CSRDER, []byte("-----BEGIN")) {
		return CredentialBundle{}, fmt.Errorf("CSR must be DER, not PEM: %w", ErrInvalid)
	}
	csr, err := x509.ParseCertificateRequest(request.CSRDER)
	if err != nil {
		return CredentialBundle{}, fmt.Errorf("parse PKCS#10 CSR: %w: %v", ErrInvalid, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return CredentialBundle{}, fmt.Errorf("verify PKCS#10 CSR signature: %w: %v", ErrInvalid, err)
	}
	if len(csr.Extensions) != 0 || len(csr.ExtraExtensions) != 0 || len(csr.Attributes) != 0 ||
		len(csr.DNSNames) != 0 || len(csr.EmailAddresses) != 0 || len(csr.IPAddresses) != 0 || len(csr.URIs) != 0 {
		return CredentialBundle{}, fmt.Errorf("CSR-requested attributes, extensions, and names are forbidden: %w", ErrInvalid)
	}
	publicKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() || publicKey.X == nil || publicKey.Y == nil ||
		!publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		return CredentialBundle{}, fmt.Errorf("CSR key must be ECDSA P-256: %w", ErrInvalid)
	}
	lifetime := request.Lifetime
	if lifetime == 0 {
		lifetime = authority.defaultLeafLifetime
	}
	if lifetime < minimumLeafLifetime || lifetime > authority.maximumLeafLifetime {
		return CredentialBundle{}, fmt.Errorf("leaf lifetime is outside configured bounds: %w", ErrInvalid)
	}

	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return CredentialBundle{}, err
	}
	now := authority.clock().UTC()
	notBefore := now.Add(-authority.backdate)
	if notBefore.Before(authority.certificate.NotBefore) {
		notBefore = authority.certificate.NotBefore.UTC()
	}
	notAfter := now.Add(lifetime)
	if notAfter.After(authority.certificate.NotAfter) {
		notAfter = authority.certificate.NotAfter.UTC()
	}
	if notAfter.Sub(now) < minimumLeafLifetime || !notAfter.After(notBefore) {
		return CredentialBundle{}, fmt.Errorf("issuing CA validity cannot satisfy leaf lifetime: %w", ErrInvalid)
	}
	serial, err := randomPositiveSerial(authority.random)
	if err != nil {
		return CredentialBundle{}, err
	}
	generationID, err := randomIdentifier(authority.random, "gen_", 16)
	if err != nil {
		return CredentialBundle{}, err
	}
	identity := &url.URL{
		Scheme: "spiffe",
		Host:   authority.trustDomain,
		Path:   authority.nodePathPrefix + request.NodeID,
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{identity},
	}
	leafDER, err := x509.CreateCertificate(
		authority.random,
		template,
		authority.certificate,
		publicKey,
		authority.privateKey,
	)
	if err != nil {
		return CredentialBundle{}, fmt.Errorf("sign node certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return CredentialBundle{}, fmt.Errorf("parse issued node certificate: %w", err)
	}
	if err := validateIssuedLeaf(leaf, request.NodeID, identity, authority.certificate); err != nil {
		return CredentialBundle{}, err
	}
	validity := leaf.NotAfter.Sub(leaf.NotBefore)
	renewAfter := leaf.NotBefore.Add(validity * 2 / 3).UTC()
	chain := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authority.certificate.Raw})...,
	)
	return CredentialBundle{
		GenerationID:      generationID,
		ChainPEM:          string(chain),
		TrustBundlePEM:    authority.trustBundlePEM,
		LeafFingerprint:   fingerprint(leaf.Raw),
		IssuerFingerprint: authority.issuerFingerprint,
		Serial:            leaf.SerialNumber.Text(16),
		NotBefore:         leaf.NotBefore.UTC(),
		NotAfter:          leaf.NotAfter.UTC(),
		RenewAfter:        renewAfter,
	}, nil
}

func validateIssuingCertificate(certificate *x509.Certificate, now time.Time) error {
	if err := validateTrustCertificate(certificate, now); err != nil {
		return fmt.Errorf("invalid issuing CA: %w", err)
	}
	publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return fmt.Errorf("issuing CA key must be ECDSA P-256: %w", ErrInvalid)
	}
	return nil
}

func validateTrustCertificate(certificate *x509.Certificate, now time.Time) error {
	if !certificate.BasicConstraintsValid || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("trust certificate is not a certificate-signing CA: %w", ErrInvalid)
	}
	if len(certificate.UnhandledCriticalExtensions) != 0 || len(certificate.UnknownExtKeyUsage) != 0 {
		return fmt.Errorf("trust certificate has unsupported critical or extended usage: %w", ErrInvalid)
	}
	if len(certificate.ExtKeyUsage) != 0 {
		allowed := false
		for _, usage := range certificate.ExtKeyUsage {
			allowed = allowed || usage == x509.ExtKeyUsageAny || usage == x509.ExtKeyUsageClientAuth
		}
		if !allowed {
			return fmt.Errorf("trust certificate does not permit client certificates: %w", ErrInvalid)
		}
	}
	if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return fmt.Errorf("trust certificate is not valid at the required time: %w", ErrInvalid)
	}
	return nil
}

func parseECDSAPrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	blocks, err := strictPEMBlocks(data, "PRIVATE KEY", "EC PRIVATE KEY")
	if err != nil || len(blocks) != 1 {
		return nil, fmt.Errorf("issuing CA key file must contain exactly one unencrypted private key: %w", joinInvalid(err))
	}
	var parsed any
	switch blocks[0].Type {
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(blocks[0].Bytes)
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(blocks[0].Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("parse issuing CA private key: %w: %v", ErrInvalid, err)
	}
	privateKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || privateKey.Curve != elliptic.P256() || privateKey.D == nil {
		return nil, fmt.Errorf("issuing CA private key must be ECDSA P-256: %w", ErrInvalid)
	}
	return privateKey, nil
}

func strictPEMBlocks(data []byte, allowedTypes ...string) ([]*pem.Block, error) {
	allowed := make(map[string]struct{}, len(allowedTypes))
	for _, blockType := range allowedTypes {
		allowed[blockType] = struct{}{}
	}
	remaining := bytes.TrimSpace(data)
	var blocks []*pem.Block
	for len(remaining) != 0 {
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN ")) {
			return nil, fmt.Errorf("PEM contains non-PEM data: %w", ErrInvalid)
		}
		block, rest := pem.Decode(remaining)
		if block == nil || len(block.Headers) != 0 {
			return nil, fmt.Errorf("PEM block is malformed or has headers: %w", ErrInvalid)
		}
		if _, ok := allowed[block.Type]; !ok {
			return nil, fmt.Errorf("PEM block type %q is unsupported: %w", block.Type, ErrInvalid)
		}
		blocks = append(blocks, block)
		remaining = bytes.TrimSpace(rest)
	}
	if len(blocks) == 0 {
		return nil, fmt.Errorf("PEM contains no blocks: %w", ErrInvalid)
	}
	return blocks, nil
}

func validateIssuedLeaf(leaf *x509.Certificate, nodeID string, identity *url.URL, issuer *x509.Certificate) error {
	if leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		len(leaf.URIs) != 1 || leaf.URIs[0].String() != identity.String() ||
		len(leaf.DNSNames) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.IPAddresses) != 0 {
		return fmt.Errorf("issued certificate violates the node leaf profile for %q: %w", nodeID, ErrCorrupt)
	}
	if err := leaf.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("issued certificate signature is invalid: %w: %v", ErrCorrupt, err)
	}
	return nil
}

func randomPositiveSerial(reader io.Reader) (*big.Int, error) {
	for attempts := 0; attempts < 8; attempts++ {
		value := make([]byte, 16)
		if _, err := io.ReadFull(reader, value); err != nil {
			return nil, fmt.Errorf("generate certificate serial: %w", err)
		}
		serial := new(big.Int).SetBytes(value)
		if serial.Sign() > 0 {
			return serial, nil
		}
	}
	return nil, fmt.Errorf("random source repeatedly produced a zero serial: %w", ErrConflict)
}

func joinInvalid(err error) error {
	if err != nil {
		return err
	}
	return ErrInvalid
}
