package discovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxCertificateFileBytes = 256 << 10
	maxPrivateKeyFileBytes  = 64 << 10
	maxTrustBundleBytes     = 1 << 20
	maxRevocationFileBytes  = 1 << 20
)

// RevokedCredential identifies either one certificate or every certificate
// issued to a node. Serial revocation is scoped to its issuing certificate.
type RevokedCredential struct {
	NodeID                string    `json:"node_id"`
	CredentialFingerprint string    `json:"credential_fingerprint,omitempty"`
	IssuerFingerprint     string    `json:"issuer_fingerprint,omitempty"`
	SerialNumber          string    `json:"serial_number,omitempty"`
	RevokedAt             time.Time `json:"revoked_at"`
	Reason                string    `json:"reason"`
}

// RevocationDocument is the bounded, fail-closed local revocation snapshot.
// The document must be refreshed before ValidUntil; an expired snapshot denies
// new and established discovery credentials.
type RevocationDocument struct {
	Version    uint32              `json:"version"`
	Generation uint64              `json:"generation"`
	UpdatedAt  time.Time           `json:"updated_at"`
	ValidUntil time.Time           `json:"valid_until"`
	Revoked    []RevokedCredential `json:"revoked"`
}

// TLSLifecycleOptions defines one atomic server/trust/revocation generation.
type TLSLifecycleOptions struct {
	ServerCertificatePath string
	ServerPrivateKeyPath  string
	ClientTrustBundlePath string
	RevocationPath        string
	ServerName            string
	ReloadInterval        time.Duration
	MinimumValidity       time.Duration
	Clock                 func() time.Time
	OnReload              func(TLSLifecycleStatus)
}

// TLSLifecycleStatus is a bounded operator projection; it never contains key
// bytes, enrollment secrets, or certificate bodies.
type TLSLifecycleStatus struct {
	Generation              string
	TrustGeneration         string
	RevocationGeneration    uint64
	ServerCertificateExpiry time.Time
	LastAttempt             time.Time
	LastSuccess             time.Time
	ReloadSuccesses         uint64
	ReloadFailures          uint64
	LastError               string
}

type tlsLifecycleState struct {
	generation           string
	trustGeneration      string
	revocationDigest     string
	serverCertificate    tls.Certificate
	serverNotAfter       time.Time
	clientRoots          *x509.CertPool
	rootFingerprints     map[string]struct{}
	revocationGeneration uint64
	revocationValidUntil time.Time
	revokedNodes         map[string]struct{}
	revokedFingerprints  map[string]struct{}
	revokedSerials       map[string]struct{}
}

// TLSLifecycle atomically reloads complete TLS material. A malformed or
// partial candidate never replaces the last valid generation.
type TLSLifecycle struct {
	options TLSLifecycleOptions
	state   atomic.Pointer[tlsLifecycleState]
	mu      sync.Mutex
	status  TLSLifecycleStatus
}

// OpenTLSLifecycle validates and publishes the first complete generation.
func OpenTLSLifecycle(options TLSLifecycleOptions) (*TLSLifecycle, error) {
	if strings.TrimSpace(options.ServerCertificatePath) == "" ||
		strings.TrimSpace(options.ServerPrivateKeyPath) == "" ||
		strings.TrimSpace(options.ClientTrustBundlePath) == "" ||
		strings.TrimSpace(options.RevocationPath) == "" || options.ReloadInterval <= 0 ||
		options.MinimumValidity < 0 {
		return nil, ErrInvalidOptions
	}
	paths := []string{
		options.ServerCertificatePath, options.ServerPrivateKeyPath,
		options.ClientTrustBundlePath, options.RevocationPath,
	}
	seenPaths := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		clean := filepath.Clean(path)
		if !filepath.IsAbs(clean) || clean == string(filepath.Separator) {
			return nil, ErrInvalidOptions
		}
		if _, duplicate := seenPaths[clean]; duplicate {
			return nil, ErrInvalidOptions
		}
		seenPaths[clean] = struct{}{}
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	lifecycle := &TLSLifecycle{options: options}
	if err := lifecycle.Reload(); err != nil {
		return nil, err
	}
	return lifecycle, nil
}

// Run polls immutable files for complete replacements until ctx is canceled.
// Reload errors are retained in Status while the last valid generation stays
// active; an expired revocation document still fails credential validation.
func (lifecycle *TLSLifecycle) Run(ctx context.Context) {
	ticker := time.NewTicker(lifecycle.options.ReloadInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = lifecycle.Reload()
		}
	}
}

// Reload validates every candidate input before one atomic publication.
func (lifecycle *TLSLifecycle) Reload() error {
	lifecycle.mu.Lock()
	now := lifecycle.options.Clock().UTC()
	lifecycle.status.LastAttempt = now
	candidate, err := loadTLSLifecycleState(lifecycle.options, now)
	if err != nil {
		lifecycle.status.ReloadFailures++
		lifecycle.status.LastError = boundedError(err)
		statusSnapshot := lifecycle.status
		callback := lifecycle.options.OnReload
		lifecycle.mu.Unlock()
		if callback != nil {
			callback(statusSnapshot)
		}
		return err
	}
	current := lifecycle.state.Load()
	if current != nil && (candidate.revocationGeneration < current.revocationGeneration ||
		(candidate.revocationGeneration == current.revocationGeneration &&
			candidate.revocationDigest != current.revocationDigest)) {
		err = errors.New("revocation generation rollback or mutation was rejected")
		lifecycle.status.ReloadFailures++
		lifecycle.status.LastError = boundedError(err)
		statusSnapshot := lifecycle.status
		callback := lifecycle.options.OnReload
		lifecycle.mu.Unlock()
		if callback != nil {
			callback(statusSnapshot)
		}
		return err
	}
	if current == nil || current.generation != candidate.generation {
		lifecycle.state.Store(candidate)
		lifecycle.status.ReloadSuccesses++
	}
	lifecycle.status.Generation = candidate.generation
	lifecycle.status.TrustGeneration = candidate.trustGeneration
	lifecycle.status.RevocationGeneration = candidate.revocationGeneration
	lifecycle.status.ServerCertificateExpiry = candidate.serverNotAfter
	lifecycle.status.LastSuccess = now
	lifecycle.status.LastError = ""
	statusSnapshot := lifecycle.status
	callback := lifecycle.options.OnReload
	lifecycle.mu.Unlock()
	if callback != nil {
		callback(statusSnapshot)
	}
	return nil
}

// Status returns a copy of the current bounded lifecycle status.
func (lifecycle *TLSLifecycle) Status() TLSLifecycleStatus {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	return lifecycle.status
}

// ServerTLSConfig returns a TLS 1.3-only configuration with dynamic server
// selection and explicit verification against the current client trust state.
func (lifecycle *TLSLifecycle) ServerTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		MaxVersion:     tls.VersionTLS13,
		ClientAuth:     tls.RequireAnyClientCert,
		GetCertificate: lifecycle.currentServerCertificate,
		VerifyConnection: func(connection tls.ConnectionState) error {
			_, err := lifecycle.VerifyClientCertificate(
				connection.PeerCertificates, lifecycle.options.Clock().UTC(),
			)
			return err
		},
	}
}

// EnrollmentTLSConfig authenticates the server while deliberately requesting
// no client certificate. Enrollment authorization is the single-use token;
// this configuration must never be used for rollout discovery or renewal.
func (lifecycle *TLSLifecycle) EnrollmentTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		MaxVersion:     tls.VersionTLS13,
		ClientAuth:     tls.NoClientCert,
		GetCertificate: lifecycle.currentServerCertificate,
	}
}

func (lifecycle *TLSLifecycle) currentServerCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	state := lifecycle.state.Load()
	if state == nil {
		return nil, ErrUnauthenticated
	}
	now := lifecycle.options.Clock().UTC()
	if !now.Before(state.serverNotAfter) {
		return nil, errors.New("server certificate is expired")
	}
	return &state.serverCertificate, nil
}

// VerifyClientCertificate validates a peer chain against the current trust,
// time, EKU, and certificate-specific revocation state.
func (lifecycle *TLSLifecycle) VerifyClientCertificate(
	peerCertificates []*x509.Certificate,
	now time.Time,
) ([]*x509.Certificate, error) {
	state := lifecycle.state.Load()
	if state == nil || len(peerCertificates) == 0 || !now.Before(state.revocationValidUntil) {
		return nil, ErrUnauthenticated
	}
	leaf := peerCertificates[0]
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, ErrUnauthenticated
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range peerCertificates[1:] {
		intermediates.AddCert(certificate)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots: state.clientRoots, Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil || len(chains) == 0 {
		return nil, ErrUnauthenticated
	}
	slices.SortFunc(chains, func(left, right []*x509.Certificate) int {
		return bytes.Compare(left[len(left)-1].Raw, right[len(right)-1].Raw)
	})
	chain := chains[0]
	leafFingerprint := certificateFingerprint(leaf)
	issuer := leaf
	if len(chain) > 1 {
		issuer = chain[1]
	}
	serialKey := certificateFingerprint(issuer) + ":" + strings.ToLower(leaf.SerialNumber.Text(16))
	if _, revoked := state.revokedFingerprints[leafFingerprint]; revoked {
		return nil, ErrUnauthenticated
	}
	if _, revoked := state.revokedSerials[serialKey]; revoked {
		return nil, ErrUnauthenticated
	}
	return chain, nil
}

// ValidateCredential rechecks active stream metadata against current trust,
// revocation freshness, node revocation, and certificate time.
func (lifecycle *TLSLifecycle) ValidateCredential(identity AuthenticatedNode, now time.Time) error {
	state := lifecycle.state.Load()
	if state == nil || !now.Before(state.revocationValidUntil) ||
		now.Before(identity.CredentialNotBefore) || !now.Before(identity.CredentialNotAfter) {
		return ErrUnauthenticated
	}
	if _, trusted := state.rootFingerprints[identity.TrustAnchorFingerprint]; !trusted {
		return ErrUnauthenticated
	}
	if _, revoked := state.revokedNodes[identity.NodeID]; revoked {
		return ErrUnauthenticated
	}
	if _, revoked := state.revokedFingerprints[identity.CredentialFingerprint]; revoked {
		return ErrUnauthenticated
	}
	serialKey := identity.IssuerFingerprint + ":" + identity.CredentialSerial
	if _, revoked := state.revokedSerials[serialKey]; revoked {
		return ErrUnauthenticated
	}
	return nil
}

func loadTLSLifecycleState(options TLSLifecycleOptions, now time.Time) (*tlsLifecycleState, error) {
	certificatePEM, err := readLifecycleFile(options.ServerCertificatePath, maxCertificateFileBytes, false)
	if err != nil {
		return nil, fmt.Errorf("read server certificate: %w", err)
	}
	keyPEM, err := readLifecycleFile(options.ServerPrivateKeyPath, maxPrivateKeyFileBytes, true)
	if err != nil {
		return nil, fmt.Errorf("read server private key: %w", err)
	}
	trustPEM, err := readLifecycleFile(options.ClientTrustBundlePath, maxTrustBundleBytes, false)
	if err != nil {
		return nil, fmt.Errorf("read client trust bundle: %w", err)
	}
	revocationJSON, err := readLifecycleFile(options.RevocationPath, maxRevocationFileBytes, false)
	if err != nil {
		return nil, fmt.Errorf("read revocation document: %w", err)
	}

	serverCertificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load server certificate and key: %w", err)
	}
	if len(serverCertificate.Certificate) == 0 {
		return nil, errors.New("server certificate chain is empty")
	}
	serverLeaf, err := x509.ParseCertificate(serverCertificate.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse server leaf: %w", err)
	}
	if err := validatePresentedServerChain(serverCertificate.Certificate, now); err != nil {
		return nil, err
	}
	serverCertificate.Leaf = serverLeaf
	if now.Before(serverLeaf.NotBefore) || !now.Add(options.MinimumValidity).Before(serverLeaf.NotAfter) {
		return nil, errors.New("server certificate is not currently valid for the required margin")
	}
	if serverLeaf.IsCA || !containsServerAuth(serverLeaf.ExtKeyUsage) {
		return nil, errors.New("server certificate profile is invalid")
	}
	if options.ServerName != "" {
		if err := serverLeaf.VerifyHostname(options.ServerName); err != nil {
			return nil, fmt.Errorf("server certificate identity: %w", err)
		}
	}

	roots, rootCertificates, err := parseStrictCABundle(trustPEM)
	if err != nil {
		return nil, err
	}
	rootFingerprints := make(map[string]struct{}, len(rootCertificates))
	for _, root := range rootCertificates {
		rootFingerprints[certificateFingerprint(root)] = struct{}{}
	}

	document, err := parseRevocationDocument(revocationJSON, now)
	if err != nil {
		return nil, err
	}
	revokedNodes := make(map[string]struct{})
	revokedFingerprints := make(map[string]struct{})
	revokedSerials := make(map[string]struct{})
	for _, revoked := range document.Revoked {
		if revoked.CredentialFingerprint == "" && revoked.SerialNumber == "" {
			revokedNodes[revoked.NodeID] = struct{}{}
		}
		if revoked.CredentialFingerprint != "" {
			revokedFingerprints[revoked.CredentialFingerprint] = struct{}{}
		}
		if revoked.SerialNumber != "" {
			revokedSerials[revoked.IssuerFingerprint+":"+revoked.SerialNumber] = struct{}{}
		}
	}

	generationInput := bytes.Join([][]byte{certificatePEM, keyPEM, trustPEM, revocationJSON}, nil)
	generationHash := sha256.Sum256(generationInput)
	trustHash := sha256.Sum256(trustPEM)
	revocationHash := sha256.Sum256(revocationJSON)
	return &tlsLifecycleState{
		generation:        fmt.Sprintf("sha256:%x", generationHash),
		trustGeneration:   fmt.Sprintf("sha256:%x", trustHash),
		revocationDigest:  fmt.Sprintf("sha256:%x", revocationHash),
		serverCertificate: serverCertificate, serverNotAfter: serverLeaf.NotAfter.UTC(),
		clientRoots: roots, rootFingerprints: rootFingerprints,
		revocationGeneration: document.Generation, revocationValidUntil: document.ValidUntil.UTC(),
		revokedNodes: revokedNodes, revokedFingerprints: revokedFingerprints,
		revokedSerials: revokedSerials,
	}, nil
}

func validatePresentedServerChain(chainDER [][]byte, now time.Time) error {
	certificates := make([]*x509.Certificate, 0, len(chainDER))
	seen := make(map[string]struct{}, len(chainDER))
	for index, der := range chainDER {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("parse server certificate %d: %w", index+1, err)
		}
		fingerprint := certificateFingerprint(certificate)
		if _, duplicate := seen[fingerprint]; duplicate {
			return errors.New("server certificate chain contains a duplicate certificate")
		}
		seen[fingerprint] = struct{}{}
		if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			return fmt.Errorf("server certificate %d is outside its validity period", index+1)
		}
		certificates = append(certificates, certificate)
	}
	for index := 0; index+1 < len(certificates); index++ {
		issuer := certificates[index+1]
		if !issuer.IsCA || !issuer.BasicConstraintsValid || issuer.KeyUsage&x509.KeyUsageCertSign == 0 {
			return fmt.Errorf("server certificate %d has an invalid issuer", index+1)
		}
		if err := certificates[index].CheckSignatureFrom(issuer); err != nil {
			return fmt.Errorf("server certificate %d issuer signature: %w", index+1, err)
		}
	}
	return nil
}

func readLifecycleFile(path string, maximum int64, private bool) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("path is not a regular non-symlink file")
	}
	if private {
		if before.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("private key permits group or other access")
		}
	} else if before.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("public material is group- or world-writable")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.New("file changed while it was opened")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if len(contents) == 0 || int64(len(contents)) > maximum {
		return nil, errors.New("file size is outside the accepted bound")
	}
	return contents, nil
}

func parseStrictCABundle(contents []byte) (*x509.CertPool, []*x509.Certificate, error) {
	pool := x509.NewCertPool()
	certificates := make([]*x509.Certificate, 0, 4)
	remaining := contents
	for len(remaining) != 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			if len(bytes.TrimSpace(remaining)) != 0 {
				return nil, nil, errors.New("trust bundle contains non-PEM data")
			}
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, nil, errors.New("trust bundle contains an unsupported PEM block")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid ||
			certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, nil, errors.New("trust bundle contains an invalid certificate authority")
		}
		pool.AddCert(certificate)
		certificates = append(certificates, certificate)
		remaining = rest
	}
	if len(certificates) == 0 {
		return nil, nil, errors.New("trust bundle contains no certificate authorities")
	}
	return pool, certificates, nil
}

func parseRevocationDocument(contents []byte, now time.Time) (RevocationDocument, error) {
	return decodeRevocationDocument(contents, now, true)
}

func decodeRevocationDocument(
	contents []byte,
	now time.Time,
	requireFresh bool,
) (RevocationDocument, error) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var document RevocationDocument
	if err := decoder.Decode(&document); err != nil {
		return RevocationDocument{}, fmt.Errorf("decode revocation document: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return RevocationDocument{}, err
	}
	if document.Version != 1 || document.Generation == 0 || document.UpdatedAt.IsZero() ||
		document.ValidUntil.IsZero() || document.ValidUntil.Before(document.UpdatedAt) ||
		document.UpdatedAt.After(now.Add(time.Minute)) ||
		(requireFresh && !now.Before(document.ValidUntil)) ||
		len(document.Revoked) > 100000 {
		return RevocationDocument{}, errors.New("revocation document metadata is invalid or expired")
	}
	seen := make(map[string]struct{}, len(document.Revoked))
	for index := range document.Revoked {
		revoked := &document.Revoked[index]
		revoked.NodeID = strings.TrimSpace(revoked.NodeID)
		revoked.CredentialFingerprint = strings.ToLower(strings.TrimSpace(revoked.CredentialFingerprint))
		revoked.IssuerFingerprint = strings.ToLower(strings.TrimSpace(revoked.IssuerFingerprint))
		originalSerial := strings.ToLower(strings.TrimSpace(revoked.SerialNumber))
		revoked.SerialNumber = strings.TrimLeft(originalSerial, "0")
		if revoked.SerialNumber == "" && originalSerial != "" {
			return RevocationDocument{}, fmt.Errorf("revocation record %d has a zero serial", index)
		}
		if validateIdentifier("revoked node ID", revoked.NodeID) != nil || revoked.RevokedAt.IsZero() ||
			revoked.RevokedAt.After(now.Add(time.Minute)) || strings.TrimSpace(revoked.Reason) == "" ||
			len(revoked.Reason) > 128 {
			return RevocationDocument{}, fmt.Errorf("revocation record %d is invalid", index)
		}
		if revoked.CredentialFingerprint != "" && !validSHA256Fingerprint(revoked.CredentialFingerprint) {
			return RevocationDocument{}, fmt.Errorf("revocation record %d has an invalid fingerprint", index)
		}
		if revoked.SerialNumber != "" &&
			(!validSHA256Fingerprint(revoked.IssuerFingerprint) || !validLowerHex(revoked.SerialNumber, 64)) {
			return RevocationDocument{}, fmt.Errorf("revocation record %d has an invalid issuer or serial", index)
		}
		key := revoked.NodeID + "\x00" + revoked.CredentialFingerprint + "\x00" +
			revoked.IssuerFingerprint + "\x00" + revoked.SerialNumber
		if _, duplicate := seen[key]; duplicate {
			return RevocationDocument{}, fmt.Errorf("revocation record %d is duplicated", index)
		}
		seen[key] = struct{}{}
	}
	return document, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("revocation document contains trailing JSON")
	}
	return nil
}

func containsServerAuth(usages []x509.ExtKeyUsage) bool {
	return slices.Contains(usages, x509.ExtKeyUsageServerAuth)
}

func certificateFingerprint(certificate *x509.Certificate) string {
	digest := sha256.Sum256(certificate.Raw)
	return fmt.Sprintf("sha256:%x", digest)
}

func validSHA256Fingerprint(value string) bool {
	return strings.HasPrefix(value, "sha256:") && len(value) == 71 && validLowerHex(value[7:], 64)
}

func validLowerHex(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func boundedError(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if len(message) > 256 {
		return message[:256]
	}
	return message
}
