package nodecredentials

import (
	"errors"
	"time"
)

const (
	// MaximumServerClockSkew is the largest caller-selected skew allowance.
	// Larger values would weaken certificate-time validation rather than merely
	// account for ordinary clock error.
	MaximumServerClockSkew = 5 * time.Minute
	manifestSchemaVersion  = 1
)

var (
	// ErrInvalid identifies caller input or credential responses that fail the
	// node credential contract.
	ErrInvalid = errors.New("invalid node credential input")
	// ErrUnsafePath identifies roots, files, or manifest paths that could escape
	// the private credential store or traverse a symbolic link.
	ErrUnsafePath = errors.New("unsafe node credential path")
	// ErrCorrupt identifies durable state that no longer agrees with its strict
	// manifest or cryptographic material.
	ErrCorrupt = errors.New("node credential state is corrupt")
	// ErrConflict identifies an attempt to reuse an immutable generation name
	// for different credential material.
	ErrConflict = errors.New("node credential generation conflicts with durable state")
	// ErrNotFound identifies a private root without a published current
	// generation.
	ErrNotFound = errors.New("current node credential generation not found")
)

// CertificateRequest contains one locally generated ECDSA P-256 key and its
// signed PKCS#10 request. Accessors return copies so callers cannot mutate the
// request after generation.
type CertificateRequest struct {
	privateKeyPEM []byte
	csrDER        []byte
}

// PrivateKeyPEM returns the PKCS#8 private key used to sign the request.
func (request *CertificateRequest) PrivateKeyPEM() []byte {
	if request == nil {
		return nil
	}
	return append([]byte(nil), request.privateKeyPEM...)
}

// CSRDER returns the signed PKCS#10 request in DER form.
func (request *CertificateRequest) CSRDER() []byte {
	if request == nil {
		return nil
	}
	return append([]byte(nil), request.csrDER...)
}

// ValidationOptions supplies the local identity and trust policy against
// which one server response is checked.
type ValidationOptions struct {
	ExpectedNodeID     string
	TrustDomain        string
	NodePathPrefix     string
	PrivateKeyPEM      []byte
	Clock              func() time.Time
	MaxServerClockSkew time.Duration
}

// Manifest is the strict, secret-free description of one immutable
// credential generation. All paths are clean paths relative to Root.
type Manifest struct {
	SchemaVersion          uint32    `json:"schema_version"`
	CredentialGeneration   string    `json:"credential_generation"`
	NodeID                 string    `json:"node_id"`
	TrustDomain            string    `json:"trust_domain"`
	NodePathPrefix         string    `json:"node_path_prefix"`
	SPIFFEID               string    `json:"spiffe_id"`
	CertificateSHA256      string    `json:"certificate_sha256"`
	IssuerSHA256           string    `json:"issuer_sha256"`
	CertificateChainSHA256 string    `json:"certificate_chain_sha256"`
	TrustBundleSHA256      string    `json:"trust_bundle_sha256"`
	SerialNumber           string    `json:"serial_number"`
	NotBefore              time.Time `json:"not_before"`
	NotAfter               time.Time `json:"not_after"`
	RenewAfter             time.Time `json:"renew_after"`
	ServerTime             time.Time `json:"server_time"`
	CertificatePath        string    `json:"certificate_path"`
	TrustBundlePath        string    `json:"trust_bundle_path"`
	PrivateKeyPath         string    `json:"private_key_path"`
}

// ValidatedGeneration is an immutable candidate. Its key and certificate
// bytes remain private to this package and can only be durably published.
type ValidatedGeneration struct {
	manifest       Manifest
	certificatePEM []byte
	trustBundlePEM []byte
	privateKeyPEM  []byte
}

// Manifest returns a copy of the generation's secret-free metadata.
func (generation *ValidatedGeneration) Manifest() Manifest {
	if generation == nil {
		return Manifest{}
	}
	return generation.manifest
}

// CredentialStatus is a bounded operator projection of the current durable
// generation. It never contains certificate bodies or private key material.
type CredentialStatus struct {
	CredentialGeneration   string
	NodeID                 string
	SPIFFEID               string
	CertificateSHA256      string
	IssuerSHA256           string
	CertificateChainSHA256 string
	TrustBundleSHA256      string
	SerialNumber           string
	NotBefore              time.Time
	NotAfter               time.Time
	RenewAfter             time.Time
	ServerTime             time.Time
	ExpiresIn              time.Duration
	NotYetValid            bool
	RenewalDue             bool
	Expired                bool
}
