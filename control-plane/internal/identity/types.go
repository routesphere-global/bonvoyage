package identity

import (
	"context"
	"errors"
	"io"
	"time"
)

const (
	// DefaultEnrollmentTTL is used when a token request omits a lifetime.
	DefaultEnrollmentTTL = 10 * time.Minute
	// MaximumEnrollmentTTL is the hard upper bound for bootstrap credentials.
	MaximumEnrollmentTTL = time.Hour
	// DefaultLeafLifetime is used when an issuance request omits a lifetime.
	DefaultLeafLifetime = 24 * time.Hour
	// MaximumLeafLifetime limits credentials even if an operator asks for more.
	MaximumLeafLifetime = 30 * 24 * time.Hour
)

// NodeLifecycleState is the durable operator lifecycle for one stable node
// identity. Runtime connection and rollout state are projected separately.
type NodeLifecycleState string

const (
	NodeLifecycleEnrolling NodeLifecycleState = "ENROLLING"
	NodeLifecycleReady     NodeLifecycleState = "READY"
	NodeLifecycleDraining  NodeLifecycleState = "DRAINING"
	NodeLifecycleRetired   NodeLifecycleState = "RETIRED"
	NodeLifecycleRevoked   NodeLifecycleState = "REVOKED"
)

// NodeEventKind names one immutable transition retained in node history.
type NodeEventKind string

const (
	NodeEventEnrollmentCreated  NodeEventKind = "ENROLLMENT_CREATED"
	NodeEventEnrollmentReissued NodeEventKind = "ENROLLMENT_REISSUED"
	NodeEventEnrolled           NodeEventKind = "ENROLLED"
	NodeEventImported           NodeEventKind = "IMPORTED"
	NodeEventMetadataUpdated    NodeEventKind = "METADATA_UPDATED"
	NodeEventDrainRequested     NodeEventKind = "DRAIN_REQUESTED"
	NodeEventRetired            NodeEventKind = "RETIRED"
	NodeEventRevoked            NodeEventKind = "REVOKED"
	NodeEventReplacementCreated NodeEventKind = "REPLACEMENT_CREATED"
)

var (
	ErrClosed              = errors.New("identity repository is closed")
	ErrConflict            = errors.New("identity repository conflict")
	ErrCorrupt             = errors.New("identity repository is corrupt")
	ErrEnrollmentRejected  = errors.New("enrollment credential rejected")
	ErrInvalid             = errors.New("invalid identity input")
	ErrLocked              = errors.New("identity repository is already open")
	ErrNotFound            = errors.New("identity record not found")
	ErrRevoked             = errors.New("identity is revoked")
	ErrUnsupportedPlatform = errors.New("identity repository locking is unsupported on this platform")
)

// FileRepositoryOptions provides deterministic dependencies for tests.
type FileRepositoryOptions struct {
	Clock            func() time.Time
	Random           io.Reader
	MaxEnrollmentTTL time.Duration
}

// AuthorityOptions identifies operator-managed CA material and issuance
// policy. PrivateKeyPath must refer to an owner-only regular file.
type AuthorityOptions struct {
	CertificatePath     string
	PrivateKeyPath      string
	TrustBundlePath     string
	TrustDomain         string
	NodePathPrefix      string
	Clock               func() time.Time
	Random              io.Reader
	DefaultLeafLifetime time.Duration
	MaximumLeafLifetime time.Duration
	Backdate            time.Duration
}

// EnrollmentTokenInput requests one short-lived, node-bound bootstrap token.
type EnrollmentTokenInput struct {
	NodeID   string
	Audience string
	TTL      time.Duration
}

// NodeMetadata is operator-owned presentation and placement intent. NodeID is
// deliberately absent because runtime identity is immutable.
type NodeMetadata struct {
	DisplayName string            `json:"display_name"`
	Group       string            `json:"group"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// NodeRecord is the durable lifecycle record for one stable node identity.
// Retirement and revocation never remove this record or its event history.
type NodeRecord struct {
	NodeID           string             `json:"node_id"`
	Metadata         NodeMetadata       `json:"metadata"`
	Lifecycle        NodeLifecycleState `json:"lifecycle"`
	Version          uint64             `json:"version"`
	ReplacementFor   string             `json:"replacement_for,omitempty"`
	ReplacedBy       string             `json:"replaced_by,omitempty"`
	CreatedAt        time.Time          `json:"created_at"`
	UpdatedAt        time.Time          `json:"updated_at"`
	DrainRequestedAt *time.Time         `json:"drain_requested_at,omitempty"`
	RetiredAt        *time.Time         `json:"retired_at,omitempty"`
	RevokedAt        *time.Time         `json:"revoked_at,omitempty"`
}

// NodeLifecycleEvent is an append-only, secret-free audit event. EventID is
// caller supplied for mutations and repository generated for node enrollment.
type NodeLifecycleEvent struct {
	Index         uint64        `json:"index"`
	EventID       string        `json:"event_id"`
	RequestSHA256 string        `json:"request_sha256,omitempty"`
	NodeID        string        `json:"node_id"`
	Kind          NodeEventKind `json:"kind"`
	Actor         string        `json:"actor"`
	Reason        string        `json:"reason"`
	NodeVersion   uint64        `json:"node_version"`
	RelatedNodeID string        `json:"related_node_id,omitempty"`
	CreatedAt     time.Time     `json:"created_at"`
}

// NodeEnrollmentInput atomically creates a node record and its latest
// short-lived, one-time enrollment credential.
type NodeEnrollmentInput struct {
	RequestID       string
	Actor           string
	Reason          string
	NodeID          string
	ExpectedVersion uint64
	Metadata        NodeMetadata
	Audience        string
	TTL             time.Duration
	ReplacementFor  string
}

// NodeEnrollmentPlan returns a bearer token only for the fresh mutation. An
// idempotent replay returns the durable node but never replays secret bytes.
type NodeEnrollmentPlan struct {
	Node     NodeRecord
	Token    EnrollmentToken
	Replayed bool
}

// NodeMutationPlan distinguishes a committed mutation from an idempotent
// replay while returning the current durable node projection in both cases.
type NodeMutationPlan struct {
	Node     NodeRecord
	Replayed bool
}

// ManagedNodeRevocationPlan preserves replay truth across the repository and
// the separately published transport-revocation snapshot.
type ManagedNodeRevocationPlan struct {
	Revocation NodeRevocation
	Node       NodeRecord
	Replayed   bool
}

// NodeMetadataUpdateInput applies an optimistic, auditable metadata change.
type NodeMetadataUpdateInput struct {
	RequestID       string
	Actor           string
	Reason          string
	NodeID          string
	ExpectedVersion uint64
	Metadata        NodeMetadata
}

// NodeTransitionInput applies one optimistic lifecycle transition.
type NodeTransitionInput struct {
	RequestID       string
	Actor           string
	Reason          string
	NodeID          string
	ExpectedVersion uint64
}

// ManagedNodeRevocationInput applies a whole-node revocation with durable
// operator attribution in addition to the certificate revocation record.
type ManagedNodeRevocationInput struct {
	RequestID       string
	Actor           string
	Reason          string
	NodeID          string
	ExpectedVersion uint64
}

// NodeIdentitySummary is the secret-free node and credential projection used
// by the management API.
type NodeIdentitySummary struct {
	Node                 NodeRecord `json:"node"`
	Enrolled             bool       `json:"enrolled"`
	CredentialGeneration string     `json:"credential_generation,omitempty"`
	CertificateNotAfter  time.Time  `json:"certificate_not_after,omitempty"`
	RenewAfter           time.Time  `json:"renew_after,omitempty"`
	Revoked              bool       `json:"revoked"`
}

// EnrollmentToken contains the only copy of the bearer credential returned by
// the repository. Value is never written to repository state.
type EnrollmentToken struct {
	ID        string
	Value     string
	NodeID    string
	Audience  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// IssueRequest asks the authority to issue one node client certificate from a
// PKCS#10 request. CSRDER must contain DER, not PEM.
type IssueRequest struct {
	NodeID   string
	CSRDER   []byte
	Lifetime time.Duration
}

// EnrollmentRequest atomically redeems one bootstrap token and records the
// newly issued credential as the node's current generation.
type EnrollmentRequest struct {
	Token    string
	NodeID   string
	Audience string
	CSRDER   []byte
	Lifetime time.Duration
}

// RotationRequest issues and durably activates a replacement generation for
// an already enrolled, non-revoked node. Caller authentication is enforced by
// the service layer that invokes this internal package.
type RotationRequest struct {
	NodeID   string
	CSRDER   []byte
	Lifetime time.Duration
}

// CredentialBundle is an immutable-by-convention public certificate artifact.
// It contains no private key material.
type CredentialBundle struct {
	GenerationID      string    `json:"generation_id"`
	ChainPEM          string    `json:"chain_pem"`
	TrustBundlePEM    string    `json:"trust_bundle_pem"`
	LeafFingerprint   string    `json:"leaf_fingerprint"`
	IssuerFingerprint string    `json:"issuer_fingerprint"`
	Serial            string    `json:"serial"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	RenewAfter        time.Time `json:"renew_after"`
}

// CredentialRecord binds an issued generation to one validated node.
type CredentialRecord struct {
	NodeID   string           `json:"node_id"`
	Bundle   CredentialBundle `json:"bundle"`
	IssuedAt time.Time        `json:"issued_at"`
}

// CredentialRevocationInput revokes one recorded credential generation.
type CredentialRevocationInput struct {
	NodeID       string
	GenerationID string
	Reason       string
}

// CredentialRevocation is addressable by both issuer/serial and leaf digest.
type CredentialRevocation struct {
	NodeID            string    `json:"node_id"`
	GenerationID      string    `json:"generation_id"`
	IssuerFingerprint string    `json:"issuer_fingerprint"`
	Serial            string    `json:"serial"`
	LeafFingerprint   string    `json:"leaf_fingerprint"`
	Reason            string    `json:"reason"`
	RevokedAt         time.Time `json:"revoked_at"`
}

// NodeRevocationInput revokes every credential belonging to one node.
type NodeRevocationInput struct {
	NodeID string
	Reason string
}

// NodeRevocation is the durable whole-node revocation record.
type NodeRevocation struct {
	NodeID    string    `json:"node_id"`
	Reason    string    `json:"reason"`
	RevokedAt time.Time `json:"revoked_at"`
}

// RevocationStatusQuery supplies the authenticated certificate identity to a
// dynamic verifier. All certificate fields must be canonical and complete.
type RevocationStatusQuery struct {
	NodeID            string
	IssuerFingerprint string
	Serial            string
	LeafFingerprint   string
}

// RevocationStatus reports credential- and node-level revocation in one read.
type RevocationStatus struct {
	Revoked              bool
	CredentialRevocation *CredentialRevocation
	NodeRevocation       *NodeRevocation
}

// AuthorityLoader acquires one fresh issuing authority after an enrollment
// token has been authorized while its one-use repository transaction is held.
type AuthorityLoader func() (*Authority, error)

// Repository is the persistence contract used by standalone identity services
// and future enterprise-backed implementations.
type Repository interface {
	CreateEnrollmentToken(context.Context, EnrollmentTokenInput) (EnrollmentToken, error)
	CreateNodeEnrollment(context.Context, NodeEnrollmentInput) (NodeEnrollmentPlan, error)
	ReissueNodeEnrollment(context.Context, NodeEnrollmentInput) (NodeEnrollmentPlan, error)
	CreateNodeReplacement(context.Context, NodeEnrollmentInput) (NodeEnrollmentPlan, error)
	UpdateNodeMetadata(context.Context, NodeMetadataUpdateInput) (NodeMutationPlan, error)
	RequestNodeDrain(context.Context, NodeTransitionInput) (NodeMutationPlan, error)
	RetireNode(context.Context, NodeTransitionInput) (NodeMutationPlan, error)
	RevokeManagedNode(context.Context, ManagedNodeRevocationInput) (ManagedNodeRevocationPlan, error)
	GetNode(context.Context, string) (NodeIdentitySummary, error)
	ListNodes(context.Context) ([]NodeIdentitySummary, error)
	ListNodeEvents(context.Context, string) ([]NodeLifecycleEvent, error)
	Enroll(context.Context, AuthorityLoader, EnrollmentRequest) (CredentialRecord, error)
	RotateCredential(context.Context, *Authority, RotationRequest) (CredentialRecord, error)
	CurrentCredential(context.Context, string) (CredentialRecord, error)
	CredentialByGeneration(context.Context, string, string) (CredentialRecord, error)
	RevokeCredential(context.Context, CredentialRevocationInput) (CredentialRevocation, error)
	RevokeNode(context.Context, NodeRevocationInput) (NodeRevocation, error)
	RevocationByIssuerSerial(context.Context, string, string) (CredentialRevocation, error)
	RevocationByLeafFingerprint(context.Context, string) (CredentialRevocation, error)
	NodeRevocation(context.Context, string) (NodeRevocation, error)
	RevocationStatus(context.Context, RevocationStatusQuery) (RevocationStatus, error)
	Close() error
}
