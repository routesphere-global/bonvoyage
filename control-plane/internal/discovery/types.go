// Package discovery implements the authenticated Phase 4 snapshot-discovery
// stream over the transport-independent rollout coordinator.
package discovery

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"sync"
	"time"

	bonvoyagev1 "github.com/routesphere-global/bonvoyage/api/gen/go/bonvoyage/v1"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/rollout"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/rolloutservice"
)

var (
	ErrInvalidOptions    = errors.New("invalid discovery server options")
	ErrUnauthenticated   = errors.New("discovery stream is not authenticated")
	ErrRolloutInProgress = errors.New("selected rollout is still in progress")
	ErrRolloutSuperseded = errors.New("rollout operation was superseded")
	ErrRollbackRequired  = errors.New("an explicit rollback is required")
)

const (
	defaultHelloTimeout         = 5 * time.Second
	defaultHeartbeatTimeout     = 15 * time.Second
	defaultCredentialCheck      = time.Second
	defaultMaxClockSkew         = 30 * time.Second
	defaultMaxObservationAge    = time.Minute
	defaultCommandQueueCapacity = 16
)

// Coordinator is the durable rollout boundary consumed by the stream server.
type Coordinator interface {
	Observe(context.Context, string, rollout.Report) (rolloutservice.Transition, error)
	Reconnect(context.Context, string, rollout.RuntimeState) (rolloutservice.Transition, error)
	Disconnect(string, string) error
}

// ManagedCoordinator is the complete runtime boundary required to replace a
// selected rollout without splitting stream and management authority.
type ManagedCoordinator interface {
	Coordinator
	Start(context.Context, string) (rolloutservice.Transition, error)
	Cancel(context.Context, string, rolloutservice.CancellationInput) (rolloutservice.Transition, error)
	Evaluate(context.Context, string, rollout.PolicyObservation) (rolloutservice.PolicyTransition, error)
	Status() (rollout.Phase, map[string]rollout.NodeSnapshot, error)
	Policy() rollout.Policy
	Sequence() uint64
}

// RolloutMutation distinguishes forward apply from explicit rollback when
// checking whether the current state permits a coordinator replacement.
type RolloutMutation string

const (
	RolloutMutationApply    RolloutMutation = "APPLY"
	RolloutMutationRollback RolloutMutation = "ROLLBACK"
)

// RolloutSelector durably advances the selected sequence while the discovery
// transition lock is held. The candidate must already have a durable START
// event, but its commands must not have been published independently.
type RolloutSelector func(context.Context, uint64, uint64) error

// RolloutSelection is the server-authoritative selected rollout projection.
type RolloutSelection struct {
	Sequence uint64
	Phase    rollout.Phase
	Nodes    map[string]rollout.NodeSnapshot
	Replayed bool
}

// PolicyEvaluationResult is the server-authoritative outcome of one policy
// reconciliation attempt. Changed is false when no deadline or health gate is
// ready to transition.
type PolicyEvaluationResult struct {
	Sequence uint64
	Phase    rollout.Phase
	Changed  bool
	Replayed bool
	Decision rollout.PolicyDecision
	Reason   string
}

// AuthenticatedNode is the certificate-bound peer identity.
type AuthenticatedNode struct {
	NodeID                 string
	CredentialFingerprint  string
	CredentialSerial       string
	IssuerFingerprint      string
	TrustAnchorFingerprint string
	CredentialNotBefore    time.Time
	CredentialNotAfter     time.Time
}

// Authenticator extracts an identity from the gRPC transport context.
type Authenticator interface {
	Authenticate(context.Context) (AuthenticatedNode, error)
}

// CredentialValidator reauthorizes an established stream against current
// trust and revocation state. Validation must not relax X.509 time checks.
type CredentialValidator interface {
	ValidateCredential(AuthenticatedNode, time.Time) error
}

// CertificateVerifier validates a presented client chain against the current
// trust generation. The returned chain starts with the peer leaf and ends at
// the accepted trust anchor.
type CertificateVerifier interface {
	VerifyClientCertificate([]*x509.Certificate, time.Time) ([]*x509.Certificate, error)
}

// Options bounds stream ownership, liveness, and command buffering.
type Options struct {
	Authenticator           Authenticator
	RequiredSchemaVersion   uint32
	RequiredCapabilities    map[bonvoyagev1.NodeCapabilityType]uint32
	HelloTimeout            time.Duration
	HeartbeatTimeout        time.Duration
	CredentialCheckInterval time.Duration
	MaxClockSkew            time.Duration
	MaxObservationAge       time.Duration
	CommandQueueCapacity    int
	Clock                   func() time.Time
	Random                  io.Reader
}

// DefaultOptions requires the complete Phase 4 v1 node contract.
func DefaultOptions(authenticator Authenticator) Options {
	return Options{
		Authenticator:         authenticator,
		RequiredSchemaVersion: 1,
		RequiredCapabilities: map[bonvoyagev1.NodeCapabilityType]uint32{
			bonvoyagev1.NodeCapabilityType_NODE_CAPABILITY_TYPE_TWO_PHASE_ROLLOUT:       1,
			bonvoyagev1.NodeCapabilityType_NODE_CAPABILITY_TYPE_EXACT_ARTIFACT_ROLLBACK: 1,
			bonvoyagev1.NodeCapabilityType_NODE_CAPABILITY_TYPE_HEARTBEAT_STATE_REPORT:  1,
		},
		HelloTimeout:            defaultHelloTimeout,
		HeartbeatTimeout:        defaultHeartbeatTimeout,
		CredentialCheckInterval: defaultCredentialCheck,
		MaxClockSkew:            defaultMaxClockSkew,
		MaxObservationAge:       defaultMaxObservationAge,
		CommandQueueCapacity:    defaultCommandQueueCapacity,
		Clock:                   time.Now,
		Random:                  rand.Reader,
	}
}

// ConnectionSnapshot is the bounded operator projection of one current owner.
type ConnectionSnapshot struct {
	NodeID                 string
	ProcessInstance        string
	CredentialFingerprint  string
	CredentialSerial       string
	IssuerFingerprint      string
	TrustAnchorFingerprint string
	CredentialNotAfter     time.Time
	ConnectedAt            time.Time
	LastSeen               time.Time
	LastRolloutSequence    uint64
	ActiveSnapshotID       string
	PreparedSequence       uint64
	PendingCommands        int
	Reconciled             bool
}

// dispatchResult makes unavailable and backpressured delivery explicit.
type dispatchResult struct {
	Enqueued    []string
	Unavailable []string
	Overflowed  []string
}

// Server owns authenticated node streams for one restartable rollout.
type Server struct {
	bonvoyagev1.UnimplementedSnapshotDiscoveryServiceServer

	coordinator             Coordinator
	authenticator           Authenticator
	credentialValidator     CredentialValidator
	requiredSchema          uint32
	requiredCapabilities    map[bonvoyagev1.NodeCapabilityType]uint32
	helloTimeout            time.Duration
	heartbeatTimeout        time.Duration
	credentialCheckInterval time.Duration
	maxClockSkew            time.Duration
	maxObservationAge       time.Duration
	queueCapacity           int
	clock                   func() time.Time
	random                  io.Reader

	// transitionMu keeps durable state changes and their command publication
	// ordered across streams. mu protects only ephemeral owner state.
	transitionMu sync.Mutex
	// rollbackQuiescedSequence records the rollout whose streams were revoked
	// for authoritative rollback reconciliation. It is protected by
	// transitionMu and prevents a policy tick from continuously reconnecting
	// otherwise healthy nodes.
	rollbackQuiescedSequence uint64
	mu                       sync.Mutex
	nextToken                uint64
	owners                   map[string]*streamOwner
}

type streamOwner struct {
	deliveryMu             sync.Mutex
	token                  uint64
	nodeID                 string
	processInstance        string
	credentialFingerprint  string
	credentialSerial       string
	issuerFingerprint      string
	trustAnchorFingerprint string
	credentialNotBefore    time.Time
	credentialNotAfter     time.Time
	connectedAt            time.Time
	lastSeen               time.Time
	lastRolloutSequence    uint64
	activeSnapshotID       string
	preparedSequence       uint64
	ready                  bool
	queue                  chan *bonvoyagev1.StreamSnapshotsResponse
	ctx                    context.Context
	cancel                 context.CancelCauseFunc
}
