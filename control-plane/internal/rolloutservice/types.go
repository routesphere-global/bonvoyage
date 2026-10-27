// Package rolloutservice binds the pure rollout state machine to a durable,
// replay-verifiable operation journal.
package rolloutservice

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/rollout"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
)

var (
	ErrDurabilityUncertain = errors.New("rollout journal durability is uncertain")
	ErrJournalAdvanced     = errors.New("rollout journal advanced by another writer")
	ErrReplayMismatch      = errors.New("rollout journal replay mismatch")
	ErrServicePoisoned     = errors.New("rollout service is fail-stopped")
)

const (
	eventKindStart     = "START"
	eventKindReport    = "REPORT"
	eventKindReconnect = "RECONNECT"
	eventKindCancel    = "CANCEL"
	eventKindEvaluate  = "POLICY_EVALUATE"
)

// Repository is the minimum persistence contract required by one rollout
// service. It intentionally excludes desired-state mutation APIs.
type Repository interface {
	GetRollout(context.Context, uint64) (storage.RolloutRecord, error)
	GetSnapshotArtifact(context.Context, storage.Digest) (storage.SnapshotArtifact, error)
	AppendRolloutEvent(context.Context, storage.RolloutEventInput) (storage.RolloutEvent, error)
	ListRolloutEvents(context.Context, uint64) ([]storage.RolloutEvent, error)
}

// Transition is the command result for one accepted operation. Replayed is
// true when EventID already names the same immutable input.
type Transition struct {
	Commands []rollout.Command
	Replayed bool
}

// CancellationInput is the authenticated operator attribution durably bound
// to an explicit cancellation event. Automatic policy and node-report
// cancellations retain their existing causal journal representations.
type CancellationInput struct {
	Reason        string
	Actor         string
	SourceChannel storage.SourceChannel
}

// CancellationAttribution describes whether a cancellation journal record
// contains authenticated attribution or predates that journal capability.
type CancellationAttribution string

const (
	CancellationAttributionRecorded          CancellationAttribution = "RECORDED"
	CancellationAttributionLegacyUnavailable CancellationAttribution = "LEGACY_UNAVAILABLE"
)

// PolicyTransition is one state-changing safe-rollout decision. Pending
// evaluations return rollout.ErrPolicyPending and are not journaled.
type PolicyTransition struct {
	Transition
	Result rollout.PolicyResult
}

// Diagnostic is a bounded, immutable projection of one accepted journal
// event. It deliberately excludes artifact bytes and raw journal payloads.
type Diagnostic struct {
	Index        uint64
	EventID      string
	Kind         string
	Digest       storage.Digest
	Phase        rollout.Phase
	CreatedAt    time.Time
	Error        *DiagnosticError
	Report       *ReportDiagnostic
	Policy       *PolicyDiagnostic
	Cancellation *CancellationDiagnostic
}

// CancellationDiagnostic exposes bounded explicit-cancellation evidence.
// Actor and SourceChannel are intentionally empty for legacy version-1
// records because historical attribution cannot be reconstructed truthfully.
type CancellationDiagnostic struct {
	Reason            string
	Actor             string
	SourceChannel     storage.SourceChannel
	AttributionStatus CancellationAttribution
}

// DiagnosticError preserves a stable transition code and its bounded
// operator-facing explanation.
type DiagnosticError struct {
	Code    string
	Message string
}

// ReportDiagnostic exposes the structured ACK/NACK facts retained in the
// operation journal.
type ReportDiagnostic struct {
	NodeID          string
	ProcessInstance string
	Sequence        uint64
	Operation       rollout.Operation
	Result          rollout.Result
	ShardCount      uint32
	CompletedShards uint32
	Issues          []rollout.Issue
}

// PolicyDiagnostic exposes the exact bounded health sample that caused a
// promotion, cancellation, or rollback-required decision.
type PolicyDiagnostic struct {
	ObservedAt time.Time
	Decision   rollout.PolicyDecision
	Reason     string
	Nodes      []rollout.NodeHealth
}

// Service serializes one rollout and publishes commands only after its event
// is durably appended. A persistence ambiguity permanently fail-stops this
// instance; reopening from the journal is the only recovery path.
type Service struct {
	mu         sync.Mutex
	repository Repository
	sequence   uint64
	machine    *rollout.Coordinator
	events     map[string]journalEntry
	lastIndex  uint64
	poisoned   error
}

type journalEntry struct {
	index             uint64
	record            journalRecord
	commands          []rollout.Command
	transitionError   error
	issuedThisProcess bool
}
