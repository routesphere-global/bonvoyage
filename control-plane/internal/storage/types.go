// Package storage defines durable standalone control-plane lineage storage.
package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrClosed              = errors.New("control-plane repository is closed")
	ErrConflict            = errors.New("control-plane repository conflict")
	ErrCorrupt             = errors.New("control-plane repository is corrupt")
	ErrInvalid             = errors.New("invalid control-plane repository input")
	ErrLocked              = errors.New("control-plane repository is already open")
	ErrNotFound            = errors.New("control-plane repository record not found")
	ErrUnsupportedPlatform = errors.New("control-plane repository locking is unsupported on this platform")
)

// Digest is the authoritative SHA-256 identity of immutable bytes.
type Digest [sha256.Size]byte

// Sum returns the SHA-256 identity of data.
func Sum(data []byte) Digest {
	return sha256.Sum256(data)
}

// ParseDigest parses one canonical or uppercase hexadecimal SHA-256 digest.
func ParseDigest(value string) (Digest, error) {
	var digest Digest
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return digest, fmt.Errorf("parse SHA-256 digest %q: %w", value, ErrInvalid)
	}
	copy(digest[:], decoded)
	return digest, nil
}

func (d Digest) String() string {
	return hex.EncodeToString(d[:])
}

// IsZero reports whether a digest is absent.
func (d Digest) IsZero() bool {
	return d == Digest{}
}

// SourceChannel identifies the public control-plane input surface.
type SourceChannel string

const (
	SourceAPI     SourceChannel = "api"
	SourceCLI     SourceChannel = "cli"
	SourceConsole SourceChannel = "console"
	SourceFile    SourceChannel = "file"
	SourceGitOps  SourceChannel = "gitops"
	SourceSystem  SourceChannel = "system"
)

// RolloutKind distinguishes a forward desired-state activation from an exact
// retained-artifact rollback. Both use the same prepare/activate protocol.
type RolloutKind string

const (
	RolloutKindApply    RolloutKind = "APPLY"
	RolloutKindRollback RolloutKind = "ROLLBACK"
)

// RolloutStrategy selects the activation shape for one immutable rollout.
// Legacy records have Policy.Enabled=false and retain the original all-at-once
// behavior without synthetic deadlines.
type RolloutStrategy string

const (
	RolloutStrategyImmediate RolloutStrategy = "IMMEDIATE"
	RolloutStrategyCanary    RolloutStrategy = "CANARY"
)

// RolloutPolicy is the durable, replayable safety policy attached to one
// rollout. Durations are bounded during allocation and never inferred from
// process-local defaults after the record is written.
type RolloutPolicy struct {
	Enabled                     bool
	Strategy                    RolloutStrategy
	CanaryNodeIDs               []string
	MinimumHealthyCanaryPercent uint32
	CanaryObservationWindow     time.Duration
	PrepareTimeout              time.Duration
	ActivationTimeout           time.Duration
	HeartbeatStaleAfter         time.Duration
	AutomaticRollback           bool
}

// NodeExpectedArtifact records the exact active bytes expected on one node.
// It is used when a rollback begins from an honestly mixed fleet after only a
// canary subset activated the failed artifact.
type NodeExpectedArtifact struct {
	NodeID         string
	ArtifactDigest Digest
}

// DesiredRevisionInput creates one immutable, strictly valid desired-state
// revision. RequestID makes a retried caller operation idempotent.
type DesiredRevisionInput struct {
	RequestID      string
	Document       []byte
	SourceChannel  SourceChannel
	SourceRevision string
	Actor          string
}

// DesiredRevision is one immutable desired-state lineage point.
type DesiredRevision struct {
	ID             string
	RequestID      string
	Digest         Digest
	Document       []byte
	SourceChannel  SourceChannel
	SourceRevision string
	Actor          string
	CreatedAt      time.Time
}

// SnapshotArtifactInput retains exact deterministic protobuf bytes compiled
// from one stored desired revision.
type SnapshotArtifactInput struct {
	DesiredRevisionID string
	CompilerVersion   string
	Bytes             []byte
}

// SnapshotArtifact is immutable and content-addressed by Digest.
type SnapshotArtifact struct {
	SnapshotID              string
	Digest                  Digest
	Bytes                   []byte
	SchemaVersion           uint32
	MinimumDataplaneVersion string
	Compilations            []CompilationLineage
	CreatedAt               time.Time
}

// CompilationLineage records one desired revision/compiler pair that produced
// an artifact. Multiple semantically equivalent revisions may share bytes.
type CompilationLineage struct {
	DesiredRevisionID string
	CompilerVersion   string
	CreatedAt         time.Time
}

// RolloutInput allocates a monotonic sequence for one exact artifact and
// target set. RequestID prevents retries from allocating another sequence.
type RolloutInput struct {
	RequestID               string
	RequestDigest           Digest
	ArtifactDigest          Digest
	PreviousArtifactDigest  Digest
	BaselineRolloutSequence uint64
	DesiredRevisionID       string
	CompilerVersion         string
	TargetNodeIDs           []string
	ExpectedActiveByNode    []NodeExpectedArtifact
	Policy                  RolloutPolicy
	SourceChannel           SourceChannel
	Actor                   string
	Reason                  string
	Kind                    RolloutKind
	RollbackTargetSequence  uint64
}

// RolloutRecord is the immutable lineage header for one rollout attempt.
type RolloutRecord struct {
	ID                      string
	RequestID               string
	RequestDigest           Digest
	Sequence                uint64
	ArtifactDigest          Digest
	PreviousArtifactDigest  Digest
	BaselineRolloutSequence uint64
	DesiredRevisionID       string
	CompilerVersion         string
	TargetNodeIDs           []string
	ExpectedActiveByNode    []NodeExpectedArtifact
	Policy                  RolloutPolicy
	SourceChannel           SourceChannel
	Actor                   string
	Reason                  string
	Kind                    RolloutKind
	RollbackTargetSequence  uint64
	CreatedAt               time.Time
}

// RolloutEventInput appends one canonical accepted transition to a rollout's
// immutable operation journal. EventID makes retried persistence idempotent.
type RolloutEventInput struct {
	RolloutSequence       uint64
	ExpectedPreviousIndex uint64
	EventID               string
	Kind                  string
	Payload               []byte
}

// RolloutEvent is one immutable, ordered operation-journal entry.
type RolloutEvent struct {
	RolloutSequence uint64
	Index           uint64
	EventID         string
	Kind            string
	Digest          Digest
	Payload         []byte
	CreatedAt       time.Time
}

// Lineage joins one artifact to its desired-state source and rollout uses.
type Lineage struct {
	DesiredRevisions []DesiredRevision
	Artifact         SnapshotArtifact
	Rollouts         []RolloutRecord
}

// Repository is the persistence boundary shared by standalone and future
// Enterprise implementations.
type Repository interface {
	CreateDesiredRevision(context.Context, DesiredRevisionInput) (DesiredRevision, error)
	GetDesiredRevision(context.Context, string) (DesiredRevision, error)
	CreateSnapshotArtifact(context.Context, SnapshotArtifactInput) (SnapshotArtifact, error)
	GetSnapshotArtifact(context.Context, Digest) (SnapshotArtifact, error)
	AllocateRollout(context.Context, RolloutInput) (RolloutRecord, error)
	GetRollout(context.Context, uint64) (RolloutRecord, error)
	GetRolloutByRequestID(context.Context, string) (RolloutRecord, error)
	InitializeSelectedRollout(context.Context, uint64) (RolloutRecord, error)
	GetSelectedRollout(context.Context) (RolloutRecord, error)
	SelectRollout(context.Context, uint64, uint64) (RolloutRecord, error)
	AppendRolloutEvent(context.Context, RolloutEventInput) (RolloutEvent, error)
	ListRolloutEvents(context.Context, uint64) ([]RolloutEvent, error)
	GetLineage(context.Context, Digest) (Lineage, error)
	LastRolloutSequence(context.Context) (uint64, error)
	Close() error
}

func validSourceChannel(channel SourceChannel) bool {
	switch channel {
	case SourceAPI, SourceCLI, SourceConsole, SourceFile, SourceGitOps, SourceSystem:
		return true
	default:
		return false
	}
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

func validateIdentifier(name, value string) error {
	if len(value) == 0 || len(value) > 128 {
		return fmt.Errorf("%s must contain 1-128 bytes: %w", name, ErrInvalid)
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
