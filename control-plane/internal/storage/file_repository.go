package storage

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/snapshot"
)

const (
	repositorySchemaVersion uint32 = 1
	maxDesiredBytes                = int(snapshot.MaxConfigBytes)
	maxSnapshotBytes               = 64 << 20
	maxRolloutEventBytes           = 256 << 10
	maxStateBytes                  = 16 << 20
	maxTargetNodes                 = 10_000

	stateFileName = "state.json"
	lockFileName  = ".lock"
)

// FileOptions provides deterministic dependencies for tests. Production code
// normally leaves every field unset.
type FileOptions struct {
	Clock  func() time.Time
	Random io.Reader
}

// FileRepository stores immutable blobs beside one checksummed atomic index.
// One process owns a repository directory at a time.
type FileRepository struct {
	mu     sync.Mutex
	root   string
	clock  func() time.Time
	random io.Reader
	lock   *repositoryLock
	state  persistedState
	closed bool
}

type persistedState struct {
	SchemaVersion           uint32             `json:"schema_version"`
	Generation              uint64             `json:"generation"`
	LastRolloutSequence     uint64             `json:"last_rollout_sequence"`
	SelectedRolloutSequence uint64             `json:"selected_rollout_sequence,omitempty"`
	DesiredRevisions        []desiredMetadata  `json:"desired_revisions"`
	SnapshotArtifacts       []artifactMetadata `json:"snapshot_artifacts"`
	Rollouts                []rolloutMetadata  `json:"rollouts"`
	RolloutEvents           []eventMetadata    `json:"rollout_events,omitempty"`
}

type stateEnvelope struct {
	IntegritySHA256 string         `json:"integrity_sha256"`
	State           persistedState `json:"state"`
}

type desiredMetadata struct {
	ID             string        `json:"id"`
	RequestID      string        `json:"request_id"`
	Digest         string        `json:"digest"`
	Size           int64         `json:"size"`
	SourceChannel  SourceChannel `json:"source_channel"`
	SourceRevision string        `json:"source_revision,omitempty"`
	Actor          string        `json:"actor"`
	CreatedAt      time.Time     `json:"created_at"`
}

type artifactMetadata struct {
	SnapshotID              string                `json:"snapshot_id"`
	Digest                  string                `json:"digest"`
	Size                    int64                 `json:"size"`
	SchemaVersion           uint32                `json:"schema_version"`
	MinimumDataplaneVersion string                `json:"minimum_dataplane_version"`
	Compilations            []compilationMetadata `json:"compilations"`
	CreatedAt               time.Time             `json:"created_at"`
}

type compilationMetadata struct {
	DesiredRevisionID string    `json:"desired_revision_id"`
	CompilerVersion   string    `json:"compiler_version"`
	CreatedAt         time.Time `json:"created_at"`
}

type rolloutMetadata struct {
	ID                      string                         `json:"id"`
	RequestID               string                         `json:"request_id"`
	RequestDigest           string                         `json:"request_digest,omitempty"`
	Sequence                uint64                         `json:"sequence"`
	ArtifactDigest          string                         `json:"artifact_digest"`
	PreviousArtifactDigest  string                         `json:"previous_artifact_digest,omitempty"`
	BaselineRolloutSequence uint64                         `json:"baseline_rollout_sequence,omitempty"`
	DesiredRevisionID       string                         `json:"desired_revision_id"`
	CompilerVersion         string                         `json:"compiler_version"`
	TargetNodeIDs           []string                       `json:"target_node_ids"`
	ExpectedActiveByNode    []nodeExpectedArtifactMetadata `json:"expected_active_by_node,omitempty"`
	Policy                  *rolloutPolicyMetadata         `json:"policy,omitempty"`
	SourceChannel           SourceChannel                  `json:"source_channel"`
	Actor                   string                         `json:"actor"`
	Reason                  string                         `json:"reason"`
	Kind                    RolloutKind                    `json:"kind,omitempty"`
	RollbackTargetSequence  uint64                         `json:"rollback_target_sequence,omitempty"`
	CreatedAt               time.Time                      `json:"created_at"`
}

type nodeExpectedArtifactMetadata struct {
	NodeID         string `json:"node_id"`
	ArtifactDigest string `json:"artifact_digest"`
}

type rolloutPolicyMetadata struct {
	Strategy                    RolloutStrategy `json:"strategy"`
	CanaryNodeIDs               []string        `json:"canary_node_ids,omitempty"`
	MinimumHealthyCanaryPercent uint32          `json:"minimum_healthy_canary_percent,omitempty"`
	CanaryObservationMillis     int64           `json:"canary_observation_milliseconds,omitempty"`
	PrepareTimeoutMillis        int64           `json:"prepare_timeout_milliseconds"`
	ActivationTimeoutMillis     int64           `json:"activation_timeout_milliseconds"`
	HeartbeatStaleAfterMillis   int64           `json:"heartbeat_stale_after_milliseconds,omitempty"`
	AutomaticRollback           bool            `json:"automatic_rollback"`
}

// OpenFileRepository opens or initializes one private standalone repository.
func OpenFileRepository(root string, options FileOptions) (_ *FileRepository, returnErr error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("repository path is empty: %w", ErrInvalid)
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve repository path: %w", err)
	}
	if err := ensurePrivateDirectoryTree(absoluteRoot); err != nil {
		return nil, err
	}
	lock, err := acquireRepositoryLock(filepath.Join(absoluteRoot, lockFileName))
	if err != nil {
		return nil, err
	}
	defer func() {
		if returnErr != nil {
			_ = lock.release()
		}
	}()

	repository := &FileRepository{
		root:   absoluteRoot,
		clock:  options.Clock,
		random: options.Random,
		lock:   lock,
	}
	if repository.clock == nil {
		repository.clock = time.Now
	}
	if repository.random == nil {
		repository.random = rand.Reader
	}
	for _, directory := range []string{
		filepath.Join(repository.root, "blobs"),
		filepath.Join(repository.root, "blobs", "desired"),
		repository.desiredBlobDirectory(),
		filepath.Join(repository.root, "blobs", "snapshots"),
		repository.snapshotBlobDirectory(),
		filepath.Join(repository.root, "blobs", "events"),
		repository.eventBlobDirectory(),
	} {
		if err := ensurePrivateDirectory(directory); err != nil {
			return nil, err
		}
	}

	state, err := repository.loadState()
	if errors.Is(err, os.ErrNotExist) {
		state = persistedState{SchemaVersion: repositorySchemaVersion, Generation: 1}
		if err := repository.writeState(state); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if err := repository.validateState(state); err != nil {
		return nil, err
	}
	repository.state = state
	return repository, nil
}

func (repository *FileRepository) CreateDesiredRevision(
	ctx context.Context,
	input DesiredRevisionInput,
) (DesiredRevision, error) {
	if err := contextError(ctx); err != nil {
		return DesiredRevision{}, err
	}
	if err := validateDesiredInput(input); err != nil {
		return DesiredRevision{}, err
	}
	document := append([]byte(nil), input.Document...)
	if _, err := snapshot.Compile(bytes.NewReader(document)); err != nil {
		return DesiredRevision{}, fmt.Errorf("desired state is not strictly valid: %w: %v", ErrInvalid, err)
	}
	digest := Sum(document)

	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return DesiredRevision{}, err
	}
	if err := contextError(ctx); err != nil {
		return DesiredRevision{}, err
	}
	for _, metadata := range repository.state.DesiredRevisions {
		if metadata.RequestID != input.RequestID {
			continue
		}
		if metadata.Digest != digest.String() || metadata.SourceChannel != input.SourceChannel ||
			metadata.SourceRevision != input.SourceRevision || metadata.Actor != input.Actor {
			return DesiredRevision{}, fmt.Errorf("desired-state request %q changed: %w", input.RequestID, ErrConflict)
		}
		return repository.materializeDesiredLocked(metadata)
	}

	id, err := repository.newIDLocked("dsr_", func(candidate string) bool {
		_, found := findDesiredByID(repository.state.DesiredRevisions, candidate)
		return found
	})
	if err != nil {
		return DesiredRevision{}, err
	}
	metadata := desiredMetadata{
		ID:             id,
		RequestID:      input.RequestID,
		Digest:         digest.String(),
		Size:           int64(len(document)),
		SourceChannel:  input.SourceChannel,
		SourceRevision: input.SourceRevision,
		Actor:          input.Actor,
		CreatedAt:      repository.now(),
	}
	if err := repository.putBlob(repository.desiredBlobPath(digest), document, maxDesiredBytes); err != nil {
		return DesiredRevision{}, err
	}
	next, err := nextState(repository.state)
	if err != nil {
		return DesiredRevision{}, err
	}
	next.DesiredRevisions = append(next.DesiredRevisions, metadata)
	if err := repository.writeState(next); err != nil {
		return DesiredRevision{}, err
	}
	repository.state = next
	return desiredFromMetadata(metadata, document), nil
}

func (repository *FileRepository) GetDesiredRevision(ctx context.Context, id string) (DesiredRevision, error) {
	if err := contextError(ctx); err != nil {
		return DesiredRevision{}, err
	}
	if err := validateIdentifier("desired revision ID", id); err != nil {
		return DesiredRevision{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return DesiredRevision{}, err
	}
	if err := contextError(ctx); err != nil {
		return DesiredRevision{}, err
	}
	metadata, found := findDesiredByID(repository.state.DesiredRevisions, id)
	if !found {
		return DesiredRevision{}, ErrNotFound
	}
	return repository.materializeDesiredLocked(metadata)
}

func (repository *FileRepository) CreateSnapshotArtifact(
	ctx context.Context,
	input SnapshotArtifactInput,
) (SnapshotArtifact, error) {
	if err := contextError(ctx); err != nil {
		return SnapshotArtifact{}, err
	}
	if err := validateIdentifier("desired revision ID", input.DesiredRevisionID); err != nil {
		return SnapshotArtifact{}, err
	}
	if err := validateText("compiler version", input.CompilerVersion, 128, true); err != nil {
		return SnapshotArtifact{}, err
	}
	if len(input.Bytes) == 0 || len(input.Bytes) > maxSnapshotBytes {
		return SnapshotArtifact{}, fmt.Errorf("snapshot artifact must contain 1-%d bytes: %w", maxSnapshotBytes, ErrInvalid)
	}
	artifactBytes := append([]byte(nil), input.Bytes...)

	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return SnapshotArtifact{}, err
	}
	if err := contextError(ctx); err != nil {
		return SnapshotArtifact{}, err
	}
	desiredMetadata, found := findDesiredByID(repository.state.DesiredRevisions, input.DesiredRevisionID)
	if !found {
		return SnapshotArtifact{}, fmt.Errorf("desired revision %q: %w", input.DesiredRevisionID, ErrNotFound)
	}
	desired, err := repository.materializeDesiredLocked(desiredMetadata)
	if err != nil {
		return SnapshotArtifact{}, err
	}
	compiled, err := snapshot.Compile(bytes.NewReader(desired.Document))
	if err != nil {
		return SnapshotArtifact{}, fmt.Errorf("recompile stored desired revision: %w", err)
	}
	expectedBytes, err := snapshot.MarshalDeterministic(compiled)
	if err != nil {
		return SnapshotArtifact{}, err
	}
	if !bytes.Equal(expectedBytes, artifactBytes) {
		return SnapshotArtifact{}, fmt.Errorf("artifact does not match deterministic desired-state compilation: %w", ErrConflict)
	}
	digest := Sum(artifactBytes)
	for index, metadata := range repository.state.SnapshotArtifacts {
		if metadata.Digest == digest.String() {
			if metadata.SnapshotID != compiled.GetSnapshotId() ||
				metadata.Size != int64(len(artifactBytes)) ||
				metadata.SchemaVersion != compiled.GetSchemaVersion() ||
				metadata.MinimumDataplaneVersion != compiled.GetMinimumDataplaneVersion() {
				return SnapshotArtifact{}, fmt.Errorf("artifact digest has inconsistent metadata: %w", ErrCorrupt)
			}
			stored, err := repository.materializeArtifactLocked(metadata)
			if err != nil {
				return SnapshotArtifact{}, err
			}
			for _, compilation := range metadata.Compilations {
				if compilation.DesiredRevisionID == input.DesiredRevisionID &&
					compilation.CompilerVersion == input.CompilerVersion {
					return stored, nil
				}
			}

			next, err := nextState(repository.state)
			if err != nil {
				return SnapshotArtifact{}, err
			}
			next.SnapshotArtifacts[index].Compilations = append(
				next.SnapshotArtifacts[index].Compilations,
				compilationMetadata{
					DesiredRevisionID: input.DesiredRevisionID,
					CompilerVersion:   input.CompilerVersion,
					CreatedAt:         repository.now(),
				},
			)
			if err := repository.writeState(next); err != nil {
				return SnapshotArtifact{}, err
			}
			repository.state = next
			return artifactFromMetadata(next.SnapshotArtifacts[index], stored.Bytes), nil
		}
		if metadata.SnapshotID == compiled.GetSnapshotId() {
			return SnapshotArtifact{}, fmt.Errorf("snapshot ID %q already identifies different bytes: %w", metadata.SnapshotID, ErrConflict)
		}
	}
	createdAt := repository.now()
	metadata := artifactMetadata{
		SnapshotID:              compiled.GetSnapshotId(),
		Digest:                  digest.String(),
		Size:                    int64(len(artifactBytes)),
		SchemaVersion:           compiled.GetSchemaVersion(),
		MinimumDataplaneVersion: compiled.GetMinimumDataplaneVersion(),
		Compilations: []compilationMetadata{{
			DesiredRevisionID: input.DesiredRevisionID,
			CompilerVersion:   input.CompilerVersion,
			CreatedAt:         createdAt,
		}},
		CreatedAt: createdAt,
	}
	if err := repository.putBlob(repository.snapshotBlobPath(digest), artifactBytes, maxSnapshotBytes); err != nil {
		return SnapshotArtifact{}, err
	}
	next, err := nextState(repository.state)
	if err != nil {
		return SnapshotArtifact{}, err
	}
	next.SnapshotArtifacts = append(next.SnapshotArtifacts, metadata)
	if err := repository.writeState(next); err != nil {
		return SnapshotArtifact{}, err
	}
	repository.state = next
	return artifactFromMetadata(metadata, artifactBytes), nil
}

func (repository *FileRepository) GetSnapshotArtifact(ctx context.Context, digest Digest) (SnapshotArtifact, error) {
	if err := contextError(ctx); err != nil {
		return SnapshotArtifact{}, err
	}
	if digest.IsZero() {
		return SnapshotArtifact{}, fmt.Errorf("snapshot digest is empty: %w", ErrInvalid)
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return SnapshotArtifact{}, err
	}
	if err := contextError(ctx); err != nil {
		return SnapshotArtifact{}, err
	}
	metadata, found := findArtifactByDigest(repository.state.SnapshotArtifacts, digest.String())
	if !found {
		return SnapshotArtifact{}, ErrNotFound
	}
	return repository.materializeArtifactLocked(metadata)
}

func (repository *FileRepository) AllocateRollout(ctx context.Context, input RolloutInput) (RolloutRecord, error) {
	return repository.allocateRollout(ctx, input)
}

func (repository *FileRepository) allocateRollout(
	ctx context.Context,
	input RolloutInput,
) (RolloutRecord, error) {
	if err := contextError(ctx); err != nil {
		return RolloutRecord{}, err
	}
	normalized, err := normalizeRolloutInput(input)
	if err != nil {
		return RolloutRecord{}, err
	}

	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return RolloutRecord{}, err
	}
	if err := contextError(ctx); err != nil {
		return RolloutRecord{}, err
	}
	for _, metadata := range repository.state.Rollouts {
		if metadata.RequestID != normalized.RequestID {
			continue
		}
		if rolloutMatchesInput(metadata, normalized) {
			return rolloutFromMetadata(metadata)
		}
		return RolloutRecord{}, fmt.Errorf("rollout request %q changed: %w", normalized.RequestID, ErrConflict)
	}
	artifactMetadata, found := findArtifactByDigest(repository.state.SnapshotArtifacts, normalized.ArtifactDigest.String())
	if !found {
		return RolloutRecord{}, fmt.Errorf("target artifact: %w", ErrNotFound)
	}
	if !hasCompilation(
		artifactMetadata.Compilations,
		normalized.DesiredRevisionID,
		normalized.CompilerVersion,
	) {
		return RolloutRecord{}, fmt.Errorf("target artifact does not contain requested compilation lineage: %w", ErrConflict)
	}
	if !normalized.PreviousArtifactDigest.IsZero() {
		if _, found := findArtifactByDigest(repository.state.SnapshotArtifacts, normalized.PreviousArtifactDigest.String()); !found {
			return RolloutRecord{}, fmt.Errorf("previous artifact: %w", ErrNotFound)
		}
	}
	var baseline rolloutMetadata
	if normalized.BaselineRolloutSequence != 0 {
		var found bool
		baseline, found = findRolloutBySequence(repository.state.Rollouts, normalized.BaselineRolloutSequence)
		if !found {
			return RolloutRecord{}, fmt.Errorf("rollout baseline: %w", ErrNotFound)
		}
		if baseline.ArtifactDigest != optionalDigestString(normalized.PreviousArtifactDigest) {
			return RolloutRecord{}, fmt.Errorf("rollout baseline artifact differs from previous artifact: %w", ErrConflict)
		}
	}
	if normalized.PreviousArtifactDigest == normalized.ArtifactDigest {
		if normalized.BaselineRolloutSequence == 0 {
			return RolloutRecord{}, fmt.Errorf("identical target and previous artifacts require a baseline: %w", ErrInvalid)
		}
		baselinePolicy, err := policyFromMetadata(baseline.Policy, baseline.TargetNodeIDs)
		if err != nil {
			return RolloutRecord{}, err
		}
		if slices.Equal(baseline.TargetNodeIDs, normalized.TargetNodeIDs) &&
			rolloutPoliciesEqual(baselinePolicy, normalized.Policy) {
			return RolloutRecord{}, fmt.Errorf("artifact, targets, and policy are unchanged: %w", ErrInvalid)
		}
	}
	for _, expected := range normalized.ExpectedActiveByNode {
		if _, found := findArtifactByDigest(repository.state.SnapshotArtifacts, expected.ArtifactDigest.String()); !found {
			return RolloutRecord{}, fmt.Errorf("node %q expected artifact: %w", expected.NodeID, ErrNotFound)
		}
	}
	if normalized.Kind == RolloutKindRollback {
		target, found := findRolloutBySequence(repository.state.Rollouts, normalized.RollbackTargetSequence)
		if !found {
			return RolloutRecord{}, fmt.Errorf("rollback target rollout: %w", ErrNotFound)
		}
		if target.ArtifactDigest != normalized.ArtifactDigest.String() ||
			target.DesiredRevisionID != normalized.DesiredRevisionID ||
			target.CompilerVersion != normalized.CompilerVersion {
			return RolloutRecord{}, fmt.Errorf("rollback target lineage changed: %w", ErrConflict)
		}
	}
	if repository.state.LastRolloutSequence == math.MaxUint64 {
		return RolloutRecord{}, fmt.Errorf("rollout sequence exhausted: %w", ErrConflict)
	}
	id, err := repository.newIDLocked("rol_", func(candidate string) bool {
		for _, rollout := range repository.state.Rollouts {
			if rollout.ID == candidate {
				return true
			}
		}
		return false
	})
	if err != nil {
		return RolloutRecord{}, err
	}
	sequence := repository.state.LastRolloutSequence + 1
	metadata := rolloutMetadata{
		ID:                      id,
		RequestID:               normalized.RequestID,
		RequestDigest:           optionalDigestString(normalized.RequestDigest),
		Sequence:                sequence,
		ArtifactDigest:          normalized.ArtifactDigest.String(),
		PreviousArtifactDigest:  optionalDigestString(normalized.PreviousArtifactDigest),
		BaselineRolloutSequence: normalized.BaselineRolloutSequence,
		DesiredRevisionID:       normalized.DesiredRevisionID,
		CompilerVersion:         normalized.CompilerVersion,
		TargetNodeIDs:           append([]string(nil), normalized.TargetNodeIDs...),
		ExpectedActiveByNode:    expectedActiveMetadata(normalized.ExpectedActiveByNode),
		Policy:                  policyMetadata(normalized.Policy),
		SourceChannel:           normalized.SourceChannel,
		Actor:                   normalized.Actor,
		Reason:                  normalized.Reason,
		Kind:                    normalized.Kind,
		RollbackTargetSequence:  normalized.RollbackTargetSequence,
		CreatedAt:               repository.now(),
	}
	next, err := nextState(repository.state)
	if err != nil {
		return RolloutRecord{}, err
	}
	next.LastRolloutSequence = sequence
	next.Rollouts = append(next.Rollouts, metadata)
	if err := repository.writeState(next); err != nil {
		return RolloutRecord{}, err
	}
	repository.state = next
	return rolloutFromMetadata(metadata)
}

func (repository *FileRepository) GetRollout(ctx context.Context, sequence uint64) (RolloutRecord, error) {
	if err := contextError(ctx); err != nil {
		return RolloutRecord{}, err
	}
	if sequence == 0 {
		return RolloutRecord{}, fmt.Errorf("rollout sequence is zero: %w", ErrInvalid)
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return RolloutRecord{}, err
	}
	if err := contextError(ctx); err != nil {
		return RolloutRecord{}, err
	}
	metadata, found := findRolloutBySequence(repository.state.Rollouts, sequence)
	if !found {
		return RolloutRecord{}, ErrNotFound
	}
	return rolloutFromMetadata(metadata)
}

// GetRolloutByRequestID resolves the immutable operation created by an
// idempotency key. It lets an API retry return the original sequence even
// after a process restart or a later rollout has become current.
func (repository *FileRepository) GetRolloutByRequestID(
	ctx context.Context,
	requestID string,
) (RolloutRecord, error) {
	if err := contextError(ctx); err != nil {
		return RolloutRecord{}, err
	}
	if err := validateIdentifier("request ID", requestID); err != nil {
		return RolloutRecord{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return RolloutRecord{}, err
	}
	if err := contextError(ctx); err != nil {
		return RolloutRecord{}, err
	}
	for _, metadata := range repository.state.Rollouts {
		if metadata.RequestID == requestID {
			return rolloutFromMetadata(metadata)
		}
	}
	return RolloutRecord{}, ErrNotFound
}

// InitializeSelectedRollout establishes the first runtime authority for an
// existing repository. Once set, only AllocateAndSelectRollout may advance it.
func (repository *FileRepository) InitializeSelectedRollout(
	ctx context.Context,
	sequence uint64,
) (RolloutRecord, error) {
	if err := contextError(ctx); err != nil {
		return RolloutRecord{}, err
	}
	if sequence == 0 {
		return RolloutRecord{}, fmt.Errorf("selected rollout sequence is zero: %w", ErrInvalid)
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return RolloutRecord{}, err
	}
	metadata, found := findRolloutBySequence(repository.state.Rollouts, sequence)
	if !found {
		return RolloutRecord{}, ErrNotFound
	}
	if repository.state.SelectedRolloutSequence != 0 {
		if repository.state.SelectedRolloutSequence != sequence {
			return RolloutRecord{}, fmt.Errorf(
				"rollout %d is already selected: %w",
				repository.state.SelectedRolloutSequence,
				ErrConflict,
			)
		}
		return rolloutFromMetadata(metadata)
	}
	next, err := nextState(repository.state)
	if err != nil {
		return RolloutRecord{}, err
	}
	next.SelectedRolloutSequence = sequence
	if err := repository.writeState(next); err != nil {
		return RolloutRecord{}, err
	}
	repository.state = next
	return rolloutFromMetadata(metadata)
}

// GetSelectedRollout returns the explicitly persisted runtime authority. It
// never infers selection from the highest historical sequence.
func (repository *FileRepository) GetSelectedRollout(ctx context.Context) (RolloutRecord, error) {
	if err := contextError(ctx); err != nil {
		return RolloutRecord{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return RolloutRecord{}, err
	}
	if repository.state.SelectedRolloutSequence == 0 {
		return RolloutRecord{}, ErrNotFound
	}
	metadata, found := findRolloutBySequence(repository.state.Rollouts, repository.state.SelectedRolloutSequence)
	if !found {
		return RolloutRecord{}, fmt.Errorf("selected rollout is missing: %w", ErrCorrupt)
	}
	return rolloutFromMetadata(metadata)
}

// SelectRollout atomically advances runtime authority to an already-started
// rollout. The compare-and-set precondition prevents stale API or GitOps
// writers from replacing a newer selection.
func (repository *FileRepository) SelectRollout(
	ctx context.Context,
	expectedSequence uint64,
	nextSequence uint64,
) (RolloutRecord, error) {
	if err := contextError(ctx); err != nil {
		return RolloutRecord{}, err
	}
	if nextSequence == 0 || nextSequence <= expectedSequence {
		return RolloutRecord{}, fmt.Errorf("selected rollout must advance monotonically: %w", ErrInvalid)
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return RolloutRecord{}, err
	}
	if repository.state.SelectedRolloutSequence != expectedSequence {
		return RolloutRecord{}, fmt.Errorf(
			"selected rollout changed from %d to %d: %w",
			expectedSequence,
			repository.state.SelectedRolloutSequence,
			ErrConflict,
		)
	}
	metadata, found := findRolloutBySequence(repository.state.Rollouts, nextSequence)
	if !found {
		return RolloutRecord{}, ErrNotFound
	}
	started := false
	for _, event := range repository.state.RolloutEvents {
		if event.RolloutSequence == nextSequence && event.Index == 1 && event.Kind == "START" {
			started = true
			break
		}
	}
	if !started {
		return RolloutRecord{}, fmt.Errorf("rollout %d has no durable START event: %w", nextSequence, ErrConflict)
	}
	next, err := nextState(repository.state)
	if err != nil {
		return RolloutRecord{}, err
	}
	next.SelectedRolloutSequence = nextSequence
	if err := repository.writeState(next); err != nil {
		return RolloutRecord{}, err
	}
	repository.state = next
	return rolloutFromMetadata(metadata)
}

func (repository *FileRepository) GetLineage(ctx context.Context, digest Digest) (Lineage, error) {
	if err := contextError(ctx); err != nil {
		return Lineage{}, err
	}
	if digest.IsZero() {
		return Lineage{}, fmt.Errorf("snapshot digest is empty: %w", ErrInvalid)
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return Lineage{}, err
	}
	if err := contextError(ctx); err != nil {
		return Lineage{}, err
	}
	artifactMetadata, found := findArtifactByDigest(repository.state.SnapshotArtifacts, digest.String())
	if !found {
		return Lineage{}, ErrNotFound
	}
	artifact, err := repository.materializeArtifactLocked(artifactMetadata)
	if err != nil {
		return Lineage{}, err
	}
	lineage := Lineage{Artifact: artifact}
	seenDesired := make(map[string]struct{}, len(artifactMetadata.Compilations))
	for _, compilation := range artifactMetadata.Compilations {
		if _, seen := seenDesired[compilation.DesiredRevisionID]; seen {
			continue
		}
		desiredMetadata, found := findDesiredByID(repository.state.DesiredRevisions, compilation.DesiredRevisionID)
		if !found {
			return Lineage{}, fmt.Errorf("artifact source revision is missing: %w", ErrCorrupt)
		}
		desired, err := repository.materializeDesiredLocked(desiredMetadata)
		if err != nil {
			return Lineage{}, err
		}
		lineage.DesiredRevisions = append(lineage.DesiredRevisions, desired)
		seenDesired[compilation.DesiredRevisionID] = struct{}{}
	}
	for _, metadata := range repository.state.Rollouts {
		if metadata.ArtifactDigest == digest.String() {
			rollout, err := rolloutFromMetadata(metadata)
			if err != nil {
				return Lineage{}, err
			}
			lineage.Rollouts = append(lineage.Rollouts, rollout)
		}
	}
	return lineage, nil
}

func (repository *FileRepository) LastRolloutSequence(ctx context.Context) (uint64, error) {
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return 0, err
	}
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	return repository.state.LastRolloutSequence, nil
}

func (repository *FileRepository) Close() error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.closed {
		return nil
	}
	repository.closed = true
	return repository.lock.release()
}

func (repository *FileRepository) ensureOpenLocked() error {
	if repository.closed {
		return ErrClosed
	}
	return nil
}

func (repository *FileRepository) now() time.Time {
	return repository.clock().UTC().Round(0)
}

func (repository *FileRepository) newIDLocked(prefix string, exists func(string) bool) (string, error) {
	for range 8 {
		var randomBytes [16]byte
		if _, err := io.ReadFull(repository.random, randomBytes[:]); err != nil {
			return "", fmt.Errorf("generate repository ID: %w", err)
		}
		candidate := prefix + fmt.Sprintf("%x", randomBytes)
		if !exists(candidate) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("generate unique repository ID: %w", ErrConflict)
}

func (repository *FileRepository) desiredBlobDirectory() string {
	return filepath.Join(repository.root, "blobs", "desired", "sha256")
}

func (repository *FileRepository) snapshotBlobDirectory() string {
	return filepath.Join(repository.root, "blobs", "snapshots", "sha256")
}

func (repository *FileRepository) desiredBlobPath(digest Digest) string {
	return filepath.Join(repository.desiredBlobDirectory(), digest.String()+".yaml")
}

func (repository *FileRepository) snapshotBlobPath(digest Digest) string {
	return filepath.Join(repository.snapshotBlobDirectory(), digest.String()+".pb")
}

func (repository *FileRepository) materializeDesiredLocked(metadata desiredMetadata) (DesiredRevision, error) {
	digest, err := ParseDigest(metadata.Digest)
	if err != nil {
		return DesiredRevision{}, fmt.Errorf("stored desired digest: %w", ErrCorrupt)
	}
	document, err := repository.readVerifiedFile(repository.desiredBlobPath(digest), digest, metadata.Size, maxDesiredBytes)
	if err != nil {
		return DesiredRevision{}, err
	}
	return desiredFromMetadata(metadata, document), nil
}

func (repository *FileRepository) materializeArtifactLocked(metadata artifactMetadata) (SnapshotArtifact, error) {
	digest, err := ParseDigest(metadata.Digest)
	if err != nil {
		return SnapshotArtifact{}, fmt.Errorf("stored artifact digest: %w", ErrCorrupt)
	}
	data, err := repository.readVerifiedFile(repository.snapshotBlobPath(digest), digest, metadata.Size, maxSnapshotBytes)
	if err != nil {
		return SnapshotArtifact{}, err
	}
	return artifactFromMetadata(metadata, data), nil
}

func desiredFromMetadata(metadata desiredMetadata, document []byte) DesiredRevision {
	digest, _ := ParseDigest(metadata.Digest)
	return DesiredRevision{
		ID:             metadata.ID,
		RequestID:      metadata.RequestID,
		Digest:         digest,
		Document:       append([]byte(nil), document...),
		SourceChannel:  metadata.SourceChannel,
		SourceRevision: metadata.SourceRevision,
		Actor:          metadata.Actor,
		CreatedAt:      metadata.CreatedAt,
	}
}

func artifactFromMetadata(metadata artifactMetadata, data []byte) SnapshotArtifact {
	digest, _ := ParseDigest(metadata.Digest)
	compilations := make([]CompilationLineage, len(metadata.Compilations))
	for index, compilation := range metadata.Compilations {
		compilations[index] = CompilationLineage{
			DesiredRevisionID: compilation.DesiredRevisionID,
			CompilerVersion:   compilation.CompilerVersion,
			CreatedAt:         compilation.CreatedAt,
		}
	}
	return SnapshotArtifact{
		SnapshotID:              metadata.SnapshotID,
		Digest:                  digest,
		Bytes:                   append([]byte(nil), data...),
		SchemaVersion:           metadata.SchemaVersion,
		MinimumDataplaneVersion: metadata.MinimumDataplaneVersion,
		Compilations:            compilations,
		CreatedAt:               metadata.CreatedAt,
	}
}

func rolloutFromMetadata(metadata rolloutMetadata) (RolloutRecord, error) {
	artifactDigest, err := ParseDigest(metadata.ArtifactDigest)
	if err != nil {
		return RolloutRecord{}, fmt.Errorf("stored rollout artifact digest: %w", ErrCorrupt)
	}
	var previousDigest Digest
	if metadata.PreviousArtifactDigest != "" {
		previousDigest, err = ParseDigest(metadata.PreviousArtifactDigest)
		if err != nil {
			return RolloutRecord{}, fmt.Errorf("stored rollout previous digest: %w", ErrCorrupt)
		}
	}
	var requestDigest Digest
	if metadata.RequestDigest != "" {
		requestDigest, err = ParseDigest(metadata.RequestDigest)
		if err != nil {
			return RolloutRecord{}, fmt.Errorf("stored rollout request digest: %w", ErrCorrupt)
		}
	}
	expectedActive, err := expectedActiveFromMetadata(metadata.ExpectedActiveByNode)
	if err != nil {
		return RolloutRecord{}, err
	}
	policy, err := policyFromMetadata(metadata.Policy, metadata.TargetNodeIDs)
	if err != nil {
		return RolloutRecord{}, err
	}
	return RolloutRecord{
		ID:                      metadata.ID,
		RequestID:               metadata.RequestID,
		RequestDigest:           requestDigest,
		Sequence:                metadata.Sequence,
		ArtifactDigest:          artifactDigest,
		PreviousArtifactDigest:  previousDigest,
		BaselineRolloutSequence: metadata.BaselineRolloutSequence,
		DesiredRevisionID:       metadata.DesiredRevisionID,
		CompilerVersion:         metadata.CompilerVersion,
		TargetNodeIDs:           append([]string(nil), metadata.TargetNodeIDs...),
		ExpectedActiveByNode:    expectedActive,
		Policy:                  policy,
		SourceChannel:           metadata.SourceChannel,
		Actor:                   metadata.Actor,
		Reason:                  metadata.Reason,
		Kind:                    normalizedRolloutKind(metadata.Kind),
		RollbackTargetSequence:  metadata.RollbackTargetSequence,
		CreatedAt:               metadata.CreatedAt,
	}, nil
}

func expectedActiveMetadata(values []NodeExpectedArtifact) []nodeExpectedArtifactMetadata {
	if len(values) == 0 {
		return nil
	}
	result := make([]nodeExpectedArtifactMetadata, len(values))
	for index, value := range values {
		result[index] = nodeExpectedArtifactMetadata{
			NodeID: value.NodeID, ArtifactDigest: value.ArtifactDigest.String(),
		}
	}
	return result
}

func expectedActiveFromMetadata(values []nodeExpectedArtifactMetadata) ([]NodeExpectedArtifact, error) {
	if len(values) == 0 {
		return nil, nil
	}
	result := make([]NodeExpectedArtifact, len(values))
	for index, value := range values {
		digest, err := ParseDigest(value.ArtifactDigest)
		if err != nil || digest.IsZero() {
			return nil, fmt.Errorf("stored node expected artifact digest: %w", ErrCorrupt)
		}
		result[index] = NodeExpectedArtifact{NodeID: value.NodeID, ArtifactDigest: digest}
	}
	return result, nil
}

func policyMetadata(policy RolloutPolicy) *rolloutPolicyMetadata {
	if !policy.Enabled {
		return nil
	}
	return &rolloutPolicyMetadata{
		Strategy: policy.Strategy, CanaryNodeIDs: append([]string(nil), policy.CanaryNodeIDs...),
		MinimumHealthyCanaryPercent: policy.MinimumHealthyCanaryPercent,
		CanaryObservationMillis:     policy.CanaryObservationWindow.Milliseconds(),
		PrepareTimeoutMillis:        policy.PrepareTimeout.Milliseconds(),
		ActivationTimeoutMillis:     policy.ActivationTimeout.Milliseconds(),
		HeartbeatStaleAfterMillis:   policy.HeartbeatStaleAfter.Milliseconds(),
		AutomaticRollback:           policy.AutomaticRollback,
	}
}

func policyFromMetadata(metadata *rolloutPolicyMetadata, targetNodeIDs []string) (RolloutPolicy, error) {
	if metadata == nil {
		return RolloutPolicy{}, nil
	}
	policy, err := NormalizeRolloutPolicy(RolloutPolicy{
		Enabled: true, Strategy: metadata.Strategy,
		CanaryNodeIDs:               append([]string(nil), metadata.CanaryNodeIDs...),
		MinimumHealthyCanaryPercent: metadata.MinimumHealthyCanaryPercent,
		CanaryObservationWindow:     time.Duration(metadata.CanaryObservationMillis) * time.Millisecond,
		PrepareTimeout:              time.Duration(metadata.PrepareTimeoutMillis) * time.Millisecond,
		ActivationTimeout:           time.Duration(metadata.ActivationTimeoutMillis) * time.Millisecond,
		HeartbeatStaleAfter:         time.Duration(metadata.HeartbeatStaleAfterMillis) * time.Millisecond,
		AutomaticRollback:           metadata.AutomaticRollback,
	}, targetNodeIDs)
	if err != nil {
		return RolloutPolicy{}, fmt.Errorf("stored rollout policy: %w", ErrCorrupt)
	}
	return policy, nil
}

func rolloutPoliciesEqual(left, right RolloutPolicy) bool {
	return left.Enabled == right.Enabled && left.Strategy == right.Strategy &&
		slices.Equal(left.CanaryNodeIDs, right.CanaryNodeIDs) &&
		left.MinimumHealthyCanaryPercent == right.MinimumHealthyCanaryPercent &&
		left.CanaryObservationWindow == right.CanaryObservationWindow &&
		left.PrepareTimeout == right.PrepareTimeout &&
		left.ActivationTimeout == right.ActivationTimeout &&
		left.HeartbeatStaleAfter == right.HeartbeatStaleAfter &&
		left.AutomaticRollback == right.AutomaticRollback
}

func validateDesiredInput(input DesiredRevisionInput) error {
	if err := validateIdentifier("request ID", input.RequestID); err != nil {
		return err
	}
	if len(input.Document) == 0 || len(input.Document) > maxDesiredBytes {
		return fmt.Errorf("desired state must contain 1-%d bytes: %w", maxDesiredBytes, ErrInvalid)
	}
	if !validSourceChannel(input.SourceChannel) {
		return fmt.Errorf("unsupported desired-state source channel %q: %w", input.SourceChannel, ErrInvalid)
	}
	if err := validateText("source revision", input.SourceRevision, 256, false); err != nil {
		return err
	}
	return validateText("actor", input.Actor, 256, true)
}

func normalizeRolloutInput(input RolloutInput) (RolloutInput, error) {
	if err := validateIdentifier("request ID", input.RequestID); err != nil {
		return RolloutInput{}, err
	}
	if input.ArtifactDigest.IsZero() {
		return RolloutInput{}, fmt.Errorf("artifact digest is empty: %w", ErrInvalid)
	}
	if err := validateIdentifier("desired revision ID", input.DesiredRevisionID); err != nil {
		return RolloutInput{}, err
	}
	if err := validateText("compiler version", input.CompilerVersion, 128, true); err != nil {
		return RolloutInput{}, err
	}
	if !validSourceChannel(input.SourceChannel) {
		return RolloutInput{}, fmt.Errorf("unsupported rollout source channel %q: %w", input.SourceChannel, ErrInvalid)
	}
	if err := validateText("actor", input.Actor, 256, true); err != nil {
		return RolloutInput{}, err
	}
	if err := validateText("reason", input.Reason, 1024, true); err != nil {
		return RolloutInput{}, err
	}
	if len(input.TargetNodeIDs) == 0 || len(input.TargetNodeIDs) > maxTargetNodes {
		return RolloutInput{}, fmt.Errorf("target node count must be 1-%d: %w", maxTargetNodes, ErrInvalid)
	}
	normalized := input
	normalized.Kind = normalizedRolloutKind(input.Kind)
	switch normalized.Kind {
	case RolloutKindApply:
		if normalized.RollbackTargetSequence != 0 {
			return RolloutInput{}, fmt.Errorf("apply rollout has a rollback target: %w", ErrInvalid)
		}
	case RolloutKindRollback:
		if normalized.RollbackTargetSequence == 0 {
			return RolloutInput{}, fmt.Errorf("rollback target sequence is zero: %w", ErrInvalid)
		}
	default:
		return RolloutInput{}, fmt.Errorf("unsupported rollout kind %q: %w", normalized.Kind, ErrInvalid)
	}
	normalized.TargetNodeIDs = append([]string(nil), input.TargetNodeIDs...)
	slices.Sort(normalized.TargetNodeIDs)
	for index, nodeID := range normalized.TargetNodeIDs {
		if err := validateIdentifier("target node ID", nodeID); err != nil {
			return RolloutInput{}, err
		}
		if index > 0 && normalized.TargetNodeIDs[index-1] == nodeID {
			return RolloutInput{}, fmt.Errorf("duplicate target node %q: %w", nodeID, ErrInvalid)
		}
	}
	policy, err := NormalizeRolloutPolicy(input.Policy, normalized.TargetNodeIDs)
	if err != nil {
		return RolloutInput{}, err
	}
	normalized.Policy = policy
	if normalized.Policy.Enabled && normalized.BaselineRolloutSequence == 0 {
		return RolloutInput{}, fmt.Errorf("policy rollout baseline sequence is zero: %w", ErrInvalid)
	}
	normalized.ExpectedActiveByNode = append([]NodeExpectedArtifact(nil), input.ExpectedActiveByNode...)
	slices.SortFunc(normalized.ExpectedActiveByNode, func(left, right NodeExpectedArtifact) int {
		return strings.Compare(left.NodeID, right.NodeID)
	})
	if len(normalized.ExpectedActiveByNode) != 0 &&
		len(normalized.ExpectedActiveByNode) != len(normalized.TargetNodeIDs) {
		return RolloutInput{}, fmt.Errorf("per-node expected artifacts must cover every target: %w", ErrInvalid)
	}
	for index, expected := range normalized.ExpectedActiveByNode {
		if err := validateIdentifier("expected-artifact node ID", expected.NodeID); err != nil {
			return RolloutInput{}, err
		}
		if expected.ArtifactDigest.IsZero() {
			return RolloutInput{}, fmt.Errorf("expected artifact digest is empty: %w", ErrInvalid)
		}
		if index >= len(normalized.TargetNodeIDs) || normalized.TargetNodeIDs[index] != expected.NodeID {
			return RolloutInput{}, fmt.Errorf("per-node expected artifact target set differs: %w", ErrInvalid)
		}
		if expected.ArtifactDigest != normalized.ArtifactDigest &&
			expected.ArtifactDigest != normalized.PreviousArtifactDigest {
			return RolloutInput{}, fmt.Errorf("per-node expected artifact is outside rollout lineage: %w", ErrInvalid)
		}
	}
	return normalized, nil
}

func rolloutMatchesInput(metadata rolloutMetadata, input RolloutInput) bool {
	return metadata.ArtifactDigest == input.ArtifactDigest.String() &&
		metadata.RequestDigest == optionalDigestString(input.RequestDigest) &&
		metadata.PreviousArtifactDigest == optionalDigestString(input.PreviousArtifactDigest) &&
		metadata.BaselineRolloutSequence == input.BaselineRolloutSequence &&
		metadata.DesiredRevisionID == input.DesiredRevisionID &&
		metadata.CompilerVersion == input.CompilerVersion &&
		metadata.SourceChannel == input.SourceChannel && metadata.Actor == input.Actor &&
		metadata.Reason == input.Reason && normalizedRolloutKind(metadata.Kind) == input.Kind &&
		metadata.RollbackTargetSequence == input.RollbackTargetSequence &&
		slices.Equal(metadata.TargetNodeIDs, input.TargetNodeIDs) &&
		reflectExpectedActive(metadata.ExpectedActiveByNode, input.ExpectedActiveByNode) &&
		reflectPolicy(metadata.Policy, input.Policy)
}

func reflectExpectedActive(metadata []nodeExpectedArtifactMetadata, values []NodeExpectedArtifact) bool {
	return slices.EqualFunc(metadata, values, func(left nodeExpectedArtifactMetadata, right NodeExpectedArtifact) bool {
		return left.NodeID == right.NodeID && left.ArtifactDigest == right.ArtifactDigest.String()
	})
}

func reflectPolicy(metadata *rolloutPolicyMetadata, policy RolloutPolicy) bool {
	converted := policyMetadata(policy)
	if metadata == nil || converted == nil {
		return metadata == nil && converted == nil
	}
	return metadata.Strategy == converted.Strategy &&
		metadata.MinimumHealthyCanaryPercent == converted.MinimumHealthyCanaryPercent &&
		metadata.CanaryObservationMillis == converted.CanaryObservationMillis &&
		metadata.PrepareTimeoutMillis == converted.PrepareTimeoutMillis &&
		metadata.ActivationTimeoutMillis == converted.ActivationTimeoutMillis &&
		metadata.HeartbeatStaleAfterMillis == converted.HeartbeatStaleAfterMillis &&
		metadata.AutomaticRollback == converted.AutomaticRollback &&
		slices.Equal(metadata.CanaryNodeIDs, converted.CanaryNodeIDs)
}

func normalizedRolloutKind(kind RolloutKind) RolloutKind {
	if kind == "" {
		return RolloutKindApply
	}
	return kind
}

func hasCompilation(compilations []compilationMetadata, desiredRevisionID, compilerVersion string) bool {
	for _, compilation := range compilations {
		if compilation.DesiredRevisionID == desiredRevisionID && compilation.CompilerVersion == compilerVersion {
			return true
		}
	}
	return false
}

func optionalDigestString(digest Digest) string {
	if digest.IsZero() {
		return ""
	}
	return digest.String()
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context is nil: %w", ErrInvalid)
	}
	return ctx.Err()
}

func findDesiredByID(records []desiredMetadata, id string) (desiredMetadata, bool) {
	for _, record := range records {
		if record.ID == id {
			return record, true
		}
	}
	return desiredMetadata{}, false
}

func findArtifactByDigest(records []artifactMetadata, digest string) (artifactMetadata, bool) {
	for _, record := range records {
		if record.Digest == digest {
			return record, true
		}
	}
	return artifactMetadata{}, false
}

func findRolloutBySequence(records []rolloutMetadata, sequence uint64) (rolloutMetadata, bool) {
	for _, record := range records {
		if record.Sequence == sequence {
			return record, true
		}
	}
	return rolloutMetadata{}, false
}

func cloneState(state persistedState) persistedState {
	cloned := state
	cloned.DesiredRevisions = append([]desiredMetadata(nil), state.DesiredRevisions...)
	cloned.SnapshotArtifacts = make([]artifactMetadata, len(state.SnapshotArtifacts))
	copy(cloned.SnapshotArtifacts, state.SnapshotArtifacts)
	for index := range cloned.SnapshotArtifacts {
		cloned.SnapshotArtifacts[index].Compilations = append(
			[]compilationMetadata(nil),
			state.SnapshotArtifacts[index].Compilations...,
		)
	}
	cloned.Rollouts = make([]rolloutMetadata, len(state.Rollouts))
	copy(cloned.Rollouts, state.Rollouts)
	for index := range cloned.Rollouts {
		cloned.Rollouts[index].TargetNodeIDs = append([]string(nil), state.Rollouts[index].TargetNodeIDs...)
	}
	cloned.RolloutEvents = append([]eventMetadata(nil), state.RolloutEvents...)
	return cloned
}

func nextState(state persistedState) (persistedState, error) {
	if state.Generation == math.MaxUint64 {
		return persistedState{}, fmt.Errorf("repository generation exhausted: %w", ErrConflict)
	}
	next := cloneState(state)
	next.Generation++
	return next, nil
}
