package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	bonvoyagev1 "github.com/routesphere-global/bonvoyage/api/gen/go/bonvoyage/v1"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/snapshot"
	"google.golang.org/protobuf/proto"
)

func (repository *FileRepository) loadState() (persistedState, error) {
	data, err := readPrivateFile(filepath.Join(repository.root, stateFileName), maxStateBytes)
	if err != nil {
		return persistedState{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var envelope stateEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return persistedState{}, fmt.Errorf("decode repository state: %w: %w", ErrCorrupt, err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return persistedState{}, err
	}
	stateBytes, err := json.Marshal(envelope.State)
	if err != nil {
		return persistedState{}, fmt.Errorf("remarshal repository state: %w", err)
	}
	if envelope.IntegritySHA256 != Sum(stateBytes).String() {
		return persistedState{}, fmt.Errorf("repository state checksum mismatch: %w", ErrCorrupt)
	}
	return envelope.State, nil
}

func (repository *FileRepository) writeState(state persistedState) error {
	stateBytes, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal repository state: %w", err)
	}
	envelope := stateEnvelope{IntegritySHA256: Sum(stateBytes).String(), State: state}
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal repository envelope: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxStateBytes {
		return fmt.Errorf("repository state exceeds %d bytes: %w", maxStateBytes, ErrConflict)
	}
	return writeFileAtomicPrivate(filepath.Join(repository.root, stateFileName), data)
}

func (repository *FileRepository) validateState(state persistedState) error {
	if state.SchemaVersion != repositorySchemaVersion || state.Generation == 0 {
		return fmt.Errorf("unsupported repository state header: %w", ErrCorrupt)
	}
	desiredIDs := make(map[string]struct{}, len(state.DesiredRevisions))
	desiredRequests := make(map[string]struct{}, len(state.DesiredRevisions))
	for _, metadata := range state.DesiredRevisions {
		if err := validateIdentifier("stored desired revision ID", metadata.ID); err != nil {
			return fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		if err := validateIdentifier("stored desired request ID", metadata.RequestID); err != nil {
			return fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		if _, exists := desiredIDs[metadata.ID]; exists {
			return fmt.Errorf("duplicate desired revision ID %q: %w", metadata.ID, ErrCorrupt)
		}
		if _, exists := desiredRequests[metadata.RequestID]; exists {
			return fmt.Errorf("duplicate desired request ID %q: %w", metadata.RequestID, ErrCorrupt)
		}
		desiredIDs[metadata.ID] = struct{}{}
		desiredRequests[metadata.RequestID] = struct{}{}
		digest, err := ParseDigest(metadata.Digest)
		if err != nil || digest.String() != metadata.Digest || metadata.Size <= 0 ||
			metadata.Size > int64(maxDesiredBytes) || metadata.CreatedAt.IsZero() {
			return fmt.Errorf("invalid desired revision metadata %q: %w", metadata.ID, ErrCorrupt)
		}
		if !validSourceChannel(metadata.SourceChannel) {
			return fmt.Errorf("invalid desired source channel: %w", ErrCorrupt)
		}
		if err := validateText("stored source revision", metadata.SourceRevision, 256, false); err != nil {
			return fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		if err := validateText("stored desired actor", metadata.Actor, 256, true); err != nil {
			return fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		if _, err := repository.readVerifiedFile(repository.desiredBlobPath(digest), digest, metadata.Size, maxDesiredBytes); err != nil {
			return err
		}
	}

	artifactDigests := make(map[string]struct{}, len(state.SnapshotArtifacts))
	snapshotIDs := make(map[string]struct{}, len(state.SnapshotArtifacts))
	for _, metadata := range state.SnapshotArtifacts {
		if _, exists := artifactDigests[metadata.Digest]; exists {
			return fmt.Errorf("duplicate artifact digest %q: %w", metadata.Digest, ErrCorrupt)
		}
		if _, exists := snapshotIDs[metadata.SnapshotID]; exists {
			return fmt.Errorf("duplicate snapshot ID %q: %w", metadata.SnapshotID, ErrCorrupt)
		}
		digest, err := ParseDigest(metadata.Digest)
		if err != nil || digest.String() != metadata.Digest || metadata.Size <= 0 || metadata.Size > int64(maxSnapshotBytes) ||
			metadata.SchemaVersion == 0 || metadata.CreatedAt.IsZero() {
			return fmt.Errorf("invalid snapshot artifact metadata %q: %w", metadata.SnapshotID, ErrCorrupt)
		}
		if err := validateText("stored snapshot ID", metadata.SnapshotID, 128, true); err != nil {
			return fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		if err := validateText("stored minimum dataplane version", metadata.MinimumDataplaneVersion, 128, true); err != nil {
			return fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		if len(metadata.Compilations) == 0 {
			return fmt.Errorf("artifact %q has no compilation lineage: %w", metadata.SnapshotID, ErrCorrupt)
		}
		compilationPairs := make(map[string]struct{}, len(metadata.Compilations))
		for _, compilation := range metadata.Compilations {
			if _, exists := desiredIDs[compilation.DesiredRevisionID]; !exists {
				return fmt.Errorf("artifact %q source revision %q is missing: %w", metadata.SnapshotID, compilation.DesiredRevisionID, ErrCorrupt)
			}
			if err := validateText("stored compiler version", compilation.CompilerVersion, 128, true); err != nil {
				return fmt.Errorf("%w: %v", ErrCorrupt, err)
			}
			if compilation.CreatedAt.IsZero() {
				return fmt.Errorf("artifact %q has undated compilation lineage: %w", metadata.SnapshotID, ErrCorrupt)
			}
			pair := compilation.DesiredRevisionID + "\x00" + compilation.CompilerVersion
			if _, exists := compilationPairs[pair]; exists {
				return fmt.Errorf("artifact %q has duplicate compilation lineage: %w", metadata.SnapshotID, ErrCorrupt)
			}
			compilationPairs[pair] = struct{}{}
		}
		data, err := repository.readVerifiedFile(repository.snapshotBlobPath(digest), digest, metadata.Size, maxSnapshotBytes)
		if err != nil {
			return err
		}
		if err := validateArtifactPayload(metadata, data); err != nil {
			return err
		}
		artifactDigests[metadata.Digest] = struct{}{}
		snapshotIDs[metadata.SnapshotID] = struct{}{}
	}

	rolloutIDs := make(map[string]struct{}, len(state.Rollouts))
	rolloutRequests := make(map[string]struct{}, len(state.Rollouts))
	rolloutSequences := make(map[uint64]struct{}, len(state.Rollouts))
	for index, metadata := range state.Rollouts {
		expectedSequence := uint64(index + 1)
		if metadata.Sequence != expectedSequence {
			return fmt.Errorf("rollout sequence %d is not contiguous at %d: %w", metadata.Sequence, expectedSequence, ErrCorrupt)
		}
		if _, exists := rolloutIDs[metadata.ID]; exists {
			return fmt.Errorf("duplicate rollout ID %q: %w", metadata.ID, ErrCorrupt)
		}
		if _, exists := rolloutRequests[metadata.RequestID]; exists {
			return fmt.Errorf("duplicate rollout request ID %q: %w", metadata.RequestID, ErrCorrupt)
		}
		if _, exists := artifactDigests[metadata.ArtifactDigest]; !exists {
			return fmt.Errorf("rollout %d target artifact is missing: %w", metadata.Sequence, ErrCorrupt)
		}
		if metadata.PreviousArtifactDigest != "" {
			if _, exists := artifactDigests[metadata.PreviousArtifactDigest]; !exists {
				return fmt.Errorf("rollout %d previous artifact is missing: %w", metadata.Sequence, ErrCorrupt)
			}
		}
		artifact, _ := findArtifactByDigest(state.SnapshotArtifacts, metadata.ArtifactDigest)
		if !hasCompilation(artifact.Compilations, metadata.DesiredRevisionID, metadata.CompilerVersion) ||
			metadata.CreatedAt.IsZero() || !validSourceChannel(metadata.SourceChannel) {
			return fmt.Errorf("invalid rollout metadata at sequence %d: %w", metadata.Sequence, ErrCorrupt)
		}
		if err := validateIdentifier("stored rollout ID", metadata.ID); err != nil {
			return fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		if err := validateIdentifier("stored rollout request ID", metadata.RequestID); err != nil {
			return fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		if metadata.RequestDigest != "" {
			digest, err := ParseDigest(metadata.RequestDigest)
			if err != nil || digest.String() != metadata.RequestDigest {
				return fmt.Errorf("rollout %d has an invalid request digest: %w", metadata.Sequence, ErrCorrupt)
			}
		}
		if err := validateText("stored rollout actor", metadata.Actor, 256, true); err != nil {
			return fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		if err := validateText("stored rollout reason", metadata.Reason, 1024, true); err != nil {
			return fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		kind := normalizedRolloutKind(metadata.Kind)
		switch kind {
		case RolloutKindApply:
			if metadata.RollbackTargetSequence != 0 {
				return fmt.Errorf("apply rollout %d has a rollback target: %w", metadata.Sequence, ErrCorrupt)
			}
		case RolloutKindRollback:
			if metadata.RollbackTargetSequence == 0 || metadata.RollbackTargetSequence >= metadata.Sequence {
				return fmt.Errorf("rollback %d has an invalid target sequence: %w", metadata.Sequence, ErrCorrupt)
			}
			target, found := findRolloutBySequence(state.Rollouts, metadata.RollbackTargetSequence)
			if !found || target.ArtifactDigest != metadata.ArtifactDigest ||
				target.DesiredRevisionID != metadata.DesiredRevisionID ||
				target.CompilerVersion != metadata.CompilerVersion {
				return fmt.Errorf("rollback %d target lineage is invalid: %w", metadata.Sequence, ErrCorrupt)
			}
		default:
			return fmt.Errorf("rollout %d has an unsupported kind: %w", metadata.Sequence, ErrCorrupt)
		}
		if len(metadata.TargetNodeIDs) == 0 || len(metadata.TargetNodeIDs) > maxTargetNodes ||
			!slices.IsSorted(metadata.TargetNodeIDs) {
			return fmt.Errorf("invalid rollout target set at sequence %d: %w", metadata.Sequence, ErrCorrupt)
		}
		for targetIndex, nodeID := range metadata.TargetNodeIDs {
			if err := validateIdentifier("stored target node ID", nodeID); err != nil {
				return fmt.Errorf("%w: %v", ErrCorrupt, err)
			}
			if targetIndex > 0 && metadata.TargetNodeIDs[targetIndex-1] == nodeID {
				return fmt.Errorf("duplicate stored target node %q: %w", nodeID, ErrCorrupt)
			}
		}
		if metadata.BaselineRolloutSequence != 0 {
			if metadata.BaselineRolloutSequence >= metadata.Sequence {
				return fmt.Errorf("rollout %d baseline sequence is not older: %w", metadata.Sequence, ErrCorrupt)
			}
			baseline, found := findRolloutBySequence(state.Rollouts, metadata.BaselineRolloutSequence)
			if !found || baseline.ArtifactDigest != metadata.PreviousArtifactDigest {
				return fmt.Errorf("rollout %d baseline lineage is invalid: %w", metadata.Sequence, ErrCorrupt)
			}
			if metadata.PreviousArtifactDigest == metadata.ArtifactDigest {
				baselinePolicy, baselineErr := policyFromMetadata(baseline.Policy, baseline.TargetNodeIDs)
				currentPolicy, currentErr := policyFromMetadata(metadata.Policy, metadata.TargetNodeIDs)
				if baselineErr != nil || currentErr != nil ||
					(slices.Equal(baseline.TargetNodeIDs, metadata.TargetNodeIDs) &&
						rolloutPoliciesEqual(baselinePolicy, currentPolicy)) {
					return fmt.Errorf("rollout %d repeats artifact, targets, and policy: %w", metadata.Sequence, ErrCorrupt)
				}
			}
		} else if metadata.PreviousArtifactDigest == metadata.ArtifactDigest {
			return fmt.Errorf("rollout %d repeats an artifact without a baseline: %w", metadata.Sequence, ErrCorrupt)
		}
		if metadata.Policy != nil && metadata.BaselineRolloutSequence == 0 {
			return fmt.Errorf("rollout %d policy has no baseline sequence: %w", metadata.Sequence, ErrCorrupt)
		}
		if _, err := policyFromMetadata(metadata.Policy, metadata.TargetNodeIDs); err != nil {
			return err
		}
		if len(metadata.ExpectedActiveByNode) != 0 {
			if len(metadata.ExpectedActiveByNode) != len(metadata.TargetNodeIDs) {
				return fmt.Errorf("rollout %d has incomplete per-node expectations: %w", metadata.Sequence, ErrCorrupt)
			}
			for expectedIndex, expected := range metadata.ExpectedActiveByNode {
				if expected.NodeID != metadata.TargetNodeIDs[expectedIndex] ||
					(expected.ArtifactDigest != metadata.ArtifactDigest &&
						expected.ArtifactDigest != metadata.PreviousArtifactDigest) {
					return fmt.Errorf("rollout %d has invalid per-node expectation: %w", metadata.Sequence, ErrCorrupt)
				}
				if _, exists := artifactDigests[expected.ArtifactDigest]; !exists {
					return fmt.Errorf("rollout %d expected artifact is missing: %w", metadata.Sequence, ErrCorrupt)
				}
			}
		}
		rolloutIDs[metadata.ID] = struct{}{}
		rolloutRequests[metadata.RequestID] = struct{}{}
		rolloutSequences[metadata.Sequence] = struct{}{}
	}
	if state.LastRolloutSequence != uint64(len(state.Rollouts)) {
		return fmt.Errorf("last rollout sequence does not match history: %w", ErrCorrupt)
	}
	if state.SelectedRolloutSequence > state.LastRolloutSequence {
		return fmt.Errorf("selected rollout sequence is outside history: %w", ErrCorrupt)
	}
	if state.SelectedRolloutSequence != 0 {
		if _, exists := rolloutSequences[state.SelectedRolloutSequence]; !exists {
			return fmt.Errorf("selected rollout sequence is missing: %w", ErrCorrupt)
		}
	}

	eventIndexes := make(map[uint64]uint64, len(state.Rollouts))
	eventIDs := make(map[uint64]map[string]struct{}, len(state.Rollouts))
	for _, metadata := range state.RolloutEvents {
		if _, exists := rolloutSequences[metadata.RolloutSequence]; !exists {
			return fmt.Errorf("event references missing rollout %d: %w", metadata.RolloutSequence, ErrCorrupt)
		}
		expectedIndex := eventIndexes[metadata.RolloutSequence] + 1
		if metadata.Index != expectedIndex {
			return fmt.Errorf(
				"rollout %d event index %d is not contiguous at %d: %w",
				metadata.RolloutSequence,
				metadata.Index,
				expectedIndex,
				ErrCorrupt,
			)
		}
		if err := validateIdentifier("stored rollout event ID", metadata.EventID); err != nil {
			return fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		if err := validateText("stored rollout event kind", metadata.Kind, 64, true); err != nil {
			return fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		digest, err := ParseDigest(metadata.Digest)
		if err != nil || digest.String() != metadata.Digest || metadata.Size <= 0 ||
			metadata.Size > int64(maxRolloutEventBytes) || metadata.CreatedAt.IsZero() {
			return fmt.Errorf("invalid rollout event metadata %q: %w", metadata.EventID, ErrCorrupt)
		}
		ids := eventIDs[metadata.RolloutSequence]
		if ids == nil {
			ids = make(map[string]struct{})
			eventIDs[metadata.RolloutSequence] = ids
		}
		if _, exists := ids[metadata.EventID]; exists {
			return fmt.Errorf("duplicate rollout event ID %q: %w", metadata.EventID, ErrCorrupt)
		}
		if _, err := repository.readVerifiedFile(
			repository.eventBlobPath(digest),
			digest,
			metadata.Size,
			maxRolloutEventBytes,
		); err != nil {
			return err
		}
		ids[metadata.EventID] = struct{}{}
		eventIndexes[metadata.RolloutSequence] = metadata.Index
	}
	return nil
}

func validateArtifactPayload(metadata artifactMetadata, data []byte) error {
	var compiled bonvoyagev1.Snapshot
	if err := proto.Unmarshal(data, &compiled); err != nil {
		return fmt.Errorf("decode retained snapshot artifact %q: %w: %v", metadata.SnapshotID, ErrCorrupt, err)
	}
	canonical, err := snapshot.MarshalDeterministic(&compiled)
	if err != nil {
		return fmt.Errorf("canonicalize retained snapshot artifact %q: %w", metadata.SnapshotID, err)
	}
	if !bytes.Equal(canonical, data) {
		return fmt.Errorf("snapshot artifact %q is not deterministically encoded: %w", metadata.SnapshotID, ErrCorrupt)
	}
	if compiled.GetSnapshotId() != metadata.SnapshotID ||
		compiled.GetSchemaVersion() != metadata.SchemaVersion ||
		compiled.GetMinimumDataplaneVersion() != metadata.MinimumDataplaneVersion {
		return fmt.Errorf("snapshot artifact %q payload metadata disagrees with index: %w", metadata.SnapshotID, ErrCorrupt)
	}
	return nil
}

func (repository *FileRepository) putBlob(path string, data []byte, maxBytes int) error {
	if len(data) == 0 || len(data) > maxBytes {
		return fmt.Errorf("blob size is outside 1-%d bytes: %w", maxBytes, ErrInvalid)
	}
	digest := Sum(data)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("existing blob has unsafe type or permissions: %w", ErrCorrupt)
		}
		existing, err := repository.readVerifiedFile(path, digest, int64(len(data)), maxBytes)
		if err != nil {
			return err
		}
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("content-addressed blob differs: %w", ErrCorrupt)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect blob path: %w", err)
	}
	return writeFileAtomicPrivate(path, data)
}

func (repository *FileRepository) readVerifiedFile(
	path string,
	digest Digest,
	expectedSize int64,
	maxBytes int,
) ([]byte, error) {
	data, err := readPrivateFile(path, maxBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("immutable blob is missing: %w", ErrCorrupt)
		}
		return nil, err
	}
	if int64(len(data)) != expectedSize || Sum(data) != digest {
		return nil, fmt.Errorf("immutable blob size or digest mismatch: %w", ErrCorrupt)
	}
	return data, nil
}

func ensurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return fmt.Errorf("create private repository directory %q: %w", path, err)
		}
		if err := syncDirectory(filepath.Dir(path)); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect repository directory %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("repository path %q is not a real directory: %w", path, ErrInvalid)
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o700); err != nil {
			return fmt.Errorf("restrict repository directory %q permissions: %w", path, err)
		}
	}
	return nil
}

func ensurePrivateDirectoryTree(path string) error {
	var missing []string
	current := filepath.Clean(path)
	for {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return fmt.Errorf("repository path %q is not a real directory: %w", current, ErrInvalid)
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect repository directory %q: %w", current, err)
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("repository path has no existing ancestor: %w", ErrInvalid)
		}
		current = parent
	}
	for index := len(missing) - 1; index >= 0; index-- {
		if err := ensurePrivateDirectory(missing[index]); err != nil {
			return err
		}
	}
	return ensurePrivateDirectory(path)
}

func readPrivateFile(path string, maxBytes int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("file %q has unsafe type or permissions: %w", path, ErrCorrupt)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open private file %q: %w", path, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("read private file %q: %w", path, err)
	}
	if len(data) > maxBytes {
		return nil, fmt.Errorf("file %q exceeds %d bytes: %w", path, maxBytes, ErrCorrupt)
	}
	return data, nil
}

func writeFileAtomicPrivate(path string, data []byte) (returnErr error) {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".bonvoyage-state-*")
	if err != nil {
		return fmt.Errorf("create temporary repository file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		if returnErr != nil {
			_ = temporary.Close()
		}
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("set temporary repository permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("write temporary repository file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary repository file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary repository file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("atomically replace repository file: %w", err)
	}
	return syncDirectory(directory)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open repository directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync repository directory: %w", err)
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra json.RawMessage
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode trailing repository state: %w: %w", ErrCorrupt, err)
	}
	return fmt.Errorf("repository state contains multiple JSON values: %w", ErrCorrupt)
}
