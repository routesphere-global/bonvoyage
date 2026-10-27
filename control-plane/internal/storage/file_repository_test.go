package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/snapshot"
)

func TestFileRepositoryPersistsLineageAndMonotonicSequences(t *testing.T) {
	root := t.TempDir()
	options := deterministicOptions()
	repository := openTestRepository(t, root, options)
	documentV1 := testDesiredDocument(t)
	desiredV1 := createDesired(t, repository, "desired-request-1", documentV1)

	duplicate, err := repository.CreateDesiredRevision(context.Background(), DesiredRevisionInput{
		RequestID: "desired-request-1", Document: documentV1, SourceChannel: SourceGitOps,
		SourceRevision: "git:abc123", Actor: "operator@example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if duplicate.ID != desiredV1.ID || duplicate.Digest != desiredV1.Digest {
		t.Fatalf("idempotent desired revision changed: got %#v want %#v", duplicate, desiredV1)
	}
	if _, err := repository.CreateDesiredRevision(context.Background(), DesiredRevisionInput{
		RequestID: "desired-request-1", Document: documentV1, SourceChannel: SourceGitOps,
		SourceRevision: "git:different", Actor: "operator@example.test",
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed desired request error = %v", err)
	}

	artifactV1 := createArtifact(t, repository, desiredV1, "0.4.0")
	artifactDuplicate := createArtifact(t, repository, desiredV1, "0.4.0")
	if artifactDuplicate.Digest != artifactV1.Digest {
		t.Fatalf("idempotent artifact changed digest: got %s want %s", artifactDuplicate.Digest, artifactV1.Digest)
	}
	rolloutV1 := allocateRollout(t, repository, RolloutInput{
		RequestID: "rollout-request-1", ArtifactDigest: artifactV1.Digest,
		DesiredRevisionID: desiredV1.ID, CompilerVersion: "0.4.0",
		TargetNodeIDs: []string{"node-b", "node-a"}, SourceChannel: SourceConsole,
		Actor: "operator@example.test", Reason: "activate initial configuration",
	})
	if rolloutV1.Sequence != 1 || !slices.Equal(rolloutV1.TargetNodeIDs, []string{"node-a", "node-b"}) {
		t.Fatalf("first rollout = %#v", rolloutV1)
	}
	rolloutDuplicate := allocateRollout(t, repository, RolloutInput{
		RequestID: "rollout-request-1", ArtifactDigest: artifactV1.Digest,
		DesiredRevisionID: desiredV1.ID, CompilerVersion: "0.4.0",
		TargetNodeIDs: []string{"node-a", "node-b"}, SourceChannel: SourceConsole,
		Actor: "operator@example.test", Reason: "activate initial configuration",
	})
	if rolloutDuplicate.ID != rolloutV1.ID || rolloutDuplicate.Sequence != rolloutV1.Sequence {
		t.Fatalf("idempotent rollout changed: got %#v want %#v", rolloutDuplicate, rolloutV1)
	}
	rolloutByRequest, err := repository.GetRolloutByRequestID(context.Background(), "rollout-request-1")
	if err != nil {
		t.Fatal(err)
	}
	if rolloutByRequest.ID != rolloutV1.ID || rolloutByRequest.Sequence != rolloutV1.Sequence {
		t.Fatalf("rollout request lookup = %#v, want %#v", rolloutByRequest, rolloutV1)
	}
	if _, err := repository.GetRolloutByRequestID(context.Background(), "rollout-request-missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing rollout request error = %v", err)
	}

	documentV2 := bytes.Replace(documentV1, []byte("local-bootstrap"), []byte("local-bootstrap-v2"), 1)
	desiredV2 := createDesired(t, repository, "desired-request-2", documentV2)
	artifactV2 := createArtifact(t, repository, desiredV2, "0.4.0")
	rolloutV2 := allocateRollout(t, repository, RolloutInput{
		RequestID: "rollout-request-2", ArtifactDigest: artifactV2.Digest,
		DesiredRevisionID: desiredV2.ID, CompilerVersion: "0.4.0",
		PreviousArtifactDigest: artifactV1.Digest, TargetNodeIDs: []string{"node-a", "node-b"},
		SourceChannel: SourceCLI, Actor: "operator@example.test", Reason: "activate revision two",
	})
	if rolloutV2.Sequence != 2 || rolloutV2.PreviousArtifactDigest != artifactV1.Digest {
		t.Fatalf("second rollout = %#v", rolloutV2)
	}
	lineage, err := repository.GetLineage(context.Background(), artifactV2.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(lineage.DesiredRevisions) != 1 || lineage.DesiredRevisions[0].ID != desiredV2.ID ||
		lineage.Artifact.Digest != artifactV2.Digest ||
		len(lineage.Rollouts) != 1 || lineage.Rollouts[0].Sequence != 2 {
		t.Fatalf("lineage = %#v", lineage)
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := openTestRepository(t, root, options)
	t.Cleanup(func() { _ = reopened.Close() })
	lastSequence, err := reopened.LastRolloutSequence(context.Background())
	if err != nil || lastSequence != 2 {
		t.Fatalf("last sequence = %d, err=%v", lastSequence, err)
	}
	restored, err := reopened.GetSnapshotArtifact(context.Background(), artifactV2.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored.Bytes, artifactV2.Bytes) || len(restored.Compilations) != 1 ||
		restored.Compilations[0].DesiredRevisionID != desiredV2.ID {
		t.Fatalf("restored artifact = %#v", restored)
	}
	assertPrivateMode(t, filepath.Join(root, stateFileName), 0o600)
	assertPrivateMode(t, reopened.snapshotBlobPath(artifactV2.Digest), 0o600)
	assertPrivateMode(t, root, 0o700)
}

func TestFileRepositoryAllowsSameArtifactForChangedTargets(t *testing.T) {
	repository := openTestRepository(t, t.TempDir(), deterministicOptions())
	desired := createDesired(t, repository, "target-change-desired", testDesiredDocument(t))
	artifact := createArtifact(t, repository, desired, "0.4.0")
	baseline := allocateRollout(t, repository, RolloutInput{
		RequestID: "target-change-baseline", ArtifactDigest: artifact.Digest,
		DesiredRevisionID: desired.ID, CompilerVersion: "0.4.0",
		TargetNodeIDs: []string{"node-a"}, SourceChannel: SourceConsole,
		Actor: "operator@example.test", Reason: "initial target",
	})
	replacement := allocateRollout(t, repository, RolloutInput{
		RequestID: "target-change-rollout", ArtifactDigest: artifact.Digest,
		PreviousArtifactDigest: artifact.Digest, BaselineRolloutSequence: baseline.Sequence,
		DesiredRevisionID: desired.ID, CompilerVersion: "0.4.0",
		TargetNodeIDs: []string{"node-a", "node-b"}, SourceChannel: SourceConsole,
		Actor: "operator@example.test", Reason: "add replacement target",
	})
	if replacement.Sequence != baseline.Sequence+1 || replacement.ArtifactDigest != artifact.Digest ||
		!slices.Equal(replacement.TargetNodeIDs, []string{"node-a", "node-b"}) {
		t.Fatalf("target-only rollout = %#v", replacement)
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTestRepository(t, repository.root, deterministicOptions())
	t.Cleanup(func() { _ = reopened.Close() })
	if _, err := reopened.GetRollout(context.Background(), replacement.Sequence); err != nil {
		t.Fatalf("reopen target-only rollout: %v", err)
	}
}

func TestFileRepositoryRetainsManyToOneCompilationLineage(t *testing.T) {
	root := t.TempDir()
	repository := openTestRepository(t, root, deterministicOptions())
	documentV1 := testDesiredDocument(t)
	documentV2 := append([]byte("# semantically equivalent source revision\n"), documentV1...)
	desiredV1 := createDesired(t, repository, "desired-equivalent-1", documentV1)
	sameBytesDesired := createDesired(t, repository, "desired-equivalent-same-bytes", documentV1)
	if sameBytesDesired.ID == desiredV1.ID || sameBytesDesired.Digest != desiredV1.Digest {
		t.Fatalf("shared desired-state blob identity = first=%#v second=%#v", desiredV1, sameBytesDesired)
	}
	desiredV2 := createDesired(t, repository, "desired-equivalent-2", documentV2)
	artifactV1 := createArtifact(t, repository, desiredV1, "0.4.0")
	artifactV2 := createArtifact(t, repository, desiredV2, "0.4.1")

	if artifactV1.Digest != artifactV2.Digest || len(artifactV2.Compilations) != 2 {
		t.Fatalf("equivalent compilations did not share one artifact: first=%#v second=%#v", artifactV1, artifactV2)
	}
	if artifactV2.Compilations[0].DesiredRevisionID != desiredV1.ID ||
		artifactV2.Compilations[1].DesiredRevisionID != desiredV2.ID {
		t.Fatalf("compilation lineage = %#v", artifactV2.Compilations)
	}
	duplicate := createArtifact(t, repository, desiredV2, "0.4.1")
	if len(duplicate.Compilations) != 2 {
		t.Fatalf("idempotent compilation added lineage: %#v", duplicate.Compilations)
	}
	if _, err := repository.AllocateRollout(context.Background(), RolloutInput{
		RequestID: "rollout-wrong-lineage", ArtifactDigest: artifactV2.Digest,
		DesiredRevisionID: desiredV1.ID, CompilerVersion: "0.4.1",
		TargetNodeIDs: []string{"node-a"}, SourceChannel: SourceAPI,
		Actor: "operator@example.test", Reason: "invalid desired/compiler pair",
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("unrecorded compilation lineage error = %v", err)
	}
	rollout := allocateRollout(t, repository, RolloutInput{
		RequestID: "rollout-equivalent-2", ArtifactDigest: artifactV2.Digest,
		DesiredRevisionID: desiredV2.ID, CompilerVersion: "0.4.1",
		TargetNodeIDs: []string{"node-a"}, SourceChannel: SourceAPI,
		Actor: "operator@example.test", Reason: "activate equivalent revision",
	})
	storedRollout, err := repository.GetRollout(context.Background(), rollout.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if storedRollout.DesiredRevisionID != desiredV2.ID || storedRollout.CompilerVersion != "0.4.1" {
		t.Fatalf("stored rollout provenance = %#v", storedRollout)
	}
	lineage, err := repository.GetLineage(context.Background(), artifactV2.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(lineage.DesiredRevisions) != 2 || len(lineage.Artifact.Compilations) != 2 ||
		len(lineage.Rollouts) != 1 {
		t.Fatalf("many-to-one lineage = %#v", lineage)
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := openTestRepository(t, root, deterministicOptions())
	t.Cleanup(func() { _ = reopened.Close() })
	restored, err := reopened.GetLineage(context.Background(), artifactV2.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.DesiredRevisions) != 2 || len(restored.Artifact.Compilations) != 2 ||
		restored.Rollouts[0].DesiredRevisionID != desiredV2.ID {
		t.Fatalf("restored many-to-one lineage = %#v", restored)
	}
}

func TestFileRepositoryAtomicallySelectsApplyAndExactRollback(t *testing.T) {
	root := t.TempDir()
	repository := openTestRepository(t, root, deterministicOptions())
	documentV1 := testDesiredDocument(t)
	desiredV1 := createDesired(t, repository, "selected-desired-1", documentV1)
	artifactV1 := createArtifact(t, repository, desiredV1, "0.4.0")
	rolloutV1 := allocateRollout(t, repository, RolloutInput{
		RequestID: "selected-rollout-1", ArtifactDigest: artifactV1.Digest,
		DesiredRevisionID: desiredV1.ID, CompilerVersion: "0.4.0",
		TargetNodeIDs: []string{"node-a"}, SourceChannel: SourceSystem,
		Actor: "selection-test", Reason: "bootstrap runtime authority",
	})
	if _, err := repository.InitializeSelectedRollout(context.Background(), rolloutV1.Sequence); err != nil {
		t.Fatal(err)
	}

	documentV2 := bytes.Replace(documentV1, []byte("local-bootstrap"), []byte("selected-v2"), 1)
	desiredV2 := createDesired(t, repository, "selected-desired-2", documentV2)
	artifactV2 := createArtifact(t, repository, desiredV2, "0.4.0")
	rolloutV2 := allocateRollout(t, repository, RolloutInput{
		RequestID: "selected-rollout-2", ArtifactDigest: artifactV2.Digest,
		PreviousArtifactDigest: artifactV1.Digest,
		DesiredRevisionID:      desiredV2.ID, CompilerVersion: "0.4.0",
		TargetNodeIDs: []string{"node-a"}, SourceChannel: SourceGitOps,
		Actor: "spiffe://admin.test/service-accounts/deployer", Reason: "apply revision two",
	})
	appendStartedEvent(t, repository, rolloutV2.Sequence, "selected-start-2")
	if _, err := repository.SelectRollout(context.Background(), rolloutV1.Sequence, rolloutV2.Sequence); err != nil {
		t.Fatal(err)
	}
	selected, err := repository.GetSelectedRollout(context.Background())
	if err != nil || selected.Sequence != rolloutV2.Sequence || selected.Kind != RolloutKindApply {
		t.Fatalf("selected apply = %#v, err=%v", selected, err)
	}
	stale := allocateRollout(t, repository, RolloutInput{
		RequestID: "stale-selected-rollout", ArtifactDigest: artifactV1.Digest,
		PreviousArtifactDigest: artifactV2.Digest,
		DesiredRevisionID:      desiredV1.ID, CompilerVersion: "0.4.0",
		TargetNodeIDs: []string{"node-a"}, SourceChannel: SourceAPI,
		Actor: "selection-test", Reason: "stale write",
	})
	appendStartedEvent(t, repository, stale.Sequence, "stale-selected-start")
	if _, err := repository.SelectRollout(context.Background(), rolloutV1.Sequence, stale.Sequence); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale selection error = %v", err)
	}

	rollback := allocateRollout(t, repository, RolloutInput{
		RequestID: "selected-rollback-1", ArtifactDigest: artifactV1.Digest,
		PreviousArtifactDigest: artifactV2.Digest,
		DesiredRevisionID:      desiredV1.ID, CompilerVersion: "0.4.0",
		TargetNodeIDs: []string{"node-a"}, SourceChannel: SourceAPI,
		Actor: "spiffe://admin.test/operators/alice", Reason: "restore revision one",
		Kind: RolloutKindRollback, RollbackTargetSequence: rolloutV1.Sequence,
	})
	appendStartedEvent(t, repository, rollback.Sequence, "selected-rollback-start")
	if _, err := repository.SelectRollout(context.Background(), rolloutV2.Sequence, rollback.Sequence); err != nil {
		t.Fatal(err)
	}
	if rollback.Kind != RolloutKindRollback || rollback.RollbackTargetSequence != rolloutV1.Sequence {
		t.Fatalf("rollback lineage = %#v", rollback)
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := openTestRepository(t, root, deterministicOptions())
	t.Cleanup(func() { _ = reopened.Close() })
	selected, err = reopened.GetSelectedRollout(context.Background())
	if err != nil || selected.Sequence != rollback.Sequence || selected.RollbackTargetSequence != rolloutV1.Sequence {
		t.Fatalf("reopened selection = %#v, err=%v", selected, err)
	}
}

func TestFileRepositoryRejectsInvalidLineageAndNoOpRollout(t *testing.T) {
	repository := openTestRepository(t, t.TempDir(), deterministicOptions())
	t.Cleanup(func() { _ = repository.Close() })
	invalid := append(testDesiredDocument(t), []byte("unknown_top_level: true\n")...)
	if _, err := repository.CreateDesiredRevision(context.Background(), DesiredRevisionInput{
		RequestID: "invalid-desired", Document: invalid, SourceChannel: SourceFile, Actor: "test",
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid desired state error = %v", err)
	}

	desired := createDesired(t, repository, "desired-valid", testDesiredDocument(t))
	wrongDocument := bytes.Replace(desired.Document, []byte("local-bootstrap"), []byte("wrong-artifact"), 1)
	wrongBytes := compileDocument(t, wrongDocument)
	if _, err := repository.CreateSnapshotArtifact(context.Background(), SnapshotArtifactInput{
		DesiredRevisionID: desired.ID, CompilerVersion: "0.4.0", Bytes: wrongBytes,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong artifact lineage error = %v", err)
	}
	artifact := createArtifact(t, repository, desired, "0.4.0")
	if _, err := repository.AllocateRollout(context.Background(), RolloutInput{
		RequestID: "rollout-no-op", ArtifactDigest: artifact.Digest,
		DesiredRevisionID: desired.ID, CompilerVersion: "0.4.0",
		PreviousArtifactDigest: artifact.Digest, TargetNodeIDs: []string{"node-a"},
		SourceChannel: SourceAPI, Actor: "test", Reason: "no-op",
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no-op rollout error = %v", err)
	}
	if _, err := repository.AllocateRollout(context.Background(), RolloutInput{
		RequestID: "rollout-missing", ArtifactDigest: Sum([]byte("missing")),
		DesiredRevisionID: desired.ID, CompilerVersion: "0.4.0",
		TargetNodeIDs: []string{"node-a"}, SourceChannel: SourceAPI, Actor: "test", Reason: "missing",
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing artifact error = %v", err)
	}
}

func TestFileRepositoryValidatesPublicInputsAndConflicts(t *testing.T) {
	if _, err := OpenFileRepository(" ", deterministicOptions()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty repository path error = %v", err)
	}
	nestedRoot := filepath.Join(t.TempDir(), "one", "two", "repository")
	nested := openTestRepository(t, nestedRoot, deterministicOptions())
	if err := nested.Close(); err != nil {
		t.Fatal(err)
	}

	repository := openTestRepository(t, t.TempDir(), deterministicOptions())
	validDocument := testDesiredDocument(t)
	invalidDesired := []DesiredRevisionInput{
		{RequestID: "-invalid", Document: validDocument, SourceChannel: SourceFile, Actor: "test"},
		{RequestID: "empty-document", SourceChannel: SourceFile, Actor: "test"},
		{RequestID: "bad-channel", Document: validDocument, SourceChannel: "unknown", Actor: "test"},
		{RequestID: "bad-source-revision", Document: validDocument, SourceChannel: SourceFile, SourceRevision: "bad\nrevision", Actor: "test"},
		{RequestID: "empty-actor", Document: validDocument, SourceChannel: SourceFile},
	}
	for _, input := range invalidDesired {
		if _, err := repository.CreateDesiredRevision(context.Background(), input); !errors.Is(err, ErrInvalid) {
			t.Errorf("invalid desired input %#v error = %v", input, err)
		}
	}
	if _, err := repository.GetDesiredRevision(context.Background(), ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty desired revision ID error = %v", err)
	}

	desired := createDesired(t, repository, "desired-validation", validDocument)
	artifact := createArtifact(t, repository, desired, "0.4.0")
	if _, err := repository.CreateSnapshotArtifact(context.Background(), SnapshotArtifactInput{
		DesiredRevisionID: desired.ID, CompilerVersion: "0.4.0",
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty artifact error = %v", err)
	}
	if _, err := repository.CreateSnapshotArtifact(context.Background(), SnapshotArtifactInput{
		DesiredRevisionID: "dsr_missing", CompilerVersion: "0.4.0", Bytes: artifact.Bytes,
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing artifact source error = %v", err)
	}
	if _, err := repository.CreateSnapshotArtifact(context.Background(), SnapshotArtifactInput{
		DesiredRevisionID: desired.ID, CompilerVersion: "bad\nversion", Bytes: artifact.Bytes,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid compiler version error = %v", err)
	}
	collisionDocument := bytes.Replace(validDocument, []byte("ready\\n"), []byte("different\\n"), 1)
	collisionDesired := createDesired(t, repository, "desired-snapshot-id-collision", collisionDocument)
	if _, err := repository.CreateSnapshotArtifact(context.Background(), SnapshotArtifactInput{
		DesiredRevisionID: collisionDesired.ID,
		CompilerVersion:   "0.4.0",
		Bytes:             compileDocument(t, collisionDocument),
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("snapshot ID collision error = %v", err)
	}
	if _, err := repository.GetSnapshotArtifact(context.Background(), Digest{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero artifact digest error = %v", err)
	}
	if _, err := repository.GetSnapshotArtifact(context.Background(), Sum([]byte("unknown"))); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing artifact error = %v", err)
	}
	if _, err := repository.GetLineage(context.Background(), Digest{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero lineage digest error = %v", err)
	}
	if _, err := repository.GetLineage(context.Background(), Sum([]byte("unknown"))); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing lineage error = %v", err)
	}

	validRollout := RolloutInput{
		RequestID: "rollout-validation", ArtifactDigest: artifact.Digest,
		DesiredRevisionID: desired.ID, CompilerVersion: "0.4.0",
		TargetNodeIDs: []string{"node-a"}, SourceChannel: SourceAPI,
		Actor: "test", Reason: "validate public inputs",
	}
	invalidRollouts := []RolloutInput{
		func() RolloutInput { value := validRollout; value.RequestID = "-invalid"; return value }(),
		func() RolloutInput { value := validRollout; value.ArtifactDigest = Digest{}; return value }(),
		func() RolloutInput { value := validRollout; value.DesiredRevisionID = "-invalid"; return value }(),
		func() RolloutInput { value := validRollout; value.CompilerVersion = ""; return value }(),
		func() RolloutInput { value := validRollout; value.SourceChannel = "unknown"; return value }(),
		func() RolloutInput { value := validRollout; value.Actor = ""; return value }(),
		func() RolloutInput { value := validRollout; value.Reason = ""; return value }(),
		func() RolloutInput { value := validRollout; value.TargetNodeIDs = nil; return value }(),
		func() RolloutInput {
			value := validRollout
			value.TargetNodeIDs = []string{"node-a", "node-a"}
			return value
		}(),
		func() RolloutInput { value := validRollout; value.TargetNodeIDs = []string{"-invalid"}; return value }(),
	}
	for _, input := range invalidRollouts {
		if _, err := repository.AllocateRollout(context.Background(), input); !errors.Is(err, ErrInvalid) {
			t.Errorf("invalid rollout input %#v error = %v", input, err)
		}
	}
	missingPrevious := validRollout
	missingPrevious.RequestID = "rollout-missing-previous"
	missingPrevious.PreviousArtifactDigest = Sum([]byte("missing previous"))
	if _, err := repository.AllocateRollout(context.Background(), missingPrevious); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing previous artifact error = %v", err)
	}
	created := allocateRollout(t, repository, validRollout)
	changed := validRollout
	changed.Reason = "changed retry"
	if _, err := repository.AllocateRollout(context.Background(), changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed rollout retry error = %v", err)
	}
	if _, err := repository.GetRollout(context.Background(), 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero rollout sequence error = %v", err)
	}
	if _, err := repository.GetRollout(context.Background(), created.Sequence+1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing rollout sequence error = %v", err)
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}
	if err := repository.Close(); err != nil {
		t.Fatalf("second close error = %v", err)
	}
}

func TestFileRepositoryExclusiveLockAndClosedState(t *testing.T) {
	root := t.TempDir()
	repository := openTestRepository(t, root, deterministicOptions())
	if _, err := OpenFileRepository(root, deterministicOptions()); !errors.Is(err, ErrLocked) {
		t.Fatalf("second open error = %v", err)
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.LastRolloutSequence(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed repository error = %v", err)
	}
	reopened := openTestRepository(t, root, deterministicOptions())
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFileRepositoryDetectsBlobAndStateCorruption(t *testing.T) {
	t.Run("blob", func(t *testing.T) {
		root := t.TempDir()
		repository := openTestRepository(t, root, deterministicOptions())
		desired := createDesired(t, repository, "desired-corruption", testDesiredDocument(t))
		artifact := createArtifact(t, repository, desired, "0.4.0")
		artifactPath := repository.snapshotBlobPath(artifact.Digest)
		if err := repository.Close(); err != nil {
			t.Fatal(err)
		}
		corrupt := append([]byte(nil), artifact.Bytes...)
		corrupt[len(corrupt)/2] ^= 0xff
		if err := os.WriteFile(artifactPath, corrupt, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFileRepository(root, deterministicOptions()); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("corrupt blob open error = %v", err)
		}
	})

	t.Run("state checksum", func(t *testing.T) {
		root := t.TempDir()
		repository := openTestRepository(t, root, deterministicOptions())
		if err := repository.Close(); err != nil {
			t.Fatal(err)
		}
		statePath := filepath.Join(root, stateFileName)
		state, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		state = bytes.Replace(state, []byte(`"generation": 1`), []byte(`"generation": 2`), 1)
		if err := os.WriteFile(statePath, state, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFileRepository(root, deterministicOptions()); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("corrupt state open error = %v", err)
		}
	})

	t.Run("trailing state", func(t *testing.T) {
		root := t.TempDir()
		repository := openTestRepository(t, root, deterministicOptions())
		if err := repository.Close(); err != nil {
			t.Fatal(err)
		}
		statePath := filepath.Join(root, stateFileName)
		state, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(statePath, append(state, []byte("{}")...), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFileRepository(root, deterministicOptions()); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("trailing state open error = %v", err)
		}
	})

	t.Run("unsafe state permissions", func(t *testing.T) {
		root := t.TempDir()
		repository := openTestRepository(t, root, deterministicOptions())
		if err := repository.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(root, stateFileName), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFileRepository(root, deterministicOptions()); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("unsafe state permissions error = %v", err)
		}
	})
}

func TestFileRepositoryRejectsPersistedStateInvariantViolations(t *testing.T) {
	repository := openTestRepository(t, t.TempDir(), deterministicOptions())
	t.Cleanup(func() { _ = repository.Close() })
	desired := createDesired(t, repository, "desired-state-invariants", testDesiredDocument(t))
	artifact := createArtifact(t, repository, desired, "0.4.0")
	allocateRollout(t, repository, RolloutInput{
		RequestID: "rollout-state-invariants", ArtifactDigest: artifact.Digest,
		DesiredRevisionID: desired.ID, CompilerVersion: "0.4.0",
		TargetNodeIDs: []string{"node-a", "node-b"}, SourceChannel: SourceSystem,
		Actor: "state-test", Reason: "establish valid persisted state",
	})

	tests := []struct {
		name   string
		mutate func(*persistedState)
	}{
		{"header", func(state *persistedState) { state.SchemaVersion = 0 }},
		{"duplicate desired ID", func(state *persistedState) {
			state.DesiredRevisions = append(state.DesiredRevisions, state.DesiredRevisions[0])
		}},
		{"duplicate desired request", func(state *persistedState) {
			duplicate := state.DesiredRevisions[0]
			duplicate.ID = "dsr_duplicate"
			state.DesiredRevisions = append(state.DesiredRevisions, duplicate)
		}},
		{"noncanonical desired digest", func(state *persistedState) {
			state.DesiredRevisions[0].Digest = strings.ToUpper(state.DesiredRevisions[0].Digest)
		}},
		{"desired source", func(state *persistedState) { state.DesiredRevisions[0].SourceChannel = "unknown" }},
		{"desired actor", func(state *persistedState) { state.DesiredRevisions[0].Actor = "" }},
		{"duplicate artifact digest", func(state *persistedState) {
			state.SnapshotArtifacts = append(state.SnapshotArtifacts, state.SnapshotArtifacts[0])
		}},
		{"artifact size", func(state *persistedState) { state.SnapshotArtifacts[0].Size = 0 }},
		{"artifact payload metadata", func(state *persistedState) { state.SnapshotArtifacts[0].SnapshotID = "different-valid-id" }},
		{"artifact has no lineage", func(state *persistedState) { state.SnapshotArtifacts[0].Compilations = nil }},
		{"artifact source missing", func(state *persistedState) {
			state.SnapshotArtifacts[0].Compilations[0].DesiredRevisionID = "dsr_missing"
		}},
		{"artifact compiler", func(state *persistedState) { state.SnapshotArtifacts[0].Compilations[0].CompilerVersion = "" }},
		{"artifact compilation date", func(state *persistedState) { state.SnapshotArtifacts[0].Compilations[0].CreatedAt = time.Time{} }},
		{"duplicate compilation", func(state *persistedState) {
			state.SnapshotArtifacts[0].Compilations = append(
				state.SnapshotArtifacts[0].Compilations,
				state.SnapshotArtifacts[0].Compilations[0],
			)
		}},
		{"rollout sequence", func(state *persistedState) { state.Rollouts[0].Sequence = 2 }},
		{"rollout target missing", func(state *persistedState) { state.Rollouts[0].ArtifactDigest = Sum([]byte("missing")).String() }},
		{"rollout previous same", func(state *persistedState) {
			state.Rollouts[0].PreviousArtifactDigest = state.Rollouts[0].ArtifactDigest
		}},
		{"rollout lineage", func(state *persistedState) { state.Rollouts[0].CompilerVersion = "different" }},
		{"rollout actor", func(state *persistedState) { state.Rollouts[0].Actor = "" }},
		{"rollout targets unsorted", func(state *persistedState) { state.Rollouts[0].TargetNodeIDs = []string{"node-b", "node-a"} }},
		{"rollout targets duplicate", func(state *persistedState) { state.Rollouts[0].TargetNodeIDs = []string{"node-a", "node-a"} }},
		{"last sequence", func(state *persistedState) { state.LastRolloutSequence = 2 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := cloneState(repository.state)
			test.mutate(&state)
			if err := repository.validateState(state); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("validateState error = %v", err)
			}
		})
	}
}

func TestFileRepositoryIgnoresUnpublishedCrashResidue(t *testing.T) {
	root := t.TempDir()
	repository := openTestRepository(t, root, deterministicOptions())
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".bonvoyage-state-interrupted"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	orphan := []byte("orphan snapshot bytes")
	orphanDigest := Sum(orphan)
	orphanPath := filepath.Join(root, "blobs", "snapshots", "sha256", orphanDigest.String()+".pb")
	if err := os.WriteFile(orphanPath, orphan, 0o600); err != nil {
		t.Fatal(err)
	}
	reopened := openTestRepository(t, root, deterministicOptions())
	t.Cleanup(func() { _ = reopened.Close() })
	if _, err := reopened.GetSnapshotArtifact(context.Background(), orphanDigest); !errors.Is(err, ErrNotFound) {
		t.Fatalf("orphan became published: %v", err)
	}
}

func TestFileRepositoryAllocatesConcurrentSequencesExactlyOnce(t *testing.T) {
	repository := openTestRepository(t, t.TempDir(), deterministicOptions())
	t.Cleanup(func() { _ = repository.Close() })
	desired := createDesired(t, repository, "desired-concurrent", testDesiredDocument(t))
	artifact := createArtifact(t, repository, desired, "0.4.0")

	const count = 24
	sequences := make(chan uint64, count)
	errorsSeen := make(chan error, count)
	var wait sync.WaitGroup
	for index := range count {
		wait.Add(1)
		go func() {
			defer wait.Done()
			record, err := repository.AllocateRollout(context.Background(), RolloutInput{
				RequestID: fmt.Sprintf("concurrent-%02d", index), ArtifactDigest: artifact.Digest,
				DesiredRevisionID: desired.ID, CompilerVersion: "0.4.0",
				TargetNodeIDs: []string{"node-a"}, SourceChannel: SourceSystem,
				Actor: "concurrency-test", Reason: "prove atomic sequence allocation",
			})
			if err != nil {
				errorsSeen <- err
				return
			}
			sequences <- record.Sequence
		}()
	}
	wait.Wait()
	close(sequences)
	close(errorsSeen)
	for err := range errorsSeen {
		t.Error(err)
	}
	seen := make(map[uint64]struct{}, count)
	for sequence := range sequences {
		seen[sequence] = struct{}{}
	}
	if len(seen) != count {
		t.Fatalf("unique sequence count = %d, want %d", len(seen), count)
	}
	for sequence := uint64(1); sequence <= count; sequence++ {
		if _, exists := seen[sequence]; !exists {
			t.Errorf("missing sequence %d", sequence)
		}
	}
}

func TestFileRepositoryContextAndPathSafety(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	repository := openTestRepository(t, t.TempDir(), deterministicOptions())
	t.Cleanup(func() { _ = repository.Close() })
	if _, err := repository.LastRolloutSequence(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error = %v", err)
	}
	if _, err := repository.LastRolloutSequence(nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil context error = %v", err)
	}
	if _, err := repository.GetDesiredRevision(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing revision error = %v", err)
	}

	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileRepository(link, deterministicOptions()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("symlink repository error = %v", err)
	}

	lockRoot := t.TempDir()
	lockTarget := filepath.Join(t.TempDir(), "lock-target")
	if err := os.WriteFile(lockTarget, []byte("do not follow"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(lockTarget, filepath.Join(lockRoot, lockFileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileRepository(lockRoot, deterministicOptions()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("symlink repository lock error = %v", err)
	}
}

func createDesired(t *testing.T, repository Repository, requestID string, document []byte) DesiredRevision {
	t.Helper()
	revision, err := repository.CreateDesiredRevision(context.Background(), DesiredRevisionInput{
		RequestID: requestID, Document: document, SourceChannel: SourceGitOps,
		SourceRevision: "git:abc123", Actor: "operator@example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return revision
}

func createArtifact(t *testing.T, repository Repository, desired DesiredRevision, compilerVersion string) SnapshotArtifact {
	t.Helper()
	artifact, err := repository.CreateSnapshotArtifact(context.Background(), SnapshotArtifactInput{
		DesiredRevisionID: desired.ID,
		CompilerVersion:   compilerVersion,
		Bytes:             compileDocument(t, desired.Document),
	})
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func allocateRollout(t *testing.T, repository Repository, input RolloutInput) RolloutRecord {
	t.Helper()
	record, err := repository.AllocateRollout(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func appendStartedEvent(t *testing.T, repository Repository, sequence uint64, eventID string) {
	t.Helper()
	payload := []byte(`{"version":1,"kind":"START"}`)
	if _, err := repository.AppendRolloutEvent(context.Background(), RolloutEventInput{
		RolloutSequence: sequence, ExpectedPreviousIndex: 0,
		EventID: eventID, Kind: "START", Payload: payload,
	}); err != nil {
		t.Fatal(err)
	}
}

func compileDocument(t *testing.T, document []byte) []byte {
	t.Helper()
	compiled, err := snapshot.Compile(bytes.NewReader(document))
	if err != nil {
		t.Fatal(err)
	}
	data, err := snapshot.MarshalDeterministic(compiled)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func testDesiredDocument(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "..", "config", "examples", "local.yaml")
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func openTestRepository(t *testing.T, root string, options FileOptions) *FileRepository {
	t.Helper()
	repository, err := OpenFileRepository(root, options)
	if err != nil {
		t.Fatal(err)
	}
	return repository
}

func deterministicOptions() FileOptions {
	return FileOptions{
		Clock:  newTestClock(),
		Random: &counterReader{},
	}
}

func newTestClock() func() time.Time {
	var lock sync.Mutex
	now := time.Date(2026, time.September, 22, 0, 0, 0, 0, time.UTC)
	return func() time.Time {
		lock.Lock()
		defer lock.Unlock()
		result := now
		now = now.Add(time.Second)
		return result
	}
}

type counterReader struct {
	mu   sync.Mutex
	next uint64
}

func (reader *counterReader) Read(target []byte) (int, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	written := 0
	for written < len(target) {
		reader.next++
		var counter [8]byte
		binary.BigEndian.PutUint64(counter[:], reader.next)
		digest := sha256.Sum256(counter[:])
		written += copy(target[written:], digest[:])
	}
	return len(target), nil
}

func assertPrivateMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %o", path, got, want)
	}
}
