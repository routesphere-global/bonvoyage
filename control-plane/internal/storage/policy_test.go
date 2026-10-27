package storage

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

func TestNormalizeRolloutPolicyCanonicalizesAndRejectsUnsafeBounds(t *testing.T) {
	policy, err := NormalizeRolloutPolicy(RolloutPolicy{
		Enabled: true, Strategy: RolloutStrategyCanary,
		CanaryNodeIDs:               []string{"node-b", "node-a"},
		MinimumHealthyCanaryPercent: 75,
		CanaryObservationWindow:     30 * time.Second,
		PrepareTimeout:              20 * time.Second,
		ActivationTimeout:           25 * time.Second,
		HeartbeatStaleAfter:         10 * time.Second,
		AutomaticRollback:           true,
	}, []string{"node-a", "node-b", "node-c"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(policy.CanaryNodeIDs, []string{"node-a", "node-b"}) {
		t.Fatalf("canonical canaries = %#v", policy.CanaryNodeIDs)
	}

	tests := map[string]RolloutPolicy{
		"disabled settings": {
			Strategy: RolloutStrategyImmediate,
		},
		"canary is whole fleet": {
			Enabled: true, Strategy: RolloutStrategyCanary,
			CanaryNodeIDs:               []string{"node-a", "node-b", "node-c"},
			MinimumHealthyCanaryPercent: 100, CanaryObservationWindow: time.Second,
			PrepareTimeout: time.Second, ActivationTimeout: time.Second,
			HeartbeatStaleAfter: time.Second,
		},
		"stale window exceeds observation": {
			Enabled: true, Strategy: RolloutStrategyCanary, CanaryNodeIDs: []string{"node-a"},
			MinimumHealthyCanaryPercent: 100, CanaryObservationWindow: 5 * time.Second,
			PrepareTimeout: time.Second, ActivationTimeout: time.Second,
			HeartbeatStaleAfter: 6 * time.Second,
		},
		"deadline below floor": {
			Enabled: true, Strategy: RolloutStrategyImmediate,
			PrepareTimeout: time.Millisecond, ActivationTimeout: time.Second,
		},
	}
	for name, candidate := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NormalizeRolloutPolicy(candidate, []string{"node-a", "node-b", "node-c"}); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestFileRepositoryPersistsSafePolicyAndMixedFleetExpectations(t *testing.T) {
	root := t.TempDir()
	options := deterministicOptions()
	repository := openTestRepository(t, root, options)
	documentV1 := testDesiredDocument(t)
	desiredV1 := createDesired(t, repository, "policy-desired-1", documentV1)
	artifactV1 := createArtifact(t, repository, desiredV1, "0.4.0")
	baseline := allocateRollout(t, repository, RolloutInput{
		RequestID: "policy-rollout-1", ArtifactDigest: artifactV1.Digest,
		DesiredRevisionID: desiredV1.ID, CompilerVersion: "0.4.0",
		TargetNodeIDs: []string{"node-a", "node-b", "node-c"},
		SourceChannel: SourceSystem, Actor: "policy-test", Reason: "baseline",
	})

	documentV2 := bytes.Replace(documentV1, []byte("local-bootstrap"), []byte("policy-candidate"), 1)
	desiredV2 := createDesired(t, repository, "policy-desired-2", documentV2)
	artifactV2 := createArtifact(t, repository, desiredV2, "0.4.0")
	candidate := allocateRollout(t, repository, RolloutInput{
		RequestID: "policy-rollout-2", ArtifactDigest: artifactV2.Digest,
		PreviousArtifactDigest: artifactV1.Digest, BaselineRolloutSequence: baseline.Sequence,
		DesiredRevisionID: desiredV2.ID, CompilerVersion: "0.4.0",
		TargetNodeIDs: []string{"node-c", "node-a", "node-b"},
		Policy: RolloutPolicy{
			Enabled: true, Strategy: RolloutStrategyCanary, CanaryNodeIDs: []string{"node-b", "node-a"},
			MinimumHealthyCanaryPercent: 50, CanaryObservationWindow: 30 * time.Second,
			PrepareTimeout: 20 * time.Second, ActivationTimeout: 25 * time.Second,
			HeartbeatStaleAfter: 10 * time.Second, AutomaticRollback: true,
		},
		SourceChannel: SourceGitOps, Actor: "policy-test", Reason: "safe candidate",
	})
	rollback := allocateRollout(t, repository, RolloutInput{
		RequestID: "policy-rollback-3", ArtifactDigest: artifactV1.Digest,
		PreviousArtifactDigest: artifactV2.Digest, BaselineRolloutSequence: candidate.Sequence,
		DesiredRevisionID: desiredV1.ID, CompilerVersion: "0.4.0",
		TargetNodeIDs: []string{"node-c", "node-b", "node-a"},
		ExpectedActiveByNode: []NodeExpectedArtifact{
			{NodeID: "node-c", ArtifactDigest: artifactV1.Digest},
			{NodeID: "node-a", ArtifactDigest: artifactV2.Digest},
			{NodeID: "node-b", ArtifactDigest: artifactV1.Digest},
		},
		Policy: RolloutPolicy{
			Enabled: true, Strategy: RolloutStrategyImmediate,
			PrepareTimeout: 20 * time.Second, ActivationTimeout: 25 * time.Second,
			AutomaticRollback: true,
		},
		SourceChannel: SourceSystem, Actor: "policy-test", Reason: "exact mixed rollback",
		Kind: RolloutKindRollback, RollbackTargetSequence: baseline.Sequence,
	})
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := openTestRepository(t, root, options)
	t.Cleanup(func() { _ = reopened.Close() })
	restoredCandidate, err := reopened.GetRollout(context.Background(), candidate.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if restoredCandidate.BaselineRolloutSequence != baseline.Sequence ||
		!slices.Equal(restoredCandidate.Policy.CanaryNodeIDs, []string{"node-a", "node-b"}) ||
		!restoredCandidate.Policy.AutomaticRollback {
		t.Fatalf("restored policy rollout = %#v", restoredCandidate)
	}
	restoredRollback, err := reopened.GetRollout(context.Background(), rollback.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if len(restoredRollback.ExpectedActiveByNode) != 3 ||
		restoredRollback.ExpectedActiveByNode[0].NodeID != "node-a" ||
		restoredRollback.ExpectedActiveByNode[0].ArtifactDigest != artifactV2.Digest ||
		restoredRollback.ExpectedActiveByNode[1].ArtifactDigest != artifactV1.Digest {
		t.Fatalf("restored mixed expectations = %#v", restoredRollback.ExpectedActiveByNode)
	}
}
