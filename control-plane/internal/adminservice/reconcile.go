package adminservice

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/discovery"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/rollout"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/rolloutservice"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
)

// Cancel durably stops a selected rollout before any activation command has
// been emitted. Once activation starts, the only safe outcome is a new exact
// rollback sequence.
func (service *Service) Cancel(
	ctx context.Context,
	principal Principal,
	input CancelInput,
) (MutationResult, error) {
	if err := requirePermission(principal, permissionCancel); err != nil {
		return MutationResult{}, err
	}
	if err := validateText("request ID", input.RequestID, 128, true); err != nil ||
		input.Sequence == 0 {
		return MutationResult{}, ErrInvalidInput
	}
	if err := validateText("cancellation reason", input.Reason, 1024, true); err != nil {
		return MutationResult{}, err
	}
	if err := contextError(ctx); err != nil {
		return MutationResult{}, err
	}

	service.mutationMu.Lock()
	defer service.mutationMu.Unlock()
	selection, err := service.runtime.CurrentRollout()
	if err != nil {
		return MutationResult{}, err
	}
	if selection.Sequence != input.Sequence {
		return MutationResult{}, ErrPrecondition
	}
	selection, err = service.runtime.CancelRollout(
		ctx, input.Sequence, "cancel."+input.RequestID, rolloutservice.CancellationInput{
			Reason:        input.Reason,
			Actor:         principal.Actor,
			SourceChannel: principal.SourceChannel,
		},
	)
	if err != nil {
		return MutationResult{}, err
	}
	status, err := service.status(ctx, selection.Sequence)
	if err != nil {
		return MutationResult{}, err
	}
	return MutationResult{APIVersion: APIVersion, Replayed: selection.Replayed, Status: status}, nil
}

// ReconcilePolicy runs one bounded policy evaluation and, when enabled,
// creates an exact automatic rollback only after every target node has
// reconciled an unambiguous active artifact.
func (service *Service) ReconcilePolicy(
	ctx context.Context,
	observedAt time.Time,
) (PolicyReconcileResult, error) {
	if err := contextError(ctx); err != nil {
		return PolicyReconcileResult{}, err
	}
	service.mutationMu.Lock()
	defer service.mutationMu.Unlock()
	evaluation, err := service.runtime.EvaluateRollout(ctx, observedAt.UTC().Round(0))
	if err != nil {
		return PolicyReconcileResult{}, err
	}
	result := PolicyReconcileResult{Evaluation: evaluation}
	selection, err := service.runtime.CurrentRollout()
	if err != nil {
		return result, err
	}
	selected, err := service.repository.GetSelectedRollout(ctx)
	if err != nil {
		return result, err
	}
	if selection.Sequence != selected.Sequence {
		return result, ErrAuthorityMismatch
	}
	if selection.Phase != rollout.PhaseRequiresRollback || !selected.Policy.AutomaticRollback {
		return result, nil
	}
	mutation, err := service.automaticRollbackLocked(ctx, selected, evaluation.Reason)
	if err != nil {
		return result, err
	}
	result.AutomaticRollback = &mutation
	return result, nil
}

func (service *Service) automaticRollbackLocked(
	ctx context.Context,
	failed storage.RolloutRecord,
	policyReason string,
) (MutationResult, error) {
	if failed.BaselineRolloutSequence == 0 {
		return MutationResult{}, fmt.Errorf("failed rollout has no rollback baseline: %w", storage.ErrCorrupt)
	}
	target, err := service.repository.GetRollout(ctx, failed.BaselineRolloutSequence)
	if err != nil {
		return MutationResult{}, err
	}
	expected, err := service.mixedRollbackExpectations(
		ctx, failed, target, service.runtime.Connections(),
	)
	if err != nil {
		return MutationResult{}, err
	}
	requestID := fmt.Sprintf("auto-rollback-%d", failed.Sequence)
	reason := fmt.Sprintf("automatic exact rollback of rollout %d", failed.Sequence)
	if policyReason != "" {
		reason += ": " + policyReason
	}
	if len(reason) > 1024 {
		reason = reason[:1024]
	}
	rollbackPolicy := storage.RolloutPolicy{
		Enabled: true, Strategy: storage.RolloutStrategyImmediate,
		PrepareTimeout:    failed.Policy.PrepareTimeout,
		ActivationTimeout: failed.Policy.ActivationTimeout,
	}
	requestDigest, err := mutationDigest(struct {
		Kind           string                         `json:"kind"`
		FailedSequence uint64                         `json:"failed_sequence"`
		TargetSequence uint64                         `json:"target_sequence"`
		TargetNodes    []string                       `json:"target_nodes"`
		Expected       []storage.NodeExpectedArtifact `json:"expected"`
		Reason         string                         `json:"reason"`
	}{
		Kind: "AUTO_ROLLBACK", FailedSequence: failed.Sequence,
		TargetSequence: target.Sequence, TargetNodes: failed.TargetNodeIDs,
		Expected: expected, Reason: reason,
	})
	if err != nil {
		return MutationResult{}, err
	}
	existing, existingErr := service.repository.GetRolloutByRequestID(ctx, requestID)
	if existingErr != nil && !errors.Is(existingErr, storage.ErrNotFound) {
		return MutationResult{}, existingErr
	}
	record, err := service.repository.AllocateRollout(ctx, storage.RolloutInput{
		RequestID: requestID, RequestDigest: requestDigest,
		ArtifactDigest: target.ArtifactDigest, PreviousArtifactDigest: failed.ArtifactDigest,
		BaselineRolloutSequence: failed.Sequence,
		DesiredRevisionID:       target.DesiredRevisionID, CompilerVersion: target.CompilerVersion,
		TargetNodeIDs:        append([]string(nil), failed.TargetNodeIDs...),
		ExpectedActiveByNode: expected, Policy: rollbackPolicy,
		SourceChannel: storage.SourceSystem, Actor: "system:safe-rollout-policy",
		Reason: reason, Kind: storage.RolloutKindRollback,
		RollbackTargetSequence: target.Sequence,
	})
	if err != nil {
		return MutationResult{}, err
	}
	if existingErr == nil && existing.Sequence != record.Sequence {
		return MutationResult{}, fmt.Errorf("automatic rollback identity changed: %w", storage.ErrCorrupt)
	}
	return service.startAndSelect(ctx, record, discovery.RolloutMutationRollback, existingErr == nil)
}

func (service *Service) mixedRollbackExpectations(
	ctx context.Context,
	failed storage.RolloutRecord,
	target storage.RolloutRecord,
	connections []discovery.ConnectionSnapshot,
) ([]storage.NodeExpectedArtifact, error) {
	failedArtifact, err := service.repository.GetSnapshotArtifact(ctx, failed.ArtifactDigest)
	if err != nil {
		return nil, err
	}
	targetArtifact, err := service.repository.GetSnapshotArtifact(ctx, target.ArtifactDigest)
	if err != nil {
		return nil, err
	}
	byNode := make(map[string]discovery.ConnectionSnapshot, len(connections))
	for _, connection := range connections {
		byNode[connection.NodeID] = connection
	}
	expected := make([]storage.NodeExpectedArtifact, 0, len(failed.TargetNodeIDs))
	for _, nodeID := range failed.TargetNodeIDs {
		connection, found := byNode[nodeID]
		if !found || !connection.Reconciled || connection.PreparedSequence != 0 {
			return nil, ErrPolicyAwaitingReconciliation
		}
		digest := storage.Digest{}
		switch connection.ActiveSnapshotID {
		case failedArtifact.SnapshotID:
			digest = failed.ArtifactDigest
		case targetArtifact.SnapshotID:
			digest = target.ArtifactDigest
		default:
			return nil, fmt.Errorf("node %q reports an artifact outside rollback lineage: %w",
				nodeID, ErrPrecondition)
		}
		expected = append(expected, storage.NodeExpectedArtifact{NodeID: nodeID, ArtifactDigest: digest})
	}
	slices.SortFunc(expected, func(left, right storage.NodeExpectedArtifact) int {
		if left.NodeID < right.NodeID {
			return -1
		}
		if left.NodeID > right.NodeID {
			return 1
		}
		return 0
	})
	return expected, nil
}
