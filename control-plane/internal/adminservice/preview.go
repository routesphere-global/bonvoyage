package adminservice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	bonvoyagev1 "github.com/routesphere-global/bonvoyage/api/gen/go/bonvoyage/v1"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/configauthoring"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/snapshot"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
	"google.golang.org/protobuf/proto"
)

type compiledDocument struct {
	snapshot *bonvoyagev1.Snapshot
	bytes    []byte
	summary  SnapshotSummary
	digest   storage.Digest
}

func (service *Service) Validate(
	ctx context.Context,
	principal Principal,
	input ValidateInput,
) (ValidationResult, error) {
	if err := requirePermission(principal, permissionValidate); err != nil {
		return ValidationResult{}, err
	}
	if err := contextError(ctx); err != nil {
		return ValidationResult{}, err
	}
	response := configauthoring.ValidateReader(
		bytes.NewReader(input.Document),
		"admin-api.yaml",
		configauthoring.Requirements{},
	)
	if response.Status == "rejected" {
		return ValidationResult{}, validationError(response)
	}
	if response.Status != "accepted" {
		return ValidationResult{}, fmt.Errorf(
			"configuration authoring returned status %q", response.Status,
		)
	}
	validated, ok := response.Result.(*configauthoring.ValidationResult)
	if !ok || !validated.Valid || validated.Artifact == nil {
		return ValidationResult{}, fmt.Errorf("configuration authoring returned an incomplete accepted result")
	}
	artifact := validated.Artifact
	return ValidationResult{
		APIVersion: APIVersion, Valid: true, SnapshotID: artifact.SnapshotID,
		ArtifactSHA256:          artifact.SHA256,
		SchemaVersion:           artifact.SchemaVersion,
		MinimumDataplaneVersion: artifact.MinimumDataplaneVersion,
		ArtifactBytes:           artifact.Bytes,
	}, nil
}

func validationError(response configauthoring.Response) error {
	limit := len(response.Diagnostics)
	truncated := response.DiagnosticsTruncated
	if limit > MaxConfigurationDiagnostics {
		limit = MaxConfigurationDiagnostics
		truncated = true
	}
	diagnostics := make([]ConfigurationDiagnostic, 0, limit)
	for _, diagnostic := range response.Diagnostics[:limit] {
		projected := ConfigurationDiagnostic{
			Code: diagnostic.Code, Severity: diagnostic.Severity,
			Message: diagnostic.Message, Path: diagnostic.Path,
			Redacted: diagnostic.Redacted,
		}
		if diagnostic.Source != nil {
			projected.Source = &ConfigurationSourceRange{
				Start: ConfigurationPosition{
					Line: diagnostic.Source.Start.Line, Column: diagnostic.Source.Start.Column,
					ByteOffset: diagnostic.Source.Start.ByteOffset,
				},
				End: ConfigurationPosition{
					Line: diagnostic.Source.End.Line, Column: diagnostic.Source.End.Column,
					ByteOffset: diagnostic.Source.End.ByteOffset,
				},
			}
		}
		diagnostics = append(diagnostics, projected)
	}
	return &ConfigurationValidationError{
		Diagnostics: diagnostics, DiagnosticsTruncated: truncated,
	}
}

func (service *Service) Preview(
	ctx context.Context,
	principal Principal,
	input PreviewInput,
) (PreviewResult, error) {
	if err := requirePermission(principal, permissionPreview); err != nil {
		return PreviewResult{}, err
	}
	if err := contextError(ctx); err != nil {
		return PreviewResult{}, err
	}
	targets, err := normalizeTargetNodes(input.TargetNodeIDs)
	if err != nil {
		return PreviewResult{}, err
	}
	if err := service.validateNodeTargets(ctx, targets); err != nil {
		return PreviewResult{}, err
	}
	policy, _, err := normalizePolicy(input.Policy, targets)
	if err != nil {
		return PreviewResult{}, err
	}
	compiled, err := compileDocument(input.Document)
	if err != nil {
		return PreviewResult{}, err
	}
	baselineRecord, baselineArtifact, baselineSnapshot, err := service.rolloutArtifact(
		ctx, input.BaselineRolloutSequence,
	)
	if err != nil {
		return PreviewResult{}, err
	}
	return makePreview(
		"APPLY", baselineRecord.Sequence, 0,
		baselineRecord.TargetNodeIDs, baselineRecord.Policy, targets,
		artifactSummary(baselineArtifact), compiled.summary,
		baselineSnapshot, compiled.snapshot, policy,
	)
}

func (service *Service) PreviewRollback(
	ctx context.Context,
	principal Principal,
	input RollbackPreviewInput,
) (PreviewResult, error) {
	if err := requirePermission(principal, permissionPreview); err != nil {
		return PreviewResult{}, err
	}
	if err := contextError(ctx); err != nil {
		return PreviewResult{}, err
	}
	if input.CurrentRolloutSequence == 0 || input.TargetRolloutSequence == 0 ||
		input.TargetRolloutSequence >= input.CurrentRolloutSequence {
		return PreviewResult{}, fmt.Errorf("rollback sequence ordering is invalid: %w", ErrInvalidInput)
	}
	targets, err := normalizeTargetNodes(input.TargetNodeIDs)
	if err != nil {
		return PreviewResult{}, err
	}
	if err := service.validateNodeTargets(ctx, targets); err != nil {
		return PreviewResult{}, err
	}
	currentRecord, currentArtifact, currentSnapshot, err := service.rolloutArtifact(
		ctx, input.CurrentRolloutSequence,
	)
	if err != nil {
		return PreviewResult{}, err
	}
	_, targetArtifact, targetSnapshot, err := service.rolloutArtifact(ctx, input.TargetRolloutSequence)
	if err != nil {
		return PreviewResult{}, err
	}
	return makePreview(
		"ROLLBACK", currentRecord.Sequence, input.TargetRolloutSequence,
		currentRecord.TargetNodeIDs, currentRecord.Policy, targets,
		artifactSummary(currentArtifact), artifactSummary(targetArtifact),
		currentSnapshot, targetSnapshot, storage.RolloutPolicy{},
	)
}

func compileDocument(document []byte) (compiledDocument, error) {
	compiled, err := snapshot.Compile(bytes.NewReader(document))
	if err != nil {
		return compiledDocument{}, fmt.Errorf("%w: %v", ErrInvalidConfiguration, err)
	}
	artifactBytes, err := snapshot.MarshalDeterministic(compiled)
	if err != nil {
		return compiledDocument{}, fmt.Errorf("marshal deterministic snapshot: %w", err)
	}
	digest := storage.Sum(artifactBytes)
	return compiledDocument{
		snapshot: compiled, bytes: artifactBytes, digest: digest,
		summary: SnapshotSummary{
			SnapshotID: compiled.GetSnapshotId(), ArtifactSHA256: digest.String(),
			SchemaVersion:           compiled.GetSchemaVersion(),
			MinimumDataplaneVersion: compiled.GetMinimumDataplaneVersion(),
			ArtifactBytes:           len(artifactBytes),
		},
	}, nil
}

func (service *Service) rolloutArtifact(
	ctx context.Context,
	sequence uint64,
) (storage.RolloutRecord, storage.SnapshotArtifact, *bonvoyagev1.Snapshot, error) {
	if sequence == 0 {
		return storage.RolloutRecord{}, storage.SnapshotArtifact{}, nil,
			fmt.Errorf("rollout sequence is zero: %w", ErrInvalidInput)
	}
	record, err := service.repository.GetRollout(ctx, sequence)
	if err != nil {
		return storage.RolloutRecord{}, storage.SnapshotArtifact{}, nil, err
	}
	artifact, err := service.repository.GetSnapshotArtifact(ctx, record.ArtifactDigest)
	if err != nil {
		return storage.RolloutRecord{}, storage.SnapshotArtifact{}, nil, err
	}
	decoded := &bonvoyagev1.Snapshot{}
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(artifact.Bytes, decoded); err != nil {
		return storage.RolloutRecord{}, storage.SnapshotArtifact{}, nil,
			fmt.Errorf("decode retained snapshot: %w", storage.ErrCorrupt)
	}
	return record, artifact, decoded, nil
}

func makePreview(
	mode string,
	baselineSequence uint64,
	rollbackTargetSequence uint64,
	baselineTargets []string,
	baselinePolicy storage.RolloutPolicy,
	targets []string,
	baseline SnapshotSummary,
	proposed SnapshotSummary,
	baselineSnapshot *bonvoyagev1.Snapshot,
	proposedSnapshot *bonvoyagev1.Snapshot,
	policy storage.RolloutPolicy,
) (PreviewResult, error) {
	changes := diffSnapshots(baselineSnapshot, proposedSnapshot)
	fingerprintInput := struct {
		APIVersion             string              `json:"api_version"`
		Mode                   string              `json:"mode"`
		BaselineSequence       uint64              `json:"baseline_sequence"`
		BaselineArtifact       string              `json:"baseline_artifact"`
		ProposedArtifact       string              `json:"proposed_artifact"`
		RollbackTargetSequence uint64              `json:"rollback_target_sequence,omitempty"`
		TargetNodeIDs          []string            `json:"target_node_ids"`
		Policy                 *RolloutPolicyInput `json:"policy,omitempty"`
	}{
		APIVersion: APIVersion, Mode: mode, BaselineSequence: baselineSequence,
		BaselineArtifact: baseline.ArtifactSHA256, ProposedArtifact: proposed.ArtifactSHA256,
		RollbackTargetSequence: rollbackTargetSequence, TargetNodeIDs: targets,
		Policy: policyPointer(policy),
	}
	canonical, err := json.Marshal(fingerprintInput)
	if err != nil {
		return PreviewResult{}, err
	}
	return PreviewResult{
		APIVersion: APIVersion, BaselineRolloutSequence: baselineSequence,
		Baseline: baseline, Proposed: proposed, ProposedCounts: countResources(proposedSnapshot),
		TargetNodeIDs: append([]string(nil), targets...), Changes: changes,
		NoChange: baseline.ArtifactSHA256 == proposed.ArtifactSHA256 &&
			slices.Equal(baselineTargets, targets) && rolloutPoliciesEqual(baselinePolicy, policy),
		PlanFingerprintSHA256:  storage.Sum(canonical).String(),
		RollbackTargetSequence: rollbackTargetSequence, Policy: policyPointer(policy),
	}, nil
}

func rolloutPoliciesEqual(left, right storage.RolloutPolicy) bool {
	return left.Enabled == right.Enabled && left.Strategy == right.Strategy &&
		slices.Equal(left.CanaryNodeIDs, right.CanaryNodeIDs) &&
		left.MinimumHealthyCanaryPercent == right.MinimumHealthyCanaryPercent &&
		left.CanaryObservationWindow == right.CanaryObservationWindow &&
		left.PrepareTimeout == right.PrepareTimeout &&
		left.ActivationTimeout == right.ActivationTimeout &&
		left.HeartbeatStaleAfter == right.HeartbeatStaleAfter &&
		left.AutomaticRollback == right.AutomaticRollback
}

func artifactSummary(artifact storage.SnapshotArtifact) SnapshotSummary {
	return SnapshotSummary{
		SnapshotID: artifact.SnapshotID, ArtifactSHA256: artifact.Digest.String(),
		SchemaVersion:           artifact.SchemaVersion,
		MinimumDataplaneVersion: artifact.MinimumDataplaneVersion,
		ArtifactBytes:           len(artifact.Bytes),
	}
}

func countResources(value *bonvoyagev1.Snapshot) ResourceCounts {
	counts := ResourceCounts{
		Listeners: len(value.GetListeners()), VirtualHosts: len(value.GetVirtualHosts()),
		Clusters: len(value.GetClusters()),
	}
	for _, virtualHost := range value.GetVirtualHosts() {
		counts.Routes += len(virtualHost.GetRoutes())
	}
	return counts
}

func diffSnapshots(left, right *bonvoyagev1.Snapshot) []ResourceChange {
	leftResources := snapshotResources(left)
	rightResources := snapshotResources(right)
	keys := make([]string, 0, len(leftResources)+len(rightResources))
	seen := make(map[string]struct{}, len(leftResources)+len(rightResources))
	for key := range leftResources {
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	for key := range rightResources {
		if _, exists := seen[key]; !exists {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	changes := make([]ResourceChange, 0, len(keys))
	for _, key := range keys {
		leftValue, leftFound := leftResources[key]
		rightValue, rightFound := rightResources[key]
		change := ""
		switch {
		case !leftFound:
			change = "ADDED"
		case !rightFound:
			change = "REMOVED"
		case !proto.Equal(leftValue, rightValue):
			change = "MODIFIED"
		}
		if change == "" {
			continue
		}
		resourceType, resourceName, _ := strings.Cut(key, "\x00")
		changes = append(changes, ResourceChange{
			ResourceType: resourceType, ResourceName: resourceName, Change: change,
		})
	}
	return changes
}

func snapshotResources(value *bonvoyagev1.Snapshot) map[string]proto.Message {
	resources := make(map[string]proto.Message)
	resources["SNAPSHOT_METADATA\x00global"] = &bonvoyagev1.Snapshot{
		SnapshotId: value.GetSnapshotId(), Generation: value.GetGeneration(),
		MinimumDataplaneVersion: value.GetMinimumDataplaneVersion(),
		SchemaVersion:           value.GetSchemaVersion(),
	}
	for _, listener := range value.GetListeners() {
		resources["LISTENER\x00"+listener.GetName()] = listener
	}
	for _, virtualHost := range value.GetVirtualHosts() {
		resources["VIRTUAL_HOST\x00"+virtualHost.GetName()] = virtualHost
		for _, route := range virtualHost.GetRoutes() {
			resources["ROUTE\x00"+virtualHost.GetName()+"/"+route.GetName()] = route
		}
	}
	for _, cluster := range value.GetClusters() {
		resources["CLUSTER\x00"+cluster.GetName()] = cluster
	}
	if value.GetRuntimeLimits() != nil {
		resources["RUNTIME_LIMITS\x00global"] = value.GetRuntimeLimits()
	}
	return resources
}
