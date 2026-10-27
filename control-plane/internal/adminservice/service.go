package adminservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/discovery"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/identity"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/rollout"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/rolloutservice"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
)

type permission string

const (
	permissionValidate    permission = "config.validate"
	permissionPreview     permission = "config.preview"
	permissionApply       permission = "rollout.apply"
	permissionCancel      permission = "rollout.cancel"
	permissionRead        permission = "rollout.read"
	permissionRollback    permission = "rollout.rollback"
	permissionNodeRead    permission = "node.read"
	permissionNodeOperate permission = "node.operate"
	permissionNodeAdmin   permission = "node.admin"
)

// Service is the sole application authority for standalone management
// operations. mutationMu serializes apply and rollback intent inside the one
// repository-owning process; repository compare-and-set remains the durable
// stale-writer defense.
type Service struct {
	mutationMu sync.Mutex
	nodeMu     sync.Mutex
	catalogMu  sync.Mutex
	repository Repository
	runtime    Runtime
	startedAt  time.Time
	catalog    routeCatalogCache
	identity   identity.Repository
	nodePolicy NodeLifecycleOptions
}

type Option func(*Service) error

func WithNodeLifecycle(repository identity.Repository, policy NodeLifecycleOptions) Option {
	return func(service *Service) error {
		if repository == nil {
			return fmt.Errorf("node identity repository is nil: %w", ErrInvalidInput)
		}
		if err := validateNodeLifecycleOptions(policy); err != nil {
			return err
		}
		service.identity = repository
		service.nodePolicy = policy
		return nil
	}
}

func New(repository Repository, runtime Runtime, options ...Option) (*Service, error) {
	if repository == nil || runtime == nil {
		return nil, fmt.Errorf("admin service dependency is nil: %w", ErrInvalidInput)
	}
	service := &Service{
		repository: repository, runtime: runtime,
		startedAt: time.Now().UTC().Round(0),
	}
	for _, option := range options {
		if option == nil {
			return nil, fmt.Errorf("admin service option is nil: %w", ErrInvalidInput)
		}
		if err := option(service); err != nil {
			return nil, err
		}
	}
	return service, nil
}

func (service *Service) Apply(
	ctx context.Context,
	principal Principal,
	input ApplyInput,
) (MutationResult, error) {
	if err := requirePermission(principal, permissionApply); err != nil {
		return MutationResult{}, err
	}
	if err := validateMutationInput(
		input.RequestID, input.Reason, input.TargetNodeIDs,
		input.ExpectedSelectedRolloutSequence, input.ExpectedActiveArtifact,
		input.PreviewFingerprintSHA256,
	); err != nil {
		return MutationResult{}, err
	}
	if err := validateText("source revision", input.SourceRevision, 256, false); err != nil {
		return MutationResult{}, err
	}
	if err := contextError(ctx); err != nil {
		return MutationResult{}, err
	}

	service.mutationMu.Lock()
	defer service.mutationMu.Unlock()
	targets, _ := normalizeTargetNodes(input.TargetNodeIDs)
	policy, policyView, err := normalizePolicy(input.Policy, targets)
	if err != nil {
		return MutationResult{}, err
	}
	compiled, err := compileDocument(input.Document)
	if err != nil {
		return MutationResult{}, err
	}
	preview, err := service.Preview(ctx, principal, PreviewInput{
		Document: input.Document, BaselineRolloutSequence: input.ExpectedSelectedRolloutSequence,
		TargetNodeIDs: targets, Policy: policyView,
	})
	if err != nil {
		return MutationResult{}, err
	}
	if preview.PlanFingerprintSHA256 != input.PreviewFingerprintSHA256 {
		return MutationResult{}, fmt.Errorf("preview fingerprint changed: %w", ErrPrecondition)
	}
	if preview.NoChange {
		return MutationResult{}, ErrNoChange
	}
	requestDigest, err := mutationDigest(struct {
		Kind             string                `json:"kind"`
		Actor            string                `json:"actor"`
		SourceChannel    storage.SourceChannel `json:"source_channel"`
		SourceRevision   string                `json:"source_revision"`
		Reason           string                `json:"reason"`
		Targets          []string              `json:"targets"`
		ExpectedSequence uint64                `json:"expected_sequence"`
		ExpectedArtifact string                `json:"expected_artifact"`
		Preview          string                `json:"preview"`
		ProposedArtifact string                `json:"proposed_artifact"`
		Policy           *RolloutPolicyInput   `json:"policy,omitempty"`
	}{
		Kind: "APPLY", Actor: principal.Actor, SourceChannel: principal.SourceChannel,
		SourceRevision: input.SourceRevision, Reason: input.Reason, Targets: targets,
		ExpectedSequence: input.ExpectedSelectedRolloutSequence,
		ExpectedArtifact: input.ExpectedActiveArtifact.String(),
		Preview:          input.PreviewFingerprintSHA256, ProposedArtifact: compiled.digest.String(),
		Policy: policyPointer(policy),
	})
	if err != nil {
		return MutationResult{}, err
	}

	existing, existingErr := service.repository.GetRolloutByRequestID(ctx, input.RequestID)
	if existingErr != nil && !errors.Is(existingErr, storage.ErrNotFound) {
		return MutationResult{}, existingErr
	}
	if existingErr == nil && existing.Kind != storage.RolloutKindApply {
		return MutationResult{}, fmt.Errorf("idempotency key names another operation: %w", storage.ErrConflict)
	}
	if errors.Is(existingErr, storage.ErrNotFound) {
		if _, _, err := service.requireCurrent(ctx,
			input.ExpectedSelectedRolloutSequence, input.ExpectedActiveArtifact,
		); err != nil {
			return MutationResult{}, err
		}
	}
	desired, err := service.repository.CreateDesiredRevision(ctx, storage.DesiredRevisionInput{
		RequestID: input.RequestID + ".desired", Document: input.Document,
		SourceChannel: principal.SourceChannel, SourceRevision: input.SourceRevision,
		Actor: principal.Actor,
	})
	if err != nil {
		return MutationResult{}, err
	}
	artifact, err := service.repository.CreateSnapshotArtifact(ctx, storage.SnapshotArtifactInput{
		DesiredRevisionID: desired.ID, CompilerVersion: CompilerVersion, Bytes: compiled.bytes,
	})
	if err != nil {
		return MutationResult{}, err
	}
	rolloutInput := storage.RolloutInput{
		RequestID: input.RequestID, RequestDigest: requestDigest,
		ArtifactDigest: artifact.Digest, PreviousArtifactDigest: input.ExpectedActiveArtifact,
		BaselineRolloutSequence: input.ExpectedSelectedRolloutSequence,
		DesiredRevisionID:       desired.ID, CompilerVersion: CompilerVersion,
		TargetNodeIDs: targets, Policy: policy, SourceChannel: principal.SourceChannel,
		Actor: principal.Actor, Reason: input.Reason, Kind: storage.RolloutKindApply,
	}
	record, err := service.repository.AllocateRollout(ctx, rolloutInput)
	if err != nil {
		return MutationResult{}, err
	}
	if existingErr == nil && record.Sequence != existing.Sequence {
		return MutationResult{}, fmt.Errorf("idempotent rollout identity changed: %w", storage.ErrCorrupt)
	}
	return service.startAndSelect(ctx, record, discovery.RolloutMutationApply, existingErr == nil)
}

func (service *Service) Rollback(
	ctx context.Context,
	principal Principal,
	input RollbackInput,
) (MutationResult, error) {
	if err := requirePermission(principal, permissionRollback); err != nil {
		return MutationResult{}, err
	}
	if err := validateMutationInput(
		input.RequestID, input.Reason, input.TargetNodeIDs,
		input.ExpectedSelectedRolloutSequence, input.ExpectedActiveArtifact,
		input.PreviewFingerprintSHA256,
	); err != nil {
		return MutationResult{}, err
	}
	if input.RollbackTargetSequence == 0 ||
		input.RollbackTargetSequence >= input.ExpectedSelectedRolloutSequence {
		return MutationResult{}, fmt.Errorf("rollback target sequence is invalid: %w", ErrInvalidInput)
	}
	if err := contextError(ctx); err != nil {
		return MutationResult{}, err
	}

	service.mutationMu.Lock()
	defer service.mutationMu.Unlock()
	targets, _ := normalizeTargetNodes(input.TargetNodeIDs)
	preview, err := service.PreviewRollback(ctx, principal, RollbackPreviewInput{
		CurrentRolloutSequence: input.ExpectedSelectedRolloutSequence,
		TargetRolloutSequence:  input.RollbackTargetSequence, TargetNodeIDs: targets,
	})
	if err != nil {
		return MutationResult{}, err
	}
	if preview.PlanFingerprintSHA256 != input.PreviewFingerprintSHA256 {
		return MutationResult{}, fmt.Errorf("rollback preview fingerprint changed: %w", ErrPrecondition)
	}
	if preview.NoChange {
		return MutationResult{}, ErrNoChange
	}
	targetRecord, err := service.repository.GetRollout(ctx, input.RollbackTargetSequence)
	if err != nil {
		return MutationResult{}, err
	}
	requestDigest, err := mutationDigest(struct {
		Kind             string                `json:"kind"`
		Actor            string                `json:"actor"`
		SourceChannel    storage.SourceChannel `json:"source_channel"`
		Reason           string                `json:"reason"`
		Targets          []string              `json:"targets"`
		ExpectedSequence uint64                `json:"expected_sequence"`
		ExpectedArtifact string                `json:"expected_artifact"`
		TargetSequence   uint64                `json:"target_sequence"`
		Preview          string                `json:"preview"`
	}{
		Kind: "ROLLBACK", Actor: principal.Actor, SourceChannel: principal.SourceChannel,
		Reason: input.Reason, Targets: targets,
		ExpectedSequence: input.ExpectedSelectedRolloutSequence,
		ExpectedArtifact: input.ExpectedActiveArtifact.String(),
		TargetSequence:   input.RollbackTargetSequence, Preview: input.PreviewFingerprintSHA256,
	})
	if err != nil {
		return MutationResult{}, err
	}
	existing, existingErr := service.repository.GetRolloutByRequestID(ctx, input.RequestID)
	if existingErr != nil && !errors.Is(existingErr, storage.ErrNotFound) {
		return MutationResult{}, existingErr
	}
	if existingErr == nil && existing.Kind != storage.RolloutKindRollback {
		return MutationResult{}, fmt.Errorf("idempotency key names another operation: %w", storage.ErrConflict)
	}
	expectedByNode := []storage.NodeExpectedArtifact(nil)
	if existingErr == nil {
		expectedByNode = append(expectedByNode, existing.ExpectedActiveByNode...)
	}
	if errors.Is(existingErr, storage.ErrNotFound) {
		selection, current, err := service.requireCurrent(ctx,
			input.ExpectedSelectedRolloutSequence, input.ExpectedActiveArtifact,
		)
		if err != nil {
			return MutationResult{}, err
		}
		if !slices.Equal(targets, current.TargetNodeIDs) {
			return MutationResult{}, fmt.Errorf("rollback target scope differs from selected rollout: %w", ErrPrecondition)
		}
		switch selection.Phase {
		case rollout.PhaseRequiresRollback:
			expectedByNode, err = service.mixedRollbackExpectations(
				ctx, current, targetRecord, service.runtime.Connections(),
			)
			if err != nil {
				return MutationResult{}, err
			}
		case rollout.PhaseCancelled:
			expectedByNode, err = cancelledRollbackExpectations(current)
			if err != nil {
				return MutationResult{}, err
			}
		}
	}
	rolloutInput := storage.RolloutInput{
		RequestID: input.RequestID, RequestDigest: requestDigest,
		ArtifactDigest:          targetRecord.ArtifactDigest,
		PreviousArtifactDigest:  input.ExpectedActiveArtifact,
		BaselineRolloutSequence: input.ExpectedSelectedRolloutSequence,
		DesiredRevisionID:       targetRecord.DesiredRevisionID,
		CompilerVersion:         targetRecord.CompilerVersion,
		TargetNodeIDs:           targets, ExpectedActiveByNode: expectedByNode,
		SourceChannel: principal.SourceChannel,
		Actor:         principal.Actor, Reason: input.Reason, Kind: storage.RolloutKindRollback,
		RollbackTargetSequence: input.RollbackTargetSequence,
	}
	record, err := service.repository.AllocateRollout(ctx, rolloutInput)
	if err != nil {
		return MutationResult{}, err
	}
	if existingErr == nil && record.Sequence != existing.Sequence {
		return MutationResult{}, fmt.Errorf("idempotent rollback identity changed: %w", storage.ErrCorrupt)
	}
	return service.startAndSelect(ctx, record, discovery.RolloutMutationRollback, existingErr == nil)
}

func (service *Service) startAndSelect(
	ctx context.Context,
	record storage.RolloutRecord,
	mutation discovery.RolloutMutation,
	replayed bool,
) (MutationResult, error) {
	coordinator, err := rolloutservice.Open(ctx, service.repository, record.Sequence)
	if err != nil {
		return MutationResult{}, err
	}
	started, err := coordinator.Start(ctx, "start."+record.RequestID)
	if err != nil {
		return MutationResult{}, err
	}
	current, err := service.runtime.CurrentRollout()
	if err != nil {
		return MutationResult{}, err
	}
	if record.Sequence > current.Sequence {
		_, err = service.runtime.ReplaceRollout(
			ctx, mutation, coordinator,
			func(selectCtx context.Context, expected, next uint64) error {
				_, selectErr := service.repository.SelectRollout(selectCtx, expected, next)
				return selectErr
			},
		)
		if err != nil {
			return MutationResult{}, err
		}
	} else if record.Sequence < current.Sequence {
		replayed = true
	}
	status, err := service.status(ctx, record.Sequence)
	if err != nil {
		return MutationResult{}, err
	}
	return MutationResult{
		APIVersion: APIVersion, Replayed: replayed || started.Replayed, Status: status,
	}, nil
}

func (service *Service) GetStatus(
	ctx context.Context,
	principal Principal,
	sequence uint64,
) (RolloutStatus, error) {
	if err := requirePermission(principal, permissionRead); err != nil {
		return RolloutStatus{}, err
	}
	if sequence == 0 {
		selection, err := service.runtime.CurrentRollout()
		if err != nil {
			return RolloutStatus{}, err
		}
		sequence = selection.Sequence
	}
	return service.status(ctx, sequence)
}

func (service *Service) status(ctx context.Context, sequence uint64) (RolloutStatus, error) {
	if err := contextError(ctx); err != nil {
		return RolloutStatus{}, err
	}
	record, err := service.repository.GetRollout(ctx, sequence)
	if err != nil {
		return RolloutStatus{}, err
	}
	artifact, err := service.repository.GetSnapshotArtifact(ctx, record.ArtifactDigest)
	if err != nil {
		return RolloutStatus{}, err
	}
	selection, err := service.runtime.CurrentRollout()
	if err != nil {
		return RolloutStatus{}, err
	}
	phase := rollout.Phase("")
	nodes := map[string]rollout.NodeSnapshot{}
	selected := selection.Sequence == sequence
	if selected {
		phase, nodes = selection.Phase, selection.Nodes
	} else {
		coordinator, openErr := rolloutservice.Open(ctx, service.repository, sequence)
		if openErr != nil {
			return RolloutStatus{}, openErr
		}
		phase, nodes, err = coordinator.Status()
		if err != nil {
			return RolloutStatus{}, err
		}
	}
	nodeIDs := make([]string, 0, len(nodes))
	for nodeID := range nodes {
		nodeIDs = append(nodeIDs, nodeID)
	}
	slices.Sort(nodeIDs)
	nodeStatus := make([]NodeStatus, 0, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		node := nodes[nodeID]
		nodeStatus = append(nodeStatus, NodeStatus{
			NodeID: nodeID, Phase: node.Phase, Connected: node.Connected,
			ProcessInstance: node.ProcessInstance,
		})
	}
	connections := []ConnectionObservation(nil)
	if selected {
		for _, connection := range service.runtime.Connections() {
			connections = append(connections, ConnectionObservation{
				NodeID: connection.NodeID, ProcessInstance: connection.ProcessInstance,
				CredentialNotAfter: connection.CredentialNotAfter,
				ConnectedAt:        connection.ConnectedAt, LastSeen: connection.LastSeen,
				LastRolloutSequence: connection.LastRolloutSequence,
				ActiveSnapshotID:    connection.ActiveSnapshotID,
				PreparedSequence:    connection.PreparedSequence,
				PendingCommands:     connection.PendingCommands, Reconciled: connection.Reconciled,
			})
		}
	}
	return RolloutStatus{
		APIVersion: APIVersion, RolloutID: record.ID, RequestID: record.RequestID,
		Sequence: record.Sequence, Kind: record.Kind,
		RollbackTargetSequence: record.RollbackTargetSequence,
		Phase:                  phase, Artifact: artifactSummary(artifact),
		PreviousArtifactSHA256:  optionalDigest(record.PreviousArtifactDigest),
		BaselineRolloutSequence: record.BaselineRolloutSequence,
		DesiredRevisionID:       record.DesiredRevisionID, CompilerVersion: record.CompilerVersion,
		TargetNodeIDs: append([]string(nil), record.TargetNodeIDs...),
		SourceChannel: record.SourceChannel, Actor: record.Actor, Reason: record.Reason,
		CreatedAt: record.CreatedAt, Selected: selected, Nodes: nodeStatus, Connections: connections,
		Policy: policyPointer(record.Policy),
	}, nil
}

// GetDesiredState returns the immutable YAML that produced a rollout. The
// document contains unresolved references only; credentials remain in their
// owning secret stores. Binding it to the rollout and artifact identities lets
// the Console safely reopen a rejected candidate for correction.
func (service *Service) GetDesiredState(
	ctx context.Context,
	principal Principal,
	sequence uint64,
) (DesiredStateResult, error) {
	if err := requirePermission(principal, permissionRead); err != nil {
		return DesiredStateResult{}, err
	}
	if sequence == 0 {
		selection, err := service.runtime.CurrentRollout()
		if err != nil {
			return DesiredStateResult{}, err
		}
		sequence = selection.Sequence
	}
	record, err := service.repository.GetRollout(ctx, sequence)
	if err != nil {
		return DesiredStateResult{}, err
	}
	desired, err := service.repository.GetDesiredRevision(ctx, record.DesiredRevisionID)
	if err != nil {
		return DesiredStateResult{}, err
	}
	artifact, err := service.repository.GetSnapshotArtifact(ctx, record.ArtifactDigest)
	if err != nil {
		return DesiredStateResult{}, err
	}
	if desired.ID != record.DesiredRevisionID {
		return DesiredStateResult{}, fmt.Errorf("rollout desired-state identity changed: %w", storage.ErrCorrupt)
	}
	return DesiredStateResult{
		APIVersion: APIVersion, RolloutSequence: sequence,
		DesiredRevisionID: desired.ID, Document: string(desired.Document),
		SourceChannel: desired.SourceChannel, SourceRevision: desired.SourceRevision,
		Actor: desired.Actor, CreatedAt: desired.CreatedAt,
		SnapshotID: artifact.SnapshotID, ArtifactSHA256: artifact.Digest.String(),
	}, nil
}

func cancelledRollbackExpectations(
	current storage.RolloutRecord,
) ([]storage.NodeExpectedArtifact, error) {
	if current.PreviousArtifactDigest.IsZero() {
		return nil, fmt.Errorf("cancelled rollout has no last-known-good artifact: %w", storage.ErrCorrupt)
	}
	expected := make([]storage.NodeExpectedArtifact, 0, len(current.TargetNodeIDs))
	for _, nodeID := range current.TargetNodeIDs {
		expected = append(expected, storage.NodeExpectedArtifact{
			NodeID: nodeID, ArtifactDigest: current.PreviousArtifactDigest,
		})
	}
	return expected, nil
}

func (service *Service) GetDiagnostics(
	ctx context.Context,
	principal Principal,
	sequence uint64,
) (DiagnosticsResult, error) {
	if err := requirePermission(principal, permissionRead); err != nil {
		return DiagnosticsResult{}, err
	}
	if sequence == 0 {
		selection, err := service.runtime.CurrentRollout()
		if err != nil {
			return DiagnosticsResult{}, err
		}
		sequence = selection.Sequence
	}
	events, _, err := service.journalSnapshot(ctx, sequence)
	if err != nil {
		return DiagnosticsResult{}, err
	}
	return diagnosticsResult(sequence, events), nil
}

func diagnosticsResult(sequence uint64, events []rolloutservice.Diagnostic) DiagnosticsResult {
	total := len(events)
	start := 0
	if total > MaxDiagnosticEvents {
		start = total - MaxDiagnosticEvents
	}
	result := DiagnosticsResult{
		APIVersion: APIVersion, Sequence: sequence, TotalEvents: uint64(total),
		Truncated: start != 0, Events: make([]DiagnosticEvent, 0, total-start),
	}
	for _, event := range events[start:] {
		result.Events = append(result.Events, projectDiagnostic(event))
	}
	if len(result.Events) != 0 {
		result.FirstIndex = result.Events[0].Index
		result.LastIndex = result.Events[len(result.Events)-1].Index
	}
	return result
}

func projectDiagnostic(event rolloutservice.Diagnostic) DiagnosticEvent {
	projected := DiagnosticEvent{
		Index: event.Index, EventID: event.EventID, Kind: event.Kind,
		EventSHA256: event.Digest.String(), Phase: event.Phase, CreatedAt: event.CreatedAt,
	}
	if event.Error != nil {
		projected.Error = &DiagnosticError{Code: event.Error.Code, Message: event.Error.Message}
	}
	if event.Report != nil {
		projected.Report = &DiagnosticReport{
			NodeID: event.Report.NodeID, ProcessInstance: event.Report.ProcessInstance,
			Sequence: event.Report.Sequence, Operation: event.Report.Operation,
			Result: event.Report.Result, ShardCount: event.Report.ShardCount,
			CompletedShards: event.Report.CompletedShards,
		}
		for _, issue := range event.Report.Issues {
			projected.Report.Issues = append(projected.Report.Issues, DiagnosticIssue{
				Code: issue.Code, FieldPath: issue.FieldPath, Message: issue.Message,
			})
		}
	}
	if event.Policy != nil {
		projected.Policy = &DiagnosticPolicy{
			ObservedAt: event.Policy.ObservedAt, Decision: event.Policy.Decision,
			Reason: event.Policy.Reason,
			Nodes:  make([]DiagnosticNodeHealth, 0, len(event.Policy.Nodes)),
		}
		for _, node := range event.Policy.Nodes {
			projected.Policy.Nodes = append(projected.Policy.Nodes, DiagnosticNodeHealth{
				NodeID: node.NodeID, Connected: node.Connected, Reconciled: node.Reconciled,
				LastSeen: node.LastSeen, ActiveSnapshotID: node.ActiveSnapshotID,
			})
		}
	}
	if event.Cancellation != nil {
		projected.Cancellation = &DiagnosticCancellation{
			Reason:            event.Cancellation.Reason,
			Actor:             event.Cancellation.Actor,
			SourceChannel:     event.Cancellation.SourceChannel,
			AttributionStatus: event.Cancellation.AttributionStatus,
		}
	}
	return projected
}

func (service *Service) requireCurrent(
	ctx context.Context,
	expectedSequence uint64,
	expectedArtifact storage.Digest,
) (discovery.RolloutSelection, storage.RolloutRecord, error) {
	selection, err := service.runtime.CurrentRollout()
	if err != nil {
		return discovery.RolloutSelection{}, storage.RolloutRecord{}, err
	}
	selected, err := service.repository.GetSelectedRollout(ctx)
	if err != nil {
		return discovery.RolloutSelection{}, storage.RolloutRecord{}, err
	}
	if selection.Sequence != selected.Sequence {
		return discovery.RolloutSelection{}, storage.RolloutRecord{}, ErrAuthorityMismatch
	}
	if selection.Sequence != expectedSequence || selected.ArtifactDigest != expectedArtifact {
		return discovery.RolloutSelection{}, storage.RolloutRecord{}, ErrPrecondition
	}
	return selection, selected, nil
}

func requirePermission(principal Principal, requested permission) error {
	if err := validatePrincipal(principal); err != nil {
		return err
	}
	if requested == permissionRead || requested == permissionNodeRead {
		return nil
	}
	if requested == permissionNodeAdmin {
		if principal.Role == RoleAdministrator {
			return nil
		}
		return ErrForbidden
	}
	if principal.Role == RoleOperator || principal.Role == RoleAdministrator {
		return nil
	}
	return ErrForbidden
}

func validatePrincipal(principal Principal) error {
	if err := validateText("principal actor", principal.Actor, 256, true); err != nil {
		return ErrForbidden
	}
	switch principal.Role {
	case RoleAuditor, RoleViewer, RoleOperator, RoleAdministrator:
	default:
		return ErrForbidden
	}
	switch principal.SourceChannel {
	case storage.SourceAPI, storage.SourceCLI, storage.SourceConsole, storage.SourceGitOps:
	default:
		return ErrForbidden
	}
	return nil
}

func validateMutationInput(
	requestID string,
	reason string,
	targets []string,
	expectedSequence uint64,
	expectedArtifact storage.Digest,
	preview string,
) error {
	if err := validateIdentifier("request ID", requestID); err != nil {
		return err
	}
	if err := validateText("reason", reason, 1024, true); err != nil {
		return err
	}
	if _, err := normalizeTargetNodes(targets); err != nil {
		return err
	}
	if expectedSequence == 0 || expectedArtifact.IsZero() {
		return fmt.Errorf("expected rollout authority is incomplete: %w", ErrInvalidInput)
	}
	digest, err := storage.ParseDigest(preview)
	if err != nil || digest.String() != preview {
		return fmt.Errorf("preview fingerprint is not canonical SHA-256: %w", ErrInvalidInput)
	}
	return nil
}

func normalizeTargetNodes(values []string) ([]string, error) {
	if len(values) == 0 || len(values) > 10_000 {
		return nil, fmt.Errorf("target node count must be 1-10000: %w", ErrInvalidInput)
	}
	result := append([]string(nil), values...)
	slices.Sort(result)
	for index, value := range result {
		if err := validateIdentifier("target node ID", value); err != nil {
			return nil, err
		}
		if index > 0 && result[index-1] == value {
			return nil, fmt.Errorf("duplicate target node %q: %w", value, ErrInvalidInput)
		}
	}
	return result, nil
}

func mutationDigest(value any) (storage.Digest, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return storage.Digest{}, err
	}
	return storage.Sum(encoded), nil
}

func optionalDigest(value storage.Digest) string {
	if value.IsZero() {
		return ""
	}
	return value.String()
}

func validateIdentifier(name, value string) error {
	if len(value) == 0 || len(value) > 128 {
		return fmt.Errorf("%s must contain 1-128 bytes: %w", name, ErrInvalidInput)
	}
	for index, char := range value {
		valid := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' ||
			char >= '0' && char <= '9' || char == '.' || char == '_' || char == ':' || char == '-'
		if !valid || index == 0 && (char == '.' || char == ':' || char == '-') {
			return fmt.Errorf("%s contains an unsupported character: %w", name, ErrInvalidInput)
		}
	}
	return nil
}

func validateText(name, value string, maxBytes int, required bool) error {
	if !utf8.ValidString(value) || len(value) > maxBytes || required && strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is invalid: %w", name, ErrInvalidInput)
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return fmt.Errorf("%s contains a control character: %w", name, ErrInvalidInput)
		}
	}
	return nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context is nil: %w", ErrInvalidInput)
	}
	return ctx.Err()
}
