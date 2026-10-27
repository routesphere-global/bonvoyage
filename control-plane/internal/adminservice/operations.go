package adminservice

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/rollout"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/rolloutservice"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
)

const journalSnapshotAttempts = 4

// GetAudit returns a page of human-meaningful events while binding the result
// to the complete immutable rollout header and complete journal at export time.
func (service *Service) GetAudit(
	ctx context.Context,
	principal Principal,
	sequence uint64,
	afterIndex uint64,
	limit int,
) (AuditResult, error) {
	if err := requirePermission(principal, permissionRead); err != nil {
		return AuditResult{}, err
	}
	if limit < 1 || limit > MaxAuditPageSize {
		return AuditResult{}, fmt.Errorf("audit page limit must be 1-%d: %w", MaxAuditPageSize, ErrInvalidInput)
	}
	if sequence == 0 {
		selected, err := service.repository.GetSelectedRollout(ctx)
		if err != nil {
			return AuditResult{}, err
		}
		sequence = selected.Sequence
	}
	record, err := service.repository.GetRollout(ctx, sequence)
	if err != nil {
		return AuditResult{}, err
	}
	artifact, err := service.repository.GetSnapshotArtifact(ctx, record.ArtifactDigest)
	if err != nil {
		return AuditResult{}, err
	}
	diagnostics, events, err := service.journalSnapshot(ctx, sequence)
	if err != nil {
		return AuditResult{}, err
	}

	rolloutHeader := auditRollout(record, artifact)
	manifestDigest, err := auditManifestDigest(rolloutHeader, events)
	if err != nil {
		return AuditResult{}, err
	}
	start := sort.Search(len(events), func(index int) bool {
		return events[index].Index > afterIndex
	})
	end := min(start+limit, len(events))
	journal := AuditJournal{
		TotalEvents: uint64(len(events)), AfterIndex: afterIndex, Limit: limit,
		Events: make([]DiagnosticEvent, 0, end-start),
	}
	for _, event := range diagnostics[start:end] {
		journal.Events = append(journal.Events, projectDiagnostic(event))
	}
	if len(journal.Events) != 0 {
		journal.FirstIndex = journal.Events[0].Index
		journal.LastIndex = journal.Events[len(journal.Events)-1].Index
		if end < len(events) {
			journal.NextAfterIndex = journal.LastIndex
		}
	}
	return AuditResult{
		APIVersion: APIVersion, ManifestVersion: AuditManifestVersion,
		ManifestSHA256: manifestDigest.String(), Rollout: rolloutHeader, Journal: journal,
	}, nil
}

// GetOperationalTelemetry reconstructs restart-safe gauges from durable state
// and live connection ownership. Counters are represented as current-journal
// gauges because Prometheus is not a billing or audit authority.
func (service *Service) GetOperationalTelemetry(
	ctx context.Context,
	principal Principal,
) (OperationalTelemetry, error) {
	if err := requirePermission(principal, permissionRead); err != nil {
		return OperationalTelemetry{}, err
	}
	selection, err := service.runtime.CurrentRollout()
	if err != nil {
		return OperationalTelemetry{}, err
	}
	selected, err := service.repository.GetSelectedRollout(ctx)
	if err != nil {
		return OperationalTelemetry{}, err
	}
	diagnostics, events, err := service.journalSnapshot(ctx, selected.Sequence)
	if err != nil {
		return OperationalTelemetry{}, err
	}

	authorityMatch := selection.Sequence == selected.Sequence
	connectionSnapshot := service.runtime.Connections()
	connections := make(map[string]discoveryConnection, len(connectionSnapshot))
	for _, connection := range connectionSnapshot {
		connections[connection.NodeID] = discoveryConnection{
			reconciled: connection.Reconciled, pendingCommands: connection.PendingCommands,
		}
	}
	nodePhaseCounts := make(map[string]uint64)
	connectedNodes := 0
	reconciledNodes := 0
	pendingCommands := 0
	if authorityMatch {
		for _, nodeID := range selected.TargetNodeIDs {
			if node, found := selection.Nodes[nodeID]; found {
				nodePhaseCounts[string(node.Phase)]++
			}
			if connection, found := connections[nodeID]; found {
				connectedNodes++
				pendingCommands += connection.pendingCommands
				if connection.reconciled {
					reconciledNodes++
				}
			}
		}
	}

	eventKindCounts := make(map[string]uint64)
	decisionCounts := make(map[string]uint64)
	reportCounts := make(map[string]uint64)
	transitionErrors := uint64(0)
	for _, event := range diagnostics {
		eventKindCounts[event.Kind]++
		if event.Error != nil {
			transitionErrors++
		}
		if event.Policy != nil {
			decisionCounts[string(event.Policy.Decision)]++
		}
		if event.Report != nil {
			reportCounts[string(event.Report.Operation)+"\x00"+string(event.Report.Result)]++
		}
	}
	strategy := "DISABLED"
	if selected.Policy.Enabled {
		strategy = string(selected.Policy.Strategy)
	}
	telemetry := OperationalTelemetry{
		APIVersion: APIVersion, ProcessStartedAt: service.startedAt,
		Ready: authorityMatch, SelectedSequence: selected.Sequence,
		RolloutPhase: selection.Phase, RolloutKind: selected.Kind,
		PolicyStrategy: strategy, PolicyEnabled: selected.Policy.Enabled,
		AutomaticRollback:     selected.Policy.AutomaticRollback,
		RuntimeAuthorityMatch: authorityMatch, TargetNodes: len(selected.TargetNodeIDs),
		ConnectedNodes: connectedNodes, ReconciledNodes: reconciledNodes,
		UnreconciledNodes: len(selected.TargetNodeIDs) - reconciledNodes,
		PendingCommands:   pendingCommands,
		RecoveryRequired:  !authorityMatch || selection.Phase == rollout.PhaseRequiresRollback,
		JournalEvents:     uint64(len(events)), JournalTransitionErrors: transitionErrors,
		NodePhases:      fixedCounts(nodePhaseNames(), nodePhaseCounts),
		JournalKinds:    fixedCounts(journalKindNames(), eventKindCounts),
		PolicyDecisions: fixedCounts(policyDecisionNames(), decisionCounts),
		Reports:         fixedReportCounts(reportCounts),
	}
	if len(events) != 0 {
		telemetry.LastJournalEventAt = events[len(events)-1].CreatedAt
	}
	return telemetry, nil
}

type discoveryConnection struct {
	reconciled      bool
	pendingCommands int
}

func (service *Service) journalSnapshot(
	ctx context.Context,
	sequence uint64,
) ([]rolloutservice.Diagnostic, []storage.RolloutEvent, error) {
	if err := contextError(ctx); err != nil {
		return nil, nil, err
	}
	for range journalSnapshotAttempts {
		coordinator, err := rolloutservice.Open(ctx, service.repository, sequence)
		if err != nil {
			return nil, nil, err
		}
		diagnostics, err := coordinator.Diagnostics(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			continue
		}
		events, err := service.repository.ListRolloutEvents(ctx, sequence)
		if err != nil {
			return nil, nil, err
		}
		if coherentJournalSnapshot(diagnostics, events) {
			return diagnostics, events, nil
		}
	}
	return nil, nil, fmt.Errorf("rollout journal changed during bounded inspection: %w", ErrAuthorityMismatch)
}

func coherentJournalSnapshot(
	diagnostics []rolloutservice.Diagnostic,
	events []storage.RolloutEvent,
) bool {
	if len(diagnostics) != len(events) {
		return false
	}
	for index := range events {
		if diagnostics[index].Index != events[index].Index ||
			diagnostics[index].EventID != events[index].EventID ||
			diagnostics[index].Kind != events[index].Kind ||
			diagnostics[index].Digest != events[index].Digest {
			return false
		}
	}
	return true
}

func auditRollout(record storage.RolloutRecord, artifact storage.SnapshotArtifact) AuditRollout {
	expected := make([]AuditNodeArtifact, 0, len(record.ExpectedActiveByNode))
	for _, node := range record.ExpectedActiveByNode {
		expected = append(expected, AuditNodeArtifact{
			NodeID: node.NodeID, ArtifactSHA256: node.ArtifactDigest.String(),
		})
	}
	slices.SortFunc(expected, func(left, right AuditNodeArtifact) int {
		return compareText(left.NodeID, right.NodeID)
	})
	requestDigest := ""
	if !record.RequestDigest.IsZero() {
		requestDigest = record.RequestDigest.String()
	}
	return AuditRollout{
		RolloutID: record.ID, RequestID: record.RequestID, RequestSHA256: requestDigest,
		Sequence: record.Sequence, Kind: record.Kind,
		RollbackTargetSequence: record.RollbackTargetSequence,
		SnapshotID:             artifact.SnapshotID, ArtifactSHA256: record.ArtifactDigest.String(),
		PreviousArtifactSHA256:  optionalDigest(record.PreviousArtifactDigest),
		BaselineRolloutSequence: record.BaselineRolloutSequence,
		DesiredRevisionID:       record.DesiredRevisionID, CompilerVersion: record.CompilerVersion,
		TargetNodeIDs:        append([]string(nil), record.TargetNodeIDs...),
		ExpectedActiveByNode: expected, Policy: policyPointer(record.Policy),
		SourceChannel: record.SourceChannel, Actor: record.Actor, Reason: record.Reason,
		CreatedAt: record.CreatedAt,
	}
}

type auditManifestEvent struct {
	Index       uint64    `json:"index"`
	EventID     string    `json:"event_id"`
	Kind        string    `json:"kind"`
	EventSHA256 string    `json:"event_sha256"`
	CreatedAt   time.Time `json:"created_at"`
}

func auditManifestDigest(
	rolloutHeader AuditRollout,
	events []storage.RolloutEvent,
) (storage.Digest, error) {
	manifestEvents := make([]auditManifestEvent, 0, len(events))
	for _, event := range events {
		manifestEvents = append(manifestEvents, auditManifestEvent{
			Index: event.Index, EventID: event.EventID, Kind: event.Kind,
			EventSHA256: event.Digest.String(), CreatedAt: event.CreatedAt,
		})
	}
	payload, err := json.Marshal(struct {
		Version string               `json:"version"`
		Rollout AuditRollout         `json:"rollout"`
		Events  []auditManifestEvent `json:"events"`
	}{AuditManifestVersion, rolloutHeader, manifestEvents})
	if err != nil {
		return storage.Digest{}, fmt.Errorf("encode rollout audit manifest: %w", err)
	}
	return storage.Sum(payload), nil
}

func nodePhaseNames() []string {
	return []string{
		string(rollout.NodePending), string(rollout.NodePreparing), string(rollout.NodePrepared),
		string(rollout.NodeActivating), string(rollout.NodeActive), string(rollout.NodeCancelPending),
		string(rollout.NodeCancelled), string(rollout.NodeFailed), string(rollout.NodePriorActive),
	}
}

func journalKindNames() []string {
	return []string{"START", "REPORT", "RECONNECT", "CANCEL", "POLICY_EVALUATE"}
}

func policyDecisionNames() []string {
	return []string{
		string(rollout.PolicyDecisionCancel), string(rollout.PolicyDecisionPromote),
		string(rollout.PolicyDecisionRequireRollback),
	}
}

func fixedCounts(names []string, counts map[string]uint64) []NamedCount {
	result := make([]NamedCount, 0, len(names))
	for _, name := range names {
		result = append(result, NamedCount{Name: name, Count: counts[name]})
	}
	return result
}

func fixedReportCounts(counts map[string]uint64) []ReportCount {
	result := make([]ReportCount, 0, 6)
	for _, operation := range []rollout.Operation{
		rollout.OperationPrepare, rollout.OperationActivate, rollout.OperationCancel,
	} {
		for _, outcome := range []rollout.Result{rollout.ResultACK, rollout.ResultNACK} {
			result = append(result, ReportCount{
				Operation: operation, Result: outcome,
				Count: counts[string(operation)+"\x00"+string(outcome)],
			})
		}
	}
	return result
}

func compareText(left, right string) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}
