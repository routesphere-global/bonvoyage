package adminservice

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/discovery"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/rollout"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/rolloutservice"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/snapshot"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
)

func TestServiceAppliesIdempotentlyAndRejectsStaleAuthority(t *testing.T) {
	fixture := newAdminFixture(t)
	principal := fixture.operator()
	candidate := bytes.Replace(fixture.document, []byte("local-bootstrap"), []byte("admin-candidate"), 1)
	preview, err := fixture.service.Preview(context.Background(), principal, PreviewInput{
		Document: candidate, BaselineRolloutSequence: fixture.initial.Sequence,
		TargetNodeIDs: []string{"node-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if preview.NoChange || preview.PlanFingerprintSHA256 == "" || len(preview.Changes) == 0 {
		t.Fatalf("preview = %#v", preview)
	}
	input := ApplyInput{
		RequestID: "op_admin_apply_0001", Document: candidate,
		SourceRevision: "git:0123456789abcdef", Reason: "activate candidate",
		TargetNodeIDs:                   []string{"node-a"},
		ExpectedSelectedRolloutSequence: fixture.initial.Sequence,
		ExpectedActiveArtifact:          fixture.initial.ArtifactDigest,
		PreviewFingerprintSHA256:        preview.PlanFingerprintSHA256,
	}
	result, err := fixture.service.Apply(context.Background(), principal, input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Replayed || !result.Status.Selected || result.Status.Sequence != fixture.initial.Sequence+1 ||
		result.Status.Phase != rollout.PhasePreparing || result.Status.Kind != storage.RolloutKindApply {
		t.Fatalf("apply result = %#v", result)
	}
	replayed, err := fixture.service.Apply(context.Background(), principal, input)
	if err != nil || !replayed.Replayed || replayed.Status.Sequence != result.Status.Sequence {
		t.Fatalf("apply replay = %#v, err=%v", replayed, err)
	}
	changed := input
	changed.Reason = "changed replay"
	if _, err := fixture.service.Apply(context.Background(), principal, changed); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("changed replay error = %v", err)
	}
	stale := input
	stale.RequestID = "op_admin_apply_stale"
	if _, err := fixture.service.Apply(context.Background(), principal, stale); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("stale apply error = %v", err)
	}
	viewer := principal
	viewer.Role = RoleViewer
	if _, err := fixture.service.Apply(context.Background(), viewer, input); !errors.Is(err, ErrForbidden) {
		t.Fatalf("viewer apply error = %v", err)
	}
	diagnostics, err := fixture.service.GetDiagnostics(context.Background(), viewer, result.Status.Sequence)
	if err != nil || len(diagnostics.Events) != 1 || diagnostics.Events[0].Kind != "START" {
		t.Fatalf("diagnostics = %#v, err=%v", diagnostics, err)
	}
}

func TestFixedRolePermissionMatrix(t *testing.T) {
	principal := Principal{Actor: "local:test", SourceChannel: storage.SourceConsole}
	checks := []struct {
		name       string
		role       Role
		permission permission
		allowed    bool
	}{
		{name: "auditor read", role: RoleAuditor, permission: permissionRead, allowed: true},
		{name: "auditor node read", role: RoleAuditor, permission: permissionNodeRead, allowed: true},
		{name: "auditor validate", role: RoleAuditor, permission: permissionValidate, allowed: false},
		{name: "auditor preview", role: RoleAuditor, permission: permissionPreview, allowed: false},
		{name: "auditor apply", role: RoleAuditor, permission: permissionApply, allowed: false},
		{name: "legacy viewer remains read only", role: RoleViewer, permission: permissionRead, allowed: true},
		{name: "operator validate", role: RoleOperator, permission: permissionValidate, allowed: true},
		{name: "operator preview", role: RoleOperator, permission: permissionPreview, allowed: true},
		{name: "operator apply", role: RoleOperator, permission: permissionApply, allowed: true},
		{name: "operator node operate", role: RoleOperator, permission: permissionNodeOperate, allowed: true},
		{name: "operator node admin", role: RoleOperator, permission: permissionNodeAdmin, allowed: false},
		{name: "administrator node admin", role: RoleAdministrator, permission: permissionNodeAdmin, allowed: true},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			principal.Role = check.role
			err := requirePermission(principal, check.permission)
			if check.allowed && err != nil {
				t.Fatalf("permission was rejected: %v", err)
			}
			if !check.allowed && !errors.Is(err, ErrForbidden) {
				t.Fatalf("permission error = %v", err)
			}
		})
	}
}

func TestServiceTreatsTargetOnlyChangeAsARealRollout(t *testing.T) {
	fixture := newAdminFixture(t)
	principal := fixture.operator()
	preview, err := fixture.service.Preview(context.Background(), principal, PreviewInput{
		Document: fixture.document, BaselineRolloutSequence: fixture.initial.Sequence,
		TargetNodeIDs: []string{"node-a", "node-b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if preview.NoChange || len(preview.Changes) != 0 ||
		!slices.Equal(preview.TargetNodeIDs, []string{"node-a", "node-b"}) {
		t.Fatalf("target-only preview = %#v", preview)
	}
	result, err := fixture.service.Apply(context.Background(), principal, ApplyInput{
		RequestID: "op_admin_target_only_0001", Document: fixture.document,
		SourceRevision: "console:target-only", Reason: "enroll replacement target",
		TargetNodeIDs:                   []string{"node-a", "node-b"},
		ExpectedSelectedRolloutSequence: fixture.initial.Sequence,
		ExpectedActiveArtifact:          fixture.initial.ArtifactDigest,
		PreviewFingerprintSHA256:        preview.PlanFingerprintSHA256,
	})
	if err != nil || result.Status.Sequence != fixture.initial.Sequence+1 ||
		!slices.Equal(result.Status.TargetNodeIDs, []string{"node-a", "node-b"}) {
		t.Fatalf("target-only apply = %#v, err=%v", result, err)
	}
}

func TestServiceListsBoundedArtifactBoundRouteCatalog(t *testing.T) {
	fixture := newAdminFixture(t)
	viewer := fixture.operator()
	viewer.Role = RoleViewer

	page, err := fixture.service.ListCurrentRoutes(context.Background(), viewer, RouteCatalogQuery{
		ExpectedArtifactSHA256: fixture.initial.ArtifactDigest.String(),
		Offset:                 0, Limit: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if page.RolloutSequence != fixture.initial.Sequence ||
		page.ArtifactSHA256 != fixture.initial.ArtifactDigest.String() ||
		page.TotalRoutes != 2 || page.MatchingRoutes != 2 || len(page.Routes) != 1 ||
		page.Routes[0].Route != "local-response" || page.Routes[0].DestinationType != "FIXED_RESPONSE" {
		t.Fatalf("route page = %#v", page)
	}

	filtered, err := fixture.service.ListCurrentRoutes(context.Background(), viewer, RouteCatalogQuery{
		ExpectedArtifactSHA256: fixture.initial.ArtifactDigest.String(),
		Offset:                 0, Limit: MaxRoutePageSize, Query: "LOCAL-UPSTREAM",
	})
	if err != nil {
		t.Fatal(err)
	}
	if filtered.TotalRoutes != 2 || filtered.MatchingRoutes != 1 || len(filtered.Routes) != 1 ||
		filtered.Routes[0].Route != "default-route" || filtered.Routes[0].Destination != "local-upstream" {
		t.Fatalf("filtered route page = %#v", filtered)
	}

	_, err = fixture.service.ListCurrentRoutes(context.Background(), viewer, RouteCatalogQuery{
		ExpectedArtifactSHA256: strings.Repeat("0", 64), Offset: 0, Limit: 1,
	})
	if !errors.Is(err, ErrPrecondition) {
		t.Fatalf("changed artifact error = %v", err)
	}
}

func TestServiceRollsBackExactRetainedArtifactUnderNewSequence(t *testing.T) {
	fixture := newAdminFixture(t)
	principal := fixture.operator()
	candidate := bytes.Replace(fixture.document, []byte("local-bootstrap"), []byte("rollback-candidate"), 1)
	preview, err := fixture.service.Preview(context.Background(), principal, PreviewInput{
		Document: candidate, BaselineRolloutSequence: fixture.initial.Sequence,
		TargetNodeIDs: []string{"node-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	applied, err := fixture.service.Apply(context.Background(), principal, ApplyInput{
		RequestID: "op_admin_apply_for_rollback", Document: candidate,
		SourceRevision: "git:abcdef0123456789", Reason: "activate rollback candidate",
		TargetNodeIDs:                   []string{"node-a"},
		ExpectedSelectedRolloutSequence: fixture.initial.Sequence,
		ExpectedActiveArtifact:          fixture.initial.ArtifactDigest,
		PreviewFingerprintSHA256:        preview.PlanFingerprintSHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.activateCurrent(t, applied.Status.Sequence)
	current, err := fixture.repository.GetRollout(context.Background(), applied.Status.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	rollbackPreview, err := fixture.service.PreviewRollback(context.Background(), principal, RollbackPreviewInput{
		CurrentRolloutSequence: current.Sequence, TargetRolloutSequence: fixture.initial.Sequence,
		TargetNodeIDs: []string{"node-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rolledBack, err := fixture.service.Rollback(context.Background(), principal, RollbackInput{
		RequestID: "op_admin_rollback_0001", Reason: "restore known-good artifact",
		TargetNodeIDs:                   []string{"node-a"},
		ExpectedSelectedRolloutSequence: current.Sequence,
		ExpectedActiveArtifact:          current.ArtifactDigest,
		RollbackTargetSequence:          fixture.initial.Sequence,
		PreviewFingerprintSHA256:        rollbackPreview.PlanFingerprintSHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rolledBack.Status.Kind != storage.RolloutKindRollback ||
		rolledBack.Status.RollbackTargetSequence != fixture.initial.Sequence ||
		rolledBack.Status.Artifact.ArtifactSHA256 != fixture.initial.ArtifactDigest.String() {
		t.Fatalf("rollback result = %#v", rolledBack)
	}
	initialArtifact, err := fixture.repository.GetSnapshotArtifact(context.Background(), fixture.initial.ArtifactDigest)
	if err != nil {
		t.Fatal(err)
	}
	rollbackRecord, err := fixture.repository.GetRollout(context.Background(), rolledBack.Status.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	rollbackArtifact, err := fixture.repository.GetSnapshotArtifact(context.Background(), rollbackRecord.ArtifactDigest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(initialArtifact.Bytes, rollbackArtifact.Bytes) {
		t.Fatal("rollback did not reuse the exact retained artifact bytes")
	}
}

func TestServiceRollsBackCancelledCandidateFromObservedLastKnownGood(t *testing.T) {
	fixture := newAdminFixture(t)
	principal := fixture.operator()
	candidateDocument := bytes.Replace(
		fixture.document, []byte("local-bootstrap"), []byte("cancelled-candidate"), 1,
	)
	preview, err := fixture.service.Preview(context.Background(), principal, PreviewInput{
		Document: candidateDocument, BaselineRolloutSequence: fixture.initial.Sequence,
		TargetNodeIDs: []string{"node-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	applied, err := fixture.service.Apply(context.Background(), principal, ApplyInput{
		RequestID: "op_admin_cancelled_candidate", Document: candidateDocument,
		SourceRevision: "console:cancelled-candidate", Reason: "exercise NACK recovery",
		TargetNodeIDs:                   []string{"node-a"},
		ExpectedSelectedRolloutSequence: fixture.initial.Sequence,
		ExpectedActiveArtifact:          fixture.initial.ArtifactDigest,
		PreviewFingerprintSHA256:        preview.PlanFingerprintSHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := fixture.repository.GetRollout(context.Background(), applied.Status.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	candidateArtifact, err := fixture.repository.GetSnapshotArtifact(context.Background(), candidate.ArtifactDigest)
	if err != nil {
		t.Fatal(err)
	}
	initialArtifact, err := fixture.repository.GetSnapshotArtifact(context.Background(), fixture.initial.ArtifactDigest)
	if err != nil {
		t.Fatal(err)
	}
	fixture.runtime.mu.Lock()
	coordinator := fixture.runtime.current.(*rolloutservice.Service)
	fixture.runtime.mu.Unlock()
	previousReference := rollout.Reference{ID: initialArtifact.SnapshotID, SHA256: [32]byte(initialArtifact.Digest)}
	_, err = coordinator.Observe(context.Background(), "cancelled-candidate-nack", rollout.Report{
		NodeID: "node-a", ProcessInstance: "cancelled-candidate-process",
		Sequence: candidate.Sequence,
		Artifact: rollout.Reference{
			ID: candidateArtifact.SnapshotID, SHA256: [32]byte(candidateArtifact.Digest),
		},
		PreviousActive: previousReference, CurrentActive: previousReference,
		Operation: rollout.OperationPrepare, Result: rollout.ResultNACK,
		Issues: []rollout.Issue{{Code: "snapshot.listener_restart_required", FieldPath: "snapshot.listeners"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	status, err := fixture.service.GetStatus(context.Background(), principal, candidate.Sequence)
	if err != nil || status.Phase != rollout.PhaseCancelled ||
		status.BaselineRolloutSequence != fixture.initial.Sequence {
		t.Fatalf("cancelled status = %#v, err=%v", status, err)
	}
	desired, err := fixture.service.GetDesiredState(context.Background(), principal, candidate.Sequence)
	if err != nil || desired.RolloutSequence != candidate.Sequence ||
		desired.ArtifactSHA256 != candidate.ArtifactDigest.String() ||
		!bytes.Equal([]byte(desired.Document), candidateDocument) {
		t.Fatalf("desired state = %#v, err=%v", desired, err)
	}

	rollbackPreview, err := fixture.service.PreviewRollback(context.Background(), principal, RollbackPreviewInput{
		CurrentRolloutSequence: candidate.Sequence,
		TargetRolloutSequence:  fixture.initial.Sequence,
		TargetNodeIDs:          []string{"node-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := fixture.service.Rollback(context.Background(), principal, RollbackInput{
		RequestID: "op_admin_cancelled_rollback", Reason: "restore observed last-known-good",
		TargetNodeIDs:                   []string{"node-a"},
		ExpectedSelectedRolloutSequence: candidate.Sequence,
		ExpectedActiveArtifact:          candidate.ArtifactDigest,
		RollbackTargetSequence:          fixture.initial.Sequence,
		PreviewFingerprintSHA256:        rollbackPreview.PlanFingerprintSHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	rollbackRecord, err := fixture.repository.GetRollout(context.Background(), recovered.Status.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if len(rollbackRecord.ExpectedActiveByNode) != 1 ||
		rollbackRecord.ExpectedActiveByNode[0].NodeID != "node-a" ||
		rollbackRecord.ExpectedActiveByNode[0].ArtifactDigest != fixture.initial.ArtifactDigest {
		t.Fatalf("cancelled rollback expectations = %#v", rollbackRecord.ExpectedActiveByNode)
	}
	fixture.runtime.mu.Lock()
	rollbackCoordinator := fixture.runtime.current.(*rolloutservice.Service)
	fixture.runtime.mu.Unlock()
	if _, err := rollbackCoordinator.Reconnect(context.Background(), "cancelled-rollback-reconnect", rollout.RuntimeState{
		NodeID: "node-a", ProcessInstance: "cancelled-candidate-process",
		LastSequence: fixture.initial.Sequence, Active: previousReference, ActiveShardCount: 8,
	}); err != nil {
		t.Fatal(err)
	}
	active, err := fixture.service.GetStatus(context.Background(), principal, recovered.Status.Sequence)
	if err != nil || active.Phase != rollout.PhaseActive ||
		active.Artifact.ArtifactSHA256 != fixture.initial.ArtifactDigest.String() {
		t.Fatalf("recovered status = %#v, err=%v", active, err)
	}
}

func TestServicePersistsSafePolicyAndCancelsIdempotently(t *testing.T) {
	fixture := newAdminFixture(t)
	principal := fixture.operator()
	candidate := bytes.Replace(fixture.document, []byte("local-bootstrap"), []byte("policy-cancel-candidate"), 1)
	policy := RolloutPolicyInput{
		Enabled: true, Strategy: storage.RolloutStrategyImmediate,
		PrepareTimeoutSeconds: 20, ActivationTimeoutSeconds: 30,
		AutomaticRollback: true,
	}
	preview, err := fixture.service.Preview(context.Background(), principal, PreviewInput{
		Document: candidate, BaselineRolloutSequence: fixture.initial.Sequence,
		TargetNodeIDs: []string{"node-a"}, Policy: policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	withoutPolicy, err := fixture.service.Preview(context.Background(), principal, PreviewInput{
		Document: candidate, BaselineRolloutSequence: fixture.initial.Sequence,
		TargetNodeIDs: []string{"node-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if preview.Policy == nil || preview.PlanFingerprintSHA256 == withoutPolicy.PlanFingerprintSHA256 {
		t.Fatalf("policy was not bound into preview: with=%#v without=%#v", preview, withoutPolicy)
	}
	applied, err := fixture.service.Apply(context.Background(), principal, ApplyInput{
		RequestID: "op_admin_policy_cancel_apply", Document: candidate,
		SourceRevision: "git:policy-cancel", Reason: "exercise bounded cancellation",
		TargetNodeIDs:                   []string{"node-a"},
		ExpectedSelectedRolloutSequence: fixture.initial.Sequence,
		ExpectedActiveArtifact:          fixture.initial.ArtifactDigest,
		PreviewFingerprintSHA256:        preview.PlanFingerprintSHA256,
		Policy:                          policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if applied.Status.Policy == nil || !applied.Status.Policy.AutomaticRollback {
		t.Fatalf("applied policy status = %#v", applied.Status)
	}
	cancelled, err := fixture.service.Cancel(context.Background(), principal, CancelInput{
		RequestID: "op_admin_policy_cancel", Sequence: applied.Status.Sequence,
		Reason: "operator stopped the canary before activation",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.Status.Phase != rollout.PhaseCancelled {
		t.Fatalf("cancelled status = %#v", cancelled.Status)
	}
	replayed, err := fixture.service.Cancel(context.Background(), principal, CancelInput{
		RequestID: "op_admin_policy_cancel", Sequence: applied.Status.Sequence,
		Reason: "operator stopped the canary before activation",
	})
	if err != nil || !replayed.Replayed {
		t.Fatalf("cancel replay = %#v, err=%v", replayed, err)
	}
	diagnostics, err := fixture.service.GetDiagnostics(context.Background(), principal, applied.Status.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	last := diagnostics.Events[len(diagnostics.Events)-1]
	if last.Kind != "CANCEL" || last.Cancellation == nil ||
		last.Cancellation.Reason != "operator stopped the canary before activation" ||
		last.Cancellation.Actor != principal.Actor ||
		last.Cancellation.SourceChannel != principal.SourceChannel ||
		last.Cancellation.AttributionStatus != rolloutservice.CancellationAttributionRecorded {
		t.Fatalf("cancellation diagnostic = %#v", last)
	}
}

func TestServiceCreatesExactAutomaticRollbackAfterReconciliation(t *testing.T) {
	fixture := newAdminFixture(t)
	principal := fixture.operator()
	candidate := bytes.Replace(fixture.document, []byte("local-bootstrap"), []byte("auto-rollback-candidate"), 1)
	policy := RolloutPolicyInput{
		Enabled: true, Strategy: storage.RolloutStrategyImmediate,
		PrepareTimeoutSeconds: 20, ActivationTimeoutSeconds: 30,
		AutomaticRollback: true,
	}
	preview, err := fixture.service.Preview(context.Background(), principal, PreviewInput{
		Document: candidate, BaselineRolloutSequence: fixture.initial.Sequence,
		TargetNodeIDs: []string{"node-a"}, Policy: policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	applied, err := fixture.service.Apply(context.Background(), principal, ApplyInput{
		RequestID: "op_admin_auto_rollback_apply", Document: candidate,
		SourceRevision: "git:auto-rollback", Reason: "exercise exact automatic rollback",
		TargetNodeIDs:                   []string{"node-a"},
		ExpectedSelectedRolloutSequence: fixture.initial.Sequence,
		ExpectedActiveArtifact:          fixture.initial.ArtifactDigest,
		PreviewFingerprintSHA256:        preview.PlanFingerprintSHA256,
		Policy:                          policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	failed, err := fixture.repository.GetRollout(context.Background(), applied.Status.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	targetArtifact, err := fixture.repository.GetSnapshotArtifact(context.Background(), failed.ArtifactDigest)
	if err != nil {
		t.Fatal(err)
	}
	baselineArtifact, err := fixture.repository.GetSnapshotArtifact(context.Background(), fixture.initial.ArtifactDigest)
	if err != nil {
		t.Fatal(err)
	}
	targetReference := rollout.Reference{ID: targetArtifact.SnapshotID, SHA256: [32]byte(targetArtifact.Digest)}
	baselineReference := rollout.Reference{ID: baselineArtifact.SnapshotID, SHA256: [32]byte(baselineArtifact.Digest)}
	fixture.runtime.mu.Lock()
	coordinator := fixture.runtime.current
	fixture.runtime.mu.Unlock()
	prepare := rollout.Report{
		NodeID: "node-a", ProcessInstance: "auto-rollback-process", Sequence: failed.Sequence,
		Artifact: targetReference, Operation: rollout.OperationPrepare, Result: rollout.ResultACK,
		PreviousActive: baselineReference, CurrentActive: baselineReference,
		ShardCount: 8, CompletedShards: 8, CompletedAt: failed.CreatedAt.Add(time.Second).UTC(),
	}
	if _, err := coordinator.Observe(context.Background(), "auto-rollback-prepare", prepare); err != nil {
		t.Fatal(err)
	}
	nack := prepare
	nack.Operation = rollout.OperationActivate
	nack.Result = rollout.ResultNACK
	nack.CompletedShards = 7
	nack.CompletedAt = failed.CreatedAt.Add(2 * time.Second).UTC()
	nack.Issues = []rollout.Issue{{Code: "activation.swap.failed", FieldPath: "snapshot"}}
	if _, err := coordinator.Observe(context.Background(), "auto-rollback-activation-nack", nack); err != nil {
		t.Fatal(err)
	}
	fixture.runtime.connections = []discovery.ConnectionSnapshot{{
		NodeID: "node-a", ProcessInstance: "auto-rollback-process",
		ActiveSnapshotID: baselineArtifact.SnapshotID, PreparedSequence: failed.Sequence,
		Reconciled: true,
	}}
	if _, err := fixture.service.ReconcilePolicy(
		context.Background(), failed.CreatedAt.Add(3*time.Second),
	); !errors.Is(err, ErrPolicyAwaitingReconciliation) {
		t.Fatalf("uncleared prepared candidate error = %v", err)
	}
	selectedBeforeRollback, err := fixture.repository.GetSelectedRollout(context.Background())
	if err != nil || selectedBeforeRollback.Sequence != failed.Sequence {
		t.Fatalf("selection advanced before cleanup: selected=%#v err=%v", selectedBeforeRollback, err)
	}
	fixture.runtime.connections[0].PreparedSequence = 0
	reconciled, err := fixture.service.ReconcilePolicy(context.Background(), failed.CreatedAt.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.AutomaticRollback == nil ||
		reconciled.AutomaticRollback.Status.Kind != storage.RolloutKindRollback ||
		reconciled.AutomaticRollback.Status.RollbackTargetSequence != fixture.initial.Sequence {
		t.Fatalf("automatic rollback = %#v", reconciled)
	}
	rollback, err := fixture.repository.GetRollout(
		context.Background(), reconciled.AutomaticRollback.Status.Sequence,
	)
	if err != nil {
		t.Fatal(err)
	}
	if rollback.RequestID != "auto-rollback-"+strconv.FormatUint(failed.Sequence, 10) ||
		len(rollback.ExpectedActiveByNode) != 1 ||
		rollback.ExpectedActiveByNode[0].ArtifactDigest != fixture.initial.ArtifactDigest ||
		rollback.Policy.AutomaticRollback {
		t.Fatalf("automatic rollback record = %#v", rollback)
	}
}

type adminFixture struct {
	repository *storage.FileRepository
	runtime    *fakeRuntime
	service    *Service
	document   []byte
	initial    storage.RolloutRecord
}

func newAdminFixture(t *testing.T) adminFixture {
	t.Helper()
	repository, err := storage.OpenFileRepository(t.TempDir(), storage.FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	document, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "examples", "local.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	desired, artifact := createAdminArtifact(t, repository, "admin-initial", document)
	record, err := repository.AllocateRollout(context.Background(), storage.RolloutInput{
		RequestID: "admin-initial-rollout", ArtifactDigest: artifact.Digest,
		DesiredRevisionID: desired.ID, CompilerVersion: CompilerVersion,
		TargetNodeIDs: []string{"node-a"}, SourceChannel: storage.SourceSystem,
		Actor: "admin-test", Reason: "establish initial runtime",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.InitializeSelectedRollout(context.Background(), record.Sequence); err != nil {
		t.Fatal(err)
	}
	coordinator, err := rolloutservice.Open(context.Background(), repository, record.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Start(context.Background(), "admin-initial-start"); err != nil {
		t.Fatal(err)
	}
	reference := rollout.Reference{ID: artifact.SnapshotID, SHA256: [32]byte(artifact.Digest)}
	prepare := rollout.Report{
		NodeID: "node-a", ProcessInstance: "admin-initial-process", Sequence: record.Sequence,
		Artifact: reference, Operation: rollout.OperationPrepare, Result: rollout.ResultACK,
		ShardCount: 8, CompletedShards: 8,
	}
	if _, err := coordinator.Observe(context.Background(), "admin-initial-prepare", prepare); err != nil {
		t.Fatal(err)
	}
	activate := prepare
	activate.Operation = rollout.OperationActivate
	activate.CurrentActive = reference
	if _, err := coordinator.Observe(context.Background(), "admin-initial-activate", activate); err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{repository: repository, current: coordinator}
	service, err := New(repository, runtime)
	if err != nil {
		t.Fatal(err)
	}
	return adminFixture{
		repository: repository, runtime: runtime, service: service,
		document: document, initial: record,
	}
}

func (fixture adminFixture) operator() Principal {
	return Principal{
		Actor: "spiffe://admin.test/service-accounts/gitops",
		Role:  RoleOperator, SourceChannel: storage.SourceGitOps,
	}
}

func (fixture adminFixture) activateCurrent(t *testing.T, sequence uint64) {
	t.Helper()
	fixture.runtime.mu.Lock()
	coordinator := fixture.runtime.current.(*rolloutservice.Service)
	fixture.runtime.mu.Unlock()
	record, err := fixture.repository.GetRollout(context.Background(), sequence)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := fixture.repository.GetSnapshotArtifact(context.Background(), record.ArtifactDigest)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := fixture.repository.GetSnapshotArtifact(context.Background(), record.PreviousArtifactDigest)
	if err != nil {
		t.Fatal(err)
	}
	targetReference := rollout.Reference{ID: artifact.SnapshotID, SHA256: [32]byte(artifact.Digest)}
	previousReference := rollout.Reference{ID: previous.SnapshotID, SHA256: [32]byte(previous.Digest)}
	prepare := rollout.Report{
		NodeID: "node-a", ProcessInstance: "admin-candidate-process", Sequence: sequence,
		Artifact: targetReference, Operation: rollout.OperationPrepare, Result: rollout.ResultACK,
		PreviousActive: previousReference, CurrentActive: previousReference,
		ShardCount: 8, CompletedShards: 8,
	}
	if _, err := coordinator.Observe(context.Background(), "admin-candidate-prepare", prepare); err != nil {
		t.Fatal(err)
	}
	activate := prepare
	activate.Operation = rollout.OperationActivate
	activate.CurrentActive = targetReference
	if _, err := coordinator.Observe(context.Background(), "admin-candidate-activate", activate); err != nil {
		t.Fatal(err)
	}
}

func createAdminArtifact(
	t *testing.T,
	repository *storage.FileRepository,
	requestID string,
	document []byte,
) (storage.DesiredRevision, storage.SnapshotArtifact) {
	t.Helper()
	desired, err := repository.CreateDesiredRevision(context.Background(), storage.DesiredRevisionInput{
		RequestID: requestID + ".desired", Document: document,
		SourceChannel: storage.SourceSystem, Actor: "admin-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := snapshot.Compile(bytes.NewReader(document))
	if err != nil {
		t.Fatal(err)
	}
	artifactBytes, err := snapshot.MarshalDeterministic(compiled)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := repository.CreateSnapshotArtifact(context.Background(), storage.SnapshotArtifactInput{
		DesiredRevisionID: desired.ID, CompilerVersion: CompilerVersion, Bytes: artifactBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	return desired, artifact
}

type fakeRuntime struct {
	mu          sync.Mutex
	repository  *storage.FileRepository
	current     discovery.ManagedCoordinator
	connections []discovery.ConnectionSnapshot
}

func (runtime *fakeRuntime) CurrentRollout() (discovery.RolloutSelection, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	phase, nodes, err := runtime.current.Status()
	return discovery.RolloutSelection{
		Sequence: runtime.current.Sequence(), Phase: phase, Nodes: nodes,
	}, err
}

func (runtime *fakeRuntime) ReplaceRollout(
	ctx context.Context,
	_ discovery.RolloutMutation,
	next discovery.ManagedCoordinator,
	selector discovery.RolloutSelector,
) (discovery.RolloutSelection, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if err := selector(ctx, runtime.current.Sequence(), next.Sequence()); err != nil {
		return discovery.RolloutSelection{}, err
	}
	runtime.current = next
	phase, nodes, err := next.Status()
	return discovery.RolloutSelection{Sequence: next.Sequence(), Phase: phase, Nodes: nodes}, err
}

func (runtime *fakeRuntime) CancelRollout(
	ctx context.Context,
	sequence uint64,
	eventID string,
	cancellation rolloutservice.CancellationInput,
) (discovery.RolloutSelection, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.current.Sequence() != sequence {
		return discovery.RolloutSelection{}, discovery.ErrRolloutSuperseded
	}
	transition, err := runtime.current.Cancel(ctx, eventID, cancellation)
	if err != nil {
		return discovery.RolloutSelection{}, err
	}
	phase, nodes, err := runtime.current.Status()
	return discovery.RolloutSelection{
		Sequence: sequence, Phase: phase, Nodes: nodes, Replayed: transition.Replayed,
	}, err
}

func (runtime *fakeRuntime) EvaluateRollout(
	ctx context.Context,
	observedAt time.Time,
) (discovery.PolicyEvaluationResult, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	phase, _, err := runtime.current.Status()
	if err != nil {
		return discovery.PolicyEvaluationResult{}, err
	}
	result := discovery.PolicyEvaluationResult{Sequence: runtime.current.Sequence(), Phase: phase}
	if !runtime.current.Policy().Enabled {
		return result, nil
	}
	transition, err := runtime.current.Evaluate(ctx, "test-policy-evaluation", rollout.PolicyObservation{
		ObservedAt: observedAt.UTC(),
	})
	if errors.Is(err, rollout.ErrPolicyPending) || errors.Is(err, rollout.ErrPolicyDisabled) {
		return result, nil
	}
	if err != nil {
		return discovery.PolicyEvaluationResult{}, err
	}
	phase, _, err = runtime.current.Status()
	return discovery.PolicyEvaluationResult{
		Sequence: runtime.current.Sequence(), Phase: phase, Changed: true,
		Replayed: transition.Replayed, Decision: transition.Result.Decision,
		Reason: transition.Result.Reason,
	}, err
}

func (runtime *fakeRuntime) Connections() []discovery.ConnectionSnapshot {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return append([]discovery.ConnectionSnapshot(nil), runtime.connections...)
}
