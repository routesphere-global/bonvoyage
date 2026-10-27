package adminservice

import (
	"context"
	"testing"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/discovery"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/rollout"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/rolloutservice"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
)

func TestAuditProjectionIsPagedIntegrityBoundAndRestartStable(t *testing.T) {
	fixture := newAdminFixture(t)
	viewer := fixture.operator()
	viewer.Role = RoleViewer

	first, err := fixture.service.GetAudit(
		context.Background(), viewer, fixture.initial.Sequence, 0, 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	if first.ManifestVersion != AuditManifestVersion || first.ManifestSHA256 == "" ||
		first.Rollout.Actor != "admin-test" || first.Rollout.SnapshotID == "" ||
		first.Journal.TotalEvents != 3 || len(first.Journal.Events) != 2 ||
		first.Journal.FirstIndex != 1 || first.Journal.LastIndex != 2 ||
		first.Journal.NextAfterIndex != 2 {
		t.Fatalf("first audit page = %#v", first)
	}
	for _, event := range first.Journal.Events {
		if event.EventSHA256 == "" {
			t.Fatalf("audit event lacks digest: %#v", event)
		}
	}
	second, err := fixture.service.GetAudit(
		context.Background(), viewer, fixture.initial.Sequence, first.Journal.NextAfterIndex, 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	if second.ManifestSHA256 != first.ManifestSHA256 || len(second.Journal.Events) != 1 ||
		second.Journal.FirstIndex != 3 || second.Journal.NextAfterIndex != 0 {
		t.Fatalf("second audit page = %#v", second)
	}

	restarted, err := New(fixture.repository, fixture.runtime)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := restarted.GetAudit(
		context.Background(), viewer, fixture.initial.Sequence, 0, MaxAuditPageSize,
	)
	if err != nil || replayed.ManifestSHA256 != first.ManifestSHA256 {
		t.Fatalf("restarted audit = %#v, err=%v", replayed, err)
	}

	artifact, err := fixture.repository.GetSnapshotArtifact(
		context.Background(), fixture.initial.ArtifactDigest,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.runtime.mu.Lock()
	coordinator := fixture.runtime.current
	fixture.runtime.mu.Unlock()
	if _, err := coordinator.Reconnect(context.Background(), "admin-audit-reconnect", rollout.RuntimeState{
		NodeID: "node-a", ProcessInstance: "admin-audit-process",
		LastSequence:     fixture.initial.Sequence,
		Active:           rollout.Reference{ID: artifact.SnapshotID, SHA256: [32]byte(artifact.Digest)},
		ActiveShardCount: 8,
	}); err != nil {
		t.Fatal(err)
	}
	appended, err := restarted.GetAudit(
		context.Background(), viewer, fixture.initial.Sequence, 0, MaxAuditPageSize,
	)
	if err != nil {
		t.Fatal(err)
	}
	if appended.Journal.TotalEvents != first.Journal.TotalEvents+1 ||
		appended.ManifestSHA256 == first.ManifestSHA256 {
		t.Fatalf("appended audit = %#v", appended)
	}
	for index, event := range first.Journal.Events {
		if appended.Journal.Events[index].EventSHA256 != event.EventSHA256 {
			t.Fatal("append-only journal changed an existing audit event")
		}
	}
}

func TestOperationalTelemetryUsesOnlyFixedDimensions(t *testing.T) {
	fixture := newAdminFixture(t)
	viewer := fixture.operator()
	viewer.Role = RoleViewer
	fixture.runtime.connections = []discovery.ConnectionSnapshot{{
		NodeID: "node-a", Reconciled: true, PendingCommands: 2,
	}}

	telemetry, err := fixture.service.GetOperationalTelemetry(context.Background(), viewer)
	if err != nil {
		t.Fatal(err)
	}
	if !telemetry.Ready || !telemetry.RuntimeAuthorityMatch ||
		telemetry.SelectedSequence != fixture.initial.Sequence ||
		telemetry.RolloutPhase != rollout.PhaseActive || telemetry.TargetNodes != 1 ||
		telemetry.ConnectedNodes != 1 || telemetry.ReconciledNodes != 1 ||
		telemetry.UnreconciledNodes != 0 || telemetry.PendingCommands != 2 ||
		telemetry.JournalEvents != 3 || telemetry.PolicyStrategy != "DISABLED" {
		t.Fatalf("telemetry = %#v", telemetry)
	}
	if countNamed(telemetry.NodePhases, string(rollout.NodeActive)) != 1 ||
		countNamed(telemetry.JournalKinds, "REPORT") != 2 ||
		countReport(telemetry.Reports, rollout.OperationPrepare, rollout.ResultACK) != 1 ||
		countReport(telemetry.Reports, rollout.OperationActivate, rollout.ResultACK) != 1 {
		t.Fatalf("fixed telemetry counts = %#v", telemetry)
	}
}

func TestDiagnosticsResultKeepsNewestBoundedEvents(t *testing.T) {
	events := make([]rolloutservice.Diagnostic, MaxDiagnosticEvents+10)
	for index := range events {
		events[index] = rolloutservice.Diagnostic{
			Index: uint64(index + 1), EventID: "event", Kind: "REPORT",
			Digest: storage.Sum([]byte{byte(index)}), Phase: rollout.PhaseActive,
		}
	}
	result := diagnosticsResult(7, events)
	if result.TotalEvents != uint64(len(events)) || !result.Truncated ||
		len(result.Events) != MaxDiagnosticEvents || result.FirstIndex != 11 ||
		result.LastIndex != uint64(len(events)) {
		t.Fatalf("bounded diagnostics = %#v", result)
	}
}

func countNamed(values []NamedCount, name string) uint64 {
	for _, value := range values {
		if value.Name == name {
			return value.Count
		}
	}
	return 0
}

func countReport(
	values []ReportCount,
	operation rollout.Operation,
	result rollout.Result,
) uint64 {
	for _, value := range values {
		if value.Operation == operation && value.Result == result {
			return value.Count
		}
	}
	return 0
}
