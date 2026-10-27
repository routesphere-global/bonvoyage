package rolloutservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/rollout"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/snapshot"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
)

func TestServiceRecoversPrepareBarrierAndRequiresRuntimeReconciliation(t *testing.T) {
	fixture := newServiceFixture(t)
	service := openTestService(t, fixture.repository, fixture.rollout.Sequence)

	started, err := service.Start(context.Background(), "event-start")
	if err != nil {
		t.Fatal(err)
	}
	assertServiceCommands(t, started.Commands, rollout.OperationPrepare, "node-a", "node-b")
	if len(started.Commands[0].Artifact.Bytes) == 0 {
		t.Fatal("prepare command omitted immutable artifact bytes")
	}
	started.Commands[0].Artifact.Bytes[0] ^= 0xff
	retried, err := service.Start(context.Background(), "event-start")
	if err != nil {
		t.Fatal(err)
	}
	if !retried.Replayed || bytes.Equal(retried.Commands[0].Artifact.Bytes, started.Commands[0].Artifact.Bytes) {
		t.Fatal("exact retry did not return an isolated command copy")
	}

	if transition, err := service.Observe(
		context.Background(), "event-prepared-a", fixture.ack("node-a", "boot-1", rollout.OperationPrepare),
	); err != nil || len(transition.Commands) != 0 {
		t.Fatalf("first prepare: transition=%#v err=%v", transition, err)
	}
	activated, err := service.Observe(
		context.Background(), "event-prepared-b", fixture.ack("node-b", "boot-1", rollout.OperationPrepare),
	)
	if err != nil {
		t.Fatal(err)
	}
	assertServiceCommands(t, activated.Commands, rollout.OperationActivate, "node-a", "node-b")

	recovered := openTestService(t, fixture.repository, fixture.rollout.Sequence)
	phase, nodes, err := recovered.Status()
	if err != nil {
		t.Fatal(err)
	}
	if phase != rollout.PhaseActivating || nodes["node-a"].Connected || nodes["node-b"].Connected {
		t.Fatalf("recovered status: phase=%s nodes=%#v", phase, nodes)
	}
	pending, err := recovered.PendingCommands()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 2 {
		t.Fatal("recovered inspection projection omitted outstanding activation")
	}
	suppressed, err := recovered.Observe(
		context.Background(), "event-prepared-b", fixture.ack("node-b", "boot-1", rollout.OperationPrepare),
	)
	if err != nil || !suppressed.Replayed || len(suppressed.Commands) != 0 {
		t.Fatalf("pre-restart command replay was not suppressed: transition=%#v err=%v", suppressed, err)
	}

	for _, nodeID := range []string{"node-a", "node-b"} {
		transition, err := recovered.Reconnect(
			context.Background(), "event-reconnect-"+nodeID, fixture.preparedRuntime(nodeID, "boot-2"),
		)
		if err != nil {
			t.Fatal(err)
		}
		assertServiceCommands(t, transition.Commands, rollout.OperationActivate, nodeID)
	}
	for _, nodeID := range []string{"node-a", "node-b"} {
		transition, err := recovered.Observe(
			context.Background(), "event-active-"+nodeID, fixture.ack(nodeID, "boot-2", rollout.OperationActivate),
		)
		if err != nil || len(transition.Commands) != 0 {
			t.Fatalf("activation %s: transition=%#v err=%v", nodeID, transition, err)
		}
	}
	phase, _, err = recovered.Status()
	if err != nil {
		t.Fatal(err)
	}
	if phase != rollout.PhaseActive {
		t.Fatalf("phase = %s, want %s", phase, rollout.PhaseActive)
	}

	reopened := openTestService(t, fixture.repository, fixture.rollout.Sequence)
	phase, nodes, err = reopened.Status()
	if err != nil {
		t.Fatal(err)
	}
	if phase != rollout.PhaseActive || nodes["node-a"].Connected || nodes["node-b"].Connected {
		t.Fatalf("final recovered status: phase=%s nodes=%#v", phase, nodes)
	}
	events, err := fixture.repository.ListRolloutEvents(context.Background(), fixture.rollout.Sequence)
	if err != nil || len(events) != 7 {
		t.Fatalf("journal count = %d, err=%v", len(events), err)
	}
}

func TestServiceEventIDsAreIdempotentAndDoNotReplayStaleCommands(t *testing.T) {
	fixture := newServiceFixture(t)
	service := openTestService(t, fixture.repository, fixture.rollout.Sequence)
	started, err := service.Start(context.Background(), "event-one")
	if err != nil {
		t.Fatal(err)
	}
	assertServiceCommands(t, started.Commands, rollout.OperationPrepare, "node-a", "node-b")
	replayed, err := service.Start(context.Background(), "event-one")
	if err != nil || !replayed.Replayed {
		t.Fatalf("start replay: transition=%#v err=%v", replayed, err)
	}
	assertServiceCommands(t, replayed.Commands, rollout.OperationPrepare, "node-a", "node-b")

	cancellation := testCancellation("operator stopped rollout")
	cancelled, err := service.Cancel(context.Background(), "event-cancel", cancellation)
	if err != nil {
		t.Fatal(err)
	}
	assertServiceCommands(t, cancelled.Commands, rollout.OperationCancel, "node-a", "node-b")
	changed := cancellation
	changed.Reason = "different reason"
	if _, err := service.Cancel(context.Background(), "event-cancel", changed); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("changed event replay error = %v", err)
	}
	changed = cancellation
	changed.Actor = "operator-b"
	if _, err := service.Cancel(context.Background(), "event-cancel", changed); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("changed actor replay error = %v", err)
	}
	stale, err := service.Start(context.Background(), "event-one")
	if err != nil || !stale.Replayed || len(stale.Commands) != 0 {
		t.Fatalf("old event replay: transition=%#v err=%v", stale, err)
	}
	events, err := fixture.repository.ListRolloutEvents(context.Background(), fixture.rollout.Sequence)
	if err != nil || len(events) != 2 {
		t.Fatalf("journal count = %d, err=%v", len(events), err)
	}
	record, err := decodeJournalRecord(events[1].Payload)
	if err != nil || record.Version != journalVersion || record.Input.Actor != cancellation.Actor ||
		record.Input.SourceChannel != cancellation.SourceChannel {
		t.Fatalf("persisted cancellation = %#v, err=%v", record, err)
	}
}

func TestServiceJournalsSafetyTransitionThatReturnsDrift(t *testing.T) {
	fixture := newServiceFixture(t)
	service := openTestService(t, fixture.repository, fixture.rollout.Sequence)
	if _, err := service.Start(context.Background(), "event-start"); err != nil {
		t.Fatal(err)
	}
	state := rollout.RuntimeState{
		NodeID: "node-a", ProcessInstance: "boot-early", LastSequence: fixture.rollout.Sequence,
		Active: fixture.target, ActiveShardCount: 8,
	}
	transition, err := service.Reconnect(context.Background(), "event-drift", state)
	if !errors.Is(err, rollout.ErrDrift) || len(transition.Commands) != 0 {
		t.Fatalf("early activation: transition=%#v err=%v", transition, err)
	}
	phase, _, err := service.Status()
	if err != nil {
		t.Fatal(err)
	}
	if phase != rollout.PhaseRequiresRollback {
		t.Fatalf("phase = %s", phase)
	}

	recovered := openTestService(t, fixture.repository, fixture.rollout.Sequence)
	phase, _, err = recovered.Status()
	if err != nil {
		t.Fatal(err)
	}
	if phase != rollout.PhaseRequiresRollback {
		t.Fatalf("recovered phase = %s", phase)
	}
	replayed, err := recovered.Reconnect(context.Background(), "event-drift", state)
	if !errors.Is(err, rollout.ErrDrift) || !replayed.Replayed || len(replayed.Commands) != 0 {
		t.Fatalf("drift replay: transition=%#v err=%v", replayed, err)
	}
}

func TestServiceRecoversPreparationNACKCancellation(t *testing.T) {
	fixture := newServiceFixture(t)
	service := openTestService(t, fixture.repository, fixture.rollout.Sequence)
	if _, err := service.Start(context.Background(), "event-start"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Observe(
		context.Background(), "event-prepared-a", fixture.ack("node-a", "boot-1", rollout.OperationPrepare),
	); err != nil {
		t.Fatal(err)
	}
	cancelled, err := service.Observe(
		context.Background(), "event-nack-b", fixture.nack("node-b", "boot-1", rollout.OperationPrepare),
	)
	if err != nil {
		t.Fatal(err)
	}
	assertServiceCommands(t, cancelled.Commands, rollout.OperationCancel, "node-a")
	if cancelled.Commands[0].Reason != "node preparation failed" {
		t.Fatalf("cancellation reason = %q", cancelled.Commands[0].Reason)
	}

	recovered := openTestService(t, fixture.repository, fixture.rollout.Sequence)
	phase, nodes, err := recovered.Status()
	if err != nil {
		t.Fatal(err)
	}
	if phase != rollout.PhaseCancelled || nodes["node-a"].Connected || nodes["node-b"].Connected {
		t.Fatalf("recovered cancellation: phase=%s nodes=%#v", phase, nodes)
	}
	transition, err := recovered.Reconnect(
		context.Background(), "event-reconnect-a", fixture.preparedRuntime("node-a", "boot-2"),
	)
	if err != nil {
		t.Fatal(err)
	}
	assertServiceCommands(t, transition.Commands, rollout.OperationCancel, "node-a")
	if transition.Commands[0].Reason != "node preparation failed" {
		t.Fatalf("recovered cancellation reason = %q", transition.Commands[0].Reason)
	}
}

func TestServiceProjectsOrderedStructuredDiagnostics(t *testing.T) {
	fixture := newServiceFixture(t)
	service := openTestService(t, fixture.repository, fixture.rollout.Sequence)
	if service.Sequence() != fixture.rollout.Sequence {
		t.Fatalf("sequence = %d, want %d", service.Sequence(), fixture.rollout.Sequence)
	}
	if _, err := service.Start(context.Background(), "event-start"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Observe(
		context.Background(), "event-nack", fixture.nack("node-a", "boot-1", rollout.OperationPrepare),
	); err != nil {
		t.Fatal(err)
	}

	diagnostics, err := service.Diagnostics(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(diagnostics) != 2 || diagnostics[0].Index != 1 || diagnostics[1].Index != 2 {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
	report := diagnostics[1].Report
	if diagnostics[1].Kind != eventKindReport || report == nil ||
		report.NodeID != "node-a" || report.Result != rollout.ResultNACK ||
		len(report.Issues) != 1 || report.Issues[0].Code != "snapshot.route.invalid" {
		t.Fatalf("NACK diagnostic = %#v", diagnostics[1])
	}
	diagnostics[1].Report.Issues[0].Code = "changed"
	again, err := service.Diagnostics(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if again[1].Report.Issues[0].Code != "snapshot.route.invalid" {
		t.Fatalf("diagnostic projection was mutable: %#v", again[1])
	}
}

func TestServiceDoesNotJournalRejectedTransitionOrConsumeEventID(t *testing.T) {
	fixture := newServiceFixture(t)
	service := openTestService(t, fixture.repository, fixture.rollout.Sequence)
	if _, err := service.Observe(
		context.Background(), "event-reusable", fixture.ack("node-a", "boot-1", rollout.OperationPrepare),
	); !errors.Is(err, rollout.ErrNotStarted) {
		t.Fatalf("pre-start report error = %v", err)
	}
	started, err := service.Start(context.Background(), "event-reusable")
	if err != nil {
		t.Fatal(err)
	}
	assertServiceCommands(t, started.Commands, rollout.OperationPrepare, "node-a", "node-b")
	events, err := fixture.repository.ListRolloutEvents(context.Background(), fixture.rollout.Sequence)
	if err != nil || len(events) != 1 || events[0].Kind != eventKindStart {
		t.Fatalf("journal = %#v, err=%v", events, err)
	}
	if _, err := service.Cancel(
		context.Background(), "event-empty-cancel", testCancellation("  "),
	); !errors.Is(err, rollout.ErrInvalidReport) {
		t.Fatalf("empty cancellation error = %v", err)
	}
}

func TestServiceRejectsInvalidCancellationAttribution(t *testing.T) {
	fixture := newServiceFixture(t)
	service := openTestService(t, fixture.repository, fixture.rollout.Sequence)
	invalid := []CancellationInput{
		{Reason: "stop", SourceChannel: storage.SourceConsole},
		{Reason: "stop", Actor: "operator-a"},
		{Reason: "stop", Actor: "operator\nadmin", SourceChannel: storage.SourceConsole},
		{Reason: "stop", Actor: "operator-a", SourceChannel: storage.SourceSystem},
	}
	for index, cancellation := range invalid {
		if _, err := service.Cancel(
			context.Background(), fmt.Sprintf("invalid-cancel-%d", index), cancellation,
		); !errors.Is(err, storage.ErrInvalid) {
			t.Fatalf("invalid cancellation %d error = %v", index, err)
		}
	}
	events, err := fixture.repository.ListRolloutEvents(context.Background(), fixture.rollout.Sequence)
	if err != nil || len(events) != 0 {
		t.Fatalf("invalid cancellation was journaled: events=%#v err=%v", events, err)
	}
}

func TestServiceRecoversLegacyCancellationWithoutInventingAttribution(t *testing.T) {
	source := newServiceFixture(t)
	service := openTestService(t, source.repository, source.rollout.Sequence)
	if _, err := service.Start(context.Background(), "legacy-start"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Cancel(
		context.Background(), "legacy-cancel", testCancellation("legacy operator stopped rollout"),
	); err != nil {
		t.Fatal(err)
	}
	sourceEvents, err := source.repository.ListRolloutEvents(context.Background(), source.rollout.Sequence)
	if err != nil {
		t.Fatal(err)
	}

	target := newServiceFixture(t)
	for index, event := range sourceEvents {
		record, err := decodeJournalRecord(event.Payload)
		if err != nil {
			t.Fatal(err)
		}
		record.Version = legacyJournalVersion
		record.Input.Actor = ""
		record.Input.SourceChannel = ""
		payload, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := target.repository.AppendRolloutEvent(context.Background(), storage.RolloutEventInput{
			RolloutSequence: target.rollout.Sequence, ExpectedPreviousIndex: uint64(index),
			EventID: event.EventID, Kind: event.Kind, Payload: payload,
		}); err != nil {
			t.Fatal(err)
		}
	}

	recovered := openTestService(t, target.repository, target.rollout.Sequence)
	diagnostics, err := recovered.Diagnostics(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cancellation := diagnostics[len(diagnostics)-1].Cancellation
	if cancellation == nil || cancellation.Reason != "legacy operator stopped rollout" ||
		cancellation.Actor != "" || cancellation.SourceChannel != "" ||
		cancellation.AttributionStatus != CancellationAttributionLegacyUnavailable {
		t.Fatalf("legacy cancellation diagnostic = %#v", cancellation)
	}
	replayed, err := recovered.Cancel(
		context.Background(), "legacy-cancel", testCancellation("legacy operator stopped rollout"),
	)
	if err != nil || !replayed.Replayed || len(replayed.Commands) != 0 {
		t.Fatalf("legacy cancellation replay = %#v, err=%v", replayed, err)
	}
	if _, err := recovered.Cancel(
		context.Background(), "legacy-cancel", testCancellation("changed legacy reason"),
	); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("changed legacy cancellation replay error = %v", err)
	}
}

func TestServiceFailStopsWhenPersistenceOutcomeIsUncertain(t *testing.T) {
	fixture := newServiceFixture(t)
	failing := &failingAppendRepository{Repository: fixture.repository, err: errors.New("simulated fsync failure")}
	service := openTestService(t, failing, fixture.rollout.Sequence)

	transition, err := service.Start(context.Background(), "event-start")
	if !errors.Is(err, ErrServicePoisoned) || !errors.Is(err, ErrDurabilityUncertain) ||
		len(transition.Commands) != 0 {
		t.Fatalf("failed append: transition=%#v err=%v", transition, err)
	}
	if _, err := service.Cancel(
		context.Background(), "event-cancel", testCancellation("cannot continue"),
	); !errors.Is(err, ErrServicePoisoned) {
		t.Fatalf("poisoned service accepted mutation: %v", err)
	}
	if _, _, err := service.Status(); !errors.Is(err, ErrServicePoisoned) {
		t.Fatalf("poisoned service exposed speculative status: %v", err)
	}
	if _, err := service.PendingCommands(); !errors.Is(err, ErrServicePoisoned) {
		t.Fatalf("poisoned service exposed speculative commands: %v", err)
	}
	events, err := fixture.repository.ListRolloutEvents(context.Background(), fixture.rollout.Sequence)
	if err != nil || len(events) != 0 {
		t.Fatalf("failed append became visible: events=%#v err=%v", events, err)
	}
	recovered := openTestService(t, fixture.repository, fixture.rollout.Sequence)
	phase, _, err := recovered.Status()
	if err != nil {
		t.Fatal(err)
	}
	if phase != rollout.PhasePending {
		t.Fatalf("authoritative recovered phase = %s", phase)
	}
}

func TestServiceRejectsStaleWriterAndRecoversPublishedHistory(t *testing.T) {
	fixture := newServiceFixture(t)
	first := openTestService(t, fixture.repository, fixture.rollout.Sequence)
	stale := openTestService(t, fixture.repository, fixture.rollout.Sequence)
	if _, err := first.Start(context.Background(), "event-first"); err != nil {
		t.Fatal(err)
	}
	transition, err := stale.Start(context.Background(), "event-stale")
	if !errors.Is(err, ErrServicePoisoned) || !errors.Is(err, ErrJournalAdvanced) || len(transition.Commands) != 0 {
		t.Fatalf("stale writer: transition=%#v err=%v", transition, err)
	}
	recovered := openTestService(t, fixture.repository, fixture.rollout.Sequence)
	phase, _, err := recovered.Status()
	if err != nil {
		t.Fatal(err)
	}
	if phase != rollout.PhasePreparing {
		t.Fatalf("recovered phase = %s", phase)
	}
	events, err := fixture.repository.ListRolloutEvents(context.Background(), fixture.rollout.Sequence)
	if err != nil || len(events) != 1 || events[0].EventID != "event-first" {
		t.Fatalf("published history = %#v, err=%v", events, err)
	}
}

func TestServiceRejectsReplayOutcomeMismatch(t *testing.T) {
	fixture := newServiceFixture(t)
	bad := journalRecord{
		Version: journalVersion,
		Kind:    eventKindStart,
		Input:   journalInput{},
		Outcome: journalOutcome{
			Phase: rollout.PhaseActive, StateSHA256: strings.Repeat("0", 64),
			CommandCount: 0, CommandsSHA256: strings.Repeat("0", 64),
		},
	}
	payload, err := json.Marshal(bad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repository.AppendRolloutEvent(context.Background(), storage.RolloutEventInput{
		RolloutSequence: fixture.rollout.Sequence, ExpectedPreviousIndex: 0,
		EventID: "event-corrupt", Kind: eventKindStart, Payload: payload,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), fixture.repository, fixture.rollout.Sequence); !errors.Is(err, ErrReplayMismatch) ||
		!errors.Is(err, storage.ErrCorrupt) {
		t.Fatalf("replay mismatch error = %v", err)
	}
}

func TestServiceConcurrentExactRetriesAreRaceFree(t *testing.T) {
	fixture := newServiceFixture(t)
	service := openTestService(t, fixture.repository, fixture.rollout.Sequence)
	if _, err := service.Start(context.Background(), "event-start"); err != nil {
		t.Fatal(err)
	}

	const count = 32
	errorsSeen := make(chan error, count)
	var wait sync.WaitGroup
	for range count {
		wait.Add(1)
		go func() {
			defer wait.Done()
			transition, err := service.Start(context.Background(), "event-start")
			if err != nil {
				errorsSeen <- err
				return
			}
			if !transition.Replayed || len(transition.Commands) != 2 {
				errorsSeen <- fmt.Errorf("unexpected replay: %#v", transition)
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Error(err)
	}
	events, err := fixture.repository.ListRolloutEvents(context.Background(), fixture.rollout.Sequence)
	if err != nil || len(events) != 1 {
		t.Fatalf("journal count = %d, err=%v", len(events), err)
	}
}

func TestServiceJournalsOnlyStateChangingPolicyDecisionsAndReplaysThem(t *testing.T) {
	fixture := newPolicyServiceFixture(t)
	service := openTestService(t, fixture.repository, fixture.rollout.Sequence)
	if _, err := service.Start(context.Background(), "policy-start"); err != nil {
		t.Fatal(err)
	}
	createdAt := fixture.rollout.CreatedAt.UTC()
	for index, nodeID := range []string{"node-a", "node-b", "node-c"} {
		if _, err := service.Observe(
			context.Background(), "policy-prepare-"+nodeID,
			fixture.ackAt(nodeID, "boot-1", rollout.OperationPrepare, createdAt.Add(time.Duration(index+1)*time.Second)),
		); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := service.Observe(
		context.Background(), "policy-activate-node-a",
		fixture.ackAt("node-a", "boot-1", rollout.OperationActivate, createdAt.Add(4*time.Second)),
	); err != nil {
		t.Fatal(err)
	}

	health := []rollout.NodeHealth{{
		NodeID: "node-a", Connected: true, Reconciled: true,
		LastSeen: createdAt.Add(8 * time.Second), ActiveSnapshotID: fixture.target.ID,
	}}
	if _, err := service.Evaluate(context.Background(), "policy-wait", rollout.PolicyObservation{
		ObservedAt: createdAt.Add(9 * time.Second), Nodes: health,
	}); !errors.Is(err, rollout.ErrPolicyPending) {
		t.Fatalf("pending evaluation error = %v", err)
	}
	events, err := fixture.repository.ListRolloutEvents(context.Background(), fixture.rollout.Sequence)
	if err != nil || len(events) != 5 {
		t.Fatalf("pending observation journal count = %d, err=%v", len(events), err)
	}

	health[0].LastSeen = createdAt.Add(13 * time.Second)
	promoted, err := service.Evaluate(context.Background(), "policy-promote", rollout.PolicyObservation{
		ObservedAt: createdAt.Add(14 * time.Second), Nodes: health,
	})
	if err != nil {
		t.Fatal(err)
	}
	if promoted.Result.Decision != rollout.PolicyDecisionPromote {
		t.Fatalf("promotion = %#v", promoted)
	}
	assertServiceCommands(t, promoted.Commands, rollout.OperationActivate, "node-b", "node-c")
	diagnostics, err := service.Diagnostics(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	last := diagnostics[len(diagnostics)-1]
	if last.Kind != eventKindEvaluate || last.Policy == nil ||
		last.Policy.Decision != rollout.PolicyDecisionPromote || len(last.Policy.Nodes) != 1 {
		t.Fatalf("policy diagnostic = %#v", last)
	}

	recovered := openTestService(t, fixture.repository, fixture.rollout.Sequence)
	phase, _, err := recovered.Status()
	if err != nil || phase != rollout.PhaseActivating {
		t.Fatalf("recovered phase = %s, err=%v", phase, err)
	}
	replayed, err := recovered.Evaluate(context.Background(), "policy-promote", rollout.PolicyObservation{
		ObservedAt: createdAt.Add(14 * time.Second), Nodes: health,
	})
	if err != nil || !replayed.Replayed || len(replayed.Commands) != 0 ||
		replayed.Result.Decision != rollout.PolicyDecisionPromote {
		t.Fatalf("policy replay = %#v, err=%v", replayed, err)
	}
	events, err = fixture.repository.ListRolloutEvents(context.Background(), fixture.rollout.Sequence)
	if err != nil || len(events) != 6 {
		t.Fatalf("policy journal count = %d, err=%v", len(events), err)
	}
}

type serviceFixture struct {
	repository *storage.FileRepository
	rollout    storage.RolloutRecord
	target     rollout.Reference
	previous   rollout.Reference
}

func newServiceFixture(t *testing.T) serviceFixture {
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
	desired, err := repository.CreateDesiredRevision(context.Background(), storage.DesiredRevisionInput{
		RequestID: "desired-service-test", Document: document, SourceChannel: storage.SourceSystem,
		Actor: "rollout-service-test",
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
		DesiredRevisionID: desired.ID, CompilerVersion: "0.4.0", Bytes: artifactBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	rolloutRecord, err := repository.AllocateRollout(context.Background(), storage.RolloutInput{
		RequestID: "rollout-service-test", ArtifactDigest: artifact.Digest,
		DesiredRevisionID: desired.ID, CompilerVersion: "0.4.0",
		TargetNodeIDs: []string{"node-b", "node-a"}, SourceChannel: storage.SourceSystem,
		Actor: "rollout-service-test", Reason: "exercise restartable coordinator",
	})
	if err != nil {
		t.Fatal(err)
	}
	return serviceFixture{
		repository: repository,
		rollout:    rolloutRecord,
		target: rollout.Reference{
			ID: artifact.SnapshotID, SHA256: [32]byte(artifact.Digest),
		},
	}
}

func newPolicyServiceFixture(t *testing.T) serviceFixture {
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
	baselineDesired, err := repository.CreateDesiredRevision(context.Background(), storage.DesiredRevisionInput{
		RequestID: "policy-service-desired-baseline", Document: document,
		SourceChannel: storage.SourceSystem, Actor: "rollout-service-policy-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	baselineCompiled, err := snapshot.Compile(bytes.NewReader(document))
	if err != nil {
		t.Fatal(err)
	}
	baselineBytes, err := snapshot.MarshalDeterministic(baselineCompiled)
	if err != nil {
		t.Fatal(err)
	}
	baselineArtifact, err := repository.CreateSnapshotArtifact(context.Background(), storage.SnapshotArtifactInput{
		DesiredRevisionID: baselineDesired.ID, CompilerVersion: "0.4.0", Bytes: baselineBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := repository.AllocateRollout(context.Background(), storage.RolloutInput{
		RequestID: "policy-service-rollout-baseline", ArtifactDigest: baselineArtifact.Digest,
		DesiredRevisionID: baselineDesired.ID, CompilerVersion: "0.4.0",
		TargetNodeIDs: []string{"node-a", "node-b", "node-c"},
		SourceChannel: storage.SourceSystem, Actor: "rollout-service-policy-test", Reason: "baseline",
	})
	if err != nil {
		t.Fatal(err)
	}
	candidateDocument := bytes.Replace(document, []byte("local-bootstrap"), []byte("safe-policy-candidate"), 1)
	candidateDesired, err := repository.CreateDesiredRevision(context.Background(), storage.DesiredRevisionInput{
		RequestID: "policy-service-desired-candidate", Document: candidateDocument,
		SourceChannel: storage.SourceSystem, Actor: "rollout-service-policy-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	candidateCompiled, err := snapshot.Compile(bytes.NewReader(candidateDocument))
	if err != nil {
		t.Fatal(err)
	}
	candidateBytes, err := snapshot.MarshalDeterministic(candidateCompiled)
	if err != nil {
		t.Fatal(err)
	}
	candidateArtifact, err := repository.CreateSnapshotArtifact(context.Background(), storage.SnapshotArtifactInput{
		DesiredRevisionID: candidateDesired.ID, CompilerVersion: "0.4.0", Bytes: candidateBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	rolloutRecord, err := repository.AllocateRollout(context.Background(), storage.RolloutInput{
		RequestID: "policy-service-rollout-candidate", ArtifactDigest: candidateArtifact.Digest,
		PreviousArtifactDigest: baselineArtifact.Digest, BaselineRolloutSequence: baseline.Sequence,
		DesiredRevisionID: candidateDesired.ID, CompilerVersion: "0.4.0",
		TargetNodeIDs: []string{"node-c", "node-a", "node-b"},
		Policy: storage.RolloutPolicy{
			Enabled: true, Strategy: storage.RolloutStrategyCanary, CanaryNodeIDs: []string{"node-a"},
			MinimumHealthyCanaryPercent: 100, CanaryObservationWindow: 10 * time.Second,
			PrepareTimeout: 20 * time.Second, ActivationTimeout: 30 * time.Second,
			HeartbeatStaleAfter: 5 * time.Second, AutomaticRollback: true,
		},
		SourceChannel: storage.SourceSystem, Actor: "rollout-service-policy-test", Reason: "safe candidate",
	})
	if err != nil {
		t.Fatal(err)
	}
	return serviceFixture{
		repository: repository, rollout: rolloutRecord,
		target:   rollout.Reference{ID: candidateArtifact.SnapshotID, SHA256: [32]byte(candidateArtifact.Digest)},
		previous: rollout.Reference{ID: baselineArtifact.SnapshotID, SHA256: [32]byte(baselineArtifact.Digest)},
	}
}

func (fixture serviceFixture) ack(nodeID, process string, operation rollout.Operation) rollout.Report {
	current := fixture.previous
	if operation == rollout.OperationActivate {
		current = fixture.target
	}
	return rollout.Report{
		NodeID: nodeID, ProcessInstance: process, Sequence: fixture.rollout.Sequence,
		Artifact: fixture.target, Operation: operation, Result: rollout.ResultACK,
		PreviousActive: fixture.previous, CurrentActive: current, ShardCount: 8, CompletedShards: 8,
	}
}

func (fixture serviceFixture) ackAt(
	nodeID, process string,
	operation rollout.Operation,
	completedAt time.Time,
) rollout.Report {
	report := fixture.ack(nodeID, process, operation)
	report.CompletedAt = completedAt
	return report
}

func (fixture serviceFixture) nack(nodeID, process string, operation rollout.Operation) rollout.Report {
	return rollout.Report{
		NodeID: nodeID, ProcessInstance: process, Sequence: fixture.rollout.Sequence,
		Artifact: fixture.target, Operation: operation, Result: rollout.ResultNACK,
		ShardCount: 8, CompletedShards: 7,
		Issues: []rollout.Issue{{Code: "snapshot.route.invalid", FieldPath: "routes[0]"}},
	}
}

func testCancellation(reason string) CancellationInput {
	return CancellationInput{
		Reason: reason, Actor: "operator-a", SourceChannel: storage.SourceConsole,
	}
}

func (fixture serviceFixture) preparedRuntime(nodeID, process string) rollout.RuntimeState {
	state := rollout.RuntimeState{
		NodeID: nodeID, ProcessInstance: process, LastSequence: fixture.rollout.Sequence,
		Prepared: &rollout.PreparedState{
			Sequence: fixture.rollout.Sequence, Artifact: fixture.target, ShardCount: 8,
		},
	}
	if fixture.previous != (rollout.Reference{}) {
		state.Active = fixture.previous
		state.ActiveShardCount = 8
		state.ObservedAt = fixture.rollout.CreatedAt.UTC()
	}
	return state
}

func openTestService(t *testing.T, repository Repository, sequence uint64) *Service {
	t.Helper()
	service, err := Open(context.Background(), repository, sequence)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func assertServiceCommands(t *testing.T, commands []rollout.Command, operation rollout.Operation, nodeIDs ...string) {
	t.Helper()
	if len(commands) != len(nodeIDs) {
		t.Fatalf("commands = %#v, want %d", commands, len(nodeIDs))
	}
	for index, nodeID := range nodeIDs {
		if commands[index].NodeID != nodeID || commands[index].Operation != operation {
			t.Fatalf("command[%d] = %#v", index, commands[index])
		}
	}
}

type failingAppendRepository struct {
	Repository
	err error
}

func (repository *failingAppendRepository) AppendRolloutEvent(
	context.Context,
	storage.RolloutEventInput,
) (storage.RolloutEvent, error) {
	return storage.RolloutEvent{}, repository.err
}
