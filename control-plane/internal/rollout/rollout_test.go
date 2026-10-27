package rollout

import (
	"errors"
	"sync"
	"testing"
)

func TestPrepareBarrierUnlocksActivationOnlyAfterEveryNode(t *testing.T) {
	coordinator := newTestCoordinator(t)
	commands, err := coordinator.Start()
	if err != nil {
		t.Fatal(err)
	}
	assertCommands(t, commands, OperationPrepare, "node-a", "node-b")

	commands, err = coordinator.Observe(ack("node-a", OperationPrepare))
	if err != nil {
		t.Fatal(err)
	}
	if len(commands) != 0 {
		t.Fatalf("activation crossed an incomplete prepare barrier: %#v", commands)
	}

	commands, err = coordinator.Observe(ack("node-b", OperationPrepare))
	if err != nil {
		t.Fatal(err)
	}
	assertCommands(t, commands, OperationActivate, "node-a", "node-b")
	assertPhase(t, coordinator, PhaseActivating)

	if commands, err = coordinator.Observe(ack("node-a", OperationActivate)); err != nil || len(commands) != 0 {
		t.Fatalf("first activation report: commands=%#v err=%v", commands, err)
	}
	assertPhase(t, coordinator, PhaseActivating)
	if commands, err = coordinator.Observe(ack("node-b", OperationActivate)); err != nil || len(commands) != 0 {
		t.Fatalf("second activation report: commands=%#v err=%v", commands, err)
	}
	assertPhase(t, coordinator, PhaseActive)
}

func TestPendingCommandProjectionTracksOutstandingOperations(t *testing.T) {
	coordinator := newTestCoordinator(t)
	if commands := coordinator.PendingCommands(); len(commands) != 0 {
		t.Fatalf("pending rollout projected commands: %#v", commands)
	}
	if _, err := coordinator.Start(); err != nil {
		t.Fatal(err)
	}
	assertCommands(t, coordinator.PendingCommands(), OperationPrepare, "node-a", "node-b")
	if _, err := coordinator.Observe(ack("node-a", OperationPrepare)); err != nil {
		t.Fatal(err)
	}
	assertCommands(t, coordinator.PendingCommands(), OperationPrepare, "node-b")
	if _, err := coordinator.Observe(ack("node-b", OperationPrepare)); err != nil {
		t.Fatal(err)
	}
	assertCommands(t, coordinator.PendingCommands(), OperationActivate, "node-a", "node-b")
	if _, err := coordinator.Observe(ack("node-a", OperationActivate)); err != nil {
		t.Fatal(err)
	}
	assertCommands(t, coordinator.PendingCommands(), OperationActivate, "node-b")
	if _, err := coordinator.Observe(ack("node-b", OperationActivate)); err != nil {
		t.Fatal(err)
	}
	if commands := coordinator.PendingCommands(); len(commands) != 0 {
		t.Fatalf("active rollout projected commands: %#v", commands)
	}

	cancelled := newTestCoordinator(t)
	if _, err := cancelled.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := cancelled.Cancel("operator cancelled"); err != nil {
		t.Fatal(err)
	}
	assertCommands(t, cancelled.PendingCommands(), OperationCancel, "node-a", "node-b")
	if _, err := cancelled.Observe(ack("node-a", OperationCancel)); err != nil {
		t.Fatal(err)
	}
	assertCommands(t, cancelled.PendingCommands(), OperationCancel, "node-b")
}

func TestPrepareNACKCancelsWithoutChangingPriorActive(t *testing.T) {
	coordinator := newTestCoordinator(t)
	if _, err := coordinator.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Observe(ack("node-a", OperationPrepare)); err != nil {
		t.Fatal(err)
	}

	commands, err := coordinator.Observe(nack("node-b", OperationPrepare, "snapshot.route.invalid"))
	if err != nil {
		t.Fatal(err)
	}
	assertCommands(t, commands, OperationCancel, "node-a")
	assertPhase(t, coordinator, PhaseCancelled)

	if _, err := coordinator.Cancel("timeout"); err != nil {
		t.Fatalf("duplicate cancellation must be idempotent: %v", err)
	}
	_, nodes := coordinator.Status()
	if nodes["node-a"].Phase != NodeCancelPending || nodes["node-b"].Phase != NodeFailed {
		t.Fatalf("unexpected node states after NACK: %#v", nodes)
	}
}

func TestDuplicateReportIsIdempotentAndConflictingReplayFails(t *testing.T) {
	coordinator := newTestCoordinator(t)
	if _, err := coordinator.Start(); err != nil {
		t.Fatal(err)
	}
	report := ack("node-a", OperationPrepare)
	if _, err := coordinator.Observe(report); err != nil {
		t.Fatal(err)
	}
	if commands, err := coordinator.Observe(report); err != nil || len(commands) != 0 {
		t.Fatalf("exact duplicate was not idempotent: commands=%#v err=%v", commands, err)
	}

	conflict := report
	conflict.CompletedShards = 7
	conflict.ShardCount = 7
	if _, err := coordinator.Observe(conflict); !errors.Is(err, ErrConflictingReplay) {
		t.Fatalf("conflicting replay error = %v", err)
	}

	stale := ack("node-b", OperationPrepare)
	stale.Sequence--
	if _, err := coordinator.Observe(stale); !errors.Is(err, ErrStaleSequence) {
		t.Fatalf("stale report error = %v", err)
	}
}

func TestActivationFailureRequiresExplicitNewRollback(t *testing.T) {
	coordinator := newTestCoordinator(t)
	if _, err := coordinator.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Observe(ack("node-a", OperationPrepare)); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Observe(ack("node-b", OperationPrepare)); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Observe(ack("node-a", OperationActivate)); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Observe(nack("node-b", OperationActivate, "activation.swap.failed")); err != nil {
		t.Fatal(err)
	}
	assertPhase(t, coordinator, PhaseRequiresRollback)
	if _, err := coordinator.Cancel("too late"); !errors.Is(err, ErrRequiresRollback) {
		t.Fatalf("late cancellation error = %v", err)
	}
}

func TestReprepareFailureAfterActivationStartedRequiresRollback(t *testing.T) {
	coordinator := newTestCoordinator(t)
	if _, err := coordinator.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Observe(ack("node-a", OperationPrepare)); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Observe(ack("node-b", OperationPrepare)); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Reconnect(RuntimeState{
		NodeID:           "node-b",
		ProcessInstance:  "boot-2",
		LastSequence:     testSequence,
		Active:           previousReference,
		ActiveShardCount: 8,
	}); err != nil {
		t.Fatal(err)
	}
	report := nack("node-b", OperationPrepare, "snapshot.reprepare.failed")
	report.ProcessInstance = "boot-2"
	if _, err := coordinator.Observe(report); err != nil {
		t.Fatal(err)
	}
	assertPhase(t, coordinator, PhaseRequiresRollback)
}

func TestReconnectReplaysOnlyTheRequiredOperation(t *testing.T) {
	coordinator := newTestCoordinator(t)
	if _, err := coordinator.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Observe(ack("node-a", OperationPrepare)); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Disconnect("node-a", "boot-1"); err != nil {
		t.Fatal(err)
	}

	commands, err := coordinator.Reconnect(RuntimeState{
		NodeID:           "node-a",
		ProcessInstance:  "boot-2",
		LastSequence:     testSequence,
		Active:           previousReference,
		ActiveShardCount: 8,
		Prepared: &PreparedState{
			Sequence:   testSequence,
			Artifact:   targetReference,
			ShardCount: 8,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(commands) != 0 {
		t.Fatalf("one prepared node must still wait for the fleet barrier: %#v", commands)
	}

	commands, err = coordinator.Reconnect(RuntimeState{
		NodeID:           "node-b",
		ProcessInstance:  "boot-2",
		LastSequence:     testSequence,
		Active:           previousReference,
		ActiveShardCount: 8,
		Prepared: &PreparedState{
			Sequence:   testSequence,
			Artifact:   targetReference,
			ShardCount: 8,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertCommands(t, commands, OperationActivate, "node-a", "node-b")

	commands, err = coordinator.Reconnect(RuntimeState{
		NodeID:           "node-b",
		ProcessInstance:  "boot-3",
		LastSequence:     testSequence,
		Active:           previousReference,
		ActiveShardCount: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertCommands(t, commands, OperationPrepare, "node-b")
}

func TestTargetOnlyRolloutAcceptsNewNodeServingSelectedArtifact(t *testing.T) {
	coordinator, err := New(Plan{
		Sequence: testSequence,
		Artifact: Artifact{Reference: targetReference, Bytes: targetBytes},
		Previous: targetReference,
		NodeIDs:  []string{"node-a", "node-b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Start(); err != nil {
		t.Fatal(err)
	}
	for _, state := range []RuntimeState{
		{
			NodeID: "node-a", ProcessInstance: "boot-existing", LastSequence: testSequence - 1,
			Active: targetReference, ActiveShardCount: 8,
		},
		{
			NodeID: "node-b", ProcessInstance: "boot-replacement", LastSequence: 0,
			Active: targetReference, ActiveShardCount: 8,
		},
	} {
		commands, reconnectErr := coordinator.Reconnect(state)
		if reconnectErr != nil || len(commands) != 0 {
			t.Fatalf("reconnect %s: commands=%#v err=%v", state.NodeID, commands, reconnectErr)
		}
	}
	assertPhase(t, coordinator, PhaseActive)
}

func TestReconnectRejectsUnknownActiveState(t *testing.T) {
	coordinator := newTestCoordinator(t)
	if _, err := coordinator.Start(); err != nil {
		t.Fatal(err)
	}
	unknown := ReferenceFor("unknown", []byte("unknown"))
	if _, err := coordinator.Reconnect(RuntimeState{
		NodeID:           "node-a",
		ProcessInstance:  "boot-2",
		Active:           unknown,
		ActiveShardCount: 8,
	}); !errors.Is(err, ErrDrift) {
		t.Fatalf("drift error = %v", err)
	}
	assertPhase(t, coordinator, PhaseRequiresRollback)
}

func TestReconnectRejectsUnauthorizedEarlyActivation(t *testing.T) {
	coordinator := newTestCoordinator(t)
	if _, err := coordinator.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Reconnect(RuntimeState{
		NodeID:           "node-a",
		ProcessInstance:  "boot-2",
		LastSequence:     testSequence,
		Active:           targetReference,
		ActiveShardCount: 8,
	}); !errors.Is(err, ErrDrift) {
		t.Fatalf("early activation error = %v", err)
	}
	assertPhase(t, coordinator, PhaseRequiresRollback)
}

func TestOperatorCancellationBeforeActivation(t *testing.T) {
	coordinator := newTestCoordinator(t)
	if _, err := coordinator.Start(); err != nil {
		t.Fatal(err)
	}
	commands, err := coordinator.Cancel("operator cancelled before activation")
	if err != nil {
		t.Fatal(err)
	}
	assertCommands(t, commands, OperationCancel, "node-a", "node-b")
	assertPhase(t, coordinator, PhaseCancelled)
	if _, err := coordinator.Cancel(""); !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("empty cancellation reason error = %v", err)
	}
}

func TestCancellationNACKIsRetainedAsNodeFailure(t *testing.T) {
	coordinator := newTestCoordinator(t)
	if _, err := coordinator.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Cancel("operator cancellation"); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Observe(nack("node-a", OperationCancel, "cancel.cleanup.failed")); err != nil {
		t.Fatal(err)
	}
	phase, nodes := coordinator.Status()
	if phase != PhaseCancelled || nodes["node-a"].Phase != NodeFailed {
		t.Fatalf("unexpected cancellation NACK state: phase=%s nodes=%#v", phase, nodes)
	}
}

func TestReconnectAfterProcessRestartCompletesTheRollout(t *testing.T) {
	coordinator := newTestCoordinator(t)
	if _, err := coordinator.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Observe(ack("node-a", OperationPrepare)); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Observe(ack("node-b", OperationPrepare)); err != nil {
		t.Fatal(err)
	}

	commands, err := coordinator.Reconnect(RuntimeState{
		NodeID:           "node-b",
		ProcessInstance:  "boot-2",
		LastSequence:     testSequence,
		Active:           previousReference,
		ActiveShardCount: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertCommands(t, commands, OperationPrepare, "node-b")

	reprepared := ack("node-b", OperationPrepare)
	reprepared.ProcessInstance = "boot-2"
	commands, err = coordinator.Observe(reprepared)
	if err != nil {
		t.Fatal(err)
	}
	assertCommands(t, commands, OperationActivate, "node-b")

	if _, err = coordinator.Reconnect(RuntimeState{
		NodeID:           "node-a",
		ProcessInstance:  "boot-2",
		LastSequence:     testSequence,
		Active:           targetReference,
		ActiveShardCount: 8,
	}); err != nil {
		t.Fatal(err)
	}
	activated := ack("node-b", OperationActivate)
	activated.ProcessInstance = "boot-2"
	if _, err = coordinator.Observe(activated); err != nil {
		t.Fatal(err)
	}
	assertPhase(t, coordinator, PhaseActive)
}

func TestCancelledReconnectDiscardsPreparedState(t *testing.T) {
	coordinator := newTestCoordinator(t)
	if _, err := coordinator.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Cancel("operator cancellation"); err != nil {
		t.Fatal(err)
	}
	commands, err := coordinator.Reconnect(RuntimeState{
		NodeID:           "node-a",
		ProcessInstance:  "boot-2",
		LastSequence:     testSequence,
		Active:           previousReference,
		ActiveShardCount: 8,
	})
	if err != nil || len(commands) != 0 {
		t.Fatalf("cancelled unprepared reconnect: commands=%#v err=%v", commands, err)
	}
	commands, err = coordinator.Reconnect(RuntimeState{
		NodeID:           "node-b",
		ProcessInstance:  "boot-2",
		LastSequence:     testSequence,
		Active:           previousReference,
		ActiveShardCount: 8,
		Prepared: &PreparedState{
			Sequence:   testSequence,
			Artifact:   targetReference,
			ShardCount: 8,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertCommands(t, commands, OperationCancel, "node-b")
	cancelled := ack("node-b", OperationCancel)
	cancelled.ProcessInstance = "boot-2"
	if _, err := coordinator.Observe(cancelled); err != nil {
		t.Fatal(err)
	}
	assertPhase(t, coordinator, PhaseCancelled)
}

func TestConcurrentExactReplayIsRaceFreeAndIdempotent(t *testing.T) {
	coordinator := newTestCoordinator(t)
	if _, err := coordinator.Start(); err != nil {
		t.Fatal(err)
	}
	report := ack("node-a", OperationPrepare)
	if _, err := coordinator.Observe(report); err != nil {
		t.Fatal(err)
	}

	var wait sync.WaitGroup
	errorsSeen := make(chan error, 32)
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			commands, err := coordinator.Observe(report)
			if err != nil {
				errorsSeen <- err
				return
			}
			if len(commands) != 0 {
				errorsSeen <- errors.New("duplicate replay emitted a command")
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Error(err)
	}
}

func TestConstructionAndSequenceValidationFailClosed(t *testing.T) {
	tests := map[string]Plan{
		"zero sequence": {
			Artifact: Artifact{Reference: targetReference, Bytes: targetBytes}, NodeIDs: []string{"node-a"},
		},
		"no nodes": {
			Sequence: testSequence, Artifact: Artifact{Reference: targetReference, Bytes: targetBytes},
		},
		"duplicate nodes": {
			Sequence: testSequence, Artifact: Artifact{Reference: targetReference, Bytes: targetBytes}, NodeIDs: []string{"node-a", "node-a"},
		},
		"digest mismatch": {
			Sequence: testSequence, Artifact: Artifact{Reference: targetReference, Bytes: []byte("different")}, NodeIDs: []string{"node-a"},
		},
	}
	for name, plan := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := New(plan); !errors.Is(err, ErrInvalidReport) {
				t.Fatalf("error = %v", err)
			}
		})
	}

	coordinator := newTestCoordinator(t)
	if _, err := coordinator.Observe(ack("node-a", OperationPrepare)); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("pre-start report error = %v", err)
	}
	if _, err := coordinator.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Start(); !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("second start error = %v", err)
	}
	future := ack("node-a", OperationPrepare)
	future.Sequence++
	if _, err := coordinator.Observe(future); !errors.Is(err, ErrFutureSequence) {
		t.Fatalf("future report error = %v", err)
	}
	unknown := ack("unknown", OperationPrepare)
	if _, err := coordinator.Observe(unknown); !errors.Is(err, ErrUnknownNode) {
		t.Fatalf("unknown node error = %v", err)
	}
}

func TestInvalidReportsFailClosed(t *testing.T) {
	coordinator := newTestCoordinator(t)
	if _, err := coordinator.Start(); err != nil {
		t.Fatal(err)
	}

	tests := map[string]Report{
		"partial ACK": {
			NodeID: "node-a", ProcessInstance: "boot-1", Sequence: testSequence,
			Artifact: targetReference, Operation: OperationPrepare, Result: ResultACK,
			ShardCount: 8, CompletedShards: 7,
		},
		"unstructured NACK": {
			NodeID: "node-a", ProcessInstance: "boot-1", Sequence: testSequence,
			Artifact: targetReference, Operation: OperationPrepare, Result: ResultNACK,
			ShardCount: 8, CompletedShards: 7,
		},
		"wrong artifact": {
			NodeID: "node-a", ProcessInstance: "boot-1", Sequence: testSequence,
			Artifact: previousReference, Operation: OperationPrepare, Result: ResultACK,
			ShardCount: 8, CompletedShards: 8,
		},
		"wrong previous active": {
			NodeID: "node-a", ProcessInstance: "boot-1", Sequence: testSequence,
			Artifact: targetReference, Operation: OperationPrepare, Result: ResultACK,
			PreviousActive: targetReference, CurrentActive: previousReference,
			ShardCount: 8, CompletedShards: 8,
		},
	}
	for name, report := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := coordinator.Observe(report); !errors.Is(err, ErrInvalidReport) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestInvalidTransitionDoesNotPoisonLaterValidReport(t *testing.T) {
	coordinator := newTestCoordinator(t)
	if _, err := coordinator.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Observe(ack("node-a", OperationActivate)); !errors.Is(err, ErrStateTransition) {
		t.Fatalf("early activation report error = %v", err)
	}
	if _, err := coordinator.Observe(ack("node-a", OperationPrepare)); err != nil {
		t.Fatalf("valid report was poisoned by rejected transition: %v", err)
	}
}

func TestReconnectStateValidation(t *testing.T) {
	tests := map[string]struct {
		state RuntimeState
		want  error
	}{
		"future sequence": {
			state: RuntimeState{NodeID: "node-a", ProcessInstance: "boot-2", LastSequence: testSequence + 1},
			want:  ErrFutureSequence,
		},
		"active without shard proof": {
			state: RuntimeState{NodeID: "node-a", ProcessInstance: "boot-2", Active: previousReference},
			want:  ErrInvalidReport,
		},
		"prepared without shard proof": {
			state: RuntimeState{
				NodeID: "node-a", ProcessInstance: "boot-2", LastSequence: testSequence,
				Active: previousReference, ActiveShardCount: 8,
				Prepared: &PreparedState{Sequence: testSequence, Artifact: targetReference},
			},
			want: ErrInvalidReport,
		},
		"current sequence with different bytes": {
			state: RuntimeState{
				NodeID: "node-a", ProcessInstance: "boot-2", LastSequence: testSequence,
				Active: previousReference, ActiveShardCount: 8,
				Prepared: &PreparedState{
					Sequence: testSequence, Artifact: ReferenceFor("other", []byte("other")), ShardCount: 8,
				},
			},
			want: ErrConflictingReplay,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			coordinator := newTestCoordinator(t)
			if _, err := coordinator.Start(); err != nil {
				t.Fatal(err)
			}
			_, err := coordinator.Reconnect(test.state)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

const testSequence uint64 = 42

var (
	targetBytes       = []byte("target snapshot bytes")
	targetReference   = ReferenceFor("snapshot-target", targetBytes)
	previousReference = ReferenceFor("snapshot-previous", []byte("previous snapshot bytes"))
)

func newTestCoordinator(t *testing.T) *Coordinator {
	t.Helper()
	coordinator, err := New(Plan{
		Sequence: testSequence,
		Artifact: Artifact{Reference: targetReference, Bytes: targetBytes},
		Previous: previousReference,
		NodeIDs:  []string{"node-b", "node-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

func ack(nodeID string, operation Operation) Report {
	report := Report{
		NodeID:          nodeID,
		ProcessInstance: "boot-1",
		Sequence:        testSequence,
		Artifact:        targetReference,
		Operation:       operation,
		Result:          ResultACK,
		PreviousActive:  previousReference,
		CurrentActive:   previousReference,
		ShardCount:      8,
		CompletedShards: 8,
	}
	if operation == OperationActivate {
		report.CurrentActive = targetReference
	}
	return report
}

func nack(nodeID string, operation Operation, code string) Report {
	report := ack(nodeID, operation)
	report.Result = ResultNACK
	report.CurrentActive = previousReference
	report.CompletedShards = 7
	report.Issues = []Issue{{Code: code, FieldPath: "snapshot"}}
	return report
}

func assertCommands(t *testing.T, commands []Command, operation Operation, nodeIDs ...string) {
	t.Helper()
	if len(commands) != len(nodeIDs) {
		t.Fatalf("%s command count = %d, want %d: %#v", operation, len(commands), len(nodeIDs), commands)
	}
	for index, nodeID := range nodeIDs {
		if commands[index].NodeID != nodeID || commands[index].Operation != operation {
			t.Fatalf("command[%d] = %#v, want %s for %s", index, commands[index], operation, nodeID)
		}
	}
}

func assertPhase(t *testing.T, coordinator *Coordinator, want Phase) {
	t.Helper()
	got, _ := coordinator.Status()
	if got != want {
		t.Fatalf("phase = %s, want %s", got, want)
	}
}
