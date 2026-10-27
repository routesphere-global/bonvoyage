package rollout

import (
	"errors"
	"testing"
	"time"
)

var policyEpoch = time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)

func TestCanaryPolicyStagesAndPromotesOnlyAfterHealthyObservation(t *testing.T) {
	coordinator := newPolicyCoordinator(t, StrategyCanary)
	commands, err := coordinator.Start()
	if err != nil {
		t.Fatal(err)
	}
	assertCommands(t, commands, OperationPrepare, "node-a", "node-b", "node-c")

	for index, nodeID := range []string{"node-a", "node-b", "node-c"} {
		commands, err = coordinator.Observe(policyACK(nodeID, OperationPrepare, policyEpoch.Add(time.Duration(index+1)*time.Second)))
		if err != nil {
			t.Fatal(err)
		}
	}
	assertCommands(t, commands, OperationActivate, "node-a")
	if _, err := coordinator.Observe(policyACK("node-a", OperationActivate, policyEpoch.Add(4*time.Second))); err != nil {
		t.Fatal(err)
	}
	assertPhase(t, coordinator, PhaseObserving)
	assertCommands(t, coordinator.PendingCommands(), Operation("") /* no commands */)

	health := []NodeHealth{{
		NodeID: "node-a", Connected: true, Reconciled: true,
		LastSeen: policyEpoch.Add(8 * time.Second), ActiveSnapshotID: targetReference.ID,
	}}
	if _, _, err := coordinator.Evaluate(PolicyObservation{
		ObservedAt: policyEpoch.Add(9 * time.Second), Nodes: health,
	}); !errors.Is(err, ErrPolicyPending) {
		t.Fatalf("early observation error = %v", err)
	}
	health[0].LastSeen = policyEpoch.Add(13 * time.Second)
	commands, result, err := coordinator.Evaluate(PolicyObservation{
		ObservedAt: policyEpoch.Add(14 * time.Second), Nodes: health,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != PolicyDecisionPromote {
		t.Fatalf("decision = %#v", result)
	}
	assertCommands(t, commands, OperationActivate, "node-b", "node-c")

	if _, err := coordinator.Observe(policyACK("node-b", OperationActivate, policyEpoch.Add(15*time.Second))); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Observe(policyACK("node-c", OperationActivate, policyEpoch.Add(16*time.Second))); err != nil {
		t.Fatal(err)
	}
	assertPhase(t, coordinator, PhaseActive)
}

func TestCanaryPolicyRequiresRollbackWhenHealthIsStale(t *testing.T) {
	coordinator := observingPolicyCoordinator(t)
	commands, result, err := coordinator.Evaluate(PolicyObservation{
		ObservedAt: policyEpoch.Add(14 * time.Second),
		Nodes: []NodeHealth{{
			NodeID: "node-a", Connected: true, Reconciled: true,
			LastSeen: policyEpoch.Add(7 * time.Second), ActiveSnapshotID: targetReference.ID,
		}},
	})
	if err != nil || len(commands) != 0 {
		t.Fatalf("health decision: commands=%#v err=%v", commands, err)
	}
	if result.Decision != PolicyDecisionRequireRollback {
		t.Fatalf("decision = %#v", result)
	}
	assertPhase(t, coordinator, PhaseRequiresRollback)
	if _, err := coordinator.Cancel("too late"); !errors.Is(err, ErrRequiresRollback) {
		t.Fatalf("late cancellation error = %v", err)
	}
}

func TestRollbackReconciliationCancelsPreparedNonCanaryCandidate(t *testing.T) {
	coordinator := observingPolicyCoordinator(t)
	if _, _, err := coordinator.Evaluate(PolicyObservation{
		ObservedAt: policyEpoch.Add(14 * time.Second),
		Nodes: []NodeHealth{{
			NodeID: "node-a", Connected: true, Reconciled: true,
			LastSeen: policyEpoch.Add(7 * time.Second), ActiveSnapshotID: targetReference.ID,
		}},
	}); err != nil {
		t.Fatal(err)
	}

	commands, err := coordinator.Reconnect(RuntimeState{
		NodeID: "node-b", ProcessInstance: "boot-2", LastSequence: testSequence,
		Active: previousReference, ActiveShardCount: 8, ObservedAt: policyEpoch.Add(15 * time.Second),
		Prepared: &PreparedState{Sequence: testSequence, Artifact: targetReference, ShardCount: 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertCommands(t, commands, OperationCancel, "node-b")
	assertCommands(t, coordinator.PendingCommands(), OperationCancel, "node-b")
	phase, nodes := coordinator.Status()
	if phase != PhaseRequiresRollback || nodes["node-b"].Phase != NodeCancelPending {
		t.Fatalf("rollback cleanup status: phase=%s nodes=%#v", phase, nodes)
	}

	report := policyACK("node-b", OperationCancel, policyEpoch.Add(16*time.Second))
	report.ProcessInstance = "boot-2"
	if _, err := coordinator.Observe(report); err != nil {
		t.Fatal(err)
	}
	_, nodes = coordinator.Status()
	if nodes["node-b"].Phase != NodePriorActive {
		t.Fatalf("node-b phase = %s, want %s", nodes["node-b"].Phase, NodePriorActive)
	}
}

func TestPolicyDeadlinesCancelPreparationAndRequireActivationRollback(t *testing.T) {
	preparing := newPolicyCoordinator(t, StrategyCanary)
	if _, err := preparing.Start(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := preparing.Evaluate(PolicyObservation{
		ObservedAt: policyEpoch.Add(19 * time.Second),
	}); !errors.Is(err, ErrPolicyPending) {
		t.Fatalf("pre-deadline error = %v", err)
	}
	commands, result, err := preparing.Evaluate(PolicyObservation{
		ObservedAt: policyEpoch.Add(20 * time.Second),
	})
	if err != nil || result.Decision != PolicyDecisionCancel {
		t.Fatalf("prepare deadline: result=%#v err=%v", result, err)
	}
	assertCommands(t, commands, OperationCancel, "node-a", "node-b", "node-c")
	assertPhase(t, preparing, PhaseCancelled)

	activating := newPolicyCoordinator(t, StrategyImmediate)
	if _, err := activating.Start(); err != nil {
		t.Fatal(err)
	}
	for index, nodeID := range []string{"node-a", "node-b", "node-c"} {
		if _, err := activating.Observe(policyACK(nodeID, OperationPrepare, policyEpoch.Add(time.Duration(index+1)*time.Second))); err != nil {
			t.Fatal(err)
		}
	}
	commands, result, err = activating.Evaluate(PolicyObservation{
		ObservedAt: policyEpoch.Add(33 * time.Second),
	})
	if err != nil || len(commands) != 0 || result.Decision != PolicyDecisionRequireRollback {
		t.Fatalf("activation deadline: commands=%#v result=%#v err=%v", commands, result, err)
	}
	assertPhase(t, activating, PhaseRequiresRollback)
}

func TestCanaryReconnectCannotActivateNonCanaryBeforePromotion(t *testing.T) {
	coordinator := observingPolicyCoordinator(t)
	commands, err := coordinator.Reconnect(RuntimeState{
		NodeID: "node-b", ProcessInstance: "boot-2", LastSequence: testSequence,
		Active: previousReference, ActiveShardCount: 8, ObservedAt: policyEpoch.Add(5 * time.Second),
		Prepared: &PreparedState{Sequence: testSequence, Artifact: targetReference, ShardCount: 8},
	})
	if err != nil || len(commands) != 0 {
		t.Fatalf("prepared non-canary reconnect: commands=%#v err=%v", commands, err)
	}
	if _, err := coordinator.Reconnect(RuntimeState{
		NodeID: "node-c", ProcessInstance: "boot-2", LastSequence: testSequence,
		Active: targetReference, ActiveShardCount: 8, ObservedAt: policyEpoch.Add(6 * time.Second),
	}); !errors.Is(err, ErrDrift) {
		t.Fatalf("early non-canary activation error = %v", err)
	}
	assertPhase(t, coordinator, PhaseRequiresRollback)
}

func TestMixedFleetRollbackActivatesOnlyNodesThatNeedChanging(t *testing.T) {
	rollbackBytes := []byte("rollback snapshot bytes")
	rollbackReference := ReferenceFor("snapshot-rollback", rollbackBytes)
	failedReference := ReferenceFor("snapshot-failed", []byte("failed snapshot bytes"))
	coordinator, err := New(Plan{
		Sequence: testSequence,
		Artifact: Artifact{Reference: rollbackReference, Bytes: rollbackBytes},
		PreviousByNode: map[string]Reference{
			"node-a": failedReference,
			"node-b": rollbackReference,
		},
		NodeIDs: []string{"node-b", "node-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Start(); err != nil {
		t.Fatal(err)
	}
	commands, err := coordinator.Reconnect(RuntimeState{
		NodeID: "node-b", ProcessInstance: "boot-2", LastSequence: testSequence - 1,
		Active: rollbackReference, ActiveShardCount: 8,
	})
	if err != nil || len(commands) != 0 {
		t.Fatalf("already-restored node: commands=%#v err=%v", commands, err)
	}
	report := Report{
		NodeID: "node-a", ProcessInstance: "boot-1", Sequence: testSequence,
		Artifact: rollbackReference, Operation: OperationPrepare, Result: ResultACK,
		PreviousActive: failedReference, CurrentActive: failedReference,
		ShardCount: 8, CompletedShards: 8,
	}
	commands, err = coordinator.Observe(report)
	if err != nil {
		t.Fatal(err)
	}
	assertCommands(t, commands, OperationActivate, "node-a")
}

func observingPolicyCoordinator(t *testing.T) *Coordinator {
	t.Helper()
	coordinator := newPolicyCoordinator(t, StrategyCanary)
	if _, err := coordinator.Start(); err != nil {
		t.Fatal(err)
	}
	for index, nodeID := range []string{"node-a", "node-b", "node-c"} {
		if _, err := coordinator.Observe(policyACK(nodeID, OperationPrepare, policyEpoch.Add(time.Duration(index+1)*time.Second))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := coordinator.Observe(policyACK("node-a", OperationActivate, policyEpoch.Add(4*time.Second))); err != nil {
		t.Fatal(err)
	}
	assertPhase(t, coordinator, PhaseObserving)
	return coordinator
}

func newPolicyCoordinator(t *testing.T, strategy Strategy) *Coordinator {
	t.Helper()
	policy := Policy{
		Enabled: true, Strategy: strategy, PrepareTimeout: 20 * time.Second,
		ActivationTimeout: 30 * time.Second, AutomaticRollback: true,
	}
	if strategy == StrategyCanary {
		policy.CanaryNodeIDs = []string{"node-a"}
		policy.MinimumHealthyCanaryPercent = 100
		policy.CanaryObservationWindow = 10 * time.Second
		policy.HeartbeatStaleAfter = 5 * time.Second
	}
	coordinator, err := New(Plan{
		Sequence:  testSequence,
		Artifact:  Artifact{Reference: targetReference, Bytes: targetBytes},
		Previous:  previousReference,
		NodeIDs:   []string{"node-c", "node-a", "node-b"},
		CreatedAt: policyEpoch,
		Policy:    policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

func policyACK(nodeID string, operation Operation, completedAt time.Time) Report {
	report := ack(nodeID, operation)
	report.CompletedAt = completedAt
	return report
}
