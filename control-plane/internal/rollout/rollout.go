// Package rollout implements the deterministic control-plane state machine for
// preparing and activating one immutable snapshot across a fixed node set.
package rollout

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"
)

var (
	ErrAlreadyStarted    = errors.New("rollout already started")
	ErrConflictingReplay = errors.New("conflicting rollout replay")
	ErrDrift             = errors.New("node state drift")
	ErrFutureSequence    = errors.New("future rollout sequence")
	ErrInvalidReport     = errors.New("invalid rollout report")
	ErrNotStarted        = errors.New("rollout not started")
	ErrRequiresRollback  = errors.New("rollout requires a new rollback sequence")
	ErrPolicyDisabled    = errors.New("safe rollout policy is disabled")
	ErrPolicyPending     = errors.New("safe rollout policy has no transition")
	ErrStaleSequence     = errors.New("stale rollout sequence")
	ErrStateTransition   = errors.New("invalid rollout state transition")
	ErrUnknownNode       = errors.New("unknown rollout node")
)

// Reference identifies immutable serialized snapshot bytes.
type Reference struct {
	ID     string
	SHA256 [sha256.Size]byte
}

// ReferenceFor constructs a reference from the exact serialized bytes.
func ReferenceFor(id string, artifact []byte) Reference {
	return Reference{ID: id, SHA256: sha256.Sum256(artifact)}
}

// Artifact contains the exact bytes distributed during preparation.
type Artifact struct {
	Reference Reference
	Bytes     []byte
}

// Plan fixes one sequence, artifact, prior state, and target set.
type Plan struct {
	Sequence       uint64
	Artifact       Artifact
	Previous       Reference
	PreviousByNode map[string]Reference
	NodeIDs        []string
	CreatedAt      time.Time
	Policy         Policy
}

// Strategy controls whether activation is immediate or staged through one
// explicit canary wave.
type Strategy string

const (
	StrategyImmediate Strategy = "IMMEDIATE"
	StrategyCanary    Strategy = "CANARY"
)

// Policy is the pure coordinator form of the durable rollout policy.
type Policy struct {
	Enabled                     bool
	Strategy                    Strategy
	CanaryNodeIDs               []string
	MinimumHealthyCanaryPercent uint32
	CanaryObservationWindow     time.Duration
	PrepareTimeout              time.Duration
	ActivationTimeout           time.Duration
	HeartbeatStaleAfter         time.Duration
	AutomaticRollback           bool
}

// NodeHealth is one bounded server-observed liveness and convergence sample.
// It is not application SLO telemetry.
type NodeHealth struct {
	NodeID           string
	Connected        bool
	Reconciled       bool
	LastSeen         time.Time
	ActiveSnapshotID string
}

// PolicyObservation is the complete input to one deterministic policy check.
type PolicyObservation struct {
	ObservedAt time.Time
	Nodes      []NodeHealth
}

// PolicyDecision names a state-changing policy outcome.
type PolicyDecision string

const (
	PolicyDecisionCancel          PolicyDecision = "CANCEL"
	PolicyDecisionPromote         PolicyDecision = "PROMOTE"
	PolicyDecisionRequireRollback PolicyDecision = "REQUIRE_ROLLBACK"
)

// PolicyResult accompanies the commands unlocked by one accepted decision.
type PolicyResult struct {
	Decision PolicyDecision
	Reason   string
}

// PolicyState is a read-only projection used by durable replay and status.
type PolicyState struct {
	Enabled              bool
	Strategy             Strategy
	CanaryNodeIDs        []string
	StartedAt            time.Time
	ActivationStartedAt  time.Time
	ObservationStartedAt time.Time
	FailureReason        string
	AutomaticRollback    bool
}

// Phase is fleet-level rollout state.
type Phase string

const (
	PhasePending          Phase = "PENDING"
	PhasePreparing        Phase = "PREPARING"
	PhaseActivating       Phase = "ACTIVATING"
	PhaseObserving        Phase = "OBSERVING"
	PhaseActive           Phase = "ACTIVE"
	PhaseCancelled        Phase = "CANCELLED"
	PhaseRequiresRollback Phase = "REQUIRES_ROLLBACK"
)

// NodePhase is the controller's last accepted state for one target node.
type NodePhase string

const (
	NodePending       NodePhase = "PENDING"
	NodePreparing     NodePhase = "PREPARING"
	NodePrepared      NodePhase = "PREPARED"
	NodeActivating    NodePhase = "ACTIVATING"
	NodeActive        NodePhase = "ACTIVE"
	NodeCancelPending NodePhase = "CANCEL_PENDING"
	NodeCancelled     NodePhase = "CANCELLED"
	NodeFailed        NodePhase = "FAILED"
	NodePriorActive   NodePhase = "PRIOR_ACTIVE"
)

// Operation names the node-local operation represented by a command/report.
type Operation string

const (
	OperationPrepare  Operation = "PREPARE"
	OperationActivate Operation = "ACTIVATE"
	OperationCancel   Operation = "CANCEL"
)

// Result is the node's outcome for one completed operation.
type Result string

const (
	ResultACK  Result = "ACK"
	ResultNACK Result = "NACK"
)

// Issue is a structured, stable NACK reason.
type Issue struct {
	Code      string
	FieldPath string
	Message   string
}

// Command is one deterministic instruction for one target node.
type Command struct {
	NodeID         string
	Sequence       uint64
	Operation      Operation
	Artifact       Artifact
	ExpectedActive Reference
	Reason         string
}

// Report records an operation only after all local shards complete or fail.
type Report struct {
	NodeID          string
	ProcessInstance string
	Sequence        uint64
	Artifact        Reference
	Operation       Operation
	Result          Result
	PreviousActive  Reference
	CurrentActive   Reference
	ShardCount      uint32
	CompletedShards uint32
	Issues          []Issue
	CompletedAt     time.Time
}

// PreparedState identifies bytes held by a node but not yet active.
type PreparedState struct {
	Sequence   uint64
	Artifact   Reference
	ShardCount uint32
}

// RuntimeState is the node-observed state supplied at connect or reconnect.
type RuntimeState struct {
	NodeID           string
	ProcessInstance  string
	LastSequence     uint64
	Active           Reference
	ActiveShardCount uint32
	Prepared         *PreparedState
	ObservedAt       time.Time
}

// NodeSnapshot is a read-only projection for status APIs and tests.
type NodeSnapshot struct {
	Phase           NodePhase
	Connected       bool
	ProcessInstance string
}

type nodeState struct {
	phase           NodePhase
	connected       bool
	processInstance string
	reports         map[Operation]Report
}

// Coordinator serializes state transitions for one immutable rollout plan.
// It never creates a rollback implicitly; rollback is a new Plan with a newer
// sequence and the retained exact artifact bytes.
type Coordinator struct {
	mu                   sync.Mutex
	plan                 Plan
	phase                Phase
	nodes                map[string]*nodeState
	cancelReason         string
	startedAt            time.Time
	activationStartedAt  time.Time
	observationStartedAt time.Time
	failureReason        string
	canaryNodes          map[string]struct{}
}

// New validates and copies a rollout plan.
func New(plan Plan) (*Coordinator, error) {
	if plan.Sequence == 0 {
		return nil, fmt.Errorf("sequence must be positive: %w", ErrInvalidReport)
	}
	if err := validateArtifact(plan.Artifact); err != nil {
		return nil, err
	}
	if err := validateOptionalReference(plan.Previous); err != nil {
		return nil, fmt.Errorf("previous snapshot: %w", err)
	}
	if len(plan.NodeIDs) == 0 {
		return nil, fmt.Errorf("at least one target node is required: %w", ErrInvalidReport)
	}

	nodeIDs := append([]string(nil), plan.NodeIDs...)
	slices.Sort(nodeIDs)
	nodes := make(map[string]*nodeState, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		if strings.TrimSpace(nodeID) == "" {
			return nil, fmt.Errorf("target node ID is empty: %w", ErrInvalidReport)
		}
		if _, exists := nodes[nodeID]; exists {
			return nil, fmt.Errorf("duplicate target node %q: %w", nodeID, ErrInvalidReport)
		}
		nodes[nodeID] = &nodeState{phase: NodePending, reports: make(map[Operation]Report)}
	}
	previousByNode := make(map[string]Reference, len(plan.PreviousByNode))
	if len(plan.PreviousByNode) != 0 && len(plan.PreviousByNode) != len(nodeIDs) {
		return nil, fmt.Errorf("per-node previous state must cover every target: %w", ErrInvalidReport)
	}
	for _, nodeID := range nodeIDs {
		previous, found := plan.PreviousByNode[nodeID]
		if len(plan.PreviousByNode) == 0 {
			previous = plan.Previous
			found = true
		}
		if !found {
			return nil, fmt.Errorf("node %q has no expected active state: %w", nodeID, ErrInvalidReport)
		}
		if err := validateOptionalReference(previous); err != nil {
			return nil, fmt.Errorf("node %q expected active snapshot: %w", nodeID, err)
		}
		previousByNode[nodeID] = previous
	}
	canaryNodes, err := validatePolicy(plan.Policy, nodeIDs, plan.CreatedAt)
	if err != nil {
		return nil, err
	}

	plan.NodeIDs = nodeIDs
	plan.Artifact.Bytes = append([]byte(nil), plan.Artifact.Bytes...)
	plan.PreviousByNode = previousByNode
	plan.Policy.CanaryNodeIDs = append([]string(nil), plan.Policy.CanaryNodeIDs...)
	return &Coordinator{
		plan: plan, phase: PhasePending, nodes: nodes, canaryNodes: canaryNodes,
	}, nil
}

func validatePolicy(policy Policy, nodeIDs []string, createdAt time.Time) (map[string]struct{}, error) {
	canaries := make(map[string]struct{})
	if !policy.Enabled {
		if policy.Strategy != "" || len(policy.CanaryNodeIDs) != 0 ||
			policy.MinimumHealthyCanaryPercent != 0 || policy.CanaryObservationWindow != 0 ||
			policy.PrepareTimeout != 0 || policy.ActivationTimeout != 0 ||
			policy.HeartbeatStaleAfter != 0 || policy.AutomaticRollback || !createdAt.IsZero() {
			return nil, fmt.Errorf("disabled rollout policy contains settings: %w", ErrInvalidReport)
		}
		return canaries, nil
	}
	if createdAt.IsZero() || createdAt.Location() != time.UTC ||
		policy.PrepareTimeout <= 0 || policy.ActivationTimeout <= 0 {
		return nil, fmt.Errorf("enabled rollout policy has invalid timing: %w", ErrInvalidReport)
	}
	switch policy.Strategy {
	case StrategyImmediate:
		if len(policy.CanaryNodeIDs) != 0 || policy.MinimumHealthyCanaryPercent != 0 ||
			policy.CanaryObservationWindow != 0 || policy.HeartbeatStaleAfter != 0 {
			return nil, fmt.Errorf("immediate policy contains canary settings: %w", ErrInvalidReport)
		}
	case StrategyCanary:
		if len(policy.CanaryNodeIDs) == 0 || len(policy.CanaryNodeIDs) >= len(nodeIDs) ||
			policy.MinimumHealthyCanaryPercent == 0 || policy.MinimumHealthyCanaryPercent > 100 ||
			policy.CanaryObservationWindow <= 0 || policy.HeartbeatStaleAfter <= 0 ||
			policy.HeartbeatStaleAfter > policy.CanaryObservationWindow {
			return nil, fmt.Errorf("canary policy is invalid: %w", ErrInvalidReport)
		}
		targets := make(map[string]struct{}, len(nodeIDs))
		for _, nodeID := range nodeIDs {
			targets[nodeID] = struct{}{}
		}
		for index, nodeID := range policy.CanaryNodeIDs {
			if index > 0 && policy.CanaryNodeIDs[index-1] >= nodeID {
				return nil, fmt.Errorf("canary nodes are not strictly sorted: %w", ErrInvalidReport)
			}
			if _, found := targets[nodeID]; !found {
				return nil, fmt.Errorf("canary node %q is outside the target set: %w", nodeID, ErrInvalidReport)
			}
			canaries[nodeID] = struct{}{}
		}
	default:
		return nil, fmt.Errorf("unsupported rollout strategy %q: %w", policy.Strategy, ErrInvalidReport)
	}
	return canaries, nil
}

// Start emits PREPARE for every target. It is deliberately single-use.
func (c *Coordinator) Start() ([]Command, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.phase != PhasePending {
		return nil, ErrAlreadyStarted
	}
	c.phase = PhasePreparing
	if c.plan.Policy.Enabled {
		c.startedAt = c.plan.CreatedAt
	}
	commands := make([]Command, 0, len(c.plan.NodeIDs))
	for _, nodeID := range c.plan.NodeIDs {
		c.nodes[nodeID].phase = NodePreparing
		commands = append(commands, c.prepareCommand(nodeID))
	}
	return commands, nil
}

// Cancel stops a rollout only before any ACTIVATE command has been emitted.
func (c *Coordinator) Cancel(reason string) ([]Command, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if strings.TrimSpace(reason) == "" {
		return nil, fmt.Errorf("cancellation reason is empty: %w", ErrInvalidReport)
	}
	if c.phase == PhaseActivating || c.phase == PhaseObserving ||
		c.phase == PhaseActive || c.phase == PhaseRequiresRollback {
		return nil, ErrRequiresRollback
	}
	if c.phase == PhaseCancelled {
		return nil, nil
	}
	if c.phase == PhasePending {
		c.phase = PhaseCancelled
		c.cancelReason = reason
		return nil, nil
	}
	if c.phase != PhasePreparing {
		return nil, ErrStateTransition
	}
	return c.cancelLocked(reason), nil
}

// Observe accepts a completed node operation and returns any newly unlocked
// commands. Exact duplicate reports are idempotent; conflicting replays fail.
func (c *Coordinator) Observe(report Report) ([]Command, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.phase == PhasePending {
		return nil, ErrNotStarted
	}
	node, err := c.validateReportLocked(report)
	if err != nil {
		return nil, err
	}
	if previous, exists := node.reports[report.Operation]; exists {
		if reflect.DeepEqual(previous, report) {
			return nil, nil
		}
		return nil, fmt.Errorf("node %q operation %s: %w", report.NodeID, report.Operation, ErrConflictingReplay)
	}

	var commands []Command
	if report.Result == ResultNACK {
		commands, err = c.observeNACKLocked(node, report)
	} else {
		switch report.Operation {
		case OperationPrepare:
			commands, err = c.observePreparedLocked(report.NodeID, node, report.CompletedAt)
		case OperationActivate:
			commands, err = c.observeActiveLocked(node, report.CompletedAt)
		case OperationCancel:
			if node.phase != NodeCancelPending ||
				(c.phase != PhaseCancelled && c.phase != PhaseRequiresRollback) {
				err = ErrStateTransition
				break
			}
			if c.phase == PhaseCancelled {
				node.phase = NodeCancelled
			} else {
				node.phase = NodePriorActive
			}
		default:
			err = ErrInvalidReport
		}
	}
	if err != nil {
		return nil, err
	}
	node.connected = true
	node.processInstance = report.ProcessInstance
	node.reports[report.Operation] = cloneReport(report)
	return commands, nil
}

// Reconnect reconciles authoritative node-observed state and returns the one
// command needed to resume this rollout. A changed process instance is valid.
func (c *Coordinator) Reconnect(state RuntimeState) ([]Command, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.phase == PhasePending {
		return nil, ErrNotStarted
	}
	node, exists := c.nodes[state.NodeID]
	if !exists {
		return nil, ErrUnknownNode
	}
	if strings.TrimSpace(state.ProcessInstance) == "" {
		return nil, fmt.Errorf("process instance is empty: %w", ErrInvalidReport)
	}
	if c.plan.Policy.Enabled && (state.ObservedAt.IsZero() || state.ObservedAt.Location() != time.UTC) {
		return nil, fmt.Errorf("runtime observation time is invalid: %w", ErrInvalidReport)
	}
	if state.LastSequence > c.plan.Sequence {
		return nil, ErrFutureSequence
	}
	if err := validateOptionalReference(state.Active); err != nil {
		return nil, fmt.Errorf("active snapshot: %w", err)
	}
	if !isEmptyReference(state.Active) && state.ActiveShardCount == 0 {
		return nil, fmt.Errorf("active shard count is zero: %w", ErrInvalidReport)
	}
	if state.Prepared != nil {
		if state.Prepared.Sequence > c.plan.Sequence {
			return nil, ErrFutureSequence
		}
		if err := validateReference(state.Prepared.Artifact); err != nil {
			return nil, fmt.Errorf("prepared snapshot: %w", err)
		}
		if state.Prepared.ShardCount == 0 {
			return nil, fmt.Errorf("prepared shard count is zero: %w", ErrInvalidReport)
		}
		if state.Prepared.Sequence > state.LastSequence {
			return nil, fmt.Errorf("prepared sequence exceeds last accepted sequence: %w", ErrInvalidReport)
		}
		if state.Prepared.Sequence == c.plan.Sequence &&
			!referencesEqual(state.Prepared.Artifact, c.plan.Artifact.Reference) {
			return nil, ErrConflictingReplay
		}
	}

	processChanged := node.processInstance != "" && node.processInstance != state.ProcessInstance
	if referencesEqual(state.Active, c.plan.Artifact.Reference) {
		alreadyTarget := referencesEqual(state.Active, c.expectedActive(state.NodeID))
		if state.LastSequence != c.plan.Sequence && !alreadyTarget {
			return nil, fmt.Errorf("active target has inconsistent sequence: %w", ErrInvalidReport)
		}
		switch c.phase {
		case PhasePreparing:
			if !referencesEqual(state.Active, c.expectedActive(state.NodeID)) {
				c.phase = PhaseRequiresRollback
				return nil, ErrDrift
			}
			c.acceptProcessInstanceLocked(node, state.ProcessInstance, processChanged)
			node.phase = NodeActive
			return c.activateWhenPreparedLocked(state.ObservedAt), nil
		case PhaseActivating:
			if !c.nodeInCurrentActivationWave(state.NodeID) && !alreadyTarget {
				c.phase = PhaseRequiresRollback
				c.failureReason = "node activated before its rollout wave"
				return nil, ErrDrift
			}
			c.acceptProcessInstanceLocked(node, state.ProcessInstance, processChanged)
			node.phase = NodeActive
			if c.allNodesInPhaseLocked(NodeActive) {
				c.phase = PhaseActive
			} else {
				c.finishActivationWaveLocked(state.ObservedAt)
			}
			return nil, nil
		case PhaseObserving:
			if !c.isCanary(state.NodeID) && !alreadyTarget {
				c.phase = PhaseRequiresRollback
				c.failureReason = "node activated before canary promotion"
				return nil, ErrDrift
			}
			c.acceptProcessInstanceLocked(node, state.ProcessInstance, processChanged)
			node.phase = NodeActive
			return nil, nil
		case PhaseActive:
			c.acceptProcessInstanceLocked(node, state.ProcessInstance, processChanged)
			node.phase = NodeActive
			if c.allNodesInPhaseLocked(NodeActive) {
				c.phase = PhaseActive
			}
			return nil, nil
		case PhaseCancelled:
			c.phase = PhaseRequiresRollback
			return nil, ErrDrift
		case PhaseRequiresRollback:
			c.acceptProcessInstanceLocked(node, state.ProcessInstance, processChanged)
			node.phase = NodeActive
			return nil, nil
		default:
			return nil, ErrStateTransition
		}
	}

	preparedCurrent := state.Prepared != nil &&
		state.Prepared.Sequence == c.plan.Sequence &&
		referencesEqual(state.Prepared.Artifact, c.plan.Artifact.Reference)
	if !isExpectedPrior(state.Active, c.expectedActive(state.NodeID)) {
		c.phase = PhaseRequiresRollback
		return nil, ErrDrift
	}

	switch c.phase {
	case PhasePreparing:
		if preparedCurrent {
			c.acceptProcessInstanceLocked(node, state.ProcessInstance, processChanged)
			node.phase = NodePrepared
			return c.activateWhenPreparedLocked(state.ObservedAt), nil
		}
		c.acceptProcessInstanceLocked(node, state.ProcessInstance, processChanged)
		node.phase = NodePreparing
		return []Command{c.prepareCommand(state.NodeID)}, nil
	case PhaseActivating:
		if preparedCurrent {
			c.acceptProcessInstanceLocked(node, state.ProcessInstance, processChanged)
			if !c.nodeInCurrentActivationWave(state.NodeID) {
				node.phase = NodePrepared
				return nil, nil
			}
			node.phase = NodeActivating
			return []Command{c.activateCommand(state.NodeID)}, nil
		}
		c.acceptProcessInstanceLocked(node, state.ProcessInstance, processChanged)
		node.phase = NodePreparing
		return []Command{c.prepareCommand(state.NodeID)}, nil
	case PhaseObserving:
		if c.isCanary(state.NodeID) {
			c.phase = PhaseRequiresRollback
			c.failureReason = "canary no longer serves the candidate artifact"
			return nil, ErrDrift
		}
		if preparedCurrent {
			c.acceptProcessInstanceLocked(node, state.ProcessInstance, processChanged)
			node.phase = NodePrepared
			return nil, nil
		}
		c.acceptProcessInstanceLocked(node, state.ProcessInstance, processChanged)
		node.phase = NodePreparing
		return []Command{c.prepareCommand(state.NodeID)}, nil
	case PhaseCancelled:
		if preparedCurrent {
			c.acceptProcessInstanceLocked(node, state.ProcessInstance, processChanged)
			node.phase = NodeCancelPending
			return []Command{c.cancelCommand(state.NodeID, c.cancelReason)}, nil
		}
		c.acceptProcessInstanceLocked(node, state.ProcessInstance, processChanged)
		node.phase = NodeCancelled
		return nil, nil
	case PhaseActive:
		c.phase = PhaseRequiresRollback
		return nil, ErrDrift
	case PhaseRequiresRollback:
		c.acceptProcessInstanceLocked(node, state.ProcessInstance, processChanged)
		if preparedCurrent {
			node.phase = NodeCancelPending
			return []Command{c.cancelCommand(state.NodeID, c.rollbackCleanupReasonLocked())}, nil
		}
		if state.Prepared != nil {
			return nil, ErrDrift
		}
		node.phase = NodePriorActive
		return nil, nil
	default:
		return nil, ErrStateTransition
	}
}

// Disconnect marks stream loss without changing prepared or active state.
func (c *Coordinator) Disconnect(nodeID, processInstance string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	node, exists := c.nodes[nodeID]
	if !exists {
		return ErrUnknownNode
	}
	if node.processInstance != "" && processInstance != "" && node.processInstance != processInstance {
		return ErrConflictingReplay
	}
	node.connected = false
	return nil
}

// Status returns immutable fleet and node projections.
func (c *Coordinator) Status() (Phase, map[string]NodeSnapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	nodes := make(map[string]NodeSnapshot, len(c.nodes))
	for nodeID, node := range c.nodes {
		nodes[nodeID] = NodeSnapshot{
			Phase:           node.phase,
			Connected:       node.connected,
			ProcessInstance: node.processInstance,
		}
	}
	return c.phase, nodes
}

// Policy returns an immutable copy of the rollout policy.
func (c *Coordinator) Policy() Policy {
	c.mu.Lock()
	defer c.mu.Unlock()
	policy := c.plan.Policy
	policy.CanaryNodeIDs = append([]string(nil), policy.CanaryNodeIDs...)
	return policy
}

// PolicyState returns the replay-relevant policy clock and decision state.
func (c *Coordinator) PolicyState() PolicyState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.policyStateLocked()
}

func (c *Coordinator) policyStateLocked() PolicyState {
	if !c.plan.Policy.Enabled {
		return PolicyState{}
	}
	return PolicyState{
		Enabled: true, Strategy: c.plan.Policy.Strategy,
		CanaryNodeIDs: append([]string(nil), c.plan.Policy.CanaryNodeIDs...),
		StartedAt:     c.startedAt, ActivationStartedAt: c.activationStartedAt,
		ObservationStartedAt: c.observationStartedAt, FailureReason: c.failureReason,
		AutomaticRollback: c.plan.Policy.AutomaticRollback,
	}
}

// Evaluate applies one deterministic deadline or canary-health decision. A
// pending result does not mutate state and must not be journaled.
func (c *Coordinator) Evaluate(observation PolicyObservation) ([]Command, PolicyResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.plan.Policy.Enabled {
		return nil, PolicyResult{}, ErrPolicyDisabled
	}
	if observation.ObservedAt.IsZero() || observation.ObservedAt.Location() != time.UTC ||
		observation.ObservedAt.Before(c.startedAt) {
		return nil, PolicyResult{}, fmt.Errorf("policy observation time is invalid: %w", ErrInvalidReport)
	}
	health, err := c.validatePolicyObservationLocked(observation)
	if err != nil {
		return nil, PolicyResult{}, err
	}
	switch c.phase {
	case PhasePreparing:
		if observation.ObservedAt.Before(c.startedAt.Add(c.plan.Policy.PrepareTimeout)) {
			return nil, PolicyResult{}, ErrPolicyPending
		}
		reason := "preparation deadline exceeded"
		commands := c.cancelLocked(reason)
		return commands, PolicyResult{Decision: PolicyDecisionCancel, Reason: reason}, nil
	case PhaseActivating:
		if c.activationStartedAt.IsZero() ||
			observation.ObservedAt.Before(c.activationStartedAt.Add(c.plan.Policy.ActivationTimeout)) {
			return nil, PolicyResult{}, ErrPolicyPending
		}
		reason := "activation deadline exceeded"
		c.phase = PhaseRequiresRollback
		c.failureReason = reason
		return nil, PolicyResult{Decision: PolicyDecisionRequireRollback, Reason: reason}, nil
	case PhaseObserving:
		if c.observationStartedAt.IsZero() ||
			observation.ObservedAt.Before(c.observationStartedAt.Add(c.plan.Policy.CanaryObservationWindow)) {
			return nil, PolicyResult{}, ErrPolicyPending
		}
		healthy := 0
		for _, nodeID := range c.plan.Policy.CanaryNodeIDs {
			candidate := health[nodeID]
			node := c.nodes[nodeID]
			if candidate.Connected && candidate.Reconciled && node.phase == NodeActive &&
				candidate.ActiveSnapshotID == c.plan.Artifact.Reference.ID &&
				!candidate.LastSeen.IsZero() && !candidate.LastSeen.After(observation.ObservedAt) &&
				observation.ObservedAt.Sub(candidate.LastSeen) <= c.plan.Policy.HeartbeatStaleAfter {
				healthy++
			}
		}
		required := (len(c.plan.Policy.CanaryNodeIDs)*int(c.plan.Policy.MinimumHealthyCanaryPercent) + 99) / 100
		if healthy < required {
			reason := fmt.Sprintf("canary health threshold failed: healthy=%d required=%d", healthy, required)
			c.phase = PhaseRequiresRollback
			c.failureReason = reason
			return nil, PolicyResult{Decision: PolicyDecisionRequireRollback, Reason: reason}, nil
		}
		commands := c.promoteLocked(observation.ObservedAt)
		return commands, PolicyResult{
			Decision: PolicyDecisionPromote,
			Reason:   fmt.Sprintf("canary health threshold passed: healthy=%d required=%d", healthy, required),
		}, nil
	default:
		return nil, PolicyResult{}, ErrPolicyPending
	}
}

func (c *Coordinator) validatePolicyObservationLocked(
	observation PolicyObservation,
) (map[string]NodeHealth, error) {
	health := make(map[string]NodeHealth, len(observation.Nodes))
	for _, node := range observation.Nodes {
		if !c.isCanary(node.NodeID) {
			return nil, fmt.Errorf("policy observation contains non-canary node %q: %w", node.NodeID, ErrInvalidReport)
		}
		if _, exists := health[node.NodeID]; exists {
			return nil, fmt.Errorf("policy observation duplicates node %q: %w", node.NodeID, ErrInvalidReport)
		}
		if !node.LastSeen.IsZero() && node.LastSeen.Location() != time.UTC {
			return nil, fmt.Errorf("policy node observation time is invalid: %w", ErrInvalidReport)
		}
		health[node.NodeID] = node
	}
	if c.phase == PhaseObserving && len(health) != len(c.plan.Policy.CanaryNodeIDs) {
		return nil, fmt.Errorf("policy observation does not cover every canary: %w", ErrInvalidReport)
	}
	return health, nil
}

func (c *Coordinator) promoteLocked(at time.Time) []Command {
	c.phase = PhaseActivating
	c.activationStartedAt = at
	commands := make([]Command, 0, len(c.plan.NodeIDs)-len(c.plan.Policy.CanaryNodeIDs))
	for _, nodeID := range c.plan.NodeIDs {
		node := c.nodes[nodeID]
		if node.phase != NodePrepared {
			continue
		}
		node.phase = NodeActivating
		commands = append(commands, c.activateCommand(nodeID))
	}
	if len(commands) == 0 {
		c.finishActivationWaveLocked(at)
	}
	return commands
}

// PendingCommands returns a deterministic read-only projection of operations
// that remain outstanding. Callers must reconcile a reconnected node's
// authoritative RuntimeState before dispatching this projection after a
// controller restart.
func (c *Coordinator) PendingCommands() []Command {
	c.mu.Lock()
	defer c.mu.Unlock()

	commands := make([]Command, 0, len(c.plan.NodeIDs))
	for _, nodeID := range c.plan.NodeIDs {
		node := c.nodes[nodeID]
		switch {
		case c.phase == PhasePreparing && node.phase == NodePreparing:
			commands = append(commands, c.prepareCommand(nodeID))
		case c.phase == PhaseActivating && node.phase == NodePreparing:
			commands = append(commands, c.prepareCommand(nodeID))
		case c.phase == PhaseActivating && node.phase == NodeActivating:
			commands = append(commands, c.activateCommand(nodeID))
		case c.phase == PhaseActivating && node.phase == NodePrepared && c.nodeInCurrentActivationWave(nodeID):
			commands = append(commands, c.activateCommand(nodeID))
		case c.phase == PhaseObserving && node.phase == NodePreparing:
			commands = append(commands, c.prepareCommand(nodeID))
		case c.phase == PhaseCancelled && node.phase == NodeCancelPending:
			commands = append(commands, c.cancelCommand(nodeID, c.cancelReason))
		case c.phase == PhaseRequiresRollback && node.phase == NodeCancelPending:
			commands = append(commands, c.cancelCommand(nodeID, c.rollbackCleanupReasonLocked()))
		}
	}
	return commands
}

func (c *Coordinator) validateReportLocked(report Report) (*nodeState, error) {
	node, exists := c.nodes[report.NodeID]
	if !exists {
		return nil, ErrUnknownNode
	}
	if report.Sequence < c.plan.Sequence {
		return nil, ErrStaleSequence
	}
	if report.Sequence > c.plan.Sequence {
		return nil, ErrFutureSequence
	}
	if strings.TrimSpace(report.ProcessInstance) == "" || !referencesEqual(report.Artifact, c.plan.Artifact.Reference) {
		return nil, ErrInvalidReport
	}
	if report.Operation != OperationPrepare && report.Operation != OperationActivate && report.Operation != OperationCancel {
		return nil, ErrInvalidReport
	}
	if report.Result != ResultACK && report.Result != ResultNACK {
		return nil, ErrInvalidReport
	}
	if report.Result == ResultACK {
		if len(report.Issues) != 0 || report.ShardCount == 0 || report.CompletedShards != report.ShardCount {
			return nil, ErrInvalidReport
		}
	} else if len(report.Issues) == 0 {
		return nil, ErrInvalidReport
	}
	for _, issue := range report.Issues {
		if strings.TrimSpace(issue.Code) == "" {
			return nil, ErrInvalidReport
		}
	}
	if c.plan.Policy.Enabled && (report.CompletedAt.IsZero() || report.CompletedAt.Location() != time.UTC ||
		report.CompletedAt.Before(c.startedAt)) {
		return nil, ErrInvalidReport
	}
	expectedActive := c.expectedActive(report.NodeID)
	if !isExpectedPrior(report.PreviousActive, expectedActive) {
		return nil, ErrInvalidReport
	}
	switch report.Operation {
	case OperationPrepare, OperationCancel:
		if !isExpectedPrior(report.CurrentActive, expectedActive) {
			return nil, ErrInvalidReport
		}
	case OperationActivate:
		want := expectedActive
		if report.Result == ResultACK {
			want = c.plan.Artifact.Reference
		}
		if !isExpectedPrior(report.CurrentActive, want) {
			return nil, ErrInvalidReport
		}
	}
	if node.processInstance != "" && node.processInstance != report.ProcessInstance {
		return nil, ErrConflictingReplay
	}
	return node, nil
}

func (c *Coordinator) observeNACKLocked(node *nodeState, report Report) ([]Command, error) {
	switch report.Operation {
	case OperationPrepare:
		if c.phase == PhasePreparing && node.phase == NodePreparing {
			node.phase = NodeFailed
			return c.cancelLocked("node preparation failed"), nil
		}
		if c.phase == PhaseActivating && node.phase == NodePreparing {
			node.phase = NodeFailed
			c.phase = PhaseRequiresRollback
			c.failureReason = "node preparation failed after activation began"
			return nil, nil
		}
		if c.phase == PhaseObserving && node.phase == NodePreparing {
			node.phase = NodeFailed
			c.phase = PhaseRequiresRollback
			c.failureReason = "node preparation failed while the canary was active"
			return nil, nil
		}
	case OperationActivate:
		if c.phase == PhaseActivating && node.phase == NodeActivating {
			node.phase = NodeFailed
			c.phase = PhaseRequiresRollback
			c.failureReason = "node activation failed"
			return nil, nil
		}
	case OperationCancel:
		if c.phase == PhaseCancelled && node.phase == NodeCancelPending {
			node.phase = NodeFailed
			return nil, nil
		}
		if c.phase == PhaseRequiresRollback && node.phase == NodeCancelPending {
			node.phase = NodeFailed
			return nil, nil
		}
	}
	return nil, ErrStateTransition
}

func (c *Coordinator) observePreparedLocked(
	nodeID string,
	node *nodeState,
	completedAt time.Time,
) ([]Command, error) {
	switch c.phase {
	case PhasePreparing:
		if node.phase != NodePreparing {
			return nil, ErrStateTransition
		}
		node.phase = NodePrepared
		return c.activateWhenPreparedLocked(completedAt), nil
	case PhaseActivating:
		if node.phase != NodePreparing {
			return nil, ErrStateTransition
		}
		if !c.nodeInCurrentActivationWave(nodeID) {
			node.phase = NodePrepared
			return nil, nil
		}
		node.phase = NodeActivating
		return []Command{c.activateCommand(nodeID)}, nil
	case PhaseObserving:
		if node.phase != NodePreparing || c.isCanary(nodeID) {
			return nil, ErrStateTransition
		}
		node.phase = NodePrepared
		return nil, nil
	default:
		return nil, ErrStateTransition
	}
}

func (c *Coordinator) observeActiveLocked(node *nodeState, completedAt time.Time) ([]Command, error) {
	if c.phase != PhaseActivating || node.phase != NodeActivating {
		return nil, ErrStateTransition
	}
	node.phase = NodeActive
	c.finishActivationWaveLocked(completedAt)
	return nil, nil
}

func (c *Coordinator) activateWhenPreparedLocked(at time.Time) []Command {
	if !c.allNodesPreparedOrActiveLocked() {
		return nil
	}
	if c.allNodesInPhaseLocked(NodeActive) {
		c.phase = PhaseActive
		return nil
	}
	c.phase = PhaseActivating
	if c.plan.Policy.Enabled {
		c.activationStartedAt = at
	}
	commands := make([]Command, 0, len(c.plan.NodeIDs))
	for _, nodeID := range c.plan.NodeIDs {
		node := c.nodes[nodeID]
		if node.phase == NodeActive || c.plan.Policy.Enabled && c.plan.Policy.Strategy == StrategyCanary &&
			!c.isCanary(nodeID) {
			continue
		}
		node.phase = NodeActivating
		commands = append(commands, c.activateCommand(nodeID))
	}
	if len(commands) == 0 {
		c.finishActivationWaveLocked(at)
	}
	return commands
}

func (c *Coordinator) finishActivationWaveLocked(at time.Time) {
	for _, node := range c.nodes {
		if node.phase == NodeActivating || node.phase == NodePreparing {
			return
		}
	}
	if c.plan.Policy.Enabled && c.plan.Policy.Strategy == StrategyCanary &&
		c.observationStartedAt.IsZero() {
		for _, node := range c.nodes {
			if node.phase == NodePrepared {
				c.phase = PhaseObserving
				c.activationStartedAt = time.Time{}
				c.observationStartedAt = at
				return
			}
		}
	}
	if c.allNodesInPhaseLocked(NodeActive) {
		c.phase = PhaseActive
		c.activationStartedAt = time.Time{}
	}
}

func (c *Coordinator) allNodesPreparedOrActiveLocked() bool {
	for _, node := range c.nodes {
		if node.phase != NodePrepared && node.phase != NodeActive {
			return false
		}
	}
	return true
}

func (c *Coordinator) isCanary(nodeID string) bool {
	_, found := c.canaryNodes[nodeID]
	return found
}

func (c *Coordinator) nodeInCurrentActivationWave(nodeID string) bool {
	if !c.plan.Policy.Enabled || c.plan.Policy.Strategy == StrategyImmediate ||
		!c.observationStartedAt.IsZero() {
		return true
	}
	return c.isCanary(nodeID)
}

func (c *Coordinator) cancelLocked(reason string) []Command {
	c.phase = PhaseCancelled
	c.cancelReason = reason
	if c.plan.Policy.Enabled {
		c.failureReason = reason
	}
	commands := make([]Command, 0, len(c.plan.NodeIDs))
	for _, nodeID := range c.plan.NodeIDs {
		node := c.nodes[nodeID]
		if node.phase == NodeFailed || node.phase == NodeCancelled {
			continue
		}
		node.phase = NodeCancelPending
		commands = append(commands, c.cancelCommand(nodeID, reason))
	}
	return commands
}

func (c *Coordinator) allNodesInPhaseLocked(phase NodePhase) bool {
	for _, node := range c.nodes {
		if node.phase != phase {
			return false
		}
	}
	return true
}

func (c *Coordinator) acceptProcessInstanceLocked(node *nodeState, processInstance string, changed bool) {
	node.connected = true
	node.processInstance = processInstance
	if changed {
		node.reports = make(map[Operation]Report)
	}
}

func (c *Coordinator) prepareCommand(nodeID string) Command {
	artifact := c.plan.Artifact
	artifact.Bytes = append([]byte(nil), artifact.Bytes...)
	return Command{
		NodeID:         nodeID,
		Sequence:       c.plan.Sequence,
		Operation:      OperationPrepare,
		Artifact:       artifact,
		ExpectedActive: c.expectedActive(nodeID),
	}
}

func (c *Coordinator) activateCommand(nodeID string) Command {
	return Command{
		NodeID:         nodeID,
		Sequence:       c.plan.Sequence,
		Operation:      OperationActivate,
		Artifact:       Artifact{Reference: c.plan.Artifact.Reference},
		ExpectedActive: c.expectedActive(nodeID),
	}
}

func (c *Coordinator) expectedActive(nodeID string) Reference {
	return c.plan.PreviousByNode[nodeID]
}

func (c *Coordinator) cancelCommand(nodeID, reason string) Command {
	return Command{
		NodeID:    nodeID,
		Sequence:  c.plan.Sequence,
		Operation: OperationCancel,
		Artifact:  Artifact{Reference: c.plan.Artifact.Reference},
		Reason:    reason,
	}
}

func (c *Coordinator) rollbackCleanupReasonLocked() string {
	if strings.TrimSpace(c.failureReason) != "" {
		return "discard failed rollout preparation: " + c.failureReason
	}
	return "discard failed rollout preparation before exact rollback"
}

func validateArtifact(artifact Artifact) error {
	if err := validateReference(artifact.Reference); err != nil {
		return err
	}
	if len(artifact.Bytes) == 0 {
		return fmt.Errorf("snapshot bytes are empty: %w", ErrInvalidReport)
	}
	if sha256.Sum256(artifact.Bytes) != artifact.Reference.SHA256 {
		return fmt.Errorf("snapshot digest does not match bytes: %w", ErrInvalidReport)
	}
	return nil
}

func validateOptionalReference(reference Reference) error {
	if isEmptyReference(reference) {
		return nil
	}
	return validateReference(reference)
}

func validateReference(reference Reference) error {
	if strings.TrimSpace(reference.ID) == "" || reference.SHA256 == ([sha256.Size]byte{}) {
		return ErrInvalidReport
	}
	return nil
}

func isExpectedPrior(actual, expected Reference) bool {
	if isEmptyReference(expected) {
		return isEmptyReference(actual)
	}
	return referencesEqual(actual, expected)
}

func isEmptyReference(reference Reference) bool {
	return reference.ID == "" && reference.SHA256 == ([sha256.Size]byte{})
}

func referencesEqual(left, right Reference) bool {
	return left.ID == right.ID && left.SHA256 == right.SHA256
}

func cloneReport(report Report) Report {
	report.Issues = append([]Issue(nil), report.Issues...)
	return report
}
