package discovery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	bonvoyagev1 "github.com/routesphere-global/bonvoyage/api/gen/go/bonvoyage/v1"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/rollout"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/rolloutservice"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// NewServer validates and copies all stream policy. Partially specified
// options are rejected so production bounds cannot silently fall back.
func NewServer(coordinator Coordinator, options Options) (*Server, error) {
	if coordinator == nil || options.Authenticator == nil || options.RequiredSchemaVersion == 0 ||
		options.HelloTimeout <= 0 || options.HeartbeatTimeout <= 0 || options.CredentialCheckInterval <= 0 ||
		options.MaxClockSkew <= 0 || options.MaxObservationAge <= 0 || options.CommandQueueCapacity < 1 ||
		options.CommandQueueCapacity > 1024 || options.Clock == nil || options.Random == nil {
		return nil, ErrInvalidOptions
	}
	if err := validateRequiredCapabilities(options.RequiredCapabilities); err != nil {
		return nil, fmt.Errorf("required capabilities: %w: %w", err, ErrInvalidOptions)
	}
	required := make(map[bonvoyagev1.NodeCapabilityType]uint32, len(options.RequiredCapabilities))
	for typeID, version := range options.RequiredCapabilities {
		required[typeID] = version
	}
	validator, _ := options.Authenticator.(CredentialValidator)
	return &Server{
		coordinator: coordinator, authenticator: options.Authenticator,
		credentialValidator: validator,
		requiredSchema:      options.RequiredSchemaVersion, requiredCapabilities: required,
		helloTimeout: options.HelloTimeout, heartbeatTimeout: options.HeartbeatTimeout,
		credentialCheckInterval: options.CredentialCheckInterval,
		maxClockSkew:            options.MaxClockSkew, maxObservationAge: options.MaxObservationAge,
		queueCapacity: options.CommandQueueCapacity, clock: options.Clock, random: options.Random,
		owners: make(map[string]*streamOwner),
	}, nil
}

func validateRequiredCapabilities(required map[bonvoyagev1.NodeCapabilityType]uint32) error {
	expected := []bonvoyagev1.NodeCapabilityType{
		bonvoyagev1.NodeCapabilityType_NODE_CAPABILITY_TYPE_TWO_PHASE_ROLLOUT,
		bonvoyagev1.NodeCapabilityType_NODE_CAPABILITY_TYPE_EXACT_ARTIFACT_ROLLBACK,
		bonvoyagev1.NodeCapabilityType_NODE_CAPABILITY_TYPE_HEARTBEAT_STATE_REPORT,
	}
	if len(required) != len(expected) {
		return fmt.Errorf("exactly %d v1 capabilities are required", len(expected))
	}
	for _, typeID := range expected {
		if required[typeID] != 1 {
			return fmt.Errorf("%s must require version 1", typeID)
		}
	}
	return nil
}

type receivedFrame struct {
	request *bonvoyagev1.StreamSnapshotsRequest
	err     error
}

// StreamSnapshots authenticates one node, negotiates the exact v1 contract,
// and keeps one current stream owner per node. Rollout transitions remain in
// the durable coordinator and are never inferred from transport liveness.
func (server *Server) StreamSnapshots(stream bonvoyagev1.SnapshotDiscoveryService_StreamSnapshotsServer) error {
	identity, err := server.authenticator.Authenticate(stream.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, "verified client identity is required")
	}
	if err := validateIdentifier("authenticated node ID", identity.NodeID); err != nil {
		return status.Error(codes.Unauthenticated, "authenticated node identity is invalid")
	}
	if err := validateText("credential fingerprint", identity.CredentialFingerprint, 128, true); err != nil {
		return status.Error(codes.Unauthenticated, "authenticated credential fingerprint is invalid")
	}
	if err := server.validateCredential(identity); err != nil {
		return status.Error(codes.Unauthenticated, "authenticated credential is no longer valid")
	}

	frames := receiveFrames(stream)
	helloTimer := time.NewTimer(server.helloTimeout)
	defer helloTimer.Stop()
	var first receivedFrame
	select {
	case first = <-frames:
	case <-helloTimer.C:
		return status.Error(codes.DeadlineExceeded, "node hello deadline exceeded")
	case <-stream.Context().Done():
		return statusFromError(stream.Context().Err())
	}
	if first.err != nil {
		return receiveError(first.err)
	}
	if first.request == nil || first.request.GetHello() == nil {
		return status.Error(codes.FailedPrecondition, "the first stream frame must be node hello")
	}
	if err := rejectUnknown(first.request); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	hello := first.request.GetHello()
	if hello.GetNodeId() != identity.NodeID {
		return status.Error(codes.PermissionDenied, "hello node ID does not match the authenticated identity")
	}
	runtime, err := validateHello(
		identity, hello, server.requiredSchema, server.requiredCapabilities,
	)
	if err != nil {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	runtime.ObservedAt = server.clock().UTC()

	owner, err := server.claimOwner(stream.Context(), identity, runtime)
	if err != nil {
		return err
	}
	defer server.releaseOwner(owner)

	server.transitionMu.Lock()
	eventID, err := reconnectEventID(server.random)
	if err != nil {
		_ = server.coordinator.Disconnect(owner.nodeID, "")
		server.transitionMu.Unlock()
		return status.Error(codes.Internal, "could not create a stream event identity")
	}
	transition, err := server.coordinator.Reconnect(stream.Context(), eventID, runtime)
	if err != nil {
		_ = server.coordinator.Disconnect(owner.nodeID, "")
		server.transitionMu.Unlock()
		return statusFromError(err)
	}
	if !server.markOwnerReady(owner) {
		server.transitionMu.Unlock()
		return status.Error(codes.Aborted, "stream ownership was superseded during reconciliation")
	}
	if err := server.dispatchForOwner(owner, transition.Commands); err != nil {
		server.transitionMu.Unlock()
		return err
	}
	server.transitionMu.Unlock()

	heartbeatTimer := time.NewTimer(server.heartbeatTimeout)
	defer heartbeatTimer.Stop()
	credentialTimer := time.NewTimer(server.nextCredentialCheck(identity))
	defer credentialTimer.Stop()
	for {
		select {
		case <-owner.ctx.Done():
			return statusFromError(context.Cause(owner.ctx))
		case <-heartbeatTimer.C:
			return status.Error(codes.DeadlineExceeded, "node heartbeat deadline exceeded")
		case <-credentialTimer.C:
			if err := server.validateCredential(identity); err != nil {
				return status.Error(codes.Unauthenticated, "authenticated credential is no longer valid")
			}
			resetTimer(credentialTimer, server.nextCredentialCheck(identity))
		case response := <-owner.queue:
			if err := server.sendOwned(stream, owner, response); err != nil {
				return receiveError(err)
			}
		case frame := <-frames:
			if frame.err != nil {
				return receiveError(frame.err)
			}
			if !server.isOwner(owner) {
				return status.Error(codes.Aborted, "stream ownership was superseded")
			}
			if err := server.validateCredential(identity); err != nil {
				return status.Error(codes.Unauthenticated, "authenticated credential is no longer valid")
			}
			if err := server.handleFrame(stream.Context(), owner, frame.request); err != nil {
				return err
			}
			resetTimer(heartbeatTimer, server.heartbeatTimeout)
		}
	}
}

func receiveFrames(stream bonvoyagev1.SnapshotDiscoveryService_StreamSnapshotsServer) <-chan receivedFrame {
	frames := make(chan receivedFrame, 1)
	go func() {
		for {
			request, err := stream.Recv()
			select {
			case frames <- receivedFrame{request: request, err: err}:
			case <-stream.Context().Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	return frames
}

func (server *Server) handleFrame(
	ctx context.Context,
	owner *streamOwner,
	request *bonvoyagev1.StreamSnapshotsRequest,
) error {
	if request == nil || request.GetRequest() == nil {
		return status.Error(codes.InvalidArgument, "stream frame is empty")
	}
	if err := rejectUnknown(request); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	switch payload := request.GetRequest().(type) {
	case *bonvoyagev1.StreamSnapshotsRequest_Hello:
		return status.Error(codes.FailedPrecondition, "node hello may only be sent once")
	case *bonvoyagev1.StreamSnapshotsRequest_Acknowledgement:
		return status.Error(codes.FailedPrecondition, "legacy acknowledgement is disabled for negotiated v1 streams")
	case *bonvoyagev1.StreamSnapshotsRequest_Heartbeat:
		if payload.Heartbeat.GetNodeId() != owner.nodeID ||
			payload.Heartbeat.GetProcessInstanceId() != owner.processInstance {
			return status.Error(codes.PermissionDenied, "heartbeat identity does not match the stream owner")
		}
		state, err := validateHeartbeat(
			payload.Heartbeat, owner, server.clock(), server.maxClockSkew, server.maxObservationAge,
		)
		if err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		if !server.touchOwner(owner, state) {
			return status.Error(codes.Aborted, "stream ownership was superseded")
		}
		return nil
	case *bonvoyagev1.StreamSnapshotsRequest_RolloutReport:
		if payload.RolloutReport.GetNodeId() != owner.nodeID ||
			payload.RolloutReport.GetProcessInstanceId() != owner.processInstance {
			return status.Error(codes.PermissionDenied, "rollout report identity does not match the stream owner")
		}
		report, err := validateReport(
			payload.RolloutReport, owner, server.clock(), server.maxClockSkew, server.maxObservationAge,
		)
		if err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		server.transitionMu.Lock()
		if !server.isOwner(owner) {
			server.transitionMu.Unlock()
			return status.Error(codes.Aborted, "stream ownership was superseded")
		}
		transition, err := server.coordinator.Observe(ctx, reportEventID(report), report)
		if err != nil {
			server.transitionMu.Unlock()
			return statusFromError(err)
		}
		result, err := server.dispatch(transition.Commands)
		if err != nil {
			server.transitionMu.Unlock()
			return status.Error(codes.Internal, "durable command could not be encoded")
		}
		if slices.Contains(result.Overflowed, owner.nodeID) {
			server.transitionMu.Unlock()
			return status.Error(codes.ResourceExhausted, "node command queue is full")
		}
		if !server.touchReport(owner, report) {
			server.transitionMu.Unlock()
			return status.Error(codes.Aborted, "stream ownership was superseded")
		}
		server.transitionMu.Unlock()
		return nil
	default:
		return status.Error(codes.InvalidArgument, "stream frame type is unsupported")
	}
}

func (server *Server) claimOwner(
	parent context.Context,
	identity AuthenticatedNode,
	runtime rollout.RuntimeState,
) (*streamOwner, error) {
	now := server.clock()
	ctx, cancel := context.WithCancelCause(parent)
	owner := &streamOwner{
		nodeID: identity.NodeID, processInstance: runtime.ProcessInstance,
		credentialFingerprint:  identity.CredentialFingerprint,
		credentialSerial:       identity.CredentialSerial,
		issuerFingerprint:      identity.IssuerFingerprint,
		trustAnchorFingerprint: identity.TrustAnchorFingerprint,
		credentialNotBefore:    identity.CredentialNotBefore,
		credentialNotAfter:     identity.CredentialNotAfter,
		connectedAt:            now, lastSeen: now, lastRolloutSequence: runtime.LastSequence,
		activeSnapshotID: runtime.Active.ID, queue: make(chan *bonvoyagev1.StreamSnapshotsResponse, server.queueCapacity),
		ctx: ctx, cancel: cancel,
	}
	if runtime.Prepared != nil {
		owner.preparedSequence = runtime.Prepared.Sequence
	}

	for {
		server.mu.Lock()
		current := server.owners[identity.NodeID]
		duplicate := current != nil && current.ctx.Err() == nil &&
			current.processInstance == runtime.ProcessInstance &&
			current.credentialFingerprint == identity.CredentialFingerprint
		server.mu.Unlock()

		if duplicate {
			server.transitionMu.Lock()
			server.mu.Lock()
			stillCurrent := server.owners[identity.NodeID] == current && current.ctx.Err() == nil &&
				current.processInstance == runtime.ProcessInstance &&
				current.credentialFingerprint == identity.CredentialFingerprint
			server.mu.Unlock()
			server.transitionMu.Unlock()
			if !stillCurrent {
				continue
			}
			cancel(status.Error(codes.AlreadyExists, "this node process already owns a stream"))
			return nil, status.Error(codes.AlreadyExists, "this node process already owns a stream")
		}

		if current == nil {
			server.transitionMu.Lock()
			server.mu.Lock()
			if server.owners[identity.NodeID] != nil {
				server.mu.Unlock()
				server.transitionMu.Unlock()
				continue
			}
			server.nextToken++
			owner.token = server.nextToken
			server.owners[identity.NodeID] = owner
			server.mu.Unlock()
			server.transitionMu.Unlock()
			return owner, nil
		}

		// Wait outside both the owner-registry and durable-transition locks for
		// any write that linearized before takeover. A slow node can delay only
		// its own replacement; it cannot stall unrelated rollout transitions.
		current.deliveryMu.Lock()
		server.transitionMu.Lock()
		server.mu.Lock()
		if server.owners[identity.NodeID] != current {
			server.mu.Unlock()
			server.transitionMu.Unlock()
			current.deliveryMu.Unlock()
			continue
		}
		if current.ctx.Err() == nil && current.processInstance == runtime.ProcessInstance &&
			current.credentialFingerprint == identity.CredentialFingerprint {
			server.mu.Unlock()
			server.transitionMu.Unlock()
			current.deliveryMu.Unlock()
			cancel(status.Error(codes.AlreadyExists, "this node process already owns a stream"))
			return nil, status.Error(codes.AlreadyExists, "this node process already owns a stream")
		}
		current.cancel(status.Error(codes.Aborted, "a newer node process or credential superseded this stream"))
		server.nextToken++
		owner.token = server.nextToken
		server.owners[identity.NodeID] = owner
		server.mu.Unlock()
		server.transitionMu.Unlock()
		current.deliveryMu.Unlock()
		return owner, nil
	}
}

func (server *Server) sendOwned(
	stream bonvoyagev1.SnapshotDiscoveryService_StreamSnapshotsServer,
	owner *streamOwner,
	response *bonvoyagev1.StreamSnapshotsResponse,
) error {
	owner.deliveryMu.Lock()
	defer owner.deliveryMu.Unlock()
	if !server.isOwner(owner) {
		return status.Error(codes.Aborted, "stream ownership was superseded")
	}
	return stream.Send(response)
}

func (server *Server) releaseOwner(owner *streamOwner) {
	server.mu.Lock()
	current := server.owners[owner.nodeID]
	if current == nil || current.token != owner.token {
		server.mu.Unlock()
		owner.cancel(nil)
		return
	}
	delete(server.owners, owner.nodeID)
	server.mu.Unlock()
	owner.cancel(nil)
	server.transitionMu.Lock()
	_ = server.coordinator.Disconnect(owner.nodeID, owner.processInstance)
	server.transitionMu.Unlock()
}

func (server *Server) isOwner(owner *streamOwner) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	current := server.owners[owner.nodeID]
	return current != nil && current.token == owner.token && current.ctx.Err() == nil
}

func (server *Server) touchOwner(owner *streamOwner, state rollout.RuntimeState) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	current := server.owners[owner.nodeID]
	if current == nil || current.token != owner.token || current.ctx.Err() != nil {
		return false
	}
	current.lastSeen = server.clock()
	current.lastRolloutSequence = state.LastSequence
	current.activeSnapshotID = state.Active.ID
	current.preparedSequence = 0
	if state.Prepared != nil {
		current.preparedSequence = state.Prepared.Sequence
	}
	return true
}

func (server *Server) markOwnerReady(owner *streamOwner) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	current := server.owners[owner.nodeID]
	if current == nil || current.token != owner.token || current.ctx.Err() != nil {
		return false
	}
	current.ready = true
	return true
}

func (server *Server) touchReport(owner *streamOwner, report rollout.Report) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	current := server.owners[owner.nodeID]
	if current == nil || current.token != owner.token || current.ctx.Err() != nil {
		return false
	}
	current.lastSeen = server.clock()
	if report.Sequence > current.lastRolloutSequence {
		current.lastRolloutSequence = report.Sequence
	}
	current.activeSnapshotID = report.CurrentActive.ID
	switch report.Operation {
	case rollout.OperationPrepare:
		if report.Result == rollout.ResultACK {
			current.preparedSequence = report.Sequence
		}
	case rollout.OperationActivate, rollout.OperationCancel:
		current.preparedSequence = 0
	}
	return true
}

// Connections returns a deterministic, immutable projection for status APIs.
func (server *Server) Connections() []ConnectionSnapshot {
	server.mu.Lock()
	defer server.mu.Unlock()
	connections := make([]ConnectionSnapshot, 0, len(server.owners))
	for _, owner := range server.owners {
		if owner.ctx.Err() != nil {
			continue
		}
		connections = append(connections, ConnectionSnapshot{
			NodeID: owner.nodeID, ProcessInstance: owner.processInstance,
			CredentialFingerprint:  owner.credentialFingerprint,
			CredentialSerial:       owner.credentialSerial,
			IssuerFingerprint:      owner.issuerFingerprint,
			TrustAnchorFingerprint: owner.trustAnchorFingerprint,
			CredentialNotAfter:     owner.credentialNotAfter,
			ConnectedAt:            owner.connectedAt, LastSeen: owner.lastSeen,
			LastRolloutSequence: owner.lastRolloutSequence,
			ActiveSnapshotID:    owner.activeSnapshotID, PreparedSequence: owner.preparedSequence,
			PendingCommands: len(owner.queue), Reconciled: owner.ready,
		})
	}
	slices.SortFunc(connections, func(left, right ConnectionSnapshot) int {
		if left.NodeID < right.NodeID {
			return -1
		}
		if left.NodeID > right.NodeID {
			return 1
		}
		return 0
	})
	return connections
}

// CurrentRollout returns the durable state owned by the same coordinator that
// accepts discovery reports. Connectivity remains a separate projection.
func (server *Server) CurrentRollout() (RolloutSelection, error) {
	server.transitionMu.Lock()
	defer server.transitionMu.Unlock()
	current, ok := server.coordinator.(ManagedCoordinator)
	if !ok {
		return RolloutSelection{}, fmt.Errorf("coordinator is not runtime-managed: %w", ErrInvalidOptions)
	}
	phase, nodes, err := current.Status()
	if err != nil {
		return RolloutSelection{}, err
	}
	return RolloutSelection{Sequence: current.Sequence(), Phase: phase, Nodes: nodes}, nil
}

// CancelRollout durably cancels the selected rollout before activation begins
// and publishes cleanup commands under the same authority lock as discovery.
func (server *Server) CancelRollout(
	ctx context.Context,
	sequence uint64,
	eventID string,
	cancellation rolloutservice.CancellationInput,
) (RolloutSelection, error) {
	if ctx == nil || sequence == 0 {
		return RolloutSelection{}, fmt.Errorf("rollout cancellation input is invalid: %w", storage.ErrInvalid)
	}
	server.transitionMu.Lock()
	defer server.transitionMu.Unlock()
	current, ok := server.coordinator.(ManagedCoordinator)
	if !ok {
		return RolloutSelection{}, fmt.Errorf("coordinator is not runtime-managed: %w", ErrInvalidOptions)
	}
	if current.Sequence() != sequence {
		return RolloutSelection{}, ErrRolloutSuperseded
	}
	transition, err := current.Cancel(ctx, eventID, cancellation)
	if err != nil {
		return RolloutSelection{}, err
	}
	if _, err := server.dispatch(transition.Commands); err != nil {
		return RolloutSelection{}, err
	}
	phase, nodes, err := current.Status()
	if err != nil {
		return RolloutSelection{}, err
	}
	return RolloutSelection{
		Sequence: sequence, Phase: phase, Nodes: nodes, Replayed: transition.Replayed,
	}, nil
}

// EvaluateRollout applies one deadline or canary-health decision. Pending
// observations are deliberately not journaled.
func (server *Server) EvaluateRollout(
	ctx context.Context,
	observedAt time.Time,
) (PolicyEvaluationResult, error) {
	if ctx == nil || observedAt.IsZero() {
		return PolicyEvaluationResult{}, fmt.Errorf("policy evaluation input is invalid: %w", storage.ErrInvalid)
	}
	server.transitionMu.Lock()
	defer server.transitionMu.Unlock()
	current, ok := server.coordinator.(ManagedCoordinator)
	if !ok {
		return PolicyEvaluationResult{}, fmt.Errorf("coordinator is not runtime-managed: %w", ErrInvalidOptions)
	}
	phase, _, err := current.Status()
	if err != nil {
		return PolicyEvaluationResult{}, err
	}
	result := PolicyEvaluationResult{Sequence: current.Sequence(), Phase: phase}
	if phase == rollout.PhaseRequiresRollback {
		server.quiesceRollbackLocked(current)
	}
	policy := current.Policy()
	if !policy.Enabled {
		return result, nil
	}
	health := server.policyHealthLocked(policy.CanaryNodeIDs)
	eventID, err := policyEventID(server.random)
	if err != nil {
		return PolicyEvaluationResult{}, err
	}
	transition, err := current.Evaluate(ctx, eventID, rollout.PolicyObservation{
		ObservedAt: observedAt.UTC().Round(0), Nodes: health,
	})
	if errors.Is(err, rollout.ErrPolicyPending) || errors.Is(err, rollout.ErrPolicyDisabled) {
		return result, nil
	}
	if err != nil {
		return PolicyEvaluationResult{}, err
	}
	if _, err := server.dispatch(transition.Commands); err != nil {
		return PolicyEvaluationResult{}, err
	}
	phase, _, err = current.Status()
	if err != nil {
		return PolicyEvaluationResult{}, err
	}
	if phase == rollout.PhaseRequiresRollback {
		server.quiesceRollbackLocked(current)
	}
	return PolicyEvaluationResult{
		Sequence: current.Sequence(), Phase: phase, Changed: true,
		Replayed: transition.Replayed, Decision: transition.Result.Decision,
		Reason: transition.Result.Reason,
	}, nil
}

func (server *Server) policyHealthLocked(canaryNodeIDs []string) []rollout.NodeHealth {
	server.mu.Lock()
	defer server.mu.Unlock()
	health := make([]rollout.NodeHealth, 0, len(canaryNodeIDs))
	for _, nodeID := range canaryNodeIDs {
		observation := rollout.NodeHealth{NodeID: nodeID}
		if owner := server.owners[nodeID]; owner != nil && owner.ctx.Err() == nil {
			observation.Connected = true
			observation.Reconciled = owner.ready
			observation.LastSeen = owner.lastSeen.UTC().Round(0)
			observation.ActiveSnapshotID = owner.activeSnapshotID
		}
		health = append(health, observation)
	}
	return health
}

// ReplaceRollout advances the persisted selection and the in-memory discovery
// authority under one transition lock. Existing streams are revoked so no
// queued command from the former rollout can cross the authority change; each
// node must reconnect and reconcile against the selected coordinator.
func (server *Server) ReplaceRollout(
	ctx context.Context,
	mutation RolloutMutation,
	next ManagedCoordinator,
	selector RolloutSelector,
) (RolloutSelection, error) {
	if ctx == nil || next == nil || selector == nil ||
		(mutation != RolloutMutationApply && mutation != RolloutMutationRollback) {
		return RolloutSelection{}, fmt.Errorf("rollout replacement input is invalid: %w", storage.ErrInvalid)
	}
	if err := ctx.Err(); err != nil {
		return RolloutSelection{}, err
	}
	server.transitionMu.Lock()
	defer server.transitionMu.Unlock()
	current, ok := server.coordinator.(ManagedCoordinator)
	if !ok {
		return RolloutSelection{}, fmt.Errorf("coordinator is not runtime-managed: %w", ErrInvalidOptions)
	}
	currentPhase, currentNodes, err := current.Status()
	if err != nil {
		return RolloutSelection{}, err
	}
	if next.Sequence() == current.Sequence() {
		return RolloutSelection{
			Sequence: current.Sequence(), Phase: currentPhase, Nodes: currentNodes, Replayed: true,
		}, nil
	}
	if next.Sequence() < current.Sequence() {
		return RolloutSelection{}, ErrRolloutSuperseded
	}
	if err := replacementAllowed(currentPhase, currentNodes, mutation); err != nil {
		return RolloutSelection{}, err
	}
	if currentPhase == rollout.PhaseRequiresRollback {
		if server.rollbackQuiescedSequence != current.Sequence() {
			server.quiesceRollbackLocked(current)
			return RolloutSelection{}, ErrRolloutInProgress
		}
		if !server.rollbackReadyLocked(currentNodes) {
			return RolloutSelection{}, ErrRolloutInProgress
		}
	}
	nextPhase, nextNodes, err := next.Status()
	if err != nil {
		return RolloutSelection{}, err
	}
	if nextPhase != rollout.PhasePreparing {
		return RolloutSelection{}, fmt.Errorf("candidate rollout is not durably started: %w", ErrRolloutInProgress)
	}
	if err := selector(ctx, current.Sequence(), next.Sequence()); err != nil {
		return RolloutSelection{}, err
	}
	server.revokeOwnersForReplacementLocked(current)
	server.coordinator = next
	server.rollbackQuiescedSequence = 0
	return RolloutSelection{Sequence: next.Sequence(), Phase: nextPhase, Nodes: nextNodes}, nil
}

func replacementAllowed(
	phase rollout.Phase,
	nodes map[string]rollout.NodeSnapshot,
	mutation RolloutMutation,
) error {
	switch phase {
	case rollout.PhaseActive:
		return nil
	case rollout.PhaseCancelled:
		for _, node := range nodes {
			if node.Phase == rollout.NodeCancelPending {
				return ErrRolloutInProgress
			}
		}
		return nil
	case rollout.PhaseRequiresRollback:
		if mutation != RolloutMutationRollback {
			return ErrRollbackRequired
		}
		return nil
	default:
		return ErrRolloutInProgress
	}
}

func (server *Server) revokeOwnersForReplacementLocked(current Coordinator) {
	server.mu.Lock()
	owners := make([]*streamOwner, 0, len(server.owners))
	for nodeID, owner := range server.owners {
		owners = append(owners, owner)
		delete(server.owners, nodeID)
	}
	server.mu.Unlock()
	for _, owner := range owners {
		_ = current.Disconnect(owner.nodeID, owner.processInstance)
		owner.cancel(status.Error(codes.Aborted, "selected rollout changed; reconnect for reconciliation"))
	}
}

func (server *Server) quiesceRollbackLocked(current ManagedCoordinator) {
	if server.rollbackQuiescedSequence == current.Sequence() {
		return
	}
	server.revokeOwnersForReplacementLocked(current)
	server.rollbackQuiescedSequence = current.Sequence()
}

func (server *Server) rollbackReadyLocked(nodes map[string]rollout.NodeSnapshot) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	for nodeID := range nodes {
		owner := server.owners[nodeID]
		if owner == nil || owner.ctx.Err() != nil || !owner.ready || owner.preparedSequence != 0 {
			return false
		}
	}
	return true
}

func (server *Server) validateCredential(identity AuthenticatedNode) error {
	now := server.clock().UTC()
	if identity.CredentialNotBefore.IsZero() || identity.CredentialNotAfter.IsZero() ||
		now.Before(identity.CredentialNotBefore) || !now.Before(identity.CredentialNotAfter) {
		return ErrUnauthenticated
	}
	if server.credentialValidator != nil {
		return server.credentialValidator.ValidateCredential(identity, now)
	}
	return nil
}

func (server *Server) nextCredentialCheck(identity AuthenticatedNode) time.Duration {
	delay := server.credentialCheckInterval
	untilExpiry := identity.CredentialNotAfter.Sub(server.clock().UTC())
	if untilExpiry <= 0 {
		return time.Nanosecond
	}
	if untilExpiry < delay {
		return untilExpiry
	}
	return delay
}

// dispatch enqueues each node's commands atomically or revokes an owner whose
// bounded queue cannot accept the complete batch. Commands for disconnected
// nodes remain durable and are regenerated by Reconnect.
func (server *Server) dispatch(commands []rollout.Command) (dispatchResult, error) {
	type pending struct {
		nodeID   string
		response *bonvoyagev1.StreamSnapshotsResponse
	}
	converted := make([]pending, 0, len(commands))
	counts := make(map[string]int)
	for _, command := range commands {
		if err := validateIdentifier("command node ID", command.NodeID); err != nil {
			return dispatchResult{}, err
		}
		response, err := server.wireCommand(command)
		if err != nil {
			return dispatchResult{}, fmt.Errorf("node %q command: %w", command.NodeID, err)
		}
		converted = append(converted, pending{nodeID: command.NodeID, response: response})
		counts[command.NodeID]++
	}
	grouped := make(map[string][]*bonvoyagev1.StreamSnapshotsResponse, len(counts))
	for _, item := range converted {
		grouped[item.nodeID] = append(grouped[item.nodeID], item.response)
	}

	result := dispatchResult{}
	server.mu.Lock()
	for nodeID, responses := range grouped {
		owner := server.owners[nodeID]
		if owner == nil || owner.ctx.Err() != nil || !owner.ready {
			result.Unavailable = append(result.Unavailable, nodeID)
			continue
		}
		if len(owner.queue)+len(responses) > cap(owner.queue) {
			result.Overflowed = append(result.Overflowed, nodeID)
			owner.cancel(status.Error(codes.ResourceExhausted, "node command queue is full"))
			continue
		}
		for _, response := range responses {
			owner.queue <- response
		}
		result.Enqueued = append(result.Enqueued, nodeID)
	}
	server.mu.Unlock()
	slices.Sort(result.Enqueued)
	slices.Sort(result.Unavailable)
	slices.Sort(result.Overflowed)
	return result, nil
}

func (server *Server) dispatchForOwner(owner *streamOwner, commands []rollout.Command) error {
	result, err := server.dispatch(commands)
	if err != nil {
		return status.Error(codes.Internal, "durable command could not be encoded")
	}
	if slices.Contains(result.Overflowed, owner.nodeID) {
		return status.Error(codes.ResourceExhausted, "node command queue is full")
	}
	return nil
}

func resetTimer(timer *time.Timer, duration time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(duration)
}

func receiveError(err error) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	return statusFromError(err)
}

func statusFromError(err error) error {
	if err == nil {
		return nil
	}
	if converted, ok := status.FromError(err); ok && converted.Code() != codes.Unknown {
		return err
	}
	switch {
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, "operation canceled")
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, "operation deadline exceeded")
	case errors.Is(err, rollout.ErrUnknownNode), errors.Is(err, storage.ErrNotFound):
		return status.Error(codes.NotFound, "rollout node or state was not found")
	case errors.Is(err, rollout.ErrConflictingReplay), errors.Is(err, storage.ErrConflict),
		errors.Is(err, rolloutservice.ErrJournalAdvanced):
		return status.Error(codes.Aborted, "rollout state conflicts with a prior event")
	case errors.Is(err, rollout.ErrInvalidReport), errors.Is(err, storage.ErrInvalid):
		return status.Error(codes.InvalidArgument, "rollout input is invalid")
	case errors.Is(err, rollout.ErrStaleSequence), errors.Is(err, rollout.ErrFutureSequence):
		return status.Error(codes.OutOfRange, "rollout sequence is outside the accepted range")
	case errors.Is(err, rollout.ErrNotStarted), errors.Is(err, rollout.ErrAlreadyStarted),
		errors.Is(err, rollout.ErrDrift), errors.Is(err, rollout.ErrRequiresRollback),
		errors.Is(err, rollout.ErrStateTransition):
		return status.Error(codes.FailedPrecondition, "rollout state does not allow this operation")
	case errors.Is(err, storage.ErrCorrupt), errors.Is(err, rolloutservice.ErrReplayMismatch):
		return status.Error(codes.DataLoss, "durable rollout state failed verification")
	case errors.Is(err, rolloutservice.ErrServicePoisoned),
		errors.Is(err, rolloutservice.ErrDurabilityUncertain), errors.Is(err, storage.ErrClosed),
		errors.Is(err, storage.ErrLocked):
		return status.Error(codes.Unavailable, "durable rollout service is unavailable")
	default:
		return status.Error(codes.Internal, "discovery stream operation failed")
	}
}
