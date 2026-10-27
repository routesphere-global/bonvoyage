package identity

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"time"
)

const (
	maxNodeDisplayNameBytes = 128
	maxNodeGroupBytes       = 128
	maxNodeLabels           = 32
	maxNodeLabelKeyBytes    = 64
	maxNodeLabelValueBytes  = 128
	maxNodeActorBytes       = 256
)

// CreateNodeEnrollment atomically records a stable identity and its latest
// one-time enrollment credential. Secret bytes are returned once and are not
// recoverable from durable state.
func (repository *FileRepository) CreateNodeEnrollment(
	ctx context.Context,
	input NodeEnrollmentInput,
) (NodeEnrollmentPlan, error) {
	if err := validateNodeEnrollmentInput(input, false, false); err != nil {
		return NodeEnrollmentPlan{}, err
	}
	requestDigest, err := nodeRequestDigest(NodeEventEnrollmentCreated, input)
	if err != nil {
		return NodeEnrollmentPlan{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return NodeEnrollmentPlan{}, err
	}
	if err := contextError(ctx); err != nil {
		return NodeEnrollmentPlan{}, err
	}
	if event, found := findNodeEventByID(repository.state.NodeEvents, input.RequestID); found {
		if event.Kind != NodeEventEnrollmentCreated || event.NodeID != input.NodeID ||
			event.RequestSHA256 != requestDigest {
			return NodeEnrollmentPlan{}, fmt.Errorf("node enrollment request ID was reused: %w", ErrConflict)
		}
		node, _, exists := findNode(repository.state.Nodes, input.NodeID)
		if !exists {
			return NodeEnrollmentPlan{}, fmt.Errorf("replayed node enrollment is missing: %w", ErrCorrupt)
		}
		return NodeEnrollmentPlan{Node: cloneNode(node), Replayed: true}, nil
	}
	if _, _, found := findNode(repository.state.Nodes, input.NodeID); found {
		return NodeEnrollmentPlan{}, fmt.Errorf("node %q already exists: %w", input.NodeID, ErrConflict)
	}
	if _, _, found := findCurrent(repository.state.CurrentCredentials, input.NodeID); found {
		return NodeEnrollmentPlan{}, fmt.Errorf("node %q already has a credential: %w", input.NodeID, ErrConflict)
	}
	if _, found := findNodeRevocation(repository.state.NodeRevocations, input.NodeID); found {
		return NodeEnrollmentPlan{}, fmt.Errorf("node %q is revoked: %w", input.NodeID, ErrRevoked)
	}
	if len(repository.state.Nodes) >= maxNodeRecords {
		return NodeEnrollmentPlan{}, fmt.Errorf("node record limit reached: %w", ErrConflict)
	}

	now := repository.now()
	next := cloneState(repository.state)
	token, err := repository.createEnrollmentTokenLocked(&next, EnrollmentTokenInput{
		NodeID: input.NodeID, Audience: input.Audience, TTL: input.TTL,
	}, now)
	if err != nil {
		return NodeEnrollmentPlan{}, err
	}
	node := NodeRecord{
		NodeID: input.NodeID, Metadata: cloneMetadata(input.Metadata),
		Lifecycle: NodeLifecycleEnrolling, Version: 1,
		CreatedAt: now, UpdatedAt: now,
	}
	next.Nodes = append(next.Nodes, node)
	if err := appendNodeEvent(&next, NodeLifecycleEvent{
		EventID: input.RequestID, NodeID: input.NodeID, Kind: NodeEventEnrollmentCreated,
		RequestSHA256: requestDigest,
		Actor:         input.Actor, Reason: input.Reason, NodeVersion: node.Version, CreatedAt: now,
	}); err != nil {
		return NodeEnrollmentPlan{}, err
	}
	if err := repository.commitLocked(next); err != nil {
		return NodeEnrollmentPlan{}, err
	}
	return NodeEnrollmentPlan{Node: cloneNode(node), Token: token}, nil
}

// ReissueNodeEnrollment invalidates every prior unconsumed token for an
// enrolling node before publishing one replacement token.
func (repository *FileRepository) ReissueNodeEnrollment(
	ctx context.Context,
	input NodeEnrollmentInput,
) (NodeEnrollmentPlan, error) {
	if err := validateNodeEnrollmentInput(input, true, false); err != nil {
		return NodeEnrollmentPlan{}, err
	}
	requestDigest, err := nodeRequestDigest(NodeEventEnrollmentReissued, input)
	if err != nil {
		return NodeEnrollmentPlan{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return NodeEnrollmentPlan{}, err
	}
	if err := contextError(ctx); err != nil {
		return NodeEnrollmentPlan{}, err
	}
	if event, found := findNodeEventByID(repository.state.NodeEvents, input.RequestID); found {
		if event.Kind != NodeEventEnrollmentReissued || event.NodeID != input.NodeID ||
			event.RequestSHA256 != requestDigest {
			return NodeEnrollmentPlan{}, fmt.Errorf("node enrollment request ID was reused: %w", ErrConflict)
		}
		node, _, exists := findNode(repository.state.Nodes, input.NodeID)
		if !exists {
			return NodeEnrollmentPlan{}, fmt.Errorf("replayed node enrollment is missing: %w", ErrCorrupt)
		}
		return NodeEnrollmentPlan{Node: cloneNode(node), Replayed: true}, nil
	}
	node, nodeIndex, found := findNode(repository.state.Nodes, input.NodeID)
	if !found {
		return NodeEnrollmentPlan{}, ErrNotFound
	}
	if node.Lifecycle != NodeLifecycleEnrolling || node.Version != input.ExpectedVersion {
		return NodeEnrollmentPlan{}, fmt.Errorf("node enrollment state changed: %w", ErrConflict)
	}
	now := repository.now()
	next := cloneState(repository.state)
	token, err := repository.createEnrollmentTokenLocked(&next, EnrollmentTokenInput{
		NodeID: input.NodeID, Audience: input.Audience, TTL: input.TTL,
	}, now)
	if err != nil {
		return NodeEnrollmentPlan{}, err
	}
	node.Version++
	node.UpdatedAt = now
	next.Nodes[nodeIndex] = node
	if err := appendNodeEvent(&next, NodeLifecycleEvent{
		EventID: input.RequestID, NodeID: input.NodeID, Kind: NodeEventEnrollmentReissued,
		RequestSHA256: requestDigest,
		Actor:         input.Actor, Reason: input.Reason, NodeVersion: node.Version, CreatedAt: now,
	}); err != nil {
		return NodeEnrollmentPlan{}, err
	}
	if err := repository.commitLocked(next); err != nil {
		return NodeEnrollmentPlan{}, err
	}
	return NodeEnrollmentPlan{Node: cloneNode(node), Token: token}, nil
}

// CreateNodeReplacement links a new stable identity to its predecessor while
// leaving the predecessor operational until an explicit drain and retirement.
func (repository *FileRepository) CreateNodeReplacement(
	ctx context.Context,
	input NodeEnrollmentInput,
) (NodeEnrollmentPlan, error) {
	if err := validateNodeEnrollmentInput(input, true, true); err != nil {
		return NodeEnrollmentPlan{}, err
	}
	requestDigest, err := nodeRequestDigest(NodeEventReplacementCreated, input)
	if err != nil {
		return NodeEnrollmentPlan{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return NodeEnrollmentPlan{}, err
	}
	if err := contextError(ctx); err != nil {
		return NodeEnrollmentPlan{}, err
	}
	if event, found := findNodeEventByID(repository.state.NodeEvents, input.RequestID); found {
		if event.Kind != NodeEventReplacementCreated || event.NodeID != input.NodeID ||
			event.RelatedNodeID != input.ReplacementFor || event.RequestSHA256 != requestDigest {
			return NodeEnrollmentPlan{}, fmt.Errorf("node replacement request ID was reused: %w", ErrConflict)
		}
		node, _, exists := findNode(repository.state.Nodes, input.NodeID)
		if !exists {
			return NodeEnrollmentPlan{}, fmt.Errorf("replayed replacement is missing: %w", ErrCorrupt)
		}
		return NodeEnrollmentPlan{Node: cloneNode(node), Replayed: true}, nil
	}
	predecessor, predecessorIndex, found := findNode(repository.state.Nodes, input.ReplacementFor)
	if !found {
		return NodeEnrollmentPlan{}, ErrNotFound
	}
	if predecessor.Version != input.ExpectedVersion || predecessor.Lifecycle == NodeLifecycleEnrolling ||
		predecessor.ReplacedBy != "" {
		return NodeEnrollmentPlan{}, fmt.Errorf("predecessor is not replaceable at the requested version: %w", ErrConflict)
	}
	if input.NodeID == input.ReplacementFor {
		return NodeEnrollmentPlan{}, fmt.Errorf("replacement identity must differ: %w", ErrInvalid)
	}
	if _, _, found := findNode(repository.state.Nodes, input.NodeID); found {
		return NodeEnrollmentPlan{}, fmt.Errorf("replacement node already exists: %w", ErrConflict)
	}
	if len(repository.state.Nodes) >= maxNodeRecords {
		return NodeEnrollmentPlan{}, fmt.Errorf("node record limit reached: %w", ErrConflict)
	}
	now := repository.now()
	next := cloneState(repository.state)
	token, err := repository.createEnrollmentTokenLocked(&next, EnrollmentTokenInput{
		NodeID: input.NodeID, Audience: input.Audience, TTL: input.TTL,
	}, now)
	if err != nil {
		return NodeEnrollmentPlan{}, err
	}
	predecessor.ReplacedBy = input.NodeID
	predecessor.Version++
	predecessor.UpdatedAt = now
	next.Nodes[predecessorIndex] = predecessor
	replacement := NodeRecord{
		NodeID: input.NodeID, Metadata: cloneMetadata(input.Metadata),
		Lifecycle: NodeLifecycleEnrolling, Version: 1, ReplacementFor: input.ReplacementFor,
		CreatedAt: now, UpdatedAt: now,
	}
	next.Nodes = append(next.Nodes, replacement)
	if err := appendNodeEvent(&next, NodeLifecycleEvent{
		EventID: input.RequestID, NodeID: input.NodeID, Kind: NodeEventReplacementCreated,
		RequestSHA256: requestDigest,
		Actor:         input.Actor, Reason: input.Reason, NodeVersion: replacement.Version,
		RelatedNodeID: input.ReplacementFor, CreatedAt: now,
	}); err != nil {
		return NodeEnrollmentPlan{}, err
	}
	if err := repository.commitLocked(next); err != nil {
		return NodeEnrollmentPlan{}, err
	}
	return NodeEnrollmentPlan{Node: cloneNode(replacement), Token: token}, nil
}

func (repository *FileRepository) UpdateNodeMetadata(
	ctx context.Context,
	input NodeMetadataUpdateInput,
) (NodeMutationPlan, error) {
	if err := validateNodeMutation(input.RequestID, input.Actor, input.Reason, input.NodeID, input.ExpectedVersion); err != nil {
		return NodeMutationPlan{}, err
	}
	if err := validateNodeMetadata(input.Metadata); err != nil {
		return NodeMutationPlan{}, err
	}
	requestDigest, err := nodeRequestDigest(NodeEventMetadataUpdated, input)
	if err != nil {
		return NodeMutationPlan{}, err
	}
	return repository.mutateNode(ctx, input.RequestID, requestDigest, input.NodeID, NodeEventMetadataUpdated,
		input.Actor, input.Reason, input.ExpectedVersion, func(node *NodeRecord, _ time.Time) error {
			if node.Lifecycle == NodeLifecycleRetired || node.Lifecycle == NodeLifecycleRevoked {
				return fmt.Errorf("terminal node metadata is immutable: %w", ErrConflict)
			}
			node.Metadata = cloneMetadata(input.Metadata)
			return nil
		})
}

func (repository *FileRepository) RequestNodeDrain(
	ctx context.Context,
	input NodeTransitionInput,
) (NodeMutationPlan, error) {
	if err := validateNodeMutation(input.RequestID, input.Actor, input.Reason, input.NodeID, input.ExpectedVersion); err != nil {
		return NodeMutationPlan{}, err
	}
	requestDigest, err := nodeRequestDigest(NodeEventDrainRequested, input)
	if err != nil {
		return NodeMutationPlan{}, err
	}
	return repository.mutateNode(ctx, input.RequestID, requestDigest, input.NodeID, NodeEventDrainRequested,
		input.Actor, input.Reason, input.ExpectedVersion, func(node *NodeRecord, now time.Time) error {
			if node.Lifecycle != NodeLifecycleEnrolling && node.Lifecycle != NodeLifecycleReady {
				return fmt.Errorf("node cannot enter drain from %s: %w", node.Lifecycle, ErrConflict)
			}
			node.Lifecycle = NodeLifecycleDraining
			node.DrainRequestedAt = timePointer(now)
			return nil
		})
}

func (repository *FileRepository) RetireNode(
	ctx context.Context,
	input NodeTransitionInput,
) (NodeMutationPlan, error) {
	if err := validateNodeMutation(input.RequestID, input.Actor, input.Reason, input.NodeID, input.ExpectedVersion); err != nil {
		return NodeMutationPlan{}, err
	}
	requestDigest, err := nodeRequestDigest(NodeEventRetired, input)
	if err != nil {
		return NodeMutationPlan{}, err
	}
	return repository.mutateNode(ctx, input.RequestID, requestDigest, input.NodeID, NodeEventRetired,
		input.Actor, input.Reason, input.ExpectedVersion, func(node *NodeRecord, now time.Time) error {
			if node.Lifecycle != NodeLifecycleDraining {
				return fmt.Errorf("node must be draining before retirement: %w", ErrConflict)
			}
			node.Lifecycle = NodeLifecycleRetired
			node.RetiredAt = timePointer(now)
			return nil
		})
}

func (repository *FileRepository) RevokeManagedNode(
	ctx context.Context,
	input ManagedNodeRevocationInput,
) (ManagedNodeRevocationPlan, error) {
	if err := validateNodeMutation(input.RequestID, input.Actor, input.Reason, input.NodeID, input.ExpectedVersion); err != nil {
		return ManagedNodeRevocationPlan{}, err
	}
	requestDigest, err := nodeRequestDigest(NodeEventRevoked, input)
	if err != nil {
		return ManagedNodeRevocationPlan{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return ManagedNodeRevocationPlan{}, err
	}
	if err := contextError(ctx); err != nil {
		return ManagedNodeRevocationPlan{}, err
	}
	if event, found := findNodeEventByID(repository.state.NodeEvents, input.RequestID); found {
		if event.Kind != NodeEventRevoked || event.NodeID != input.NodeID ||
			event.RequestSHA256 != requestDigest {
			return ManagedNodeRevocationPlan{}, fmt.Errorf("node revocation request ID was reused: %w", ErrConflict)
		}
		node, _, exists := findNode(repository.state.Nodes, input.NodeID)
		revocation, revoked := findNodeRevocation(repository.state.NodeRevocations, input.NodeID)
		if !exists || !revoked {
			return ManagedNodeRevocationPlan{}, fmt.Errorf("replayed node revocation is incomplete: %w", ErrCorrupt)
		}
		return ManagedNodeRevocationPlan{
			Revocation: revocation, Node: cloneNode(node), Replayed: true,
		}, nil
	}
	node, nodeIndex, found := findNode(repository.state.Nodes, input.NodeID)
	if !found {
		return ManagedNodeRevocationPlan{}, ErrNotFound
	}
	if node.Version != input.ExpectedVersion {
		return ManagedNodeRevocationPlan{}, fmt.Errorf("node version changed: %w", ErrConflict)
	}
	if _, _, enrolled := findCurrent(repository.state.CurrentCredentials, input.NodeID); !enrolled {
		return ManagedNodeRevocationPlan{}, fmt.Errorf("an unenrolled node has no credential to revoke: %w", ErrConflict)
	}
	if _, revoked := findNodeRevocation(repository.state.NodeRevocations, input.NodeID); revoked {
		return ManagedNodeRevocationPlan{}, fmt.Errorf("node is already revoked: %w", ErrConflict)
	}
	if len(repository.state.NodeRevocations) >= maxRevocationRecords {
		return ManagedNodeRevocationPlan{}, fmt.Errorf("node revocation limit reached: %w", ErrConflict)
	}
	now := repository.now()
	revocation := NodeRevocation{NodeID: input.NodeID, Reason: input.Reason, RevokedAt: now}
	next := cloneState(repository.state)
	next.NodeRevocations = append(next.NodeRevocations, revocation)
	node.Lifecycle = NodeLifecycleRevoked
	node.Version++
	node.UpdatedAt = now
	node.RevokedAt = timePointer(now)
	next.Nodes[nodeIndex] = node
	if err := appendNodeEvent(&next, NodeLifecycleEvent{
		EventID: input.RequestID, NodeID: input.NodeID, Kind: NodeEventRevoked,
		RequestSHA256: requestDigest,
		Actor:         input.Actor, Reason: input.Reason, NodeVersion: node.Version, CreatedAt: now,
	}); err != nil {
		return ManagedNodeRevocationPlan{}, err
	}
	if err := repository.commitLocked(next); err != nil {
		return ManagedNodeRevocationPlan{}, err
	}
	return ManagedNodeRevocationPlan{Revocation: revocation, Node: cloneNode(node)}, nil
}

func (repository *FileRepository) GetNode(ctx context.Context, nodeID string) (NodeIdentitySummary, error) {
	if err := contextError(ctx); err != nil {
		return NodeIdentitySummary{}, err
	}
	if err := validateIdentifier("node ID", nodeID); err != nil {
		return NodeIdentitySummary{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return NodeIdentitySummary{}, err
	}
	return nodeSummary(repository.state, nodeID)
}

func (repository *FileRepository) ListNodes(ctx context.Context) ([]NodeIdentitySummary, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return nil, err
	}
	result := make([]NodeIdentitySummary, 0, len(repository.state.Nodes))
	for _, node := range repository.state.Nodes {
		summary, err := nodeSummary(repository.state, node.NodeID)
		if err != nil {
			return nil, err
		}
		result = append(result, summary)
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].Node.NodeID < result[right].Node.NodeID
	})
	return result, nil
}

func (repository *FileRepository) ListNodeEvents(
	ctx context.Context,
	nodeID string,
) ([]NodeLifecycleEvent, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := validateIdentifier("node ID", nodeID); err != nil {
		return nil, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return nil, err
	}
	if _, _, found := findNode(repository.state.Nodes, nodeID); !found {
		return nil, ErrNotFound
	}
	result := make([]NodeLifecycleEvent, 0)
	for _, event := range repository.state.NodeEvents {
		if event.NodeID == nodeID || event.RelatedNodeID == nodeID {
			result = append(result, event)
		}
	}
	return result, nil
}

func (repository *FileRepository) mutateNode(
	ctx context.Context,
	requestID string,
	requestDigest string,
	nodeID string,
	kind NodeEventKind,
	actor string,
	reason string,
	expectedVersion uint64,
	mutation func(*NodeRecord, time.Time) error,
) (NodeMutationPlan, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return NodeMutationPlan{}, err
	}
	if err := contextError(ctx); err != nil {
		return NodeMutationPlan{}, err
	}
	if event, found := findNodeEventByID(repository.state.NodeEvents, requestID); found {
		if event.Kind != kind || event.NodeID != nodeID || event.RequestSHA256 != requestDigest {
			return NodeMutationPlan{}, fmt.Errorf("node mutation request ID was reused: %w", ErrConflict)
		}
		node, _, exists := findNode(repository.state.Nodes, nodeID)
		if !exists {
			return NodeMutationPlan{}, fmt.Errorf("replayed node mutation is missing: %w", ErrCorrupt)
		}
		return NodeMutationPlan{Node: cloneNode(node), Replayed: true}, nil
	}
	node, nodeIndex, found := findNode(repository.state.Nodes, nodeID)
	if !found {
		return NodeMutationPlan{}, ErrNotFound
	}
	if node.Version != expectedVersion {
		return NodeMutationPlan{}, fmt.Errorf("node version changed: %w", ErrConflict)
	}
	now := repository.now()
	if err := mutation(&node, now); err != nil {
		return NodeMutationPlan{}, err
	}
	node.Version++
	node.UpdatedAt = now
	next := cloneState(repository.state)
	next.Nodes[nodeIndex] = node
	if kind == NodeEventDrainRequested || kind == NodeEventRetired {
		next.EnrollmentTokens = removeNodeEnrollmentTokens(next.EnrollmentTokens, nodeID)
	}
	if err := appendNodeEvent(&next, NodeLifecycleEvent{
		EventID: requestID, NodeID: nodeID, Kind: kind, Actor: actor, Reason: reason,
		RequestSHA256: requestDigest, NodeVersion: node.Version, CreatedAt: now,
	}); err != nil {
		return NodeMutationPlan{}, err
	}
	if err := repository.commitLocked(next); err != nil {
		return NodeMutationPlan{}, err
	}
	return NodeMutationPlan{Node: cloneNode(node)}, nil
}

func removeNodeEnrollmentTokens(tokens []enrollmentMetadata, nodeID string) []enrollmentMetadata {
	kept := make([]enrollmentMetadata, 0, len(tokens))
	for _, token := range tokens {
		if token.NodeID != nodeID {
			kept = append(kept, token)
		}
	}
	return kept
}

func (repository *FileRepository) createEnrollmentTokenLocked(
	state *persistedState,
	input EnrollmentTokenInput,
	now time.Time,
) (EnrollmentToken, error) {
	ttl := input.TTL
	if ttl == 0 {
		ttl = DefaultEnrollmentTTL
		if ttl > repository.maxEnrollmentTTL {
			ttl = repository.maxEnrollmentTTL
		}
	}
	if ttl <= 0 || ttl > repository.maxEnrollmentTTL {
		return EnrollmentToken{}, fmt.Errorf("enrollment TTL is outside configured bounds: %w", ErrInvalid)
	}
	active := pruneEnrollmentTokens(state.EnrollmentTokens, now)
	kept := active[:0]
	for _, token := range active {
		if token.NodeID != input.NodeID {
			kept = append(kept, token)
		}
	}
	state.EnrollmentTokens = kept
	if len(state.EnrollmentTokens) >= maxActiveTokens {
		return EnrollmentToken{}, fmt.Errorf("active enrollment token limit reached: %w", ErrConflict)
	}
	var id string
	for attempts := 0; attempts < 8; attempts++ {
		candidate, err := randomIdentifier(repository.random, "", 16)
		if err != nil {
			return EnrollmentToken{}, err
		}
		if _, found := findEnrollment(state.EnrollmentTokens, candidate); !found {
			id = candidate
			break
		}
	}
	if id == "" {
		return EnrollmentToken{}, fmt.Errorf("could not allocate unique enrollment token ID: %w", ErrConflict)
	}
	secret := make([]byte, 32)
	if _, err := io.ReadFull(repository.random, secret); err != nil {
		return EnrollmentToken{}, fmt.Errorf("generate enrollment token secret: %w", err)
	}
	defer clear(secret)
	digest := sha256Digest(secret)
	expiresAt := now.Add(ttl)
	state.EnrollmentTokens = append(state.EnrollmentTokens, enrollmentMetadata{
		ID: id, SecretSHA256: digest, NodeID: input.NodeID, Audience: input.Audience,
		CreatedAt: now, ExpiresAt: expiresAt,
	})
	return EnrollmentToken{
		ID: id, Value: enrollmentTokenValue(id, secret), NodeID: input.NodeID,
		Audience: input.Audience, CreatedAt: now, ExpiresAt: expiresAt,
	}, nil
}

func nodeSummary(state persistedState, nodeID string) (NodeIdentitySummary, error) {
	node, _, found := findNode(state.Nodes, nodeID)
	if !found {
		return NodeIdentitySummary{}, ErrNotFound
	}
	result := NodeIdentitySummary{Node: cloneNode(node)}
	current, _, enrolled := findCurrent(state.CurrentCredentials, nodeID)
	if enrolled {
		record, _, found := findCredential(state.Credentials, nodeID, current.GenerationID)
		if !found {
			return NodeIdentitySummary{}, fmt.Errorf("node current credential is missing: %w", ErrCorrupt)
		}
		result.Enrolled = true
		result.CredentialGeneration = record.Bundle.GenerationID
		result.CertificateNotAfter = record.Bundle.NotAfter
		result.RenewAfter = record.Bundle.RenewAfter
	}
	_, result.Revoked = findNodeRevocation(state.NodeRevocations, nodeID)
	return result, nil
}

func appendNodeEvent(state *persistedState, event NodeLifecycleEvent) error {
	if len(state.NodeEvents) >= maxNodeEvents {
		return fmt.Errorf("node lifecycle event limit reached: %w", ErrConflict)
	}
	event.Index = uint64(len(state.NodeEvents)) + 1
	state.NodeEvents = append(state.NodeEvents, event)
	return nil
}

func nodeRequestDigest(kind NodeEventKind, input any) (string, error) {
	canonical, err := json.Marshal(struct {
		Kind  NodeEventKind `json:"kind"`
		Input any           `json:"input"`
	}{Kind: kind, Input: input})
	if err != nil {
		return "", fmt.Errorf("encode node mutation identity: %w", err)
	}
	return sha256Digest(canonical), nil
}

func findNode(nodes []NodeRecord, nodeID string) (NodeRecord, int, bool) {
	for index, node := range nodes {
		if node.NodeID == nodeID {
			return node, index, true
		}
	}
	return NodeRecord{}, -1, false
}

func findNodeEventByID(events []NodeLifecycleEvent, eventID string) (NodeLifecycleEvent, bool) {
	for _, event := range events {
		if event.EventID == eventID {
			return event, true
		}
	}
	return NodeLifecycleEvent{}, false
}

func cloneMetadata(metadata NodeMetadata) NodeMetadata {
	metadata.Labels = cloneLabels(metadata.Labels)
	return metadata
}

func cloneNode(node NodeRecord) NodeRecord {
	node.Metadata = cloneMetadata(node.Metadata)
	return node
}

func cloneLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	result := make(map[string]string, len(labels))
	for key, value := range labels {
		result[key] = value
	}
	return result
}

func validateNodeEnrollmentInput(input NodeEnrollmentInput, expectedVersion, replacement bool) error {
	if err := validateNodeMutation(input.RequestID, input.Actor, input.Reason, input.NodeID, 1); err != nil {
		return err
	}
	if expectedVersion && input.ExpectedVersion == 0 {
		return fmt.Errorf("expected node version is required: %w", ErrInvalid)
	}
	if !expectedVersion && input.ExpectedVersion != 0 {
		return fmt.Errorf("new node enrollment must not carry a version: %w", ErrInvalid)
	}
	if err := validateNodeMetadata(input.Metadata); err != nil {
		return err
	}
	if err := validateText("audience", input.Audience, maxAudienceBytes, true); err != nil {
		return err
	}
	if replacement {
		if err := validateIdentifier("replacement predecessor", input.ReplacementFor); err != nil {
			return err
		}
	} else if input.ReplacementFor != "" {
		return fmt.Errorf("replacement predecessor is not valid for this operation: %w", ErrInvalid)
	}
	return nil
}

func validateNodeMutation(requestID, actor, reason, nodeID string, expectedVersion uint64) error {
	if err := validateIdentifier("request ID", requestID); err != nil {
		return err
	}
	if err := validateIdentifier("node ID", nodeID); err != nil {
		return err
	}
	if err := validateText("actor", actor, maxNodeActorBytes, true); err != nil {
		return err
	}
	if err := validateText("reason", reason, maxReasonBytes, true); err != nil {
		return err
	}
	if expectedVersion == 0 {
		return fmt.Errorf("expected node version is required: %w", ErrInvalid)
	}
	return nil
}

func validateNodeMetadata(metadata NodeMetadata) error {
	if err := validateText("node display name", metadata.DisplayName, maxNodeDisplayNameBytes, true); err != nil {
		return err
	}
	if err := validateIdentifier("node group", metadata.Group); err != nil || len(metadata.Group) > maxNodeGroupBytes {
		return fmt.Errorf("node group is invalid: %w", ErrInvalid)
	}
	if len(metadata.Labels) > maxNodeLabels {
		return fmt.Errorf("node labels exceed %d entries: %w", maxNodeLabels, ErrInvalid)
	}
	for key, value := range metadata.Labels {
		if err := validateIdentifier("node label key", key); err != nil || len(key) > maxNodeLabelKeyBytes {
			return fmt.Errorf("node label key is invalid: %w", ErrInvalid)
		}
		if err := validateText("node label value", value, maxNodeLabelValueBytes, false); err != nil {
			return err
		}
	}
	return nil
}

func migrateLegacyState(state persistedState) (persistedState, error) {
	if state.SchemaVersion != legacySchemaVersion || state.Generation == 0 || state.Generation == math.MaxUint64 {
		return persistedState{}, fmt.Errorf("unsupported legacy identity state: %w", ErrCorrupt)
	}
	next := cloneState(state)
	next.SchemaVersion = repositorySchemaVersion
	next.Generation++
	type candidate struct {
		created time.Time
		updated time.Time
		state   NodeLifecycleState
		revoked *time.Time
	}
	candidates := make(map[string]candidate)
	for _, token := range state.EnrollmentTokens {
		value := candidates[token.NodeID]
		if value.created.IsZero() || token.CreatedAt.Before(value.created) {
			value.created = token.CreatedAt
		}
		if token.CreatedAt.After(value.updated) {
			value.updated = token.CreatedAt
		}
		if value.state == "" {
			value.state = NodeLifecycleEnrolling
		}
		candidates[token.NodeID] = value
	}
	for _, current := range state.CurrentCredentials {
		record, _, found := findCredential(state.Credentials, current.NodeID, current.GenerationID)
		if !found {
			return persistedState{}, fmt.Errorf("legacy current credential is missing: %w", ErrCorrupt)
		}
		value := candidates[current.NodeID]
		if value.created.IsZero() || record.IssuedAt.Before(value.created) {
			value.created = record.IssuedAt
		}
		if record.IssuedAt.After(value.updated) {
			value.updated = record.IssuedAt
		}
		value.state = NodeLifecycleReady
		candidates[current.NodeID] = value
	}
	for _, revocation := range state.NodeRevocations {
		value := candidates[revocation.NodeID]
		if value.created.IsZero() {
			value.created = revocation.RevokedAt
		}
		if revocation.RevokedAt.After(value.updated) {
			value.updated = revocation.RevokedAt
		}
		value.state = NodeLifecycleRevoked
		value.revoked = timePointer(revocation.RevokedAt)
		candidates[revocation.NodeID] = value
	}
	ids := make([]string, 0, len(candidates))
	for nodeID := range candidates {
		ids = append(ids, nodeID)
	}
	sort.Strings(ids)
	for _, nodeID := range ids {
		value := candidates[nodeID]
		if value.created.IsZero() || value.updated.IsZero() || value.state == "" {
			return persistedState{}, fmt.Errorf("legacy node state is incomplete: %w", ErrCorrupt)
		}
		node := NodeRecord{
			NodeID: nodeID, Metadata: NodeMetadata{DisplayName: nodeID, Group: "default"},
			Lifecycle: value.state, Version: 1, CreatedAt: value.created, UpdatedAt: value.updated,
			RevokedAt: value.revoked,
		}
		next.Nodes = append(next.Nodes, node)
		if err := appendNodeEvent(&next, NodeLifecycleEvent{
			EventID: fmt.Sprintf("migration:%d", len(next.NodeEvents)+1), NodeID: nodeID,
			Kind: NodeEventImported, Actor: "repository-migration",
			Reason: "identity state migrated from schema v1", NodeVersion: 1, CreatedAt: value.updated,
		}); err != nil {
			return persistedState{}, err
		}
	}
	if err := validateState(next); err != nil {
		return persistedState{}, err
	}
	return next, nil
}

func timePointer(value time.Time) *time.Time {
	copy := value
	return &copy
}

func canonicalNodeEventKind(kind NodeEventKind) bool {
	switch kind {
	case NodeEventEnrollmentCreated, NodeEventEnrollmentReissued, NodeEventEnrolled,
		NodeEventImported, NodeEventMetadataUpdated, NodeEventDrainRequested,
		NodeEventRetired, NodeEventRevoked, NodeEventReplacementCreated:
		return true
	default:
		return false
	}
}

func validNodeLifecycle(value NodeLifecycleState) bool {
	switch value {
	case NodeLifecycleEnrolling, NodeLifecycleReady, NodeLifecycleDraining,
		NodeLifecycleRetired, NodeLifecycleRevoked:
		return true
	default:
		return false
	}
}

func enrollmentTokenValue(id string, secret []byte) string {
	return "bv1." + id + "." + base64RawURL(secret)
}

func sha256Digest(value []byte) string {
	return hexSHA256(value)
}

// Small wrappers keep token encoding details centralized with repository
// validation without exporting secret helpers.
func base64RawURL(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func hexSHA256(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
