package adminservice

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/discovery"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/identity"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/rollout"
)

const (
	DefaultNodeEnrollmentSeconds = 600
	MaximumNodeEnrollmentSeconds = 3600
	DefaultNodeEventPageSize     = 100
	MaxNodeEventPageSize         = 250
	DefaultRevocationValidity    = 7 * 24 * time.Hour
)

// NodeLifecycleOptions binds the standalone node API to the already accepted
// enrollment and revocation authorities. No private key path is exposed.
type NodeLifecycleOptions struct {
	Audience           string
	EnrollmentAddress  string
	ServerName         string
	TrustDomain        string
	NodePathPrefix     string
	RevocationPath     string
	RevocationValidFor time.Duration
	Clock              func() time.Time
}

type NodeMetadataInput struct {
	DisplayName string            `json:"display_name"`
	Group       string            `json:"group"`
	Labels      map[string]string `json:"labels,omitempty"`
}

type CreateNodeInput struct {
	RequestID  string
	Reason     string
	NodeID     string
	Metadata   NodeMetadataInput
	TTLSeconds uint32
}

type ReissueNodeInput struct {
	RequestID       string
	Reason          string
	NodeID          string
	ExpectedVersion uint64
	TTLSeconds      uint32
}

type ReplaceNodeInput struct {
	RequestID         string
	Reason            string
	PredecessorNodeID string
	ExpectedVersion   uint64
	ReplacementNodeID string
	Metadata          NodeMetadataInput
	TTLSeconds        uint32
}

type UpdateNodeInput struct {
	RequestID       string
	Reason          string
	NodeID          string
	ExpectedVersion uint64
	Metadata        NodeMetadataInput
}

type TransitionNodeInput struct {
	RequestID       string
	Reason          string
	NodeID          string
	ExpectedVersion uint64
}

type NodeRuntimeView struct {
	Connected          bool              `json:"connected"`
	ProcessInstance    string            `json:"process_instance,omitempty"`
	LastSeen           *time.Time        `json:"last_seen,omitempty"`
	CredentialNotAfter *time.Time        `json:"credential_not_after,omitempty"`
	Reconciled         bool              `json:"reconciled"`
	RolloutPhase       rollout.NodePhase `json:"rollout_phase,omitempty"`
	ActiveSnapshotID   string            `json:"active_snapshot_id,omitempty"`
	PreparedSequence   uint64            `json:"prepared_sequence,omitempty"`
	PendingCommands    int               `json:"pending_commands"`
}

type NodeView struct {
	NodeID               string                      `json:"node_id"`
	Metadata             NodeMetadataInput           `json:"metadata"`
	Lifecycle            identity.NodeLifecycleState `json:"lifecycle"`
	Version              uint64                      `json:"version"`
	ReplacementFor       string                      `json:"replacement_for,omitempty"`
	ReplacedBy           string                      `json:"replaced_by,omitempty"`
	CreatedAt            time.Time                   `json:"created_at"`
	UpdatedAt            time.Time                   `json:"updated_at"`
	DrainRequestedAt     *time.Time                  `json:"drain_requested_at,omitempty"`
	RetiredAt            *time.Time                  `json:"retired_at,omitempty"`
	RevokedAt            *time.Time                  `json:"revoked_at,omitempty"`
	Enrolled             bool                        `json:"enrolled"`
	CredentialGeneration string                      `json:"credential_generation,omitempty"`
	CertificateNotAfter  *time.Time                  `json:"certificate_not_after,omitempty"`
	RenewAfter           *time.Time                  `json:"renew_after,omitempty"`
	Runtime              NodeRuntimeView             `json:"runtime"`
	EligibleForRollout   bool                        `json:"eligible_for_rollout"`
}

type NodeListResult struct {
	APIVersion string     `json:"api_version"`
	Nodes      []NodeView `json:"nodes"`
}

type NodeMutationResult struct {
	APIVersion string   `json:"api_version"`
	Replayed   bool     `json:"replayed"`
	Node       NodeView `json:"node"`
}

type NodeEnrollmentBootstrap struct {
	Token             string    `json:"token"`
	ExpiresAt         time.Time `json:"expires_at"`
	EnrollmentAddress string    `json:"enrollment_address"`
	ServerName        string    `json:"server_name"`
	Audience          string    `json:"audience"`
	TrustDomain       string    `json:"trust_domain"`
	NodePathPrefix    string    `json:"node_path_prefix"`
}

type NodeEnrollmentResult struct {
	APIVersion string                   `json:"api_version"`
	Replayed   bool                     `json:"replayed"`
	Node       NodeView                 `json:"node"`
	Enrollment *NodeEnrollmentBootstrap `json:"enrollment,omitempty"`
}

type NodeEventView struct {
	Index         uint64                 `json:"index"`
	EventID       string                 `json:"event_id"`
	RequestSHA256 string                 `json:"request_sha256,omitempty"`
	NodeID        string                 `json:"node_id"`
	Kind          identity.NodeEventKind `json:"kind"`
	Actor         string                 `json:"actor"`
	Reason        string                 `json:"reason"`
	NodeVersion   uint64                 `json:"node_version"`
	RelatedNodeID string                 `json:"related_node_id,omitempty"`
	CreatedAt     time.Time              `json:"created_at"`
}

type NodeEventsResult struct {
	APIVersion     string          `json:"api_version"`
	NodeID         string          `json:"node_id"`
	AfterIndex     uint64          `json:"after_index"`
	NextAfterIndex uint64          `json:"next_after_index"`
	Limit          int             `json:"limit"`
	TotalEvents    int             `json:"total_events"`
	HasMore        bool            `json:"has_more"`
	Events         []NodeEventView `json:"events"`
}

func (service *Service) ListNodes(ctx context.Context, principal Principal) (NodeListResult, error) {
	if err := requirePermission(principal, permissionNodeRead); err != nil {
		return NodeListResult{}, err
	}
	if err := service.requireNodeLifecycle(); err != nil {
		return NodeListResult{}, err
	}
	summaries, err := service.identity.ListNodes(ctx)
	if err != nil {
		return NodeListResult{}, err
	}
	return NodeListResult{APIVersion: APIVersion, Nodes: service.projectNodes(summaries)}, nil
}

func (service *Service) GetNode(ctx context.Context, principal Principal, nodeID string) (NodeView, error) {
	if err := requirePermission(principal, permissionNodeRead); err != nil {
		return NodeView{}, err
	}
	if err := service.requireNodeLifecycle(); err != nil {
		return NodeView{}, err
	}
	summary, err := service.identity.GetNode(ctx, nodeID)
	if err != nil {
		return NodeView{}, err
	}
	return service.projectNodes([]identity.NodeIdentitySummary{summary})[0], nil
}

func (service *Service) ListNodeEvents(
	ctx context.Context,
	principal Principal,
	nodeID string,
	afterIndex uint64,
	limit int,
) (NodeEventsResult, error) {
	if err := requirePermission(principal, permissionNodeRead); err != nil {
		return NodeEventsResult{}, err
	}
	if err := service.requireNodeLifecycle(); err != nil {
		return NodeEventsResult{}, err
	}
	if limit < 1 || limit > MaxNodeEventPageSize {
		return NodeEventsResult{}, fmt.Errorf("node event page limit must be 1-%d: %w", MaxNodeEventPageSize, ErrInvalidInput)
	}
	events, err := service.identity.ListNodeEvents(ctx, nodeID)
	if err != nil {
		return NodeEventsResult{}, err
	}
	result := NodeEventsResult{
		APIVersion: APIVersion, NodeID: nodeID, AfterIndex: afterIndex,
		NextAfterIndex: afterIndex, Limit: limit, TotalEvents: len(events),
		Events: make([]NodeEventView, 0, min(limit, len(events))),
	}
	for _, event := range events {
		if event.Index <= afterIndex {
			continue
		}
		if len(result.Events) == limit {
			result.HasMore = true
			break
		}
		result.Events = append(result.Events, NodeEventView{
			Index: event.Index, EventID: event.EventID, NodeID: event.NodeID, Kind: event.Kind,
			RequestSHA256: event.RequestSHA256,
			Actor:         event.Actor, Reason: event.Reason, NodeVersion: event.NodeVersion,
			RelatedNodeID: event.RelatedNodeID, CreatedAt: event.CreatedAt,
		})
		result.NextAfterIndex = event.Index
	}
	return result, nil
}

func (service *Service) CreateNode(
	ctx context.Context,
	principal Principal,
	input CreateNodeInput,
) (NodeEnrollmentResult, error) {
	if err := requirePermission(principal, permissionNodeAdmin); err != nil {
		return NodeEnrollmentResult{}, err
	}
	if err := service.requireNodeLifecycle(); err != nil {
		return NodeEnrollmentResult{}, err
	}
	service.nodeMu.Lock()
	defer service.nodeMu.Unlock()
	plan, err := service.identity.CreateNodeEnrollment(ctx, identity.NodeEnrollmentInput{
		RequestID: input.RequestID, Actor: principal.Actor, Reason: input.Reason,
		NodeID: input.NodeID, Metadata: identityMetadata(input.Metadata), Audience: service.nodePolicy.Audience,
		TTL: enrollmentTTL(input.TTLSeconds),
	})
	if err != nil {
		return NodeEnrollmentResult{}, err
	}
	return service.enrollmentResult(ctx, plan)
}

func (service *Service) ReissueNode(
	ctx context.Context,
	principal Principal,
	input ReissueNodeInput,
) (NodeEnrollmentResult, error) {
	if err := requirePermission(principal, permissionNodeAdmin); err != nil {
		return NodeEnrollmentResult{}, err
	}
	if err := service.requireNodeLifecycle(); err != nil {
		return NodeEnrollmentResult{}, err
	}
	service.nodeMu.Lock()
	defer service.nodeMu.Unlock()
	current, err := service.identity.GetNode(ctx, input.NodeID)
	if err != nil {
		return NodeEnrollmentResult{}, err
	}
	plan, err := service.identity.ReissueNodeEnrollment(ctx, identity.NodeEnrollmentInput{
		RequestID: input.RequestID, Actor: principal.Actor, Reason: input.Reason,
		NodeID: input.NodeID, ExpectedVersion: input.ExpectedVersion,
		Metadata: current.Node.Metadata, Audience: service.nodePolicy.Audience,
		TTL: enrollmentTTL(input.TTLSeconds),
	})
	if err != nil {
		return NodeEnrollmentResult{}, err
	}
	return service.enrollmentResult(ctx, plan)
}

func (service *Service) ReplaceNode(
	ctx context.Context,
	principal Principal,
	input ReplaceNodeInput,
) (NodeEnrollmentResult, error) {
	if err := requirePermission(principal, permissionNodeAdmin); err != nil {
		return NodeEnrollmentResult{}, err
	}
	if err := service.requireNodeLifecycle(); err != nil {
		return NodeEnrollmentResult{}, err
	}
	service.nodeMu.Lock()
	defer service.nodeMu.Unlock()
	plan, err := service.identity.CreateNodeReplacement(ctx, identity.NodeEnrollmentInput{
		RequestID: input.RequestID, Actor: principal.Actor, Reason: input.Reason,
		NodeID: input.ReplacementNodeID, ExpectedVersion: input.ExpectedVersion,
		Metadata: identityMetadata(input.Metadata), Audience: service.nodePolicy.Audience,
		TTL: enrollmentTTL(input.TTLSeconds), ReplacementFor: input.PredecessorNodeID,
	})
	if err != nil {
		return NodeEnrollmentResult{}, err
	}
	return service.enrollmentResult(ctx, plan)
}

func (service *Service) UpdateNode(
	ctx context.Context,
	principal Principal,
	input UpdateNodeInput,
) (NodeMutationResult, error) {
	if err := requirePermission(principal, permissionNodeOperate); err != nil {
		return NodeMutationResult{}, err
	}
	if err := service.requireNodeLifecycle(); err != nil {
		return NodeMutationResult{}, err
	}
	service.nodeMu.Lock()
	defer service.nodeMu.Unlock()
	plan, err := service.identity.UpdateNodeMetadata(ctx, identity.NodeMetadataUpdateInput{
		RequestID: input.RequestID, Actor: principal.Actor, Reason: input.Reason,
		NodeID: input.NodeID, ExpectedVersion: input.ExpectedVersion,
		Metadata: identityMetadata(input.Metadata),
	})
	if err != nil {
		return NodeMutationResult{}, err
	}
	return service.nodeMutationResult(ctx, plan.Node.NodeID, plan.Replayed)
}

func (service *Service) DrainNode(
	ctx context.Context,
	principal Principal,
	input TransitionNodeInput,
) (NodeMutationResult, error) {
	if err := requirePermission(principal, permissionNodeOperate); err != nil {
		return NodeMutationResult{}, err
	}
	if err := service.requireNodeLifecycle(); err != nil {
		return NodeMutationResult{}, err
	}
	service.nodeMu.Lock()
	defer service.nodeMu.Unlock()
	plan, err := service.identity.RequestNodeDrain(ctx, identity.NodeTransitionInput{
		RequestID: input.RequestID, Actor: principal.Actor, Reason: input.Reason,
		NodeID: input.NodeID, ExpectedVersion: input.ExpectedVersion,
	})
	if err != nil {
		return NodeMutationResult{}, err
	}
	return service.nodeMutationResult(ctx, plan.Node.NodeID, plan.Replayed)
}

func (service *Service) RetireNode(
	ctx context.Context,
	principal Principal,
	input TransitionNodeInput,
) (NodeMutationResult, error) {
	if err := requirePermission(principal, permissionNodeAdmin); err != nil {
		return NodeMutationResult{}, err
	}
	if err := service.requireNodeLifecycle(); err != nil {
		return NodeMutationResult{}, err
	}
	service.nodeMu.Lock()
	defer service.nodeMu.Unlock()
	for _, connection := range service.runtime.Connections() {
		if connection.NodeID == input.NodeID {
			return NodeMutationResult{}, fmt.Errorf("node remains connected; stop and verify it before retirement: %w", ErrPrecondition)
		}
	}
	selection, err := service.runtime.CurrentRollout()
	if err != nil {
		return NodeMutationResult{}, err
	}
	if _, targeted := selection.Nodes[input.NodeID]; targeted {
		return NodeMutationResult{}, fmt.Errorf("node remains in the selected rollout target set: %w", ErrPrecondition)
	}
	plan, err := service.identity.RetireNode(ctx, identity.NodeTransitionInput{
		RequestID: input.RequestID, Actor: principal.Actor, Reason: input.Reason,
		NodeID: input.NodeID, ExpectedVersion: input.ExpectedVersion,
	})
	if err != nil {
		return NodeMutationResult{}, err
	}
	return service.nodeMutationResult(ctx, plan.Node.NodeID, plan.Replayed)
}

func (service *Service) RevokeNode(
	ctx context.Context,
	principal Principal,
	input TransitionNodeInput,
) (NodeMutationResult, error) {
	if err := requirePermission(principal, permissionNodeAdmin); err != nil {
		return NodeMutationResult{}, err
	}
	if err := service.requireNodeLifecycle(); err != nil {
		return NodeMutationResult{}, err
	}
	service.nodeMu.Lock()
	defer service.nodeMu.Unlock()
	plan, err := service.identity.RevokeManagedNode(ctx, identity.ManagedNodeRevocationInput{
		RequestID: input.RequestID, Actor: principal.Actor, Reason: input.Reason,
		NodeID: input.NodeID, ExpectedVersion: input.ExpectedVersion,
	})
	if err != nil {
		return NodeMutationResult{}, err
	}
	if _, err := discovery.AddNodeRevocation(
		service.nodePolicy.RevocationPath, input.NodeID, input.Reason,
		service.nodeClock(), service.nodePolicy.RevocationValidFor,
	); err != nil {
		return NodeMutationResult{}, fmt.Errorf("publish node revocation snapshot: %w", err)
	}
	return service.nodeMutationResult(ctx, plan.Node.NodeID, plan.Replayed)
}

func (service *Service) enrollmentResult(
	ctx context.Context,
	plan identity.NodeEnrollmentPlan,
) (NodeEnrollmentResult, error) {
	mutation, err := service.nodeMutationResult(ctx, plan.Node.NodeID, plan.Replayed)
	if err != nil {
		return NodeEnrollmentResult{}, err
	}
	result := NodeEnrollmentResult{
		APIVersion: APIVersion, Replayed: plan.Replayed, Node: mutation.Node,
	}
	if !plan.Replayed {
		result.Enrollment = &NodeEnrollmentBootstrap{
			Token: plan.Token.Value, ExpiresAt: plan.Token.ExpiresAt,
			EnrollmentAddress: service.nodePolicy.EnrollmentAddress,
			ServerName:        service.nodePolicy.ServerName, Audience: service.nodePolicy.Audience,
			TrustDomain: service.nodePolicy.TrustDomain, NodePathPrefix: service.nodePolicy.NodePathPrefix,
		}
	}
	return result, nil
}

func (service *Service) nodeMutationResult(
	ctx context.Context,
	nodeID string,
	replayed bool,
) (NodeMutationResult, error) {
	summary, err := service.identity.GetNode(ctx, nodeID)
	if err != nil {
		return NodeMutationResult{}, err
	}
	return NodeMutationResult{
		APIVersion: APIVersion, Replayed: replayed,
		Node: service.projectNodes([]identity.NodeIdentitySummary{summary})[0],
	}, nil
}

func (service *Service) projectNodes(summaries []identity.NodeIdentitySummary) []NodeView {
	connections := make(map[string]discovery.ConnectionSnapshot)
	for _, connection := range service.runtime.Connections() {
		connections[connection.NodeID] = connection
	}
	selection, selectionErr := service.runtime.CurrentRollout()
	result := make([]NodeView, 0, len(summaries))
	for _, summary := range summaries {
		node := summary.Node
		view := NodeView{
			NodeID: node.NodeID,
			Metadata: NodeMetadataInput{
				DisplayName: node.Metadata.DisplayName, Group: node.Metadata.Group,
				Labels: cloneStringMap(node.Metadata.Labels),
			},
			Lifecycle: node.Lifecycle, Version: node.Version,
			ReplacementFor: node.ReplacementFor, ReplacedBy: node.ReplacedBy,
			CreatedAt: node.CreatedAt, UpdatedAt: node.UpdatedAt,
			DrainRequestedAt: node.DrainRequestedAt, RetiredAt: node.RetiredAt, RevokedAt: node.RevokedAt,
			Enrolled: summary.Enrolled, CredentialGeneration: summary.CredentialGeneration,
			EligibleForRollout: summary.Enrolled && node.Lifecycle == identity.NodeLifecycleReady,
		}
		if !summary.CertificateNotAfter.IsZero() {
			value := summary.CertificateNotAfter
			view.CertificateNotAfter = &value
		}
		if !summary.RenewAfter.IsZero() {
			value := summary.RenewAfter
			view.RenewAfter = &value
		}
		if connection, found := connections[node.NodeID]; found {
			lastSeen := connection.LastSeen
			credentialNotAfter := connection.CredentialNotAfter
			view.Runtime = NodeRuntimeView{
				Connected: true, ProcessInstance: connection.ProcessInstance,
				LastSeen: &lastSeen, CredentialNotAfter: &credentialNotAfter,
				Reconciled: connection.Reconciled, ActiveSnapshotID: connection.ActiveSnapshotID,
				PreparedSequence: connection.PreparedSequence, PendingCommands: connection.PendingCommands,
			}
		}
		if selectionErr == nil {
			if snapshot, found := selection.Nodes[node.NodeID]; found {
				view.Runtime.RolloutPhase = snapshot.Phase
			}
		}
		result = append(result, view)
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].NodeID < result[right].NodeID
	})
	return result
}

func (service *Service) validateNodeTargets(ctx context.Context, targets []string) error {
	if service.identity == nil {
		return nil
	}
	for _, nodeID := range targets {
		summary, err := service.identity.GetNode(ctx, nodeID)
		if err != nil {
			return fmt.Errorf("target node %q is not registered: %w", nodeID, ErrPrecondition)
		}
		if !summary.Enrolled || summary.Node.Lifecycle != identity.NodeLifecycleReady {
			return fmt.Errorf("target node %q is not rollout eligible: %w", nodeID, ErrPrecondition)
		}
	}
	return nil
}

func (service *Service) requireNodeLifecycle() error {
	if service.identity == nil {
		return fmt.Errorf("node lifecycle is not configured: %w", ErrPrecondition)
	}
	return nil
}

func (service *Service) nodeClock() time.Time {
	if service.nodePolicy.Clock != nil {
		return service.nodePolicy.Clock().UTC()
	}
	return time.Now().UTC()
}

func identityMetadata(input NodeMetadataInput) identity.NodeMetadata {
	return identity.NodeMetadata{
		DisplayName: input.DisplayName, Group: input.Group, Labels: cloneStringMap(input.Labels),
	}
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func enrollmentTTL(seconds uint32) time.Duration {
	if seconds == 0 {
		seconds = DefaultNodeEnrollmentSeconds
	}
	return time.Duration(seconds) * time.Second
}

func validateNodeLifecycleOptions(options NodeLifecycleOptions) error {
	if strings.TrimSpace(options.Audience) == "" || strings.TrimSpace(options.ServerName) == "" ||
		strings.ContainsAny(options.ServerName, "/:@?#%") || strings.TrimSpace(options.TrustDomain) == "" ||
		!strings.HasPrefix(options.NodePathPrefix, "/") || !strings.HasSuffix(options.NodePathPrefix, "/") ||
		!filepath.IsAbs(options.RevocationPath) {
		return fmt.Errorf("node lifecycle options are invalid: %w", ErrInvalidInput)
	}
	host, port, err := net.SplitHostPort(options.EnrollmentAddress)
	if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
		return fmt.Errorf("node enrollment address is invalid: %w", ErrInvalidInput)
	}
	if options.RevocationValidFor <= 0 || options.RevocationValidFor > 30*24*time.Hour {
		return fmt.Errorf("node revocation validity is invalid: %w", ErrInvalidInput)
	}
	return nil
}
