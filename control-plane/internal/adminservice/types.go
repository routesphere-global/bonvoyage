// Package adminservice implements the versioned, transport-independent
// standalone management authority used by HTTP, GitOps, and the future
// Console. It never opens repositories or addresses dataplanes directly.
package adminservice

import (
	"context"
	"errors"
	"time"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/discovery"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/rollout"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/rolloutservice"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/snapshot"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
)

const (
	APIVersion                  = "v1"
	CompilerVersion             = snapshot.CompilerVersion
	AuditManifestVersion        = "bonvoyage.rollout.audit.v1"
	MaxConfigurationDiagnostics = 256
	MaxDiagnosticEvents         = 500
	DefaultAuditPageSize        = 100
	MaxAuditPageSize            = 250
	DefaultRoutePageSize        = 200
	MaxRoutePageSize            = 500
	MaxRouteSearchBytes         = 128
	MaxRouteOffset              = 1_000_000
)

var (
	ErrForbidden                    = errors.New("admin operation is forbidden")
	ErrInvalidInput                 = errors.New("admin operation input is invalid")
	ErrInvalidConfiguration         = errors.New("desired state is invalid")
	ErrPrecondition                 = errors.New("admin operation precondition failed")
	ErrNoChange                     = errors.New("desired state produces no artifact change")
	ErrAuthorityMismatch            = errors.New("runtime and repository authority differ")
	ErrPolicyAwaitingReconciliation = errors.New("safe rollout policy is waiting for node reconciliation")
)

// Role is a fixed server-side authorization class. Transports derive it from
// authenticated identity configuration, never from request content.
type Role string

const (
	RoleAuditor Role = "auditor"
	// RoleViewer is retained for compatibility with pre-Phase 4 authorization
	// documents. New Console accounts use RoleAuditor.
	RoleViewer        Role = "viewer"
	RoleOperator      Role = "operator"
	RoleAdministrator Role = "administrator"
)

// Principal is the transport-authenticated operator or service identity.
type Principal struct {
	Actor         string
	Role          Role
	SourceChannel storage.SourceChannel
}

// Repository is the single-writer durable boundary required by this service.
type Repository interface {
	CreateDesiredRevision(context.Context, storage.DesiredRevisionInput) (storage.DesiredRevision, error)
	GetDesiredRevision(context.Context, string) (storage.DesiredRevision, error)
	CreateSnapshotArtifact(context.Context, storage.SnapshotArtifactInput) (storage.SnapshotArtifact, error)
	GetSnapshotArtifact(context.Context, storage.Digest) (storage.SnapshotArtifact, error)
	AllocateRollout(context.Context, storage.RolloutInput) (storage.RolloutRecord, error)
	GetRollout(context.Context, uint64) (storage.RolloutRecord, error)
	GetRolloutByRequestID(context.Context, string) (storage.RolloutRecord, error)
	GetSelectedRollout(context.Context) (storage.RolloutRecord, error)
	SelectRollout(context.Context, uint64, uint64) (storage.RolloutRecord, error)
	AppendRolloutEvent(context.Context, storage.RolloutEventInput) (storage.RolloutEvent, error)
	ListRolloutEvents(context.Context, uint64) ([]storage.RolloutEvent, error)
}

// Runtime is the one process-wide authority shared with discovery streams.
type Runtime interface {
	CurrentRollout() (discovery.RolloutSelection, error)
	ReplaceRollout(
		context.Context,
		discovery.RolloutMutation,
		discovery.ManagedCoordinator,
		discovery.RolloutSelector,
	) (discovery.RolloutSelection, error)
	CancelRollout(
		context.Context,
		uint64,
		string,
		rolloutservice.CancellationInput,
	) (discovery.RolloutSelection, error)
	EvaluateRollout(context.Context, time.Time) (discovery.PolicyEvaluationResult, error)
	Connections() []discovery.ConnectionSnapshot
}

// RolloutPolicyInput is the versioned management representation of a durable
// safe-rollout policy. Whole seconds keep the public contract portable and
// unambiguous while storage retains time.Duration values.
type RolloutPolicyInput struct {
	Enabled                     bool                    `json:"enabled"`
	Strategy                    storage.RolloutStrategy `json:"strategy,omitempty"`
	CanaryNodeIDs               []string                `json:"canary_node_ids,omitempty"`
	MinimumHealthyCanaryPercent uint32                  `json:"minimum_healthy_canary_percent,omitempty"`
	CanaryObservationSeconds    uint32                  `json:"canary_observation_seconds,omitempty"`
	PrepareTimeoutSeconds       uint32                  `json:"prepare_timeout_seconds,omitempty"`
	ActivationTimeoutSeconds    uint32                  `json:"activation_timeout_seconds,omitempty"`
	HeartbeatStaleAfterSeconds  uint32                  `json:"heartbeat_stale_after_seconds,omitempty"`
	AutomaticRollback           bool                    `json:"automatic_rollback"`
}

type ValidateInput struct {
	Document []byte
}

type ValidationResult struct {
	APIVersion              string `json:"api_version"`
	Valid                   bool   `json:"valid"`
	SnapshotID              string `json:"snapshot_id,omitempty"`
	ArtifactSHA256          string `json:"artifact_sha256,omitempty"`
	SchemaVersion           uint32 `json:"schema_version,omitempty"`
	MinimumDataplaneVersion string `json:"minimum_dataplane_version,omitempty"`
	ArtifactBytes           int    `json:"artifact_bytes,omitempty"`
}

// ConfigurationPosition is a one-based human coordinate plus a zero-based
// byte offset in the bounded input observed by the compiler.
type ConfigurationPosition struct {
	Line       int `json:"line"`
	Column     int `json:"column"`
	ByteOffset int `json:"byte_offset"`
}

// ConfigurationSourceRange identifies only proven coordinates. The Admin API
// intentionally omits the local authoring source identifier because it is a
// transport detail and the Console must not derive or display source excerpts.
type ConfigurationSourceRange struct {
	Start ConfigurationPosition `json:"start"`
	End   ConfigurationPosition `json:"end"`
}

// ConfigurationDiagnostic is the bounded, redacted projection of one
// configuration-authoring diagnostic exposed through the Admin API.
type ConfigurationDiagnostic struct {
	Code     string                    `json:"code"`
	Severity string                    `json:"severity"`
	Message  string                    `json:"message"`
	Path     string                    `json:"path,omitempty"`
	Source   *ConfigurationSourceRange `json:"source,omitempty"`
	Redacted bool                      `json:"redacted"`
}

// ConfigurationValidationError distinguishes a normal rejected desired-state
// decision from an unavailable or failed Admin operation. It unwraps to the
// existing sentinel so Preview and Apply error classification remains stable.
type ConfigurationValidationError struct {
	Diagnostics          []ConfigurationDiagnostic `json:"diagnostics"`
	DiagnosticsTruncated bool                      `json:"diagnostics_truncated"`
}

func (validation *ConfigurationValidationError) Error() string {
	return ErrInvalidConfiguration.Error()
}

func (validation *ConfigurationValidationError) Unwrap() error {
	return ErrInvalidConfiguration
}

type PreviewInput struct {
	Document                []byte
	BaselineRolloutSequence uint64
	TargetNodeIDs           []string
	Policy                  RolloutPolicyInput
}

type RollbackPreviewInput struct {
	CurrentRolloutSequence uint64
	TargetRolloutSequence  uint64
	TargetNodeIDs          []string
}

type SnapshotSummary struct {
	SnapshotID              string `json:"snapshot_id"`
	ArtifactSHA256          string `json:"artifact_sha256"`
	SchemaVersion           uint32 `json:"schema_version"`
	MinimumDataplaneVersion string `json:"minimum_dataplane_version"`
	ArtifactBytes           int    `json:"artifact_bytes"`
}

type ResourceCounts struct {
	Listeners    int `json:"listeners"`
	VirtualHosts int `json:"virtual_hosts"`
	Routes       int `json:"routes"`
	Clusters     int `json:"clusters"`
}

type ResourceChange struct {
	ResourceType string `json:"resource_type"`
	ResourceName string `json:"resource_name"`
	Change       string `json:"change"`
}

type PreviewResult struct {
	APIVersion              string              `json:"api_version"`
	BaselineRolloutSequence uint64              `json:"baseline_rollout_sequence"`
	Baseline                SnapshotSummary     `json:"baseline"`
	Proposed                SnapshotSummary     `json:"proposed"`
	ProposedCounts          ResourceCounts      `json:"proposed_counts"`
	TargetNodeIDs           []string            `json:"target_node_ids"`
	Changes                 []ResourceChange    `json:"changes"`
	NoChange                bool                `json:"no_change"`
	PlanFingerprintSHA256   string              `json:"plan_fingerprint_sha256"`
	RollbackTargetSequence  uint64              `json:"rollback_target_sequence,omitempty"`
	Policy                  *RolloutPolicyInput `json:"policy,omitempty"`
}

type ApplyInput struct {
	RequestID                       string
	Document                        []byte
	SourceRevision                  string
	Reason                          string
	TargetNodeIDs                   []string
	ExpectedSelectedRolloutSequence uint64
	ExpectedActiveArtifact          storage.Digest
	PreviewFingerprintSHA256        string
	Policy                          RolloutPolicyInput
}

type CancelInput struct {
	RequestID string
	Sequence  uint64
	Reason    string
}

type RollbackInput struct {
	RequestID                       string
	Reason                          string
	TargetNodeIDs                   []string
	ExpectedSelectedRolloutSequence uint64
	ExpectedActiveArtifact          storage.Digest
	RollbackTargetSequence          uint64
	PreviewFingerprintSHA256        string
}

type MutationResult struct {
	APIVersion string        `json:"api_version"`
	Replayed   bool          `json:"replayed"`
	Status     RolloutStatus `json:"status"`
}

type PolicyReconcileResult struct {
	Evaluation        discovery.PolicyEvaluationResult
	AutomaticRollback *MutationResult
}

type RolloutStatus struct {
	APIVersion              string                  `json:"api_version"`
	RolloutID               string                  `json:"rollout_id"`
	RequestID               string                  `json:"request_id"`
	Sequence                uint64                  `json:"sequence"`
	Kind                    storage.RolloutKind     `json:"kind"`
	RollbackTargetSequence  uint64                  `json:"rollback_target_sequence,omitempty"`
	Phase                   rollout.Phase           `json:"phase"`
	Artifact                SnapshotSummary         `json:"artifact"`
	PreviousArtifactSHA256  string                  `json:"previous_artifact_sha256,omitempty"`
	BaselineRolloutSequence uint64                  `json:"baseline_rollout_sequence,omitempty"`
	DesiredRevisionID       string                  `json:"desired_revision_id"`
	CompilerVersion         string                  `json:"compiler_version"`
	TargetNodeIDs           []string                `json:"target_node_ids"`
	SourceChannel           storage.SourceChannel   `json:"source_channel"`
	Actor                   string                  `json:"actor"`
	Reason                  string                  `json:"reason"`
	CreatedAt               time.Time               `json:"created_at"`
	Selected                bool                    `json:"selected"`
	Nodes                   []NodeStatus            `json:"nodes"`
	Connections             []ConnectionObservation `json:"connections,omitempty"`
	Policy                  *RolloutPolicyInput     `json:"policy,omitempty"`
}

// DesiredStateResult returns the exact immutable source document associated
// with one rollout. It contains configuration references, never resolved
// secret material, and lets an operator correct a rejected candidate without
// relying on stale browser state.
type DesiredStateResult struct {
	APIVersion        string                `json:"api_version"`
	RolloutSequence   uint64                `json:"rollout_sequence"`
	DesiredRevisionID string                `json:"desired_revision_id"`
	Document          string                `json:"document"`
	SourceChannel     storage.SourceChannel `json:"source_channel"`
	SourceRevision    string                `json:"source_revision,omitempty"`
	Actor             string                `json:"actor"`
	CreatedAt         time.Time             `json:"created_at"`
	SnapshotID        string                `json:"snapshot_id"`
	ArtifactSHA256    string                `json:"artifact_sha256"`
}

type NodeStatus struct {
	NodeID          string            `json:"node_id"`
	Phase           rollout.NodePhase `json:"phase"`
	Connected       bool              `json:"connected"`
	ProcessInstance string            `json:"process_instance,omitempty"`
}

type ConnectionObservation struct {
	NodeID              string    `json:"node_id"`
	ProcessInstance     string    `json:"process_instance"`
	CredentialNotAfter  time.Time `json:"credential_not_after"`
	ConnectedAt         time.Time `json:"connected_at"`
	LastSeen            time.Time `json:"last_seen"`
	LastRolloutSequence uint64    `json:"last_rollout_sequence"`
	ActiveSnapshotID    string    `json:"active_snapshot_id,omitempty"`
	PreparedSequence    uint64    `json:"prepared_sequence,omitempty"`
	PendingCommands     int       `json:"pending_commands"`
	Reconciled          bool      `json:"reconciled"`
}

// RouteCatalogQuery binds a bounded route read to the artifact identity that
// the caller already observed. This prevents a Console page from combining
// rows from one immutable snapshot with metadata from another.
type RouteCatalogQuery struct {
	ExpectedArtifactSHA256 string
	Offset                 int
	Limit                  int
	Query                  string
}

// RouteCatalogPage is a bounded projection of the selected immutable
// snapshot. It intentionally excludes credentials and raw policy material.
type RouteCatalogPage struct {
	APIVersion      string              `json:"api_version"`
	RolloutSequence uint64              `json:"rollout_sequence"`
	SnapshotID      string              `json:"snapshot_id"`
	ArtifactSHA256  string              `json:"artifact_sha256"`
	TotalRoutes     int                 `json:"total_routes"`
	MatchingRoutes  int                 `json:"matching_routes"`
	Offset          int                 `json:"offset"`
	Limit           int                 `json:"limit"`
	Routes          []RouteCatalogEntry `json:"routes"`
}

// RouteCatalogEntry contains only operator-facing routing identity and policy
// presence. Secret references and policy values stay on the server.
type RouteCatalogEntry struct {
	Index           int      `json:"index"`
	VirtualHost     string   `json:"virtual_host"`
	Route           string   `json:"route"`
	Domains         []string `json:"domains"`
	MatchType       string   `json:"match_type"`
	MatchValue      string   `json:"match_value"`
	Methods         []string `json:"methods"`
	DestinationType string   `json:"destination_type"`
	Destination     string   `json:"destination"`
	Policies        []string `json:"policies"`
}

type DiagnosticsResult struct {
	APIVersion  string            `json:"api_version"`
	Sequence    uint64            `json:"sequence"`
	TotalEvents uint64            `json:"total_events"`
	FirstIndex  uint64            `json:"first_index,omitempty"`
	LastIndex   uint64            `json:"last_index,omitempty"`
	Truncated   bool              `json:"truncated"`
	Events      []DiagnosticEvent `json:"events"`
}

type DiagnosticEvent struct {
	Index        uint64                  `json:"index"`
	EventID      string                  `json:"event_id"`
	Kind         string                  `json:"kind"`
	EventSHA256  string                  `json:"event_sha256"`
	Phase        rollout.Phase           `json:"phase"`
	CreatedAt    time.Time               `json:"created_at"`
	Error        *DiagnosticError        `json:"error,omitempty"`
	Report       *DiagnosticReport       `json:"report,omitempty"`
	Policy       *DiagnosticPolicy       `json:"policy,omitempty"`
	Cancellation *DiagnosticCancellation `json:"cancellation,omitempty"`
}

type DiagnosticCancellation struct {
	Reason            string                                 `json:"reason"`
	Actor             string                                 `json:"actor,omitempty"`
	SourceChannel     storage.SourceChannel                  `json:"source_channel,omitempty"`
	AttributionStatus rolloutservice.CancellationAttribution `json:"attribution_status"`
}

type DiagnosticPolicy struct {
	ObservedAt time.Time              `json:"observed_at"`
	Decision   rollout.PolicyDecision `json:"decision"`
	Reason     string                 `json:"reason"`
	Nodes      []DiagnosticNodeHealth `json:"nodes,omitempty"`
}

type DiagnosticNodeHealth struct {
	NodeID           string    `json:"node_id"`
	Connected        bool      `json:"connected"`
	Reconciled       bool      `json:"reconciled"`
	LastSeen         time.Time `json:"last_seen,omitempty"`
	ActiveSnapshotID string    `json:"active_snapshot_id,omitempty"`
}

type DiagnosticError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type DiagnosticReport struct {
	NodeID          string            `json:"node_id"`
	ProcessInstance string            `json:"process_instance"`
	Sequence        uint64            `json:"sequence"`
	Operation       rollout.Operation `json:"operation"`
	Result          rollout.Result    `json:"result"`
	ShardCount      uint32            `json:"shard_count"`
	CompletedShards uint32            `json:"completed_shards"`
	Issues          []DiagnosticIssue `json:"issues,omitempty"`
}

type DiagnosticIssue struct {
	Code      string `json:"code"`
	FieldPath string `json:"field_path,omitempty"`
	Message   string `json:"message,omitempty"`
}

// AuditResult is a bounded page from one immutable rollout header and its
// append-only, replay-verified journal. ManifestSHA256 binds the complete
// journal at export time, including events outside the returned page.
type AuditResult struct {
	APIVersion      string       `json:"api_version"`
	ManifestVersion string       `json:"manifest_version"`
	ManifestSHA256  string       `json:"manifest_sha256"`
	Rollout         AuditRollout `json:"rollout"`
	Journal         AuditJournal `json:"journal"`
}

type AuditRollout struct {
	RolloutID               string                `json:"rollout_id"`
	RequestID               string                `json:"request_id"`
	RequestSHA256           string                `json:"request_sha256,omitempty"`
	Sequence                uint64                `json:"sequence"`
	Kind                    storage.RolloutKind   `json:"kind"`
	RollbackTargetSequence  uint64                `json:"rollback_target_sequence,omitempty"`
	SnapshotID              string                `json:"snapshot_id"`
	ArtifactSHA256          string                `json:"artifact_sha256"`
	PreviousArtifactSHA256  string                `json:"previous_artifact_sha256,omitempty"`
	BaselineRolloutSequence uint64                `json:"baseline_rollout_sequence,omitempty"`
	DesiredRevisionID       string                `json:"desired_revision_id"`
	CompilerVersion         string                `json:"compiler_version"`
	TargetNodeIDs           []string              `json:"target_node_ids"`
	ExpectedActiveByNode    []AuditNodeArtifact   `json:"expected_active_by_node,omitempty"`
	Policy                  *RolloutPolicyInput   `json:"policy,omitempty"`
	SourceChannel           storage.SourceChannel `json:"source_channel"`
	Actor                   string                `json:"actor"`
	Reason                  string                `json:"reason"`
	CreatedAt               time.Time             `json:"created_at"`
}

type AuditNodeArtifact struct {
	NodeID         string `json:"node_id"`
	ArtifactSHA256 string `json:"artifact_sha256"`
}

type AuditJournal struct {
	TotalEvents    uint64            `json:"total_events"`
	AfterIndex     uint64            `json:"after_index"`
	Limit          int               `json:"limit"`
	FirstIndex     uint64            `json:"first_index,omitempty"`
	LastIndex      uint64            `json:"last_index,omitempty"`
	NextAfterIndex uint64            `json:"next_after_index,omitempty"`
	Events         []DiagnosticEvent `json:"events"`
}

// OperationalTelemetry contains only fixed-dimension control-plane facts.
// Actor, node, artifact, request, and tenant identities are intentionally
// absent so Prometheus cannot become an audit or billing database.
type OperationalTelemetry struct {
	APIVersion              string
	ProcessStartedAt        time.Time
	Ready                   bool
	SelectedSequence        uint64
	RolloutPhase            rollout.Phase
	RolloutKind             storage.RolloutKind
	PolicyStrategy          string
	PolicyEnabled           bool
	AutomaticRollback       bool
	RuntimeAuthorityMatch   bool
	TargetNodes             int
	ConnectedNodes          int
	ReconciledNodes         int
	UnreconciledNodes       int
	PendingCommands         int
	RecoveryRequired        bool
	JournalEvents           uint64
	JournalTransitionErrors uint64
	LastJournalEventAt      time.Time
	NodePhases              []NamedCount
	JournalKinds            []NamedCount
	PolicyDecisions         []NamedCount
	Reports                 []ReportCount
}

type NamedCount struct {
	Name  string
	Count uint64
}

type ReportCount struct {
	Operation rollout.Operation
	Result    rollout.Result
	Count     uint64
}
