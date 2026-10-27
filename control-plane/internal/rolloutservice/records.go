package rolloutservice

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/rollout"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
)

const (
	legacyJournalVersion uint32 = 1
	journalVersion       uint32 = 2
	maxJournalInputBytes        = 192 << 10
)

type journalRecord struct {
	Version uint32         `json:"version"`
	Kind    string         `json:"kind"`
	Input   journalInput   `json:"input"`
	Outcome journalOutcome `json:"outcome"`
}

type journalInput struct {
	Report        *reportRecord            `json:"report,omitempty"`
	Runtime       *runtimeStateRecord      `json:"runtime,omitempty"`
	Policy        *policyObservationRecord `json:"policy,omitempty"`
	Reason        string                   `json:"reason,omitempty"`
	Actor         string                   `json:"actor,omitempty"`
	SourceChannel storage.SourceChannel    `json:"source_channel,omitempty"`
}

type journalOutcome struct {
	Phase          rollout.Phase          `json:"phase"`
	StateSHA256    string                 `json:"state_sha256"`
	CommandCount   int                    `json:"command_count"`
	CommandsSHA256 string                 `json:"commands_sha256"`
	Error          *journalErrorRecord    `json:"error,omitempty"`
	PolicyDecision rollout.PolicyDecision `json:"policy_decision,omitempty"`
	PolicyReason   string                 `json:"policy_reason,omitempty"`
}

type journalErrorRecord struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type referenceRecord struct {
	ID     string `json:"id,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

type issueRecord struct {
	Code      string `json:"code"`
	FieldPath string `json:"field_path,omitempty"`
	Message   string `json:"message,omitempty"`
}

type reportRecord struct {
	NodeID          string            `json:"node_id"`
	ProcessInstance string            `json:"process_instance"`
	Sequence        uint64            `json:"sequence"`
	Artifact        referenceRecord   `json:"artifact"`
	Operation       rollout.Operation `json:"operation"`
	Result          rollout.Result    `json:"result"`
	PreviousActive  referenceRecord   `json:"previous_active"`
	CurrentActive   referenceRecord   `json:"current_active"`
	ShardCount      uint32            `json:"shard_count"`
	CompletedShards uint32            `json:"completed_shards"`
	Issues          []issueRecord     `json:"issues,omitempty"`
	CompletedAt     *time.Time        `json:"completed_at,omitempty"`
}

type preparedStateRecord struct {
	Sequence   uint64          `json:"sequence"`
	Artifact   referenceRecord `json:"artifact"`
	ShardCount uint32          `json:"shard_count"`
}

type runtimeStateRecord struct {
	NodeID           string               `json:"node_id"`
	ProcessInstance  string               `json:"process_instance"`
	LastSequence     uint64               `json:"last_sequence"`
	Active           referenceRecord      `json:"active"`
	ActiveShardCount uint32               `json:"active_shard_count"`
	Prepared         *preparedStateRecord `json:"prepared,omitempty"`
	ObservedAt       *time.Time           `json:"observed_at,omitempty"`
}

type policyObservationRecord struct {
	ObservedAt time.Time                `json:"observed_at"`
	Nodes      []policyNodeHealthRecord `json:"nodes,omitempty"`
}

type policyNodeHealthRecord struct {
	NodeID           string     `json:"node_id"`
	Connected        bool       `json:"connected"`
	Reconciled       bool       `json:"reconciled"`
	LastSeen         *time.Time `json:"last_seen,omitempty"`
	ActiveSnapshotID string     `json:"active_snapshot_id,omitempty"`
}

type durableStateRecord struct {
	Phase  rollout.Phase        `json:"phase"`
	Nodes  []durableNodeRecord  `json:"nodes"`
	Policy *durablePolicyRecord `json:"policy,omitempty"`
}

type durablePolicyRecord struct {
	Strategy             rollout.Strategy `json:"strategy"`
	CanaryNodeIDs        []string         `json:"canary_node_ids,omitempty"`
	StartedAt            time.Time        `json:"started_at,omitempty"`
	ActivationStartedAt  time.Time        `json:"activation_started_at,omitempty"`
	ObservationStartedAt time.Time        `json:"observation_started_at,omitempty"`
	FailureReason        string           `json:"failure_reason,omitempty"`
	AutomaticRollback    bool             `json:"automatic_rollback"`
}

type durableNodeRecord struct {
	NodeID          string            `json:"node_id"`
	Phase           rollout.NodePhase `json:"phase"`
	ProcessInstance string            `json:"process_instance,omitempty"`
}

type commandRecord struct {
	NodeID          string            `json:"node_id"`
	Sequence        uint64            `json:"sequence"`
	Operation       rollout.Operation `json:"operation"`
	Artifact        referenceRecord   `json:"artifact"`
	ExpectedActive  referenceRecord   `json:"expected_active"`
	Reason          string            `json:"reason,omitempty"`
	CarriesArtifact bool              `json:"carries_artifact"`
}

func decodeJournalRecord(payload []byte) (journalRecord, error) {
	var record journalRecord
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return journalRecord{}, fmt.Errorf("decode journal event: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return journalRecord{}, err
	}
	if err := validateJournalRecord(record); err != nil {
		return journalRecord{}, err
	}
	canonical, err := json.Marshal(record)
	if err != nil {
		return journalRecord{}, err
	}
	if !bytes.Equal(payload, canonical) {
		return journalRecord{}, fmt.Errorf("journal event is not canonical JSON: %w", storage.ErrCorrupt)
	}
	return record, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("journal event has trailing JSON: %w", storage.ErrCorrupt)
		}
		return fmt.Errorf("decode journal event tail: %w", err)
	}
	return nil
}

func validateJournalRecord(record journalRecord) error {
	if record.Version != legacyJournalVersion && record.Version != journalVersion {
		return fmt.Errorf("unsupported journal version %d: %w", record.Version, storage.ErrCorrupt)
	}
	if err := validateJournalInputShape(record.Version, record.Kind, record.Input); err != nil {
		return err
	}
	if record.Outcome.Phase == "" || record.Outcome.CommandCount < 0 ||
		!canonicalDigest(record.Outcome.StateSHA256) || !canonicalDigest(record.Outcome.CommandsSHA256) {
		return fmt.Errorf("invalid journal outcome: %w", storage.ErrCorrupt)
	}
	if (record.Outcome.PolicyDecision == "") != (record.Outcome.PolicyReason == "") {
		return fmt.Errorf("incomplete journal policy outcome: %w", storage.ErrCorrupt)
	}
	if record.Kind == eventKindEvaluate {
		switch record.Outcome.PolicyDecision {
		case rollout.PolicyDecisionCancel, rollout.PolicyDecisionPromote,
			rollout.PolicyDecisionRequireRollback:
		default:
			return fmt.Errorf("invalid journal policy decision: %w", storage.ErrCorrupt)
		}
	} else if record.Outcome.PolicyDecision != "" {
		return fmt.Errorf("non-policy event contains a policy decision: %w", storage.ErrCorrupt)
	}
	if record.Outcome.Error != nil {
		if strings.TrimSpace(record.Outcome.Error.Code) == "" || strings.TrimSpace(record.Outcome.Error.Message) == "" {
			return fmt.Errorf("invalid journal error outcome: %w", storage.ErrCorrupt)
		}
		if rolloutErrorForCode(record.Outcome.Error.Code) == nil {
			return fmt.Errorf("unknown journal error code %q: %w", record.Outcome.Error.Code, storage.ErrCorrupt)
		}
	}
	return nil
}

func validateJournalInputShape(version uint32, kind string, input journalInput) error {
	valid := false
	attributionAbsent := input.Actor == "" && input.SourceChannel == ""
	switch kind {
	case eventKindStart:
		valid = input.Report == nil && input.Runtime == nil && input.Policy == nil &&
			input.Reason == "" && attributionAbsent
	case eventKindReport:
		valid = input.Report != nil && input.Runtime == nil && input.Policy == nil &&
			input.Reason == "" && attributionAbsent
	case eventKindReconnect:
		valid = input.Report == nil && input.Runtime != nil && input.Policy == nil &&
			input.Reason == "" && attributionAbsent
	case eventKindCancel:
		valid = input.Report == nil && input.Runtime == nil && input.Policy == nil && input.Reason != ""
		if version == legacyJournalVersion {
			valid = valid && attributionAbsent
		} else {
			valid = valid && validCancellationActor(input.Actor) &&
				validCancellationSource(input.SourceChannel)
		}
	case eventKindEvaluate:
		valid = input.Report == nil && input.Runtime == nil && input.Policy != nil &&
			input.Reason == "" && attributionAbsent
	}
	if !valid {
		return fmt.Errorf("invalid %q journal input shape: %w", kind, storage.ErrCorrupt)
	}
	return nil
}

func validateProspectiveInput(kind string, input journalInput) error {
	if err := validateJournalInputShape(journalVersion, kind, input); err != nil {
		return fmt.Errorf("journal input: %w", storage.ErrInvalid)
	}
	data, err := json.Marshal(struct {
		Version uint32       `json:"version"`
		Kind    string       `json:"kind"`
		Input   journalInput `json:"input"`
	}{journalVersion, kind, input})
	if err != nil {
		return fmt.Errorf("encode journal input: %w", err)
	}
	if len(data) > maxJournalInputBytes {
		return fmt.Errorf("journal input exceeds %d bytes: %w", maxJournalInputBytes, storage.ErrInvalid)
	}
	return nil
}

func validCancellationActor(actor string) bool {
	if !utf8.ValidString(actor) || strings.TrimSpace(actor) == "" || len(actor) > 256 {
		return false
	}
	for _, char := range actor {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func validCancellationSource(channel storage.SourceChannel) bool {
	switch channel {
	case storage.SourceAPI, storage.SourceCLI, storage.SourceConsole, storage.SourceGitOps:
		return true
	default:
		return false
	}
}

func canonicalDigest(value string) bool {
	digest, err := storage.ParseDigest(value)
	return err == nil && digest.String() == value
}

func reportToRecord(report rollout.Report) reportRecord {
	result := reportRecord{
		NodeID: report.NodeID, ProcessInstance: report.ProcessInstance, Sequence: report.Sequence,
		Artifact: referenceToRecord(report.Artifact), Operation: report.Operation, Result: report.Result,
		PreviousActive: referenceToRecord(report.PreviousActive), CurrentActive: referenceToRecord(report.CurrentActive),
		ShardCount: report.ShardCount, CompletedShards: report.CompletedShards,
		CompletedAt: optionalTime(report.CompletedAt),
	}
	if len(report.Issues) != 0 {
		result.Issues = make([]issueRecord, len(report.Issues))
		for index, issue := range report.Issues {
			result.Issues[index] = issueRecord{Code: issue.Code, FieldPath: issue.FieldPath, Message: issue.Message}
		}
	}
	return result
}

func reportFromRecord(record reportRecord) (rollout.Report, error) {
	artifact, err := referenceFromRecord(record.Artifact)
	if err != nil {
		return rollout.Report{}, err
	}
	previous, err := referenceFromRecord(record.PreviousActive)
	if err != nil {
		return rollout.Report{}, err
	}
	current, err := referenceFromRecord(record.CurrentActive)
	if err != nil {
		return rollout.Report{}, err
	}
	result := rollout.Report{
		NodeID: record.NodeID, ProcessInstance: record.ProcessInstance, Sequence: record.Sequence,
		Artifact: artifact, Operation: record.Operation, Result: record.Result,
		PreviousActive: previous, CurrentActive: current,
		ShardCount: record.ShardCount, CompletedShards: record.CompletedShards,
		CompletedAt: timeValue(record.CompletedAt),
	}
	if len(record.Issues) != 0 {
		result.Issues = make([]rollout.Issue, len(record.Issues))
		for index, issue := range record.Issues {
			result.Issues[index] = rollout.Issue{Code: issue.Code, FieldPath: issue.FieldPath, Message: issue.Message}
		}
	}
	return result, nil
}

func runtimeToRecord(state rollout.RuntimeState) runtimeStateRecord {
	record := runtimeStateRecord{
		NodeID: state.NodeID, ProcessInstance: state.ProcessInstance, LastSequence: state.LastSequence,
		Active: referenceToRecord(state.Active), ActiveShardCount: state.ActiveShardCount,
		ObservedAt: optionalTime(state.ObservedAt),
	}
	if state.Prepared != nil {
		record.Prepared = &preparedStateRecord{
			Sequence: state.Prepared.Sequence, Artifact: referenceToRecord(state.Prepared.Artifact),
			ShardCount: state.Prepared.ShardCount,
		}
	}
	return record
}

func runtimeFromRecord(record runtimeStateRecord) (rollout.RuntimeState, error) {
	active, err := referenceFromRecord(record.Active)
	if err != nil {
		return rollout.RuntimeState{}, err
	}
	state := rollout.RuntimeState{
		NodeID: record.NodeID, ProcessInstance: record.ProcessInstance, LastSequence: record.LastSequence,
		Active: active, ActiveShardCount: record.ActiveShardCount,
		ObservedAt: timeValue(record.ObservedAt),
	}
	if record.Prepared != nil {
		artifact, err := referenceFromRecord(record.Prepared.Artifact)
		if err != nil {
			return rollout.RuntimeState{}, err
		}
		state.Prepared = &rollout.PreparedState{
			Sequence: record.Prepared.Sequence, Artifact: artifact, ShardCount: record.Prepared.ShardCount,
		}
	}
	return state, nil
}

func policyToRecord(observation rollout.PolicyObservation) policyObservationRecord {
	record := policyObservationRecord{ObservedAt: observation.ObservedAt}
	if len(observation.Nodes) != 0 {
		record.Nodes = make([]policyNodeHealthRecord, len(observation.Nodes))
		for index, node := range observation.Nodes {
			record.Nodes[index] = policyNodeHealthRecord{
				NodeID: node.NodeID, Connected: node.Connected, Reconciled: node.Reconciled,
				LastSeen: optionalTime(node.LastSeen), ActiveSnapshotID: node.ActiveSnapshotID,
			}
		}
	}
	return record
}

func policyFromRecord(record policyObservationRecord) rollout.PolicyObservation {
	observation := rollout.PolicyObservation{ObservedAt: record.ObservedAt}
	if len(record.Nodes) != 0 {
		observation.Nodes = make([]rollout.NodeHealth, len(record.Nodes))
		for index, node := range record.Nodes {
			observation.Nodes[index] = rollout.NodeHealth{
				NodeID: node.NodeID, Connected: node.Connected, Reconciled: node.Reconciled,
				LastSeen: timeValue(node.LastSeen), ActiveSnapshotID: node.ActiveSnapshotID,
			}
		}
	}
	return observation
}

func optionalTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	copy := value
	return &copy
}

func timeValue(value *time.Time) time.Time {
	if value == nil {
		return time.Time{}
	}
	return *value
}

func referenceToRecord(reference rollout.Reference) referenceRecord {
	if reference == (rollout.Reference{}) {
		return referenceRecord{}
	}
	return referenceRecord{ID: reference.ID, SHA256: fmt.Sprintf("%x", reference.SHA256)}
}

func referenceFromRecord(record referenceRecord) (rollout.Reference, error) {
	if record.ID == "" && record.SHA256 == "" {
		return rollout.Reference{}, nil
	}
	if record.ID == "" || !canonicalDigest(record.SHA256) {
		return rollout.Reference{}, fmt.Errorf("invalid journal snapshot reference: %w", storage.ErrCorrupt)
	}
	digest, _ := storage.ParseDigest(record.SHA256)
	return rollout.Reference{ID: record.ID, SHA256: [sha256.Size]byte(digest)}, nil
}

func durableState(machine *rollout.Coordinator) durableStateRecord {
	phase, nodes := machine.Status()
	nodeIDs := make([]string, 0, len(nodes))
	for nodeID := range nodes {
		nodeIDs = append(nodeIDs, nodeID)
	}
	slices.Sort(nodeIDs)
	result := durableStateRecord{Phase: phase, Nodes: make([]durableNodeRecord, 0, len(nodeIDs))}
	for _, nodeID := range nodeIDs {
		node := nodes[nodeID]
		result.Nodes = append(result.Nodes, durableNodeRecord{
			NodeID: nodeID, Phase: node.Phase, ProcessInstance: node.ProcessInstance,
		})
	}
	policy := machine.PolicyState()
	if policy.Enabled {
		result.Policy = &durablePolicyRecord{
			Strategy: policy.Strategy, CanaryNodeIDs: append([]string(nil), policy.CanaryNodeIDs...),
			StartedAt: policy.StartedAt, ActivationStartedAt: policy.ActivationStartedAt,
			ObservationStartedAt: policy.ObservationStartedAt,
			FailureReason:        policy.FailureReason, AutomaticRollback: policy.AutomaticRollback,
		}
	}
	return result
}

func makeOutcome(
	machine *rollout.Coordinator,
	commands []rollout.Command,
	transitionError error,
	policyResult ...rollout.PolicyResult,
) (journalOutcome, error) {
	state := durableState(machine)
	stateDigest, err := digestJSON(state)
	if err != nil {
		return journalOutcome{}, err
	}
	commandRecords := make([]commandRecord, len(commands))
	for index, command := range commands {
		commandRecords[index] = commandRecord{
			NodeID: command.NodeID, Sequence: command.Sequence, Operation: command.Operation,
			Artifact:       referenceToRecord(command.Artifact.Reference),
			ExpectedActive: referenceToRecord(command.ExpectedActive), Reason: command.Reason,
			CarriesArtifact: len(command.Artifact.Bytes) != 0,
		}
	}
	commandDigest, err := digestJSON(commandRecords)
	if err != nil {
		return journalOutcome{}, err
	}
	outcome := journalOutcome{
		Phase: state.Phase, StateSHA256: stateDigest, CommandCount: len(commands),
		CommandsSHA256: commandDigest, Error: errorToRecord(transitionError),
	}
	if len(policyResult) != 0 {
		outcome.PolicyDecision = policyResult[0].Decision
		outcome.PolicyReason = policyResult[0].Reason
	}
	return outcome, nil
}

func digestJSON(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest), nil
}

func errorToRecord(err error) *journalErrorRecord {
	if err == nil {
		return nil
	}
	return &journalErrorRecord{Code: rolloutErrorCode(err), Message: err.Error()}
}

func rolloutErrorCode(err error) string {
	cases := []struct {
		err  error
		code string
	}{
		{rollout.ErrAlreadyStarted, "ALREADY_STARTED"},
		{rollout.ErrConflictingReplay, "CONFLICTING_REPLAY"},
		{rollout.ErrDrift, "DRIFT"},
		{rollout.ErrFutureSequence, "FUTURE_SEQUENCE"},
		{rollout.ErrInvalidReport, "INVALID_REPORT"},
		{rollout.ErrNotStarted, "NOT_STARTED"},
		{rollout.ErrRequiresRollback, "REQUIRES_ROLLBACK"},
		{rollout.ErrStaleSequence, "STALE_SEQUENCE"},
		{rollout.ErrStateTransition, "STATE_TRANSITION"},
		{rollout.ErrUnknownNode, "UNKNOWN_NODE"},
	}
	for _, candidate := range cases {
		if errors.Is(err, candidate.err) {
			return candidate.code
		}
	}
	return "UNKNOWN"
}

func errorFromRecord(record *journalErrorRecord) error {
	if record == nil {
		return nil
	}
	return recordedTransitionError{message: record.Message, cause: rolloutErrorForCode(record.Code)}
}

func rolloutErrorForCode(code string) error {
	causes := map[string]error{
		"ALREADY_STARTED": rollout.ErrAlreadyStarted, "CONFLICTING_REPLAY": rollout.ErrConflictingReplay,
		"DRIFT": rollout.ErrDrift, "FUTURE_SEQUENCE": rollout.ErrFutureSequence,
		"INVALID_REPORT": rollout.ErrInvalidReport, "NOT_STARTED": rollout.ErrNotStarted,
		"REQUIRES_ROLLBACK": rollout.ErrRequiresRollback, "STALE_SEQUENCE": rollout.ErrStaleSequence,
		"STATE_TRANSITION": rollout.ErrStateTransition, "UNKNOWN_NODE": rollout.ErrUnknownNode,
	}
	return causes[code]
}

type recordedTransitionError struct {
	message string
	cause   error
}

func (err recordedTransitionError) Error() string { return err.message }
func (err recordedTransitionError) Unwrap() error { return err.cause }

func sameInput(version uint32, kind string, left, right journalInput) bool {
	if version == legacyJournalVersion && kind == eventKindCancel {
		return left.Reason == right.Reason
	}
	return reflect.DeepEqual(left, right)
}

func sameDurableState(left, right durableStateRecord) bool {
	return reflect.DeepEqual(left, right)
}

func cloneCommands(commands []rollout.Command) []rollout.Command {
	if len(commands) == 0 {
		return nil
	}
	cloned := make([]rollout.Command, len(commands))
	copy(cloned, commands)
	for index := range cloned {
		cloned[index].Artifact.Bytes = append([]byte(nil), commands[index].Artifact.Bytes...)
	}
	return cloned
}
