package discovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	bonvoyagev1 "github.com/routesphere-global/bonvoyage/api/gen/go/bonvoyage/v1"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/rollout"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	maxCapabilities     = 16
	maxSchemaVersions   = 32
	maxValidationIssues = 64
	maxFieldPathBytes   = 1024
	maxIssueBytes       = 4096
)

func validateIdentifier(name, value string) error {
	if len(value) == 0 || len(value) > 128 {
		return fmt.Errorf("%s must contain 1-128 bytes", name)
	}
	for index, char := range value {
		valid := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' ||
			char >= '0' && char <= '9' || char == '.' || char == '_' || char == ':' || char == '-'
		if !valid || index == 0 && (char == '.' || char == ':' || char == '-') {
			return fmt.Errorf("%s contains an unsupported character", name)
		}
	}
	return nil
}

func validateText(name, value string, maxBytes int, required bool) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", name)
	}
	if required && strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is empty", name)
	}
	if len(value) > maxBytes {
		return fmt.Errorf("%s exceeds %d bytes", name, maxBytes)
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return fmt.Errorf("%s contains a control character", name)
		}
	}
	return nil
}

func rejectUnknown(message proto.Message) error {
	if message == nil {
		return nil
	}
	return rejectUnknownMessage(message.ProtoReflect())
}

func rejectUnknownMessage(message protoreflect.Message) error {
	if !message.IsValid() {
		return nil
	}
	if len(message.GetUnknown()) != 0 {
		return fmt.Errorf("%s contains unknown fields", message.Descriptor().FullName())
	}
	var nestedErr error
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		kind := field.Kind()
		if field.IsMap() {
			if field.MapValue().Kind() != protoreflect.MessageKind &&
				field.MapValue().Kind() != protoreflect.GroupKind {
				return true
			}
			value.Map().Range(func(_ protoreflect.MapKey, item protoreflect.Value) bool {
				nestedErr = rejectUnknownMessage(item.Message())
				return nestedErr == nil
			})
			return nestedErr == nil
		}
		if field.IsList() {
			if kind != protoreflect.MessageKind && kind != protoreflect.GroupKind {
				return true
			}
			list := value.List()
			for index := 0; index < list.Len(); index++ {
				if nestedErr = rejectUnknownMessage(list.Get(index).Message()); nestedErr != nil {
					return false
				}
			}
			return true
		}
		if kind == protoreflect.MessageKind || kind == protoreflect.GroupKind {
			nestedErr = rejectUnknownMessage(value.Message())
		}
		return nestedErr == nil
	})
	return nestedErr
}

func validateHello(
	identity AuthenticatedNode,
	hello *bonvoyagev1.NodeHello,
	requiredSchema uint32,
	requiredCapabilities map[bonvoyagev1.NodeCapabilityType]uint32,
) (rollout.RuntimeState, error) {
	if hello == nil {
		return rollout.RuntimeState{}, fmt.Errorf("hello is required")
	}
	if err := rejectUnknown(hello); err != nil {
		return rollout.RuntimeState{}, err
	}
	if err := validateIdentifier("node ID", hello.GetNodeId()); err != nil {
		return rollout.RuntimeState{}, err
	}
	if hello.GetNodeId() != identity.NodeID {
		return rollout.RuntimeState{}, fmt.Errorf("hello node ID does not match the authenticated identity")
	}
	if err := validateIdentifier("process instance ID", hello.GetProcessInstanceId()); err != nil {
		return rollout.RuntimeState{}, err
	}
	if err := validateText("data-plane version", hello.GetDataplaneVersion(), 128, true); err != nil {
		return rollout.RuntimeState{}, err
	}
	if err := validateSchemas(hello.GetSupportedSchemaVersions(), requiredSchema); err != nil {
		return rollout.RuntimeState{}, err
	}
	if err := validateCapabilities(hello.GetCapabilities(), requiredCapabilities); err != nil {
		return rollout.RuntimeState{}, err
	}
	if hello.GetRuntimeState() == nil {
		return rollout.RuntimeState{}, fmt.Errorf("runtime state is required")
	}
	state, err := runtimeState(hello.GetNodeId(), hello.GetProcessInstanceId(), hello.GetRuntimeState())
	if err != nil {
		return rollout.RuntimeState{}, err
	}
	legacyActive, err := referenceFromParts(
		"hello active snapshot",
		hello.GetActiveSnapshotId(),
		hello.GetActiveSnapshotSha256(),
	)
	if err != nil {
		return rollout.RuntimeState{}, err
	}
	if legacyActive != state.Active || hello.GetLastRolloutSequence() != state.LastSequence {
		return rollout.RuntimeState{}, fmt.Errorf("legacy hello state disagrees with runtime state")
	}
	return state, nil
}

func validateSchemas(schemas []uint32, required uint32) error {
	if len(schemas) == 0 || len(schemas) > maxSchemaVersions {
		return fmt.Errorf("supported schema version count must be 1-%d", maxSchemaVersions)
	}
	found := false
	seen := make(map[uint32]struct{}, len(schemas))
	for _, schema := range schemas {
		if schema == 0 {
			return fmt.Errorf("schema version zero is invalid")
		}
		if _, exists := seen[schema]; exists {
			return fmt.Errorf("schema version %d is duplicated", schema)
		}
		seen[schema] = struct{}{}
		found = found || schema == required
	}
	if !found {
		return fmt.Errorf("required schema version %d is not supported", required)
	}
	return nil
}

func validateCapabilities(
	capabilities []*bonvoyagev1.NodeCapability,
	required map[bonvoyagev1.NodeCapabilityType]uint32,
) error {
	if len(capabilities) == 0 || len(capabilities) > maxCapabilities {
		return fmt.Errorf("capability count must be 1-%d", maxCapabilities)
	}
	seen := make(map[bonvoyagev1.NodeCapabilityType]uint32, len(capabilities))
	for _, capability := range capabilities {
		if capability == nil {
			return fmt.Errorf("capability is nil")
		}
		typeID := capability.GetCapability()
		version, known := required[typeID]
		if !known || typeID == bonvoyagev1.NodeCapabilityType_NODE_CAPABILITY_TYPE_UNSPECIFIED {
			return fmt.Errorf("capability %d is unsupported", typeID)
		}
		if capability.GetVersion() != version {
			return fmt.Errorf("capability %s requires version %d", typeID, version)
		}
		if _, exists := seen[typeID]; exists {
			return fmt.Errorf("capability %s is duplicated", typeID)
		}
		seen[typeID] = capability.GetVersion()
	}
	for typeID, version := range required {
		if seen[typeID] != version {
			return fmt.Errorf("required capability %s version %d is missing", typeID, version)
		}
	}
	return nil
}

func runtimeState(nodeID, processInstance string, state *bonvoyagev1.NodeRuntimeState) (rollout.RuntimeState, error) {
	if state == nil {
		return rollout.RuntimeState{}, fmt.Errorf("runtime state is required")
	}
	active, err := referenceFromMessage("active snapshot", state.GetActiveSnapshot())
	if err != nil {
		return rollout.RuntimeState{}, err
	}
	if active != (rollout.Reference{}) && state.GetActiveShardCount() == 0 {
		return rollout.RuntimeState{}, fmt.Errorf("active snapshot requires a non-zero shard count")
	}
	if active == (rollout.Reference{}) && state.GetActiveShardCount() != 0 {
		return rollout.RuntimeState{}, fmt.Errorf("active shard count requires an active snapshot")
	}
	converted := rollout.RuntimeState{
		NodeID:           nodeID,
		ProcessInstance:  processInstance,
		LastSequence:     state.GetLastRolloutSequence(),
		Active:           active,
		ActiveShardCount: state.GetActiveShardCount(),
	}
	if prepared := state.GetPreparedSnapshot(); prepared != nil {
		reference, err := referenceFromMessage("prepared snapshot", prepared.GetSnapshot())
		if err != nil {
			return rollout.RuntimeState{}, err
		}
		if reference == (rollout.Reference{}) || prepared.GetRolloutSequence() == 0 || prepared.GetShardCount() == 0 {
			return rollout.RuntimeState{}, fmt.Errorf("prepared snapshot requires a sequence, reference, and shard count")
		}
		if prepared.GetRolloutSequence() > state.GetLastRolloutSequence() {
			return rollout.RuntimeState{}, fmt.Errorf("prepared sequence exceeds last accepted sequence")
		}
		converted.Prepared = &rollout.PreparedState{
			Sequence: prepared.GetRolloutSequence(), Artifact: reference, ShardCount: prepared.GetShardCount(),
		}
	}
	return converted, nil
}

func validateHeartbeat(
	heartbeat *bonvoyagev1.NodeHeartbeat,
	owner *streamOwner,
	now time.Time,
	maxClockSkew time.Duration,
	maxObservationAge time.Duration,
) (rollout.RuntimeState, error) {
	if heartbeat == nil {
		return rollout.RuntimeState{}, fmt.Errorf("heartbeat is required")
	}
	if err := rejectUnknown(heartbeat); err != nil {
		return rollout.RuntimeState{}, err
	}
	if heartbeat.GetNodeId() != owner.nodeID || heartbeat.GetProcessInstanceId() != owner.processInstance {
		return rollout.RuntimeState{}, fmt.Errorf("heartbeat identity does not match the stream owner")
	}
	if err := validateObservedTime("heartbeat observed_at", heartbeat.GetObservedAt(), now, maxClockSkew, maxObservationAge); err != nil {
		return rollout.RuntimeState{}, err
	}
	state, err := runtimeState(owner.nodeID, owner.processInstance, heartbeat.GetRuntimeState())
	if err != nil {
		return rollout.RuntimeState{}, err
	}
	state.ObservedAt = heartbeat.GetObservedAt().AsTime().UTC()
	return state, nil
}

func validateReport(
	report *bonvoyagev1.NodeRolloutReport,
	owner *streamOwner,
	now time.Time,
	maxClockSkew time.Duration,
	maxObservationAge time.Duration,
) (rollout.Report, error) {
	if report == nil {
		return rollout.Report{}, fmt.Errorf("rollout report is required")
	}
	if err := rejectUnknown(report); err != nil {
		return rollout.Report{}, err
	}
	if report.GetNodeId() != owner.nodeID || report.GetProcessInstanceId() != owner.processInstance {
		return rollout.Report{}, fmt.Errorf("rollout report identity does not match the stream owner")
	}
	if report.GetRolloutSequence() == 0 {
		return rollout.Report{}, fmt.Errorf("rollout report sequence is zero")
	}
	if err := validateObservedTime("rollout completed_at", report.GetCompletedAt(), now, maxClockSkew, maxObservationAge); err != nil {
		return rollout.Report{}, err
	}
	artifact, err := referenceFromMessage("report snapshot", report.GetSnapshot())
	if err != nil || artifact == (rollout.Reference{}) {
		if err == nil {
			err = fmt.Errorf("report snapshot is required")
		}
		return rollout.Report{}, err
	}
	previous, err := referenceFromMessage("previous active snapshot", report.GetPreviousActiveSnapshot())
	if err != nil {
		return rollout.Report{}, err
	}
	current, err := referenceFromMessage("current active snapshot", report.GetCurrentActiveSnapshot())
	if err != nil {
		return rollout.Report{}, err
	}
	operation, err := rolloutOperation(report.GetOperation())
	if err != nil {
		return rollout.Report{}, err
	}
	result, err := rolloutResult(report.GetResult())
	if err != nil {
		return rollout.Report{}, err
	}
	if len(report.GetErrors()) > maxValidationIssues {
		return rollout.Report{}, fmt.Errorf("validation issue count exceeds %d", maxValidationIssues)
	}
	issues := make([]rollout.Issue, 0, len(report.GetErrors()))
	for _, issue := range report.GetErrors() {
		if issue == nil {
			return rollout.Report{}, fmt.Errorf("validation issue is nil")
		}
		if err := validateIdentifier("validation issue code", issue.GetCode()); err != nil {
			return rollout.Report{}, err
		}
		if err := validateText("validation issue field path", issue.GetFieldPath(), maxFieldPathBytes, false); err != nil {
			return rollout.Report{}, err
		}
		if err := validateText("validation issue message", issue.GetMessage(), maxIssueBytes, true); err != nil {
			return rollout.Report{}, err
		}
		issues = append(issues, rollout.Issue{
			Code: issue.GetCode(), FieldPath: issue.GetFieldPath(), Message: issue.GetMessage(),
		})
	}
	return rollout.Report{
		NodeID: owner.nodeID, ProcessInstance: owner.processInstance,
		Sequence: report.GetRolloutSequence(), Artifact: artifact, Operation: operation, Result: result,
		PreviousActive: previous, CurrentActive: current,
		ShardCount: report.GetShardCount(), CompletedShards: report.GetCompletedShards(), Issues: issues,
		CompletedAt: report.GetCompletedAt().AsTime().UTC(),
	}, nil
}

func validateObservedTime(
	name string,
	value *timestamppb.Timestamp,
	now time.Time,
	maxClockSkew time.Duration,
	maxObservationAge time.Duration,
) error {
	if value == nil {
		return fmt.Errorf("%s is required", name)
	}
	if err := value.CheckValid(); err != nil {
		return fmt.Errorf("%s is invalid: %w", name, err)
	}
	observed := value.AsTime()
	if observed.After(now.Add(maxClockSkew)) {
		return fmt.Errorf("%s is too far in the future", name)
	}
	if observed.Before(now.Add(-maxObservationAge)) {
		return fmt.Errorf("%s is stale", name)
	}
	return nil
}

func rolloutOperation(operation bonvoyagev1.RolloutOperation) (rollout.Operation, error) {
	switch operation {
	case bonvoyagev1.RolloutOperation_ROLLOUT_OPERATION_PREPARE:
		return rollout.OperationPrepare, nil
	case bonvoyagev1.RolloutOperation_ROLLOUT_OPERATION_ACTIVATE:
		return rollout.OperationActivate, nil
	case bonvoyagev1.RolloutOperation_ROLLOUT_OPERATION_CANCEL:
		return rollout.OperationCancel, nil
	default:
		return "", fmt.Errorf("rollout operation %d is unsupported", operation)
	}
}

func rolloutResult(result bonvoyagev1.AcknowledgementResult) (rollout.Result, error) {
	switch result {
	case bonvoyagev1.AcknowledgementResult_ACKNOWLEDGEMENT_RESULT_ACK:
		return rollout.ResultACK, nil
	case bonvoyagev1.AcknowledgementResult_ACKNOWLEDGEMENT_RESULT_NACK:
		return rollout.ResultNACK, nil
	default:
		return "", fmt.Errorf("rollout result %d is unsupported", result)
	}
}

func referenceFromMessage(name string, reference *bonvoyagev1.SnapshotReference) (rollout.Reference, error) {
	if reference == nil {
		return rollout.Reference{}, nil
	}
	return referenceFromParts(name, reference.GetSnapshotId(), reference.GetSnapshotSha256())
}

func referenceFromParts(name, id string, digest []byte) (rollout.Reference, error) {
	if id == "" && len(digest) == 0 {
		return rollout.Reference{}, nil
	}
	if err := validateText(name+" ID", id, 128, true); err != nil {
		return rollout.Reference{}, err
	}
	if len(digest) != sha256.Size {
		return rollout.Reference{}, fmt.Errorf("%s digest must contain %d bytes", name, sha256.Size)
	}
	var converted [sha256.Size]byte
	copy(converted[:], digest)
	if converted == ([sha256.Size]byte{}) {
		return rollout.Reference{}, fmt.Errorf("%s digest is zero", name)
	}
	return rollout.Reference{ID: id, SHA256: converted}, nil
}

func reportEventID(report rollout.Report) string {
	digest := sha256.New()
	_, _ = io.WriteString(digest, report.NodeID)
	_, _ = digest.Write([]byte{0})
	_, _ = io.WriteString(digest, report.ProcessInstance)
	_, _ = digest.Write([]byte{0})
	var sequence [8]byte
	binary.BigEndian.PutUint64(sequence[:], report.Sequence)
	_, _ = digest.Write(sequence[:])
	_, _ = digest.Write([]byte{0})
	_, _ = io.WriteString(digest, string(report.Operation))
	return fmt.Sprintf("grpc-report-%x", digest.Sum(nil))
}

func reconnectEventID(random io.Reader) (string, error) {
	var nonce [16]byte
	if _, err := io.ReadFull(random, nonce[:]); err != nil {
		return "", fmt.Errorf("generate reconnect event ID: %w", err)
	}
	return fmt.Sprintf("grpc-reconnect-%x", nonce), nil
}

func policyEventID(random io.Reader) (string, error) {
	var nonce [16]byte
	if _, err := io.ReadFull(random, nonce[:]); err != nil {
		return "", fmt.Errorf("generate policy event ID: %w", err)
	}
	return fmt.Sprintf("policy-evaluate-%x", nonce), nil
}

func (server *Server) wireCommand(command rollout.Command) (*bonvoyagev1.StreamSnapshotsResponse, error) {
	if command.Sequence == 0 {
		return nil, fmt.Errorf("command sequence is zero")
	}
	if err := validateCommandReference("expected active snapshot", command.ExpectedActive, false); err != nil {
		return nil, err
	}
	wire := &bonvoyagev1.RolloutCommand{RolloutSequence: command.Sequence}
	switch command.Operation {
	case rollout.OperationPrepare:
		if err := validateCommandReference("prepare snapshot", command.Artifact.Reference, true); err != nil {
			return nil, err
		}
		if len(command.Artifact.Bytes) == 0 || sha256.Sum256(command.Artifact.Bytes) != command.Artifact.Reference.SHA256 {
			return nil, fmt.Errorf("prepare command artifact is invalid")
		}
		snapshot := new(bonvoyagev1.Snapshot)
		if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(command.Artifact.Bytes, snapshot); err != nil {
			return nil, fmt.Errorf("decode prepare snapshot: %w", err)
		}
		if err := rejectUnknown(snapshot); err != nil {
			return nil, err
		}
		canonical, err := (proto.MarshalOptions{Deterministic: true}).Marshal(snapshot)
		if err != nil {
			return nil, fmt.Errorf("encode prepare snapshot: %w", err)
		}
		if !bytes.Equal(canonical, command.Artifact.Bytes) {
			return nil, fmt.Errorf("prepare snapshot is not deterministically encoded")
		}
		if snapshot.GetSnapshotId() != command.Artifact.Reference.ID ||
			snapshot.GetSchemaVersion() != server.requiredSchema ||
			sha256.Sum256(canonical) != command.Artifact.Reference.SHA256 {
			return nil, fmt.Errorf("prepare snapshot metadata disagrees with the rollout command")
		}
		if err := validateText("minimum data-plane version", snapshot.GetMinimumDataplaneVersion(), 128, true); err != nil {
			return nil, err
		}
		wire.Command = &bonvoyagev1.RolloutCommand_Prepare{Prepare: &bonvoyagev1.PrepareSnapshot{
			Artifact: &bonvoyagev1.SnapshotArtifact{
				Snapshot:                commandReference(command.Artifact.Reference),
				SnapshotBytes:           append([]byte(nil), canonical...),
				SchemaVersion:           snapshot.GetSchemaVersion(),
				MinimumDataplaneVersion: snapshot.GetMinimumDataplaneVersion(),
				RequiredCapabilities:    wireCapabilities(server.requiredCapabilities),
			},
			ExpectedActiveSnapshot: commandReference(command.ExpectedActive),
		}}
	case rollout.OperationActivate:
		if err := validateCommandReference("prepared snapshot", command.Artifact.Reference, true); err != nil {
			return nil, err
		}
		wire.Command = &bonvoyagev1.RolloutCommand_Activate{Activate: &bonvoyagev1.ActivateSnapshot{
			PreparedSnapshot:       commandReference(command.Artifact.Reference),
			ExpectedActiveSnapshot: commandReference(command.ExpectedActive),
		}}
	case rollout.OperationCancel:
		if err := validateCommandReference("cancel snapshot", command.Artifact.Reference, true); err != nil {
			return nil, err
		}
		if err := validateText("cancel reason", command.Reason, 1024, true); err != nil {
			return nil, err
		}
		wire.Command = &bonvoyagev1.RolloutCommand_Cancel{Cancel: &bonvoyagev1.CancelRollout{
			Snapshot: commandReference(command.Artifact.Reference), Reason: command.Reason,
		}}
	default:
		return nil, fmt.Errorf("command operation %q is unsupported", command.Operation)
	}
	return &bonvoyagev1.StreamSnapshotsResponse{Command: wire}, nil
}

func validateCommandReference(name string, reference rollout.Reference, required bool) error {
	if reference == (rollout.Reference{}) {
		if required {
			return fmt.Errorf("%s is required", name)
		}
		return nil
	}
	if err := validateText(name+" ID", reference.ID, 128, true); err != nil {
		return err
	}
	if reference.SHA256 == ([sha256.Size]byte{}) {
		return fmt.Errorf("%s digest is zero", name)
	}
	return nil
}

func commandReference(reference rollout.Reference) *bonvoyagev1.SnapshotReference {
	if reference == (rollout.Reference{}) {
		return nil
	}
	return &bonvoyagev1.SnapshotReference{
		SnapshotId: reference.ID, SnapshotSha256: append([]byte(nil), reference.SHA256[:]...),
	}
}

func wireCapabilities(required map[bonvoyagev1.NodeCapabilityType]uint32) []*bonvoyagev1.NodeCapability {
	types := make([]bonvoyagev1.NodeCapabilityType, 0, len(required))
	for typeID := range required {
		types = append(types, typeID)
	}
	slices.Sort(types)
	capabilities := make([]*bonvoyagev1.NodeCapability, 0, len(types))
	for _, typeID := range types {
		capabilities = append(capabilities, &bonvoyagev1.NodeCapability{
			Capability: typeID, Version: required[typeID],
		})
	}
	return capabilities
}
