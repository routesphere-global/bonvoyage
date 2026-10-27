package rolloutservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/rollout"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
)

// Open reconstructs one rollout from immutable lineage and verifies every
// journaled transition before making the service available.
func Open(ctx context.Context, repository Repository, sequence uint64) (*Service, error) {
	if repository == nil {
		return nil, fmt.Errorf("repository is nil: %w", storage.ErrInvalid)
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	record, err := repository.GetRollout(ctx, sequence)
	if err != nil {
		return nil, err
	}
	artifact, err := repository.GetSnapshotArtifact(ctx, record.ArtifactDigest)
	if err != nil {
		return nil, err
	}
	plan := rollout.Plan{
		Sequence: record.Sequence,
		Artifact: rollout.Artifact{
			Reference: referenceFromArtifact(artifact),
			Bytes:     append([]byte(nil), artifact.Bytes...),
		},
		NodeIDs: append([]string(nil), record.TargetNodeIDs...),
	}
	if !record.PreviousArtifactDigest.IsZero() {
		previous, err := repository.GetSnapshotArtifact(ctx, record.PreviousArtifactDigest)
		if err != nil {
			return nil, err
		}
		plan.Previous = referenceFromArtifact(previous)
	}
	if len(record.ExpectedActiveByNode) != 0 {
		plan.PreviousByNode = make(map[string]rollout.Reference, len(record.ExpectedActiveByNode))
		for _, expected := range record.ExpectedActiveByNode {
			artifact, err := repository.GetSnapshotArtifact(ctx, expected.ArtifactDigest)
			if err != nil {
				return nil, err
			}
			plan.PreviousByNode[expected.NodeID] = referenceFromArtifact(artifact)
		}
	}
	if record.Policy.Enabled {
		plan.CreatedAt = record.CreatedAt.UTC()
		plan.Policy = rollout.Policy{
			Enabled: true, Strategy: rollout.Strategy(record.Policy.Strategy),
			CanaryNodeIDs:               append([]string(nil), record.Policy.CanaryNodeIDs...),
			MinimumHealthyCanaryPercent: record.Policy.MinimumHealthyCanaryPercent,
			CanaryObservationWindow:     record.Policy.CanaryObservationWindow,
			PrepareTimeout:              record.Policy.PrepareTimeout,
			ActivationTimeout:           record.Policy.ActivationTimeout,
			HeartbeatStaleAfter:         record.Policy.HeartbeatStaleAfter,
			AutomaticRollback:           record.Policy.AutomaticRollback,
		}
	}
	machine, err := rollout.New(plan)
	if err != nil {
		return nil, fmt.Errorf("construct rollout coordinator: %w", err)
	}
	service := &Service{
		repository: repository, sequence: sequence, machine: machine,
		events: make(map[string]journalEntry),
	}
	events, err := repository.ListRolloutEvents(ctx, sequence)
	if err != nil {
		return nil, err
	}
	for _, event := range events {
		if event.RolloutSequence != sequence || validateEventID(event.EventID) != nil ||
			event.Digest != storage.Sum(event.Payload) {
			return nil, replayFailure("invalid event repository metadata", nil)
		}
		if event.Index != service.lastIndex+1 {
			return nil, replayFailure("event indexes are not contiguous", nil)
		}
		journal, err := decodeJournalRecord(event.Payload)
		if err != nil {
			return nil, replayFailure("decode event "+event.EventID, err)
		}
		if journal.Kind != event.Kind {
			return nil, replayFailure("event kind differs from repository metadata", nil)
		}
		before := durableState(machine)
		commands, transitionError, err, policyResult := applyRecord(machine, journal)
		if err != nil {
			return nil, replayFailure("apply event "+event.EventID, err)
		}
		after := durableState(machine)
		if transitionError != nil && sameDurableState(before, after) {
			return nil, replayFailure("journal contains a rejected transition", transitionError)
		}
		var outcome journalOutcome
		if policyResult == nil {
			outcome, err = makeOutcome(machine, commands, transitionError)
		} else {
			outcome, err = makeOutcome(machine, commands, transitionError, *policyResult)
		}
		if err != nil {
			return nil, replayFailure("calculate event outcome", err)
		}
		if !reflect.DeepEqual(outcome, journal.Outcome) {
			return nil, replayFailure("event outcome does not match deterministic replay", nil)
		}
		service.lastIndex = event.Index
		service.events[event.EventID] = journalEntry{
			index: event.Index, record: journal, transitionError: errorFromRecord(journal.Outcome.Error),
		}
	}
	_, nodes := machine.Status()
	for nodeID, node := range nodes {
		if err := machine.Disconnect(nodeID, node.ProcessInstance); err != nil {
			return nil, replayFailure("mark recovered node disconnected", err)
		}
	}
	return service, nil
}

// Start begins the prepare barrier.
func (service *Service) Start(ctx context.Context, eventID string) (Transition, error) {
	input := journalInput{}
	return service.transition(ctx, eventID, eventKindStart, input, service.machine.Start)
}

// Observe durably accepts one completed node operation.
func (service *Service) Observe(ctx context.Context, eventID string, report rollout.Report) (Transition, error) {
	record := reportToRecord(report)
	normalized, err := reportFromRecord(record)
	if err != nil {
		return Transition{}, err
	}
	input := journalInput{Report: &record}
	return service.transition(ctx, eventID, eventKindReport, input, func() ([]rollout.Command, error) {
		return service.machine.Observe(normalized)
	})
}

// Reconnect reconciles node-observed runtime state before any command resumes.
func (service *Service) Reconnect(
	ctx context.Context,
	eventID string,
	state rollout.RuntimeState,
) (Transition, error) {
	record := runtimeToRecord(state)
	normalized, err := runtimeFromRecord(record)
	if err != nil {
		return Transition{}, err
	}
	input := journalInput{Runtime: &record}
	return service.transition(ctx, eventID, eventKindReconnect, input, func() ([]rollout.Command, error) {
		return service.machine.Reconnect(normalized)
	})
}

// Cancel stops a rollout before activation begins and durably binds the
// authenticated operator attribution to the cancellation event.
func (service *Service) Cancel(
	ctx context.Context,
	eventID string,
	cancellation CancellationInput,
) (Transition, error) {
	if strings.TrimSpace(cancellation.Reason) == "" {
		return Transition{}, fmt.Errorf("cancellation reason is empty: %w", rollout.ErrInvalidReport)
	}
	input := journalInput{
		Reason:        cancellation.Reason,
		Actor:         cancellation.Actor,
		SourceChannel: cancellation.SourceChannel,
	}
	return service.transition(ctx, eventID, eventKindCancel, input, func() ([]rollout.Command, error) {
		return service.machine.Cancel(cancellation.Reason)
	})
}

// Disconnect records ephemeral stream loss. Connectivity is deliberately not
// journaled because every process restart begins disconnected.
func (service *Service) Disconnect(nodeID, processInstance string) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.poisoned != nil {
		return service.poisoned
	}
	return service.machine.Disconnect(nodeID, processInstance)
}

// Status exposes authoritative reconstructed state while the service is healthy.
func (service *Service) Status() (rollout.Phase, map[string]rollout.NodeSnapshot, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.poisoned != nil {
		return "", nil, service.poisoned
	}
	phase, nodes := service.machine.Status()
	return phase, nodes, nil
}

// Sequence returns the immutable sequence owned by this service.
func (service *Service) Sequence() uint64 {
	return service.sequence
}

// Diagnostics returns an ordered, bounded projection of accepted journal
// events. The repository remains the authority; callers never receive raw
// event payloads or snapshot bytes through this status surface.
func (service *Service) Diagnostics(ctx context.Context) ([]Diagnostic, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.poisoned != nil {
		return nil, service.poisoned
	}
	events, err := service.repository.ListRolloutEvents(ctx, service.sequence)
	if err != nil {
		return nil, err
	}
	result := make([]Diagnostic, 0, len(events))
	for _, event := range events {
		entry, found := service.events[event.EventID]
		if !found || entry.index != event.Index {
			return nil, replayFailure("diagnostic event differs from replayed journal", nil)
		}
		diagnostic := Diagnostic{
			Index: event.Index, EventID: event.EventID, Kind: event.Kind,
			Digest: event.Digest, Phase: entry.record.Outcome.Phase, CreatedAt: event.CreatedAt,
		}
		if entry.record.Outcome.Error != nil {
			diagnostic.Error = &DiagnosticError{
				Code: entry.record.Outcome.Error.Code, Message: entry.record.Outcome.Error.Message,
			}
		}
		if entry.record.Input.Report != nil {
			report, err := reportFromRecord(*entry.record.Input.Report)
			if err != nil {
				return nil, replayFailure("decode diagnostic report", err)
			}
			diagnostic.Report = &ReportDiagnostic{
				NodeID: report.NodeID, ProcessInstance: report.ProcessInstance,
				Sequence: report.Sequence, Operation: report.Operation, Result: report.Result,
				ShardCount: report.ShardCount, CompletedShards: report.CompletedShards,
				Issues: append([]rollout.Issue(nil), report.Issues...),
			}
		}
		if entry.record.Input.Policy != nil {
			observation := policyFromRecord(*entry.record.Input.Policy)
			diagnostic.Policy = &PolicyDiagnostic{
				ObservedAt: observation.ObservedAt,
				Decision:   entry.record.Outcome.PolicyDecision,
				Reason:     entry.record.Outcome.PolicyReason,
				Nodes:      append([]rollout.NodeHealth(nil), observation.Nodes...),
			}
		}
		if entry.record.Kind == eventKindCancel {
			attribution := CancellationAttributionRecorded
			if entry.record.Version == legacyJournalVersion {
				attribution = CancellationAttributionLegacyUnavailable
			}
			diagnostic.Cancellation = &CancellationDiagnostic{
				Reason:            entry.record.Input.Reason,
				Actor:             entry.record.Input.Actor,
				SourceChannel:     entry.record.Input.SourceChannel,
				AttributionStatus: attribution,
			}
		}
		result = append(result, diagnostic)
	}
	slices.SortFunc(result, func(left, right Diagnostic) int {
		if left.Index < right.Index {
			return -1
		}
		if left.Index > right.Index {
			return 1
		}
		return 0
	})
	return result, nil
}

// PendingCommands is an inspection projection only. After Open, callers must
// use Reconnect and its returned commands rather than dispatching this list.
func (service *Service) PendingCommands() ([]rollout.Command, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.poisoned != nil {
		return nil, service.poisoned
	}
	return cloneCommands(service.machine.PendingCommands()), nil
}

// Policy returns the immutable safety policy owned by this rollout.
func (service *Service) Policy() rollout.Policy {
	service.mu.Lock()
	defer service.mu.Unlock()
	return service.machine.Policy()
}

// Evaluate durably records only a state-changing safe-rollout policy decision.
// Pending observations return rollout.ErrPolicyPending without growing the
// operation journal.
func (service *Service) Evaluate(
	ctx context.Context,
	eventID string,
	observation rollout.PolicyObservation,
) (PolicyTransition, error) {
	record := policyToRecord(observation)
	normalized := policyFromRecord(record)
	input := journalInput{Policy: &record}
	transition, result, err := service.transitionRecord(
		ctx, eventID, eventKindEvaluate, input,
		func() ([]rollout.Command, *rollout.PolicyResult, error) {
			commands, decision, transitionErr := service.machine.Evaluate(normalized)
			return commands, &decision, transitionErr
		},
	)
	if err != nil {
		return PolicyTransition{}, err
	}
	if result == nil {
		return PolicyTransition{}, replayFailure("policy event has no decision", nil)
	}
	return PolicyTransition{Transition: transition, Result: *result}, nil
}

func (service *Service) transition(
	ctx context.Context,
	eventID string,
	kind string,
	input journalInput,
	apply func() ([]rollout.Command, error),
) (Transition, error) {
	transition, _, err := service.transitionRecord(
		ctx, eventID, kind, input,
		func() ([]rollout.Command, *rollout.PolicyResult, error) {
			commands, transitionErr := apply()
			return commands, nil, transitionErr
		},
	)
	return transition, err
}

func (service *Service) transitionRecord(
	ctx context.Context,
	eventID string,
	kind string,
	input journalInput,
	apply func() ([]rollout.Command, *rollout.PolicyResult, error),
) (Transition, *rollout.PolicyResult, error) {
	if err := contextError(ctx); err != nil {
		return Transition{}, nil, err
	}
	if err := validateEventID(eventID); err != nil {
		return Transition{}, nil, err
	}
	if err := validateProspectiveInput(kind, input); err != nil {
		return Transition{}, nil, err
	}

	service.mu.Lock()
	defer service.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return Transition{}, nil, err
	}
	if service.poisoned != nil {
		return Transition{}, nil, service.poisoned
	}
	if existing, found := service.events[eventID]; found {
		if existing.record.Kind != kind ||
			!sameInput(existing.record.Version, kind, existing.record.Input, input) {
			return Transition{}, nil, fmt.Errorf("rollout event %q changed: %w", eventID, storage.ErrConflict)
		}
		var commands []rollout.Command
		if existing.issuedThisProcess && existing.index == service.lastIndex {
			commands = cloneCommands(existing.commands)
		}
		var result *rollout.PolicyResult
		if existing.record.Outcome.PolicyDecision != "" {
			result = &rollout.PolicyResult{
				Decision: existing.record.Outcome.PolicyDecision,
				Reason:   existing.record.Outcome.PolicyReason,
			}
		}
		return Transition{Commands: commands, Replayed: true}, result, existing.transitionError
	}

	before := durableState(service.machine)
	commands, policyResult, transitionError := apply()
	after := durableState(service.machine)
	if transitionError != nil && sameDurableState(before, after) {
		return Transition{}, nil, transitionError
	}
	var outcome journalOutcome
	var err error
	if policyResult == nil {
		outcome, err = makeOutcome(service.machine, commands, transitionError)
	} else {
		outcome, err = makeOutcome(service.machine, commands, transitionError, *policyResult)
	}
	if err != nil {
		return Transition{}, nil, service.poisonLocked(ErrDurabilityUncertain, err)
	}
	record := journalRecord{Version: journalVersion, Kind: kind, Input: input, Outcome: outcome}
	payload, err := json.Marshal(record)
	if err != nil {
		return Transition{}, nil, service.poisonLocked(ErrDurabilityUncertain, err)
	}
	persisted, err := service.repository.AppendRolloutEvent(ctx, storage.RolloutEventInput{
		RolloutSequence: service.sequence, ExpectedPreviousIndex: service.lastIndex,
		EventID: eventID, Kind: kind, Payload: payload,
	})
	if err != nil {
		cause := ErrDurabilityUncertain
		if errors.Is(err, storage.ErrConflict) {
			cause = ErrJournalAdvanced
		}
		return Transition{}, nil, service.poisonLocked(cause, err)
	}
	if persisted.RolloutSequence != service.sequence || persisted.Index != service.lastIndex+1 ||
		persisted.EventID != eventID || persisted.Kind != kind || persisted.Digest != storage.Sum(payload) ||
		!bytes.Equal(persisted.Payload, payload) {
		return Transition{}, nil, service.poisonLocked(ErrJournalAdvanced, errors.New("unexpected append result"))
	}
	service.lastIndex = persisted.Index
	service.events[eventID] = journalEntry{
		index: persisted.Index, record: record, commands: cloneCommands(commands),
		transitionError: transitionError, issuedThisProcess: true,
	}
	return Transition{Commands: cloneCommands(commands)}, policyResult, transitionError
}

func (service *Service) poisonLocked(cause, detail error) error {
	service.poisoned = fmt.Errorf("%w: %w: %w", ErrServicePoisoned, cause, detail)
	return service.poisoned
}

func applyRecord(
	machine *rollout.Coordinator,
	record journalRecord,
) ([]rollout.Command, error, error, *rollout.PolicyResult) {
	switch record.Kind {
	case eventKindStart:
		commands, err := machine.Start()
		return commands, err, nil, nil
	case eventKindReport:
		report, err := reportFromRecord(*record.Input.Report)
		if err != nil {
			return nil, nil, err, nil
		}
		commands, transitionError := machine.Observe(report)
		return commands, transitionError, nil, nil
	case eventKindReconnect:
		state, err := runtimeFromRecord(*record.Input.Runtime)
		if err != nil {
			return nil, nil, err, nil
		}
		commands, transitionError := machine.Reconnect(state)
		return commands, transitionError, nil, nil
	case eventKindCancel:
		commands, err := machine.Cancel(record.Input.Reason)
		return commands, err, nil, nil
	case eventKindEvaluate:
		commands, result, transitionError := machine.Evaluate(policyFromRecord(*record.Input.Policy))
		return commands, transitionError, nil, &result
	default:
		return nil, nil, fmt.Errorf("unknown journal kind %q: %w", record.Kind, storage.ErrCorrupt), nil
	}
}

func referenceFromArtifact(artifact storage.SnapshotArtifact) rollout.Reference {
	return rollout.Reference{ID: artifact.SnapshotID, SHA256: [sha256.Size]byte(artifact.Digest)}
}

func replayFailure(message string, cause error) error {
	if cause == nil {
		return fmt.Errorf("%s: %w: %w", message, ErrReplayMismatch, storage.ErrCorrupt)
	}
	return fmt.Errorf("%s: %v: %w: %w", message, cause, ErrReplayMismatch, storage.ErrCorrupt)
}

func validateEventID(value string) error {
	if len(value) == 0 || len(value) > 128 {
		return fmt.Errorf("event ID must contain 1-128 bytes: %w", storage.ErrInvalid)
	}
	for index, char := range value {
		valid := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' ||
			char >= '0' && char <= '9' || char == '.' || char == '_' || char == ':' || char == '-'
		if !valid || index == 0 && (char == '.' || char == ':' || char == '-') {
			return fmt.Errorf("event ID contains an unsupported character: %w", storage.ErrInvalid)
		}
	}
	return nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context is nil: %w", storage.ErrInvalid)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
