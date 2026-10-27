package storage

import (
	"context"
	"fmt"
	"math"
	"path/filepath"
	"time"
)

type eventMetadata struct {
	RolloutSequence uint64    `json:"rollout_sequence"`
	Index           uint64    `json:"index"`
	EventID         string    `json:"event_id"`
	Kind            string    `json:"kind"`
	Digest          string    `json:"digest"`
	Size            int64     `json:"size"`
	CreatedAt       time.Time `json:"created_at"`
}

// AppendRolloutEvent durably appends one canonical accepted transition.
func (repository *FileRepository) AppendRolloutEvent(
	ctx context.Context,
	input RolloutEventInput,
) (RolloutEvent, error) {
	if err := contextError(ctx); err != nil {
		return RolloutEvent{}, err
	}
	if err := validateRolloutEventInput(input); err != nil {
		return RolloutEvent{}, err
	}
	payload := append([]byte(nil), input.Payload...)
	digest := Sum(payload)

	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return RolloutEvent{}, err
	}
	if err := contextError(ctx); err != nil {
		return RolloutEvent{}, err
	}
	if _, found := findRolloutBySequence(repository.state.Rollouts, input.RolloutSequence); !found {
		return RolloutEvent{}, fmt.Errorf("rollout sequence %d: %w", input.RolloutSequence, ErrNotFound)
	}

	var lastIndex uint64
	for _, metadata := range repository.state.RolloutEvents {
		if metadata.RolloutSequence != input.RolloutSequence {
			continue
		}
		lastIndex = metadata.Index
		if metadata.EventID != input.EventID {
			continue
		}
		if metadata.Kind != input.Kind || metadata.Digest != digest.String() || metadata.Size != int64(len(payload)) {
			return RolloutEvent{}, fmt.Errorf("rollout event %q changed: %w", input.EventID, ErrConflict)
		}
		return repository.materializeEventLocked(metadata)
	}
	if lastIndex != input.ExpectedPreviousIndex {
		return RolloutEvent{}, fmt.Errorf(
			"rollout event history advanced from index %d to %d: %w",
			input.ExpectedPreviousIndex,
			lastIndex,
			ErrConflict,
		)
	}
	if lastIndex == math.MaxUint64 {
		return RolloutEvent{}, fmt.Errorf("rollout event index exhausted: %w", ErrConflict)
	}
	metadata := eventMetadata{
		RolloutSequence: input.RolloutSequence,
		Index:           lastIndex + 1,
		EventID:         input.EventID,
		Kind:            input.Kind,
		Digest:          digest.String(),
		Size:            int64(len(payload)),
		CreatedAt:       repository.now(),
	}
	if err := repository.putBlob(repository.eventBlobPath(digest), payload, maxRolloutEventBytes); err != nil {
		return RolloutEvent{}, err
	}
	next, err := nextState(repository.state)
	if err != nil {
		return RolloutEvent{}, err
	}
	next.RolloutEvents = append(next.RolloutEvents, metadata)
	if err := repository.writeState(next); err != nil {
		return RolloutEvent{}, err
	}
	repository.state = next
	return eventFromMetadata(metadata, payload), nil
}

// ListRolloutEvents returns immutable journal entries in rollout-index order.
func (repository *FileRepository) ListRolloutEvents(ctx context.Context, sequence uint64) ([]RolloutEvent, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if sequence == 0 {
		return nil, fmt.Errorf("rollout sequence is zero: %w", ErrInvalid)
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return nil, err
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if _, found := findRolloutBySequence(repository.state.Rollouts, sequence); !found {
		return nil, ErrNotFound
	}
	events := make([]RolloutEvent, 0)
	for _, metadata := range repository.state.RolloutEvents {
		if metadata.RolloutSequence != sequence {
			continue
		}
		event, err := repository.materializeEventLocked(metadata)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, nil
}

func validateRolloutEventInput(input RolloutEventInput) error {
	if input.RolloutSequence == 0 {
		return fmt.Errorf("rollout sequence is zero: %w", ErrInvalid)
	}
	if err := validateIdentifier("event ID", input.EventID); err != nil {
		return err
	}
	if err := validateText("event kind", input.Kind, 64, true); err != nil {
		return err
	}
	if len(input.Payload) == 0 || len(input.Payload) > maxRolloutEventBytes {
		return fmt.Errorf("rollout event payload must contain 1-%d bytes: %w", maxRolloutEventBytes, ErrInvalid)
	}
	return nil
}

func (repository *FileRepository) eventBlobDirectory() string {
	return filepath.Join(repository.root, "blobs", "events", "sha256")
}

func (repository *FileRepository) eventBlobPath(digest Digest) string {
	return filepath.Join(repository.eventBlobDirectory(), digest.String()+".json")
}

func (repository *FileRepository) materializeEventLocked(metadata eventMetadata) (RolloutEvent, error) {
	digest, err := ParseDigest(metadata.Digest)
	if err != nil {
		return RolloutEvent{}, fmt.Errorf("stored rollout event digest: %w", ErrCorrupt)
	}
	payload, err := repository.readVerifiedFile(
		repository.eventBlobPath(digest),
		digest,
		metadata.Size,
		maxRolloutEventBytes,
	)
	if err != nil {
		return RolloutEvent{}, err
	}
	return eventFromMetadata(metadata, payload), nil
}

func eventFromMetadata(metadata eventMetadata, payload []byte) RolloutEvent {
	digest, _ := ParseDigest(metadata.Digest)
	return RolloutEvent{
		RolloutSequence: metadata.RolloutSequence,
		Index:           metadata.Index,
		EventID:         metadata.EventID,
		Kind:            metadata.Kind,
		Digest:          digest,
		Payload:         append([]byte(nil), payload...),
		CreatedAt:       metadata.CreatedAt,
	}
}
