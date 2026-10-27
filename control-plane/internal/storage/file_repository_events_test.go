package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFileRepositoryPersistsIdempotentRolloutEvents(t *testing.T) {
	root := t.TempDir()
	repository := openTestRepository(t, root, deterministicOptions())
	rollout := createEventTestRollout(t, repository)
	payload := []byte(`{"version":1,"kind":"START"}`)

	first, err := repository.AppendRolloutEvent(context.Background(), RolloutEventInput{
		RolloutSequence: rollout.Sequence,
		EventID:         "event-start-1",
		Kind:            "START",
		Payload:         payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload[0] = 'x'
	if first.Index != 1 || first.Digest != Sum([]byte(`{"version":1,"kind":"START"}`)) {
		t.Fatalf("first event = %#v", first)
	}

	duplicate, err := repository.AppendRolloutEvent(context.Background(), RolloutEventInput{
		RolloutSequence: rollout.Sequence,
		EventID:         "event-start-1",
		Kind:            "START",
		Payload:         []byte(`{"version":1,"kind":"START"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if duplicate.Index != first.Index || duplicate.Digest != first.Digest ||
		!bytes.Equal(duplicate.Payload, first.Payload) {
		t.Fatalf("idempotent event changed: first=%#v duplicate=%#v", first, duplicate)
	}
	if _, err := repository.AppendRolloutEvent(context.Background(), RolloutEventInput{
		RolloutSequence: rollout.Sequence,
		EventID:         "event-start-1",
		Kind:            "CANCEL",
		Payload:         []byte(`{"version":1,"kind":"CANCEL"}`),
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed event ID error = %v", err)
	}
	second, err := repository.AppendRolloutEvent(context.Background(), RolloutEventInput{
		RolloutSequence:       rollout.Sequence,
		ExpectedPreviousIndex: 1,
		EventID:               "event-report-1",
		Kind:                  "REPORT",
		Payload:               []byte(`{"version":1,"kind":"REPORT"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.Index != 2 {
		t.Fatalf("second event index = %d", second.Index)
	}

	events, err := repository.ListRolloutEvents(context.Background(), rollout.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].EventID != "event-start-1" || events[1].EventID != "event-report-1" {
		t.Fatalf("events = %#v", events)
	}
	events[0].Payload[0] = 'x'
	again, err := repository.ListRolloutEvents(context.Background(), rollout.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if again[0].Payload[0] != '{' {
		t.Fatal("returned event payload aliases repository storage")
	}
	assertPrivateMode(t, repository.eventBlobPath(first.Digest), 0o600)
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := openTestRepository(t, root, deterministicOptions())
	t.Cleanup(func() { _ = reopened.Close() })
	restored, err := reopened.ListRolloutEvents(context.Background(), rollout.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != 2 || restored[0].Digest != first.Digest || restored[1].Digest != second.Digest {
		t.Fatalf("restored events = %#v", restored)
	}
}

func TestFileRepositoryValidatesRolloutEventInputs(t *testing.T) {
	repository := openTestRepository(t, t.TempDir(), deterministicOptions())
	t.Cleanup(func() { _ = repository.Close() })
	rollout := createEventTestRollout(t, repository)
	valid := RolloutEventInput{
		RolloutSequence: rollout.Sequence,
		EventID:         "event-valid",
		Kind:            "START",
		Payload:         []byte(`{"version":1}`),
	}
	tests := []struct {
		name   string
		mutate func(*RolloutEventInput)
	}{
		{"zero sequence", func(input *RolloutEventInput) { input.RolloutSequence = 0 }},
		{"missing rollout", func(input *RolloutEventInput) { input.RolloutSequence = 99 }},
		{"invalid event ID", func(input *RolloutEventInput) { input.EventID = "bad event" }},
		{"empty kind", func(input *RolloutEventInput) { input.Kind = "" }},
		{"control kind", func(input *RolloutEventInput) { input.Kind = "START\n" }},
		{"empty payload", func(input *RolloutEventInput) { input.Payload = nil }},
		{"oversized payload", func(input *RolloutEventInput) { input.Payload = make([]byte, maxRolloutEventBytes+1) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := valid
			test.mutate(&input)
			if _, err := repository.AppendRolloutEvent(context.Background(), input); err == nil ||
				(!errors.Is(err, ErrInvalid) && !errors.Is(err, ErrNotFound)) {
				t.Fatalf("AppendRolloutEvent error = %v", err)
			}
		})
	}
	if _, err := repository.ListRolloutEvents(context.Background(), 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero sequence list error = %v", err)
	}
	if _, err := repository.ListRolloutEvents(context.Background(), 99); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing rollout list error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := repository.AppendRolloutEvent(cancelled, valid); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled append error = %v", err)
	}
}

func TestFileRepositoryAppendsConcurrentRolloutEventsExactlyOnce(t *testing.T) {
	repository := openTestRepository(t, t.TempDir(), deterministicOptions())
	t.Cleanup(func() { _ = repository.Close() })
	rollout := createEventTestRollout(t, repository)

	const count = 24
	indexes := make(chan uint64, count)
	errorsSeen := make(chan error, count)
	var wait sync.WaitGroup
	for index := range count {
		wait.Add(1)
		go func() {
			defer wait.Done()
			event, err := repository.AppendRolloutEvent(context.Background(), RolloutEventInput{
				RolloutSequence:       rollout.Sequence,
				ExpectedPreviousIndex: 0,
				EventID:               fmt.Sprintf("event-concurrent-%02d", index),
				Kind:                  "REPORT",
				Payload:               []byte(fmt.Sprintf(`{"version":1,"ordinal":%d}`, index)),
			})
			if err != nil {
				errorsSeen <- err
				return
			}
			indexes <- event.Index
		}()
	}
	wait.Wait()
	close(indexes)
	close(errorsSeen)
	conflicts := 0
	for err := range errorsSeen {
		if !errors.Is(err, ErrConflict) {
			t.Error(err)
		}
		conflicts++
	}
	got := make([]uint64, 0, count)
	for index := range indexes {
		got = append(got, index)
	}
	slices.Sort(got)
	want := []uint64{1}
	if !slices.Equal(got, want) {
		t.Fatalf("event indexes = %v, want %v", got, want)
	}
	if conflicts != count-1 {
		t.Fatalf("conflicts = %d, want %d", conflicts, count-1)
	}
	events, err := repository.ListRolloutEvents(context.Background(), rollout.Sequence)
	if err != nil || len(events) != 1 {
		t.Fatalf("event count = %d, err=%v", len(events), err)
	}
}

func TestFileRepositoryConcurrentExactRolloutEventRetriesShareOneIndex(t *testing.T) {
	repository := openTestRepository(t, t.TempDir(), deterministicOptions())
	t.Cleanup(func() { _ = repository.Close() })
	rollout := createEventTestRollout(t, repository)

	const count = 24
	results := make(chan RolloutEvent, count)
	errorsSeen := make(chan error, count)
	var wait sync.WaitGroup
	for range count {
		wait.Add(1)
		go func() {
			defer wait.Done()
			event, err := repository.AppendRolloutEvent(context.Background(), RolloutEventInput{
				RolloutSequence:       rollout.Sequence,
				ExpectedPreviousIndex: 0,
				EventID:               "event-same",
				Kind:                  "START",
				Payload:               []byte(`{"version":1}`),
			})
			if err != nil {
				errorsSeen <- err
				return
			}
			results <- event
		}()
	}
	wait.Wait()
	close(results)
	close(errorsSeen)
	for err := range errorsSeen {
		t.Error(err)
	}
	for event := range results {
		if event.Index != 1 || event.EventID != "event-same" {
			t.Fatalf("event = %#v", event)
		}
	}
	events, err := repository.ListRolloutEvents(context.Background(), rollout.Sequence)
	if err != nil || len(events) != 1 {
		t.Fatalf("event count = %d, err=%v", len(events), err)
	}
}

func TestFileRepositoryRejectsRolloutEventStateInvariantViolations(t *testing.T) {
	repository := openTestRepository(t, t.TempDir(), deterministicOptions())
	t.Cleanup(func() { _ = repository.Close() })
	rollout := createEventTestRollout(t, repository)
	event, err := repository.AppendRolloutEvent(context.Background(), RolloutEventInput{
		RolloutSequence: rollout.Sequence,
		EventID:         "event-state-1",
		Kind:            "START",
		Payload:         []byte(`{"version":1}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*persistedState)
	}{
		{"missing rollout", func(state *persistedState) { state.RolloutEvents[0].RolloutSequence = 99 }},
		{"noncontiguous index", func(state *persistedState) { state.RolloutEvents[0].Index = 2 }},
		{"invalid event ID", func(state *persistedState) { state.RolloutEvents[0].EventID = "bad event" }},
		{"empty kind", func(state *persistedState) { state.RolloutEvents[0].Kind = "" }},
		{"noncanonical digest", func(state *persistedState) {
			state.RolloutEvents[0].Digest = strings.ToUpper(state.RolloutEvents[0].Digest)
		}},
		{"zero size", func(state *persistedState) { state.RolloutEvents[0].Size = 0 }},
		{"oversized", func(state *persistedState) { state.RolloutEvents[0].Size = maxRolloutEventBytes + 1 }},
		{"zero date", func(state *persistedState) { state.RolloutEvents[0].CreatedAt = time.Time{} }},
		{"duplicate ID", func(state *persistedState) {
			duplicate := state.RolloutEvents[0]
			duplicate.Index = 2
			state.RolloutEvents = append(state.RolloutEvents, duplicate)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := cloneState(repository.state)
			test.mutate(&state)
			if err := repository.validateState(state); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("validateState error = %v", err)
			}
		})
	}
	if event.Digest.IsZero() {
		t.Fatal("event digest is unexpectedly zero")
	}
}

func TestFileRepositoryRejectsCorruptRolloutEventBlobOnReopen(t *testing.T) {
	root := t.TempDir()
	repository := openTestRepository(t, root, deterministicOptions())
	rollout := createEventTestRollout(t, repository)
	event, err := repository.AppendRolloutEvent(context.Background(), RolloutEventInput{
		RolloutSequence: rollout.Sequence,
		EventID:         "event-corrupt-1",
		Kind:            "START",
		Payload:         []byte(`{"version":1}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	path := repository.eventBlobPath(event.Digest)
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenFileRepository(root, deterministicOptions()); !errors.Is(err, ErrCorrupt) {
		if err == nil {
			_ = reopened.Close()
		}
		t.Fatalf("corrupt event reopen error = %v", err)
	}
}

func createEventTestRollout(t *testing.T, repository Repository) RolloutRecord {
	t.Helper()
	desired := createDesired(t, repository, "desired-event-test", testDesiredDocument(t))
	artifact := createArtifact(t, repository, desired, "0.4.0")
	return allocateRollout(t, repository, RolloutInput{
		RequestID:         "rollout-event-test",
		ArtifactDigest:    artifact.Digest,
		DesiredRevisionID: desired.ID,
		CompilerVersion:   "0.4.0",
		TargetNodeIDs:     []string{"node-a", "node-b"},
		SourceChannel:     SourceSystem,
		Actor:             "event-test",
		Reason:            "exercise durable event journal",
	})
}
