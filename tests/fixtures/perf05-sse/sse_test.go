package main

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestParseSSEPreservesEventsAndHeartbeats(t *testing.T) {
	input := ": keepalive\n\nid: 1\nevent: token\ndata: first\ndata: second\n\ndata: default\n\n"
	var events []sseEvent
	if err := parseSSE(strings.NewReader(input), func(event sseEvent) error {
		events = append(events, event)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 || !events[0].Heartbeat {
		t.Fatalf("unexpected heartbeat parse: %#v", events)
	}
	if events[1].Event != "token" || events[1].ID != "1" ||
		!reflect.DeepEqual(events[1].Data, []string{"first", "second"}) {
		t.Fatalf("unexpected typed event: %#v", events[1])
	}
	if events[2].Event != "message" ||
		!reflect.DeepEqual(events[2].Data, []string{"default"}) {
		t.Fatalf("unexpected default event: %#v", events[2])
	}
}

func TestParseSSEDispatchesFinalUnterminatedEvent(t *testing.T) {
	var events []sseEvent
	if err := parseSSE(strings.NewReader("event: done\ndata: complete"),
		func(event sseEvent) error {
			events = append(events, event)
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Event != "done" {
		t.Fatalf("unexpected final event: %#v", events)
	}
}

func TestParseSSEStopsOnVisitorError(t *testing.T) {
	want := errors.New("stop")
	err := parseSSE(strings.NewReader("data: one\n\ndata: two\n\n"),
		func(sseEvent) error { return want })
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want visitor error", err)
	}
}

func TestFormatSSERoundTripsMultilineData(t *testing.T) {
	formatted := formatSSE("message", "7", "first\nsecond")
	var got sseEvent
	if err := parseSSE(strings.NewReader(formatted), func(event sseEvent) error {
		got = event
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got.Event != "message" || got.ID != "7" ||
		!reflect.DeepEqual(got.Data, []string{"first", "second"}) {
		t.Fatalf("unexpected round trip: %#v", got)
	}
}

func TestParseSSERejectsOversizedLineAndNULID(t *testing.T) {
	if err := parseSSE(strings.NewReader("data: "+strings.Repeat("x", maximumSSELineBytes)+"\n\n"),
		func(sseEvent) error { return nil }); err == nil {
		t.Fatal("oversized line passed")
	}
	if err := parseSSE(strings.NewReader("id: bad\x00id\n\n"),
		func(sseEvent) error { return nil }); err == nil {
		t.Fatal("NUL id passed")
	}
}
