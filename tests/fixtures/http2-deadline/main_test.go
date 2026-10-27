package main

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestExpiredObservationCannotPass(t *testing.T) {
	p := &peer{events: make(chan event, 1)}
	p.events <- event{}
	for _, complete := range []bool{false, true} {
		if err := p.wait(time.Now().Add(-time.Millisecond), func() bool { return complete }); !errors.Is(err, errObservationDeadline) {
			t.Fatalf("expired observation (condition=%t) returned %v", complete, err)
		}
	}
}

func TestResponseAssertions(t *testing.T) {
	reset := http2.ErrCodeCancel
	for _, tc := range []struct {
		name     string
		response response
		pass     bool
	}{
		{"intact", response{Status: "200", End: true, body: []byte("ok")}, true},
		{"bad-status", response{Status: "503", End: true, body: []byte("ok")}, false},
		{"corrupt", response{Status: "200", End: true, body: []byte("no")}, false},
		{"truncated", response{Status: "200", End: true, body: []byte("o")}, false},
		{"reset", response{Status: "200", End: true, body: []byte("ok"), Reset: &reset}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &peer{streams: map[uint32]*response{1: &tc.response}}
			err := p.expect(1, []byte("ok"), time.Now().Add(time.Second))
			if (err == nil) != tc.pass {
				t.Fatalf("pass=%t, got %v", tc.pass, err)
			}
		})
	}
}

func TestQuiescenceIncludesEveryActiveGauge(t *testing.T) {
	m := metrics{}
	if !quiescent(m) {
		t.Fatal("zero gauges were not quiescent")
	}
	for _, name := range []string{"active_requests", "active_route_requests", "active_http2_streams", "active_upstream_requests", "active_connections", "active_http2_connections"} {
		m[name] = 1
		if quiescent(m) {
			t.Errorf("ignored %s", name)
		}
		m[name] = 0
	}
}
