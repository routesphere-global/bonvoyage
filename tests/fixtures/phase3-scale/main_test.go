package main

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestBuildSnapshotIsDeterministicAndAddressable(t *testing.T) {
	first := buildSnapshot(3, 8080, 20_000, 600_000)
	second := buildSnapshot(3, 8080, 20_000, 600_000)
	marshal := proto.MarshalOptions{Deterministic: true}
	firstBytes, err := marshal.Marshal(first)
	if err != nil {
		t.Fatalf("marshal first snapshot: %v", err)
	}
	secondBytes, err := marshal.Marshal(second)
	if err != nil {
		t.Fatalf("marshal second snapshot: %v", err)
	}
	if string(firstBytes) != string(secondBytes) {
		t.Fatal("deterministic route snapshot bytes differ")
	}

	routes := first.GetVirtualHosts()[0].GetRoutes()
	if len(routes) != 3 {
		t.Fatalf("route count = %d, want 3", len(routes))
	}
	if got := routes[0].GetMatch().GetPathExact(); got != "/r/000000" {
		t.Fatalf("first path = %q", got)
	}
	if got := routes[2].GetFixedResponse().GetBody(); got != "r000002\n" {
		t.Fatalf("last body = %q", got)
	}
	if got := first.GetRuntimeLimits().GetMaxDownstreamConnectionsPerShard(); got != 20_000 {
		t.Fatalf("connection limit = %d", got)
	}
}
