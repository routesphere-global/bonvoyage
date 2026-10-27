package adminservice

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/discovery"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/identity"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
)

func TestNodeManagementUsesDurableIdentityAndRetirementPreconditions(t *testing.T) {
	fixture := newAdminFixture(t)
	identityRepository, err := identity.OpenFileRepository(
		filepath.Join(t.TempDir(), "identity"), identity.FileRepositoryOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityRepository.Close() })
	revocations := filepath.Join(t.TempDir(), "revocations.json")
	if _, err := discovery.InitializeRevocationDocument(
		revocations, time.Now().UTC(), DefaultRevocationValidity,
	); err != nil {
		t.Fatal(err)
	}
	service, err := New(fixture.repository, fixture.runtime, WithNodeLifecycle(
		identityRepository,
		NodeLifecycleOptions{
			Audience: "standalone-test", EnrollmentAddress: "127.0.0.1:9444",
			ServerName: "localhost", TrustDomain: "routesphere.test",
			NodePathPrefix: "/bonvoyage/nodes/", RevocationPath: revocations,
			RevocationValidFor: DefaultRevocationValidity,
		},
	))
	if err != nil {
		t.Fatal(err)
	}
	administrator := Principal{
		Actor: "spiffe://admin.test/operators/root", Role: RoleAdministrator,
		SourceChannel: storage.SourceConsole,
	}
	viewer := administrator
	viewer.Role = RoleViewer
	if _, err := service.CreateNode(context.Background(), viewer, CreateNodeInput{
		RequestID: "viewer-create-node", Reason: "must fail", NodeID: "node-b",
		Metadata: NodeMetadataInput{DisplayName: "Node B", Group: "default"},
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("viewer create error = %v", err)
	}

	created, err := service.CreateNode(context.Background(), administrator, CreateNodeInput{
		RequestID: "admin-create-node-b", Reason: "add replacement capacity", NodeID: "node-b",
		Metadata: NodeMetadataInput{
			DisplayName: "Singapore edge B", Group: "edge-sin",
			Labels: map[string]string{"zone": "ap-southeast-1b"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Enrollment == nil || created.Enrollment.Token == "" || created.Node.Version != 1 ||
		created.Node.Lifecycle != identity.NodeLifecycleEnrolling || created.Node.EligibleForRollout {
		t.Fatalf("created node = %#v", created)
	}
	replayed, err := service.CreateNode(context.Background(), administrator, CreateNodeInput{
		RequestID: "admin-create-node-b", Reason: "add replacement capacity", NodeID: "node-b",
		Metadata: NodeMetadataInput{
			DisplayName: "Singapore edge B", Group: "edge-sin",
			Labels: map[string]string{"zone": "ap-southeast-1b"},
		},
	})
	if err != nil || !replayed.Replayed || replayed.Enrollment != nil {
		t.Fatalf("replayed creation = %#v, err=%v", replayed, err)
	}

	updated, err := service.UpdateNode(context.Background(), administrator, UpdateNodeInput{
		RequestID: "admin-update-node-b", Reason: "assign payments role", NodeID: "node-b",
		ExpectedVersion: 1,
		Metadata: NodeMetadataInput{
			DisplayName: "Singapore payments B", Group: "payments",
			Labels: map[string]string{"zone": "ap-southeast-1b", "workload": "payments"},
		},
	})
	if err != nil || updated.Node.Version != 2 || updated.Node.Metadata.Group != "payments" {
		t.Fatalf("updated node = %#v, err=%v", updated, err)
	}
	draining, err := service.DrainNode(context.Background(), administrator, TransitionNodeInput{
		RequestID: "admin-drain-node-b", Reason: "retire unused enrollment", NodeID: "node-b",
		ExpectedVersion: 2,
	})
	if err != nil || draining.Node.Lifecycle != identity.NodeLifecycleDraining ||
		draining.Node.EligibleForRollout {
		t.Fatalf("draining node = %#v, err=%v", draining, err)
	}
	fixture.runtime.mu.Lock()
	fixture.runtime.connections = []discovery.ConnectionSnapshot{{NodeID: "node-b"}}
	fixture.runtime.mu.Unlock()
	if _, err := service.RetireNode(context.Background(), administrator, TransitionNodeInput{
		RequestID: "admin-retire-node-b", Reason: "finish retirement", NodeID: "node-b",
		ExpectedVersion: 3,
	}); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("connected retirement error = %v", err)
	}
	fixture.runtime.mu.Lock()
	fixture.runtime.connections = nil
	fixture.runtime.mu.Unlock()
	retired, err := service.RetireNode(context.Background(), administrator, TransitionNodeInput{
		RequestID: "admin-retire-node-b", Reason: "finish retirement", NodeID: "node-b",
		ExpectedVersion: 3,
	})
	if err != nil || retired.Node.Lifecycle != identity.NodeLifecycleRetired || retired.Node.Version != 4 {
		t.Fatalf("retired node = %#v, err=%v", retired, err)
	}
	events, err := service.ListNodeEvents(
		context.Background(), administrator, "node-b", 0, DefaultNodeEventPageSize,
	)
	if err != nil || len(events.Events) != 4 || events.TotalEvents != 4 || events.HasMore ||
		events.NextAfterIndex != 4 {
		t.Fatalf("node events = %#v, err=%v", events, err)
	}
}

func TestNodeEventsAreCursorBounded(t *testing.T) {
	service, administrator := newNodeLifecycleService(t)
	if _, err := service.CreateNode(context.Background(), administrator, CreateNodeInput{
		RequestID: "create-node-page", Reason: "pagination fixture", NodeID: "node-page",
		Metadata: NodeMetadataInput{DisplayName: "Node page", Group: "edge"}, TTLSeconds: 60,
	}); err != nil {
		t.Fatal(err)
	}
	for version := uint64(1); version <= 2; version++ {
		if _, err := service.UpdateNode(context.Background(), administrator, UpdateNodeInput{
			RequestID: fmt.Sprintf("update-node-page-%d", version), Reason: "pagination fixture",
			NodeID: "node-page", ExpectedVersion: version,
			Metadata: NodeMetadataInput{DisplayName: fmt.Sprintf("Node page %d", version), Group: "edge"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	first, err := service.ListNodeEvents(context.Background(), administrator, "node-page", 0, 1)
	if err != nil || len(first.Events) != 1 || first.NextAfterIndex == 0 || !first.HasMore || first.TotalEvents != 3 {
		t.Fatalf("first page = %#v, err=%v", first, err)
	}
	second, err := service.ListNodeEvents(
		context.Background(), administrator, "node-page", first.NextAfterIndex, 2,
	)
	if err != nil || len(second.Events) != 2 || second.HasMore || second.NextAfterIndex != 3 {
		t.Fatalf("second page = %#v, err=%v", second, err)
	}
	if _, err := service.ListNodeEvents(
		context.Background(), administrator, "node-page", 0, MaxNodeEventPageSize+1,
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("oversized page error = %v", err)
	}
}

func TestNodeLifecycleRejectsIneligibleRolloutTargets(t *testing.T) {
	fixture := newAdminFixture(t)
	identityRepository, err := identity.OpenFileRepository(t.TempDir(), identity.FileRepositoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityRepository.Close() })
	revocations := filepath.Join(t.TempDir(), "revocations.json")
	if _, err := discovery.InitializeRevocationDocument(
		revocations, time.Now().UTC(), DefaultRevocationValidity,
	); err != nil {
		t.Fatal(err)
	}
	service, err := New(fixture.repository, fixture.runtime, WithNodeLifecycle(
		identityRepository,
		NodeLifecycleOptions{
			Audience: "standalone-test", EnrollmentAddress: "127.0.0.1:9444",
			ServerName: "localhost", TrustDomain: "routesphere.test",
			NodePathPrefix: "/bonvoyage/nodes/", RevocationPath: revocations,
			RevocationValidFor: DefaultRevocationValidity,
		},
	))
	if err != nil {
		t.Fatal(err)
	}
	administrator := Principal{
		Actor: "spiffe://admin.test/operators/root", Role: RoleAdministrator,
		SourceChannel: storage.SourceConsole,
	}
	if _, err := service.CreateNode(context.Background(), administrator, CreateNodeInput{
		RequestID: "create-unenrolled-node", Reason: "test target eligibility", NodeID: "node-c",
		Metadata: NodeMetadataInput{DisplayName: "Node C", Group: "default"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Preview(context.Background(), administrator, PreviewInput{
		Document: fixture.document, BaselineRolloutSequence: fixture.initial.Sequence,
		TargetNodeIDs: []string{"node-c"},
	}); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("unenrolled target preview error = %v", err)
	}
}

func newNodeLifecycleService(t *testing.T) (*Service, Principal) {
	t.Helper()
	fixture := newAdminFixture(t)
	identityRepository, err := identity.OpenFileRepository(
		filepath.Join(t.TempDir(), "identity"), identity.FileRepositoryOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityRepository.Close() })
	revocations := filepath.Join(t.TempDir(), "revocations.json")
	if _, err := discovery.InitializeRevocationDocument(
		revocations, time.Now().UTC(), DefaultRevocationValidity,
	); err != nil {
		t.Fatal(err)
	}
	service, err := New(fixture.repository, fixture.runtime, WithNodeLifecycle(
		identityRepository,
		NodeLifecycleOptions{
			Audience: "standalone-test", EnrollmentAddress: "127.0.0.1:9444",
			ServerName: "localhost", TrustDomain: "routesphere.test",
			NodePathPrefix: "/bonvoyage/nodes/", RevocationPath: revocations,
			RevocationValidFor: DefaultRevocationValidity,
		},
	))
	if err != nil {
		t.Fatal(err)
	}
	return service, Principal{
		Actor: "spiffe://admin.test/operators/root", Role: RoleAdministrator,
		SourceChannel: storage.SourceConsole,
	}
}
