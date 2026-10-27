package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNodeLifecyclePersistsEnrollmentMetadataDrainAndRetirement(t *testing.T) {
	clock := newTestClock()
	files := writeTestAuthorityFiles(t, t.TempDir(), clock.Now())
	authority := loadTestAuthority(t, files, clock)
	root := t.TempDir()
	repository, err := OpenFileRepository(root, FileRepositoryOptions{Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := repository.CreateNodeEnrollment(context.Background(), NodeEnrollmentInput{
		RequestID: "request-create-node-a", Actor: "spiffe://operator.test/admin",
		Reason: "add Singapore edge node", NodeID: "node-a", Audience: "control-plane",
		TTL: 5 * time.Minute,
		Metadata: NodeMetadata{DisplayName: "Singapore edge A", Group: "edge-sin", Labels: map[string]string{
			"zone": "ap-southeast-1a", "role": "gateway",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Replayed || plan.Token.Value == "" || plan.Node.Version != 1 ||
		plan.Node.Lifecycle != NodeLifecycleEnrolling {
		t.Fatalf("initial plan = %#v", plan)
	}
	replayed, err := repository.CreateNodeEnrollment(context.Background(), NodeEnrollmentInput{
		RequestID: "request-create-node-a", Actor: "spiffe://operator.test/admin",
		Reason: "add Singapore edge node", NodeID: "node-a", Audience: "control-plane",
		TTL:      5 * time.Minute,
		Metadata: plan.Node.Metadata,
	})
	if err != nil || !replayed.Replayed || replayed.Token.Value != "" {
		t.Fatalf("replayed plan = %#v, err=%v", replayed, err)
	}
	if _, err := repository.CreateNodeEnrollment(context.Background(), NodeEnrollmentInput{
		RequestID: "request-create-node-a", Actor: "spiffe://operator.test/admin",
		Reason: "changed operation", NodeID: "node-a", Audience: "control-plane",
		TTL:      5 * time.Minute,
		Metadata: NodeMetadata{DisplayName: "Changed display", Group: "default"},
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed replay error = %v", err)
	}

	clock.Add(time.Second)
	reissued, err := repository.ReissueNodeEnrollment(context.Background(), NodeEnrollmentInput{
		RequestID: "request-reissue-node-a", Actor: "spiffe://operator.test/admin",
		Reason: "operator lost the first one-time token", NodeID: "node-a", ExpectedVersion: 1,
		Audience: "control-plane", TTL: 5 * time.Minute, Metadata: plan.Node.Metadata,
	})
	if err != nil || reissued.Node.Version != 2 || reissued.Token.Value == "" {
		t.Fatalf("reissued plan = %#v, err=%v", reissued, err)
	}
	csr, _ := createCSR(t, x509.CertificateRequest{})
	if _, err := repository.Enroll(context.Background(), testAuthorityLoader(authority), EnrollmentRequest{
		Token: plan.Token.Value, NodeID: "node-a", Audience: "control-plane", CSRDER: csr,
	}); !errors.Is(err, ErrEnrollmentRejected) {
		t.Fatalf("superseded enrollment token error = %v", err)
	}
	clock.Add(time.Second)
	if _, err := repository.Enroll(context.Background(), testAuthorityLoader(authority), EnrollmentRequest{
		Token: reissued.Token.Value, NodeID: "node-a", Audience: "control-plane", CSRDER: csr,
	}); err != nil {
		t.Fatal(err)
	}
	summary, err := repository.GetNode(context.Background(), "node-a")
	if err != nil || !summary.Enrolled || summary.Node.Lifecycle != NodeLifecycleReady ||
		summary.Node.Version != 3 || summary.CredentialGeneration == "" {
		t.Fatalf("enrolled summary = %#v, err=%v", summary, err)
	}

	clock.Add(time.Second)
	updated, err := repository.UpdateNodeMetadata(context.Background(), NodeMetadataUpdateInput{
		RequestID: "request-update-node-a", Actor: "spiffe://operator.test/admin",
		Reason: "move to payment gateways", NodeID: "node-a", ExpectedVersion: 3,
		Metadata: NodeMetadata{DisplayName: "Singapore payments A", Group: "payments", Labels: map[string]string{
			"zone": "ap-southeast-1a", "workload": "payments",
		}},
	})
	if err != nil || updated.Replayed || updated.Node.Version != 4 || updated.Node.Metadata.Group != "payments" {
		t.Fatalf("metadata update = %#v, err=%v", updated, err)
	}
	replayedUpdate, err := repository.UpdateNodeMetadata(context.Background(), NodeMetadataUpdateInput{
		RequestID: "request-update-node-a", Actor: "spiffe://operator.test/admin",
		Reason: "move to payment gateways", NodeID: "node-a", ExpectedVersion: 3,
		Metadata: updated.Node.Metadata,
	})
	if err != nil || !replayedUpdate.Replayed || replayedUpdate.Node.Version != 4 {
		t.Fatalf("replayed metadata update = %#v, err=%v", replayedUpdate, err)
	}
	if _, err := repository.UpdateNodeMetadata(context.Background(), NodeMetadataUpdateInput{
		RequestID: "request-update-node-a", Actor: "spiffe://operator.test/admin",
		Reason: "changed replay intent", NodeID: "node-a", ExpectedVersion: 3,
		Metadata: updated.Node.Metadata,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed metadata replay error = %v", err)
	}
	clock.Add(time.Second)
	draining, err := repository.RequestNodeDrain(context.Background(), NodeTransitionInput{
		RequestID: "request-drain-node-a", Actor: "spiffe://operator.test/admin",
		Reason: "planned maintenance", NodeID: "node-a", ExpectedVersion: 4,
	})
	if err != nil || draining.Node.Lifecycle != NodeLifecycleDraining || draining.Node.DrainRequestedAt == nil {
		t.Fatalf("draining node = %#v, err=%v", draining, err)
	}
	clock.Add(time.Second)
	retired, err := repository.RetireNode(context.Background(), NodeTransitionInput{
		RequestID: "request-retire-node-a", Actor: "spiffe://operator.test/admin",
		Reason: "node removed from service", NodeID: "node-a", ExpectedVersion: 5,
	})
	if err != nil || retired.Node.Lifecycle != NodeLifecycleRetired || retired.Node.RetiredAt == nil {
		t.Fatalf("retired node = %#v, err=%v", retired, err)
	}
	if _, err := repository.UpdateNodeMetadata(context.Background(), NodeMetadataUpdateInput{
		RequestID: "request-update-retired", Actor: "spiffe://operator.test/admin",
		Reason: "must fail", NodeID: "node-a", ExpectedVersion: 6, Metadata: retired.Node.Metadata,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("retired metadata error = %v", err)
	}
	events, err := repository.ListNodeEvents(context.Background(), "node-a")
	if err != nil || len(events) != 6 || events[0].Kind != NodeEventEnrollmentCreated ||
		events[len(events)-1].Kind != NodeEventRetired {
		t.Fatalf("events = %#v, err=%v", events, err)
	}
	stateBytes, err := os.ReadFile(repository.statePath())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stateBytes, []byte(plan.Token.Value)) || bytes.Contains(stateBytes, []byte(reissued.Token.Value)) {
		t.Fatal("identity repository retained a raw enrollment token")
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenFileRepository(root, FileRepositoryOptions{Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	restored, err := reopened.GetNode(context.Background(), "node-a")
	if err != nil || restored.Node.Lifecycle != NodeLifecycleRetired || restored.Node.Version != 6 {
		t.Fatalf("restored node = %#v, err=%v", restored, err)
	}
}

func TestNodeReplacementAndManagedRevocationRetainLinkedHistory(t *testing.T) {
	clock := newTestClock()
	files := writeTestAuthorityFiles(t, t.TempDir(), clock.Now())
	authority := loadTestAuthority(t, files, clock)
	repository, err := OpenFileRepository(t.TempDir(), FileRepositoryOptions{Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	oldPlan, err := repository.CreateNodeEnrollment(context.Background(), NodeEnrollmentInput{
		RequestID: "create-old", Actor: "operator", Reason: "create original",
		NodeID: "node-old", Audience: "control-plane",
		Metadata: NodeMetadata{DisplayName: "Old node", Group: "edge"},
	})
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := createCSR(t, x509.CertificateRequest{})
	if _, err := repository.Enroll(context.Background(), testAuthorityLoader(authority), EnrollmentRequest{
		Token: oldPlan.Token.Value, NodeID: "node-old", Audience: "control-plane", CSRDER: csr,
	}); err != nil {
		t.Fatal(err)
	}
	clock.Add(time.Second)
	replacement, err := repository.CreateNodeReplacement(context.Background(), NodeEnrollmentInput{
		RequestID: "replace-old", Actor: "operator", Reason: "roll hardware generation",
		NodeID: "node-new", ExpectedVersion: 2, ReplacementFor: "node-old",
		Audience: "control-plane", Metadata: NodeMetadata{DisplayName: "New node", Group: "edge"},
	})
	if err != nil || replacement.Node.ReplacementFor != "node-old" || replacement.Token.Value == "" {
		t.Fatalf("replacement = %#v, err=%v", replacement, err)
	}
	old, err := repository.GetNode(context.Background(), "node-old")
	if err != nil || old.Node.ReplacedBy != "node-new" || old.Node.Version != 3 {
		t.Fatalf("predecessor = %#v, err=%v", old, err)
	}
	csr, _ = createCSR(t, x509.CertificateRequest{})
	if _, err := repository.Enroll(context.Background(), testAuthorityLoader(authority), EnrollmentRequest{
		Token: replacement.Token.Value, NodeID: "node-new", Audience: "control-plane", CSRDER: csr,
	}); err != nil {
		t.Fatal(err)
	}
	clock.Add(time.Second)
	revocation, err := repository.RevokeManagedNode(context.Background(), ManagedNodeRevocationInput{
		RequestID: "revoke-old", Actor: "security-admin", Reason: "predecessor decommissioned",
		NodeID: "node-old", ExpectedVersion: 3,
	})
	if err != nil || revocation.Revocation.NodeID != "node-old" ||
		revocation.Node.Lifecycle != NodeLifecycleRevoked || revocation.Node.Version != 4 || revocation.Replayed {
		t.Fatalf("managed revocation = %#v, err=%v", revocation, err)
	}
	replayedRevocation, err := repository.RevokeManagedNode(context.Background(), ManagedNodeRevocationInput{
		RequestID: "revoke-old", Actor: "security-admin", Reason: "predecessor decommissioned",
		NodeID: "node-old", ExpectedVersion: 3,
	})
	if err != nil || !replayedRevocation.Replayed ||
		replayedRevocation.Revocation != revocation.Revocation || replayedRevocation.Node.Version != 4 {
		t.Fatalf("replayed revocation = %#v, err=%v", replayedRevocation, err)
	}
	events, err := repository.ListNodeEvents(context.Background(), "node-old")
	if err != nil {
		t.Fatal(err)
	}
	var sawReplacement, sawRevocation bool
	for _, event := range events {
		sawReplacement = sawReplacement || event.Kind == NodeEventReplacementCreated && event.NodeID == "node-new"
		sawRevocation = sawRevocation || event.Kind == NodeEventRevoked && event.NodeID == "node-old"
	}
	if !sawReplacement || !sawRevocation {
		t.Fatalf("linked lifecycle events = %#v", events)
	}
}

func TestLegacyIdentityStateMigratesToDurableNodeRecords(t *testing.T) {
	clock := newTestClock()
	root := t.TempDir()
	repository, err := OpenFileRepository(root, FileRepositoryOptions{Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateEnrollmentToken(context.Background(), EnrollmentTokenInput{
		NodeID: "legacy-node", Audience: "control-plane",
	}); err != nil {
		t.Fatal(err)
	}
	legacy := cloneState(repository.state)
	legacy.SchemaVersion = legacySchemaVersion
	legacy.Nodes = nil
	legacy.NodeEvents = nil
	if err := repository.writeState(legacy); err != nil {
		t.Fatal(err)
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenFileRepository(root, FileRepositoryOptions{Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if reopened.state.SchemaVersion != repositorySchemaVersion || reopened.state.Generation != legacy.Generation+1 {
		t.Fatalf("migrated header = version %d generation %d", reopened.state.SchemaVersion, reopened.state.Generation)
	}
	summary, err := reopened.GetNode(context.Background(), "legacy-node")
	if err != nil || summary.Node.Lifecycle != NodeLifecycleEnrolling || summary.Node.Metadata.Group != "default" {
		t.Fatalf("migrated node = %#v, err=%v", summary, err)
	}
	events, err := reopened.ListNodeEvents(context.Background(), "legacy-node")
	if err != nil || len(events) != 1 || events[0].Kind != NodeEventImported {
		t.Fatalf("migrated events = %#v, err=%v", events, err)
	}
	contents, err := os.ReadFile(filepath.Join(root, stateDirectoryName, stateFileName))
	if err != nil {
		t.Fatal(err)
	}
	var envelope stateEnvelope
	if err := json.Unmarshal(contents, &envelope); err != nil {
		t.Fatal(err)
	}
	stateBytes, err := json.Marshal(envelope.State)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(stateBytes)
	if envelope.IntegritySHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("migrated state checksum is invalid")
	}
}
