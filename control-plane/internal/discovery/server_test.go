package discovery

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	bonvoyagev1 "github.com/routesphere-global/bonvoyage/api/gen/go/bonvoyage/v1"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/rollout"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/rolloutservice"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/snapshot"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestStreamDrivesDurablePrepareAndActivationWithoutHeartbeatAcknowledgement(t *testing.T) {
	fixture := newDiscoveryFixture(t, []string{"node-a"})
	service, err := rolloutservice.Open(context.Background(), fixture.repository, fixture.rollout.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	started, err := service.Start(context.Background(), "start-discovery-test")
	if err != nil || len(started.Commands) != 1 {
		t.Fatalf("start: transition=%#v err=%v", started, err)
	}

	transport := newTestTransport(t, service, nil)
	stream, cancel := transport.stream(t, "node-a")
	defer cancel()
	if err := stream.Send(helloRequest("node-a", "process-a")); err != nil {
		t.Fatal(err)
	}
	prepare := receiveCommand(t, stream)
	if prepare.GetPrepare() == nil || prepare.GetRolloutSequence() != fixture.rollout.Sequence {
		t.Fatalf("prepare command = %#v", prepare)
	}
	if !bytes.Equal(prepare.GetPrepare().GetArtifact().GetSnapshotBytes(), fixture.artifactBytes) ||
		!bytes.Equal(prepare.GetPrepare().GetArtifact().GetSnapshot().GetSnapshotSha256(), fixture.target.SHA256[:]) {
		t.Fatal("prepare command did not preserve the exact retained artifact")
	}

	if err := stream.Send(heartbeatRequest("node-a", "process-a", &bonvoyagev1.NodeRuntimeState{})); err != nil {
		t.Fatal(err)
	}
	phase, _, err := service.Status()
	if err != nil || phase != rollout.PhasePreparing {
		t.Fatalf("heartbeat advanced rollout: phase=%s err=%v", phase, err)
	}

	if err := stream.Send(reportRequest(fixture, "node-a", "process-a", rollout.OperationPrepare, rollout.ResultACK)); err != nil {
		t.Fatal(err)
	}
	activate := receiveCommand(t, stream)
	if activate.GetActivate() == nil || activate.GetRolloutSequence() != fixture.rollout.Sequence {
		t.Fatalf("activate command = %#v", activate)
	}
	if err := stream.Send(reportRequest(fixture, "node-a", "process-a", rollout.OperationActivate, rollout.ResultACK)); err != nil {
		t.Fatal(err)
	}
	eventually(t, time.Second, func() bool {
		phase, _, statusErr := service.Status()
		return statusErr == nil && phase == rollout.PhaseActive
	})
}

func TestReplaceRolloutCommitsSelectionBeforeSwitchingAuthority(t *testing.T) {
	fixture := newDiscoveryFixture(t, []string{"node-a"})
	current, err := rolloutservice.Open(context.Background(), fixture.repository, fixture.rollout.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repository.InitializeSelectedRollout(context.Background(), fixture.rollout.Sequence); err != nil {
		t.Fatal(err)
	}
	if _, err := current.Start(context.Background(), "replace-current-start"); err != nil {
		t.Fatal(err)
	}
	prepare := rollout.Report{
		NodeID: "node-a", ProcessInstance: "boot-current", Sequence: fixture.rollout.Sequence,
		Artifact: fixture.target, Operation: rollout.OperationPrepare, Result: rollout.ResultACK,
		ShardCount: 8, CompletedShards: 8,
	}
	if _, err := current.Observe(context.Background(), "replace-current-prepare", prepare); err != nil {
		t.Fatal(err)
	}
	activate := prepare
	activate.Operation = rollout.OperationActivate
	activate.PreviousActive = rollout.Reference{}
	activate.CurrentActive = fixture.target
	if _, err := current.Observe(context.Background(), "replace-current-activate", activate); err != nil {
		t.Fatal(err)
	}

	document, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "examples", "local.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	document = bytes.Replace(document, []byte("local-bootstrap"), []byte("replacement"), 1)
	desired, err := fixture.repository.CreateDesiredRevision(context.Background(), storage.DesiredRevisionInput{
		RequestID: "replace-desired", Document: document, SourceChannel: storage.SourceAPI,
		Actor: "spiffe://admin.test/operators/alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := snapshot.Compile(bytes.NewReader(document))
	if err != nil {
		t.Fatal(err)
	}
	artifactBytes, err := snapshot.MarshalDeterministic(compiled)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := fixture.repository.CreateSnapshotArtifact(context.Background(), storage.SnapshotArtifactInput{
		DesiredRevisionID: desired.ID, CompilerVersion: "checkpoint-9-test", Bytes: artifactBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	record, err := fixture.repository.AllocateRollout(context.Background(), storage.RolloutInput{
		RequestID: "replace-rollout", ArtifactDigest: artifact.Digest,
		PreviousArtifactDigest: storage.Digest(fixture.target.SHA256),
		DesiredRevisionID:      desired.ID, CompilerVersion: "checkpoint-9-test",
		TargetNodeIDs: []string{"node-a"}, SourceChannel: storage.SourceAPI,
		Actor: "spiffe://admin.test/operators/alice", Reason: "replace selected rollout",
	})
	if err != nil {
		t.Fatal(err)
	}
	next, err := rolloutservice.Open(context.Background(), fixture.repository, record.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := next.Start(context.Background(), "replace-next-start"); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(current, DefaultOptions(staticAuthenticator{}))
	if err != nil {
		t.Fatal(err)
	}
	selection, err := server.ReplaceRollout(
		context.Background(), RolloutMutationApply, next,
		func(ctx context.Context, expected, candidate uint64) error {
			_, selectErr := fixture.repository.SelectRollout(ctx, expected, candidate)
			return selectErr
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if selection.Sequence != record.Sequence || selection.Phase != rollout.PhasePreparing {
		t.Fatalf("selection = %#v", selection)
	}
	selected, err := fixture.repository.GetSelectedRollout(context.Background())
	if err != nil || selected.Sequence != record.Sequence {
		t.Fatalf("persisted selection = %#v, err=%v", selected, err)
	}
	currentSelection, err := server.CurrentRollout()
	if err != nil || currentSelection.Sequence != record.Sequence {
		t.Fatalf("runtime selection = %#v, err=%v", currentSelection, err)
	}
	replayed, err := server.ReplaceRollout(
		context.Background(), RolloutMutationApply, next,
		func(context.Context, uint64, uint64) error { return errors.New("selector must not run") },
	)
	if err != nil || !replayed.Replayed || replayed.Sequence != record.Sequence {
		t.Fatalf("replacement replay = %#v, err=%v", replayed, err)
	}
}

func TestStreamDispatchesBarrierUnlockAcrossTwoOwners(t *testing.T) {
	fixture := newDiscoveryFixture(t, []string{"node-a", "node-b"})
	service, err := rolloutservice.Open(context.Background(), fixture.repository, fixture.rollout.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Start(context.Background(), "start-two-node-test"); err != nil {
		t.Fatal(err)
	}
	transport := newTestTransport(t, service, nil)
	streamA, cancelA := transport.stream(t, "node-a")
	defer cancelA()
	streamB, cancelB := transport.stream(t, "node-b")
	defer cancelB()
	for _, item := range []struct {
		stream bonvoyagev1.SnapshotDiscoveryService_StreamSnapshotsClient
		node   string
	}{
		{streamA, "node-a"}, {streamB, "node-b"},
	} {
		if err := item.stream.Send(helloRequest(item.node, "process-"+item.node)); err != nil {
			t.Fatal(err)
		}
		if command := receiveCommand(t, item.stream); command.GetPrepare() == nil {
			t.Fatalf("%s did not receive prepare: %#v", item.node, command)
		}
	}
	if err := streamA.Send(reportRequest(fixture, "node-a", "process-node-a", rollout.OperationPrepare, rollout.ResultACK)); err != nil {
		t.Fatal(err)
	}
	if err := streamB.Send(reportRequest(fixture, "node-b", "process-node-b", rollout.OperationPrepare, rollout.ResultACK)); err != nil {
		t.Fatal(err)
	}
	if command := receiveCommand(t, streamA); command.GetActivate() == nil {
		t.Fatalf("node-a activation = %#v", command)
	}
	if command := receiveCommand(t, streamB); command.GetActivate() == nil {
		t.Fatalf("node-b activation = %#v", command)
	}
}

func TestStreamRejectsChangedLogicalReportReplay(t *testing.T) {
	fixture := newDiscoveryFixture(t, []string{"node-a"})
	service, err := rolloutservice.Open(context.Background(), fixture.repository, fixture.rollout.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Start(context.Background(), "start-conflict-test"); err != nil {
		t.Fatal(err)
	}
	transport := newTestTransport(t, service, nil)
	stream, cancel := transport.stream(t, "node-a")
	defer cancel()
	if err := stream.Send(helloRequest("node-a", "process-a")); err != nil {
		t.Fatal(err)
	}
	_ = receiveCommand(t, stream)
	if err := stream.Send(reportRequest(fixture, "node-a", "process-a", rollout.OperationPrepare, rollout.ResultACK)); err != nil {
		t.Fatal(err)
	}
	_ = receiveCommand(t, stream)
	changed := reportRequest(fixture, "node-a", "process-a", rollout.OperationPrepare, rollout.ResultNACK)
	if err := stream.Send(changed); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.Aborted {
		t.Fatalf("changed report replay error = %v, want Aborted", err)
	}
}

func TestStreamOwnershipRejectsDuplicateAndAllowsNewProcessTakeover(t *testing.T) {
	coordinator := newRecordingCoordinator()
	transport := newTestTransport(t, coordinator, func(options *Options) {
		options.HeartbeatTimeout = time.Second
	})
	first, cancelFirst := transport.stream(t, "node-a")
	defer cancelFirst()
	if err := first.Send(helloRequest("node-a", "process-one")); err != nil {
		t.Fatal(err)
	}
	eventually(t, time.Second, func() bool {
		connections := transport.service.Connections()
		return len(connections) == 1 && connections[0].ProcessInstance == "process-one"
	})

	duplicate, cancelDuplicate := transport.stream(t, "node-a")
	defer cancelDuplicate()
	if err := duplicate.Send(helloRequest("node-a", "process-one")); err != nil {
		t.Fatal(err)
	}
	if _, err := duplicate.Recv(); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("duplicate stream error = %v, want AlreadyExists", err)
	}

	replacement, cancelReplacement := transport.stream(t, "node-a")
	defer cancelReplacement()
	if err := replacement.Send(helloRequest("node-a", "process-two")); err != nil {
		t.Fatal(err)
	}
	eventually(t, time.Second, func() bool {
		connections := transport.service.Connections()
		return len(connections) == 1 && connections[0].ProcessInstance == "process-two"
	})
	if _, err := first.Recv(); status.Code(err) != codes.Aborted {
		t.Fatalf("superseded stream error = %v, want Aborted", err)
	}
}

func TestStreamOwnershipAllowsSameProcessCredentialRotation(t *testing.T) {
	coordinator := newRecordingCoordinator()
	transport := newTestTransport(t, coordinator, nil)
	first, cancelFirst := transport.stream(t, "node-a")
	defer cancelFirst()
	if err := first.Send(helloRequest("node-a", "process-one")); err != nil {
		t.Fatal(err)
	}
	eventually(t, time.Second, func() bool { return len(transport.service.Connections()) == 1 })
	previous := transport.service.Connections()[0].CredentialFingerprint

	replacement, cancelReplacement := transport.rotatedStream(t, "node-a")
	defer cancelReplacement()
	if err := replacement.Send(helloRequest("node-a", "process-one")); err != nil {
		t.Fatal(err)
	}
	eventually(t, time.Second, func() bool {
		connections := transport.service.Connections()
		return len(connections) == 1 && connections[0].ProcessInstance == "process-one" &&
			connections[0].CredentialFingerprint != previous
	})
	if _, err := first.Recv(); status.Code(err) != codes.Aborted {
		t.Fatalf("rotated credential did not supersede old stream: %v", err)
	}
}

func TestProcessTakeoverCannotReceiveAStaleTransitionCommand(t *testing.T) {
	fixture := newDiscoveryFixture(t, []string{"node-a"})
	stale := rollout.Reference{ID: "stale-command", SHA256: sha256.Sum256([]byte("stale-command"))}
	fresh := rollout.Reference{ID: "reconciled-command", SHA256: sha256.Sum256([]byte("reconciled-command"))}
	coordinator := &handoffCoordinator{
		observeEntered: make(chan struct{}), releaseObserve: make(chan struct{}),
		stale: stale, fresh: fresh,
	}
	transport := newTestTransport(t, coordinator, func(options *Options) {
		options.HeartbeatTimeout = time.Second
	})
	first, cancelFirst := transport.stream(t, "node-a")
	defer cancelFirst()
	if err := first.Send(helloRequest("node-a", "process-one")); err != nil {
		t.Fatal(err)
	}
	eventually(t, time.Second, func() bool {
		connections := transport.service.Connections()
		return len(connections) == 1 && connections[0].ProcessInstance == "process-one" &&
			connections[0].Reconciled
	})
	if err := first.Send(reportRequest(
		fixture, "node-a", "process-one", rollout.OperationPrepare, rollout.ResultACK,
	)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-coordinator.observeEntered:
	case <-time.After(time.Second):
		t.Fatal("old-process report did not reach the coordinator")
	}

	replacement, cancelReplacement := transport.stream(t, "node-a")
	defer cancelReplacement()
	if err := replacement.Send(helloRequest("node-a", "process-two")); err != nil {
		t.Fatal(err)
	}
	// The replacement must wait behind the old owner's already-linearized
	// transition. Once that transition completes, takeover and reconnect are
	// serialized so the replacement cannot inherit its predecessor's command.
	close(coordinator.releaseObserve)
	command := receiveCommand(t, replacement)
	if command.GetActivate() == nil ||
		command.GetActivate().GetPreparedSnapshot().GetSnapshotId() != fresh.ID {
		t.Fatalf("replacement received stale command: %#v", command)
	}
}

func TestStreamRejectsCertificateIdentityMismatchAndMissingCapability(t *testing.T) {
	for _, test := range []struct {
		name  string
		hello *bonvoyagev1.StreamSnapshotsRequest
		code  codes.Code
	}{
		{name: "identity", hello: helloRequest("node-b", "process-a"), code: codes.PermissionDenied},
		{name: "capability", hello: helloRequest("node-a", "process-a"), code: codes.FailedPrecondition},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "capability" {
				test.hello.GetHello().Capabilities = test.hello.GetHello().Capabilities[:2]
			}
			transport := newTestTransport(t, newRecordingCoordinator(), nil)
			stream, cancel := transport.stream(t, "node-a")
			defer cancel()
			if err := stream.Send(test.hello); err != nil {
				t.Fatal(err)
			}
			if _, err := stream.Recv(); status.Code(err) != test.code {
				t.Fatalf("stream error = %v, want %s", err, test.code)
			}
		})
	}
}

func TestStreamExpiresWithoutHeartbeat(t *testing.T) {
	transport := newTestTransport(t, newRecordingCoordinator(), func(options *Options) {
		options.HeartbeatTimeout = 40 * time.Millisecond
	})
	stream, cancel := transport.stream(t, "node-a")
	defer cancel()
	if err := stream.Send(helloRequest("node-a", "process-a")); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("heartbeat expiry error = %v, want DeadlineExceeded", err)
	}
	eventually(t, time.Second, func() bool { return len(transport.service.Connections()) == 0 })
}

func TestStreamReauthorizesAndClosesRevokedCredential(t *testing.T) {
	now := time.Now().UTC()
	authenticator := &revocableAuthenticator{identity: AuthenticatedNode{
		NodeID: "node-a", CredentialFingerprint: "sha256:test",
		CredentialSerial: "1", IssuerFingerprint: "sha256:issuer",
		TrustAnchorFingerprint: "sha256:anchor",
		CredentialNotBefore:    now.Add(-time.Minute), CredentialNotAfter: now.Add(time.Hour),
	}}
	transport := newTestTransport(t, newRecordingCoordinator(), func(options *Options) {
		options.Authenticator = authenticator
		options.CredentialCheckInterval = 5 * time.Millisecond
	})
	stream, cancel := transport.stream(t, "node-a")
	defer cancel()
	if err := stream.Send(helloRequest("node-a", "process-a")); err != nil {
		t.Fatal(err)
	}
	eventually(t, time.Second, func() bool { return len(transport.service.Connections()) == 1 })
	authenticator.revoked.Store(true)
	if _, err := stream.Recv(); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("revoked stream error = %v, want Unauthenticated", err)
	}
	eventually(t, time.Second, func() bool { return len(transport.service.Connections()) == 0 })
}

func TestStreamClosesAtCredentialExpiry(t *testing.T) {
	now := time.Now().UTC()
	authenticator := staticAuthenticator{identity: AuthenticatedNode{
		NodeID: "node-a", CredentialFingerprint: "sha256:test",
		CredentialSerial: "1", IssuerFingerprint: "sha256:issuer",
		TrustAnchorFingerprint: "sha256:anchor",
		CredentialNotBefore:    now.Add(-time.Minute), CredentialNotAfter: now.Add(30 * time.Millisecond),
	}}
	transport := newTestTransport(t, newRecordingCoordinator(), func(options *Options) {
		options.Authenticator = authenticator
		options.CredentialCheckInterval = 5 * time.Millisecond
	})
	stream, cancel := transport.stream(t, "node-a")
	defer cancel()
	if err := stream.Send(helloRequest("node-a", "process-a")); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expired stream error = %v, want Unauthenticated", err)
	}
}

func TestDispatchRevokesOwnerBeforePartiallyEnqueuingOverflow(t *testing.T) {
	coordinator := newRecordingCoordinator()
	options := DefaultOptions(staticAuthenticator{identity: AuthenticatedNode{
		NodeID: "node-a", CredentialFingerprint: "sha256:test",
	}})
	options.CommandQueueCapacity = 1
	server, err := NewServer(coordinator, options)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := server.claimOwner(context.Background(), AuthenticatedNode{
		NodeID: "node-a", CredentialFingerprint: "sha256:test",
	}, rollout.RuntimeState{NodeID: "node-a", ProcessInstance: "process-a"})
	if err != nil {
		t.Fatal(err)
	}
	defer server.releaseOwner(owner)
	if !server.markOwnerReady(owner) {
		t.Fatal("owner could not complete reconciliation")
	}
	reference := rollout.Reference{ID: "snapshot-a", SHA256: sha256.Sum256([]byte("snapshot-a"))}
	result, err := server.dispatch([]rollout.Command{
		{NodeID: "node-a", Sequence: 1, Operation: rollout.OperationActivate, Artifact: rollout.Artifact{Reference: reference}},
		{NodeID: "node-a", Sequence: 1, Operation: rollout.OperationActivate, Artifact: rollout.Artifact{Reference: reference}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Overflowed) != 1 || result.Overflowed[0] != "node-a" || len(owner.queue) != 0 {
		t.Fatalf("overflow result=%#v queue=%d", result, len(owner.queue))
	}
	if status.Code(context.Cause(owner.ctx)) != codes.ResourceExhausted {
		t.Fatalf("owner cause = %v", context.Cause(owner.ctx))
	}
}

func TestDispatchWaitsForOwnerReconciliation(t *testing.T) {
	server, err := NewServer(newRecordingCoordinator(), DefaultOptions(staticAuthenticator{
		identity: AuthenticatedNode{NodeID: "node-a", CredentialFingerprint: "sha256:test"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	owner, err := server.claimOwner(context.Background(), AuthenticatedNode{
		NodeID: "node-a", CredentialFingerprint: "sha256:test",
	}, rollout.RuntimeState{NodeID: "node-a", ProcessInstance: "process-a"})
	if err != nil {
		t.Fatal(err)
	}
	defer server.releaseOwner(owner)
	reference := rollout.Reference{ID: "snapshot-a", SHA256: sha256.Sum256([]byte("snapshot-a"))}
	command := rollout.Command{
		NodeID: "node-a", Sequence: 1, Operation: rollout.OperationActivate,
		Artifact: rollout.Artifact{Reference: reference},
	}
	blocked, err := server.dispatch([]rollout.Command{command})
	if err != nil {
		t.Fatal(err)
	}
	if len(blocked.Unavailable) != 1 || blocked.Unavailable[0] != "node-a" || len(owner.queue) != 0 {
		t.Fatalf("pre-reconciliation dispatch=%#v queue=%d", blocked, len(owner.queue))
	}
	if !server.markOwnerReady(owner) {
		t.Fatal("owner could not complete reconciliation")
	}
	delivered, err := server.dispatch([]rollout.Command{command})
	if err != nil {
		t.Fatal(err)
	}
	if len(delivered.Enqueued) != 1 || delivered.Enqueued[0] != "node-a" || len(owner.queue) != 1 {
		t.Fatalf("post-reconciliation dispatch=%#v queue=%d", delivered, len(owner.queue))
	}
}

func TestMTLSAuthenticatorRejectsAmbiguousIdentityAndUnknownWireFields(t *testing.T) {
	hello := helloRequest("node-a", "process-a").GetHello()
	hello.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
	if _, err := validateHello(
		AuthenticatedNode{NodeID: "node-a"}, hello, 1, DefaultOptions(staticAuthenticator{}).RequiredCapabilities,
	); err == nil {
		t.Fatal("hello with unknown fields was accepted")
	}
	identityOne, _ := url.Parse("spiffe://routesphere.test/bonvoyage/nodes/node-a")
	identityTwo, _ := url.Parse("spiffe://routesphere.test/bonvoyage/nodes/node-b")
	state := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Raw: []byte("client"), URIs: []*url.URL{identityOne, identityTwo}}},
		VerifiedChains:   [][]*x509.Certificate{{{Raw: []byte("client")}}},
	}
	ctx := peerContext(state)
	_, err := (MTLSAuthenticator{
		TrustDomain: "routesphere.test", NodePathPrefix: "/bonvoyage/nodes/",
	}).Authenticate(ctx)
	if err == nil {
		t.Fatal("certificate with two node identities was accepted")
	}
	mismatched := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Raw: []byte("presented"), URIs: []*url.URL{identityOne}}},
		VerifiedChains:   [][]*x509.Certificate{{{Raw: []byte("verified"), URIs: []*url.URL{identityOne}}}},
	}
	if _, err := (MTLSAuthenticator{
		TrustDomain: "routesphere.test", NodePathPrefix: "/bonvoyage/nodes/",
	}).Authenticate(peerContext(mismatched)); err == nil {
		t.Fatal("peer certificate differing from the verified leaf was accepted")
	}
}

func TestNewGRPCServerRequiresStrictMutualTLS(t *testing.T) {
	options := DefaultOptions(staticAuthenticator{})
	service, err := NewServer(newRecordingCoordinator(), options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewGRPCServer(service, &tls.Config{MinVersion: tls.VersionTLS12}); err == nil {
		t.Fatal("TLS 1.2 without verified client certificates was accepted")
	}
	authority := newTestAuthority(t)
	serverCertificate := authority.certificate(t, "server", true, nil)
	strictConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: authority.pool, Certificates: []tls.Certificate{serverCertificate},
	}
	escapable := strictConfig.Clone()
	escapable.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return &tls.Config{MinVersion: tls.VersionTLS12}, nil
	}
	if _, err := NewGRPCServer(service, escapable); err == nil {
		t.Fatal("per-client TLS configuration override was accepted")
	}
	secure, err := NewGRPCServer(service, strictConfig)
	if err != nil {
		t.Fatal(err)
	}
	secure.Stop()
}

func TestEvaluateRolloutUsesAuthoritativeStreamHealth(t *testing.T) {
	observedAt := time.Date(2026, 9, 23, 1, 0, 0, 0, time.UTC)
	coordinator := &policyRecordingCoordinator{
		phase: rollout.PhaseObserving,
		policy: rollout.Policy{
			Enabled: true, Strategy: rollout.StrategyCanary, CanaryNodeIDs: []string{"node-a"},
		},
	}
	server, err := NewServer(coordinator, DefaultOptions(staticAuthenticator{}))
	if err != nil {
		t.Fatal(err)
	}
	ownerContext, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	server.owners["node-a"] = &streamOwner{
		nodeID: "node-a", token: 1, processInstance: "process-a",
		lastSeen: observedAt.Add(-time.Second), activeSnapshotID: "snapshot-candidate",
		ready: true, ctx: ownerContext, cancel: cancel,
	}

	result, err := server.EvaluateRollout(context.Background(), observedAt)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.Decision != rollout.PolicyDecisionPromote ||
		result.Phase != rollout.PhaseActivating {
		t.Fatalf("evaluation result = %#v", result)
	}
	if len(coordinator.observation.Nodes) != 1 {
		t.Fatalf("observation = %#v", coordinator.observation)
	}
	health := coordinator.observation.Nodes[0]
	if health.NodeID != "node-a" || !health.Connected || !health.Reconciled ||
		health.ActiveSnapshotID != "snapshot-candidate" ||
		!health.LastSeen.Equal(observedAt.Add(-time.Second)) {
		t.Fatalf("canary health = %#v", health)
	}
}

func TestCancelRolloutPropagatesAuthenticatedAttribution(t *testing.T) {
	coordinator := &policyRecordingCoordinator{
		phase: rollout.PhasePreparing, sequence: 42,
	}
	server, err := NewServer(coordinator, DefaultOptions(staticAuthenticator{}))
	if err != nil {
		t.Fatal(err)
	}
	cancellation := rolloutservice.CancellationInput{
		Reason: "operator stopped rollout", Actor: "spiffe://operator.test/account/alice",
		SourceChannel: storage.SourceConsole,
	}
	selection, err := server.CancelRollout(context.Background(), 42, "cancel-42", cancellation)
	if err != nil {
		t.Fatal(err)
	}
	if selection.Phase != rollout.PhaseCancelled || coordinator.cancelEventID != "cancel-42" ||
		coordinator.cancellation != cancellation {
		t.Fatalf("cancellation propagation: selection=%#v event=%q input=%#v",
			selection, coordinator.cancelEventID, coordinator.cancellation)
	}
}

func TestPolicyRollbackQuiescesStreamsBeforeReplacement(t *testing.T) {
	observedAt := time.Date(2026, 9, 23, 2, 0, 0, 0, time.UTC)
	coordinator := &policyRecordingCoordinator{
		phase: rollout.PhaseObserving, decision: rollout.PolicyDecisionRequireRollback,
		policy: rollout.Policy{
			Enabled: true, Strategy: rollout.StrategyCanary, CanaryNodeIDs: []string{"node-a"},
		},
	}
	server, err := NewServer(coordinator, DefaultOptions(staticAuthenticator{}))
	if err != nil {
		t.Fatal(err)
	}
	ownerContext, cancel := context.WithCancelCause(context.Background())
	server.owners["node-a"] = &streamOwner{
		nodeID: "node-a", token: 1, processInstance: "process-a",
		lastSeen: observedAt.Add(-time.Second), activeSnapshotID: "snapshot-candidate",
		ready: true, ctx: ownerContext, cancel: cancel,
	}

	result, err := server.EvaluateRollout(context.Background(), observedAt)
	if err != nil {
		t.Fatal(err)
	}
	if result.Phase != rollout.PhaseRequiresRollback ||
		result.Decision != rollout.PolicyDecisionRequireRollback {
		t.Fatalf("evaluation result = %#v", result)
	}
	if ownerContext.Err() == nil || len(server.Connections()) != 0 ||
		len(coordinator.disconnects) != 1 || coordinator.disconnects[0] != "node-a" {
		t.Fatalf("rollback quiescence: owner_err=%v connections=%#v disconnects=%#v",
			ownerContext.Err(), server.Connections(), coordinator.disconnects)
	}
	if server.rollbackQuiescedSequence != coordinator.Sequence() {
		t.Fatalf("quiesced sequence = %d", server.rollbackQuiescedSequence)
	}
}

func TestRollbackReplacementWaitsForPreparedStateCleanup(t *testing.T) {
	current := &policyRecordingCoordinator{
		phase: rollout.PhaseRequiresRollback, sequence: 42,
		nodes: map[string]rollout.NodeSnapshot{
			"node-a": {Phase: rollout.NodeCancelPending, Connected: true, ProcessInstance: "process-a"},
		},
	}
	next := &policyRecordingCoordinator{
		phase: rollout.PhasePreparing, sequence: 43,
		nodes: map[string]rollout.NodeSnapshot{
			"node-a": {Phase: rollout.NodePreparing},
		},
	}
	server, err := NewServer(current, DefaultOptions(staticAuthenticator{}))
	if err != nil {
		t.Fatal(err)
	}
	ownerContext, cancel := context.WithCancelCause(context.Background())
	server.owners["node-a"] = &streamOwner{
		nodeID: "node-a", token: 1, processInstance: "process-a", ready: true,
		preparedSequence: 42, ctx: ownerContext, cancel: cancel,
	}
	selectorCalls := 0
	selector := func(context.Context, uint64, uint64) error {
		selectorCalls++
		return nil
	}
	if _, err := server.ReplaceRollout(
		context.Background(), RolloutMutationRollback, next, selector,
	); !errors.Is(err, ErrRolloutInProgress) {
		t.Fatalf("replacement before quiescence error = %v", err)
	}
	if ownerContext.Err() == nil || selectorCalls != 0 {
		t.Fatalf("first replacement: owner_err=%v selector_calls=%d", ownerContext.Err(), selectorCalls)
	}

	reconnectedContext, reconnectedCancel := context.WithCancelCause(context.Background())
	defer reconnectedCancel(nil)
	server.owners["node-a"] = &streamOwner{
		nodeID: "node-a", token: 2, processInstance: "process-a", ready: true,
		preparedSequence: 42, ctx: reconnectedContext, cancel: reconnectedCancel,
	}
	if _, err := server.ReplaceRollout(
		context.Background(), RolloutMutationRollback, next, selector,
	); !errors.Is(err, ErrRolloutInProgress) {
		t.Fatalf("replacement with prepared state error = %v", err)
	}
	if selectorCalls != 0 {
		t.Fatalf("selector called before cleanup: %d", selectorCalls)
	}
	server.owners["node-a"].preparedSequence = 0
	selection, err := server.ReplaceRollout(
		context.Background(), RolloutMutationRollback, next, selector,
	)
	if err != nil || selection.Sequence != 43 || selectorCalls != 1 {
		t.Fatalf("replacement after cleanup: selection=%#v calls=%d err=%v",
			selection, selectorCalls, err)
	}
}

type discoveryFixture struct {
	repository    *storage.FileRepository
	rollout       storage.RolloutRecord
	target        rollout.Reference
	artifactBytes []byte
}

func newDiscoveryFixture(t *testing.T, nodeIDs []string) discoveryFixture {
	t.Helper()
	repository, err := storage.OpenFileRepository(t.TempDir(), storage.FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	document, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "examples", "local.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	desired, err := repository.CreateDesiredRevision(context.Background(), storage.DesiredRevisionInput{
		RequestID: "desired-discovery-test", Document: document, SourceChannel: storage.SourceSystem,
		Actor: "discovery-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := snapshot.Compile(bytes.NewReader(document))
	if err != nil {
		t.Fatal(err)
	}
	artifactBytes, err := snapshot.MarshalDeterministic(compiled)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := repository.CreateSnapshotArtifact(context.Background(), storage.SnapshotArtifactInput{
		DesiredRevisionID: desired.ID, CompilerVersion: "0.4.0", Bytes: artifactBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	record, err := repository.AllocateRollout(context.Background(), storage.RolloutInput{
		RequestID: "rollout-discovery-test", ArtifactDigest: artifact.Digest,
		DesiredRevisionID: desired.ID, CompilerVersion: "0.4.0", TargetNodeIDs: nodeIDs,
		SourceChannel: storage.SourceSystem, Actor: "discovery-test", Reason: "exercise authenticated streams",
	})
	if err != nil {
		t.Fatal(err)
	}
	return discoveryFixture{
		repository: repository, rollout: record, artifactBytes: artifactBytes,
		target: rollout.Reference{ID: artifact.SnapshotID, SHA256: [sha256.Size]byte(artifact.Digest)},
	}
}

func helloRequest(nodeID, process string) *bonvoyagev1.StreamSnapshotsRequest {
	return &bonvoyagev1.StreamSnapshotsRequest{Request: &bonvoyagev1.StreamSnapshotsRequest_Hello{
		Hello: &bonvoyagev1.NodeHello{
			NodeId: nodeID, ProcessInstanceId: process, DataplaneVersion: "0.4.0",
			SupportedSchemaVersions: []uint32{1}, RuntimeState: &bonvoyagev1.NodeRuntimeState{},
			Capabilities: []*bonvoyagev1.NodeCapability{
				{Capability: bonvoyagev1.NodeCapabilityType_NODE_CAPABILITY_TYPE_TWO_PHASE_ROLLOUT, Version: 1},
				{Capability: bonvoyagev1.NodeCapabilityType_NODE_CAPABILITY_TYPE_EXACT_ARTIFACT_ROLLBACK, Version: 1},
				{Capability: bonvoyagev1.NodeCapabilityType_NODE_CAPABILITY_TYPE_HEARTBEAT_STATE_REPORT, Version: 1},
			},
		},
	}}
}

func heartbeatRequest(nodeID, process string, state *bonvoyagev1.NodeRuntimeState) *bonvoyagev1.StreamSnapshotsRequest {
	return &bonvoyagev1.StreamSnapshotsRequest{Request: &bonvoyagev1.StreamSnapshotsRequest_Heartbeat{
		Heartbeat: &bonvoyagev1.NodeHeartbeat{
			NodeId: nodeID, ProcessInstanceId: process, RuntimeState: state,
			ObservedAt: timestamppb.Now(),
		},
	}}
}

func reportRequest(
	fixture discoveryFixture,
	nodeID string,
	process string,
	operation rollout.Operation,
	result rollout.Result,
) *bonvoyagev1.StreamSnapshotsRequest {
	protoOperation := bonvoyagev1.RolloutOperation_ROLLOUT_OPERATION_PREPARE
	if operation == rollout.OperationActivate {
		protoOperation = bonvoyagev1.RolloutOperation_ROLLOUT_OPERATION_ACTIVATE
	} else if operation == rollout.OperationCancel {
		protoOperation = bonvoyagev1.RolloutOperation_ROLLOUT_OPERATION_CANCEL
	}
	protoResult := bonvoyagev1.AcknowledgementResult_ACKNOWLEDGEMENT_RESULT_ACK
	completed := uint32(8)
	var issues []*bonvoyagev1.ValidationError
	if result == rollout.ResultNACK {
		protoResult = bonvoyagev1.AcknowledgementResult_ACKNOWLEDGEMENT_RESULT_NACK
		completed = 7
		issues = []*bonvoyagev1.ValidationError{{Code: "snapshot.invalid", Message: "test rejection"}}
	}
	var current *bonvoyagev1.SnapshotReference
	if operation == rollout.OperationActivate && result == rollout.ResultACK {
		current = commandReference(fixture.target)
	}
	return &bonvoyagev1.StreamSnapshotsRequest{Request: &bonvoyagev1.StreamSnapshotsRequest_RolloutReport{
		RolloutReport: &bonvoyagev1.NodeRolloutReport{
			NodeId: nodeID, ProcessInstanceId: process, RolloutSequence: fixture.rollout.Sequence,
			Snapshot: commandReference(fixture.target), Operation: protoOperation, Result: protoResult,
			CurrentActiveSnapshot: current, Errors: issues, ShardCount: 8, CompletedShards: completed,
			CompletedAt: timestamppb.Now(),
		},
	}}
}

func receiveCommand(
	t *testing.T,
	stream bonvoyagev1.SnapshotDiscoveryService_StreamSnapshotsClient,
) *bonvoyagev1.RolloutCommand {
	t.Helper()
	response, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if response.GetDelivery() != nil || response.GetCommand() == nil {
		t.Fatalf("response = %#v", response)
	}
	return response.GetCommand()
}

type recordingCoordinator struct {
	mu          sync.Mutex
	reconnects  []rollout.RuntimeState
	reports     []rollout.Report
	disconnects []string
}

type policyRecordingCoordinator struct {
	phase         rollout.Phase
	policy        rollout.Policy
	observation   rollout.PolicyObservation
	decision      rollout.PolicyDecision
	cancellation  rolloutservice.CancellationInput
	cancelEventID string
	nodes         map[string]rollout.NodeSnapshot
	sequence      uint64
	disconnects   []string
}

func (*policyRecordingCoordinator) Observe(
	context.Context, string, rollout.Report,
) (rolloutservice.Transition, error) {
	return rolloutservice.Transition{}, nil
}

func (*policyRecordingCoordinator) Reconnect(
	context.Context, string, rollout.RuntimeState,
) (rolloutservice.Transition, error) {
	return rolloutservice.Transition{}, nil
}

func (coordinator *policyRecordingCoordinator) Disconnect(nodeID, _ string) error {
	coordinator.disconnects = append(coordinator.disconnects, nodeID)
	return nil
}

func (*policyRecordingCoordinator) Start(context.Context, string) (rolloutservice.Transition, error) {
	return rolloutservice.Transition{}, nil
}

func (coordinator *policyRecordingCoordinator) Cancel(
	_ context.Context, eventID string, cancellation rolloutservice.CancellationInput,
) (rolloutservice.Transition, error) {
	coordinator.cancelEventID = eventID
	coordinator.cancellation = cancellation
	coordinator.phase = rollout.PhaseCancelled
	return rolloutservice.Transition{}, nil
}

func (coordinator *policyRecordingCoordinator) Evaluate(
	_ context.Context,
	_ string,
	observation rollout.PolicyObservation,
) (rolloutservice.PolicyTransition, error) {
	coordinator.observation = observation
	decision := coordinator.decision
	if decision == "" {
		decision = rollout.PolicyDecisionPromote
	}
	if decision == rollout.PolicyDecisionRequireRollback {
		coordinator.phase = rollout.PhaseRequiresRollback
	} else {
		coordinator.phase = rollout.PhaseActivating
	}
	return rolloutservice.PolicyTransition{Result: rollout.PolicyResult{
		Decision: decision, Reason: "recorded policy decision",
	}}, nil
}

func (coordinator *policyRecordingCoordinator) Status() (
	rollout.Phase,
	map[string]rollout.NodeSnapshot,
	error,
) {
	if coordinator.nodes != nil {
		return coordinator.phase, coordinator.nodes, nil
	}
	return coordinator.phase, map[string]rollout.NodeSnapshot{
		"node-a": {Phase: rollout.NodeActive, Connected: true, ProcessInstance: "process-a"},
	}, nil
}

func (coordinator *policyRecordingCoordinator) Policy() rollout.Policy {
	return coordinator.policy
}

func (coordinator *policyRecordingCoordinator) Sequence() uint64 {
	if coordinator.sequence != 0 {
		return coordinator.sequence
	}
	return 42
}

type handoffCoordinator struct {
	observeEntered chan struct{}
	releaseObserve chan struct{}
	stale          rollout.Reference
	fresh          rollout.Reference
	once           sync.Once
}

func (coordinator *handoffCoordinator) Observe(
	context.Context,
	string,
	rollout.Report,
) (rolloutservice.Transition, error) {
	coordinator.once.Do(func() { close(coordinator.observeEntered) })
	<-coordinator.releaseObserve
	return rolloutservice.Transition{Commands: []rollout.Command{{
		NodeID: "node-a", Sequence: 1, Operation: rollout.OperationActivate,
		Artifact: rollout.Artifact{Reference: coordinator.stale},
	}}}, nil
}

func (coordinator *handoffCoordinator) Reconnect(
	_ context.Context,
	_ string,
	state rollout.RuntimeState,
) (rolloutservice.Transition, error) {
	if state.ProcessInstance != "process-two" {
		return rolloutservice.Transition{}, nil
	}
	return rolloutservice.Transition{Commands: []rollout.Command{{
		NodeID: "node-a", Sequence: 1, Operation: rollout.OperationActivate,
		Artifact: rollout.Artifact{Reference: coordinator.fresh},
	}}}, nil
}

func (*handoffCoordinator) Disconnect(string, string) error { return nil }

func newRecordingCoordinator() *recordingCoordinator { return &recordingCoordinator{} }

func (coordinator *recordingCoordinator) Observe(
	_ context.Context,
	_ string,
	report rollout.Report,
) (rolloutservice.Transition, error) {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	coordinator.reports = append(coordinator.reports, report)
	return rolloutservice.Transition{}, nil
}

func (coordinator *recordingCoordinator) Reconnect(
	_ context.Context,
	_ string,
	state rollout.RuntimeState,
) (rolloutservice.Transition, error) {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	coordinator.reconnects = append(coordinator.reconnects, state)
	return rolloutservice.Transition{}, nil
}

func (coordinator *recordingCoordinator) Disconnect(nodeID, process string) error {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	coordinator.disconnects = append(coordinator.disconnects, nodeID+":"+process)
	return nil
}

type staticAuthenticator struct{ identity AuthenticatedNode }

func (authenticator staticAuthenticator) Authenticate(context.Context) (AuthenticatedNode, error) {
	return authenticator.identity, nil
}

type revocableAuthenticator struct {
	identity AuthenticatedNode
	revoked  atomic.Bool
}

func (authenticator *revocableAuthenticator) Authenticate(context.Context) (AuthenticatedNode, error) {
	return authenticator.identity, nil
}

func (authenticator *revocableAuthenticator) ValidateCredential(AuthenticatedNode, time.Time) error {
	if authenticator.revoked.Load() {
		return ErrUnauthenticated
	}
	return nil
}

type testTransport struct {
	t                  *testing.T
	service            *Server
	listener           *bufconn.Listener
	grpcServer         *grpc.Server
	authority          *testAuthority
	serverName         string
	mu                 sync.Mutex
	clientCertificates map[string]tls.Certificate
}

func newTestTransport(
	t *testing.T,
	coordinator Coordinator,
	configure func(*Options),
) *testTransport {
	t.Helper()
	authority := newTestAuthority(t)
	authenticator := MTLSAuthenticator{
		TrustDomain: "routesphere.test", NodePathPrefix: "/bonvoyage/nodes/",
	}
	options := DefaultOptions(authenticator)
	options.HelloTimeout = time.Second
	options.HeartbeatTimeout = 2 * time.Second
	if configure != nil {
		configure(&options)
	}
	service, err := NewServer(coordinator, options)
	if err != nil {
		t.Fatal(err)
	}
	serverName := "discovery.test"
	serverCertificate := authority.certificate(t, serverName, true, nil)
	grpcServer, err := NewGRPCServer(service, &tls.Config{
		MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: authority.pool, Certificates: []tls.Certificate{serverCertificate},
	})
	if err != nil {
		t.Fatal(err)
	}
	listener := bufconn.Listen(4 << 20)
	go func() { _ = grpcServer.Serve(listener) }()
	transport := &testTransport{
		t: t, service: service, listener: listener, grpcServer: grpcServer,
		authority: authority, serverName: serverName,
		clientCertificates: make(map[string]tls.Certificate),
	}
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
	})
	return transport
}

func (transport *testTransport) stream(
	t *testing.T,
	nodeID string,
) (bonvoyagev1.SnapshotDiscoveryService_StreamSnapshotsClient, context.CancelFunc) {
	return transport.streamWithRotation(t, nodeID, false)
}

func (transport *testTransport) rotatedStream(
	t *testing.T,
	nodeID string,
) (bonvoyagev1.SnapshotDiscoveryService_StreamSnapshotsClient, context.CancelFunc) {
	return transport.streamWithRotation(t, nodeID, true)
}

func (transport *testTransport) streamWithRotation(
	t *testing.T,
	nodeID string,
	rotate bool,
) (bonvoyagev1.SnapshotDiscoveryService_StreamSnapshotsClient, context.CancelFunc) {
	t.Helper()
	identity, err := url.Parse("spiffe://routesphere.test/bonvoyage/nodes/" + nodeID)
	if err != nil {
		t.Fatal(err)
	}
	transport.mu.Lock()
	clientCertificate, present := transport.clientCertificates[nodeID]
	if !present || rotate {
		clientCertificate = transport.authority.certificate(t, nodeID, false, []*url.URL{identity})
		transport.clientCertificates[nodeID] = clientCertificate
	}
	transport.mu.Unlock()
	connection, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return transport.listener.Dial()
		}),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS13, ServerName: transport.serverName,
			RootCAs: transport.authority.pool, Certificates: []tls.Certificate{clientCertificate},
		})),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stream, err := bonvoyagev1.NewSnapshotDiscoveryServiceClient(connection).StreamSnapshots(ctx)
	if err != nil {
		cancel()
		_ = connection.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return stream, cancel
}

type testAuthority struct {
	certificateValue *x509.Certificate
	key              *ecdsa.PrivateKey
	pool             *x509.CertPool
}

func newTestAuthority(t *testing.T) *testAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "BonVoyage test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificateValue, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(certificateValue)
	return &testAuthority{certificateValue: certificateValue, key: key, pool: pool}
}

func (authority *testAuthority) certificate(
	t *testing.T,
	name string,
	server bool,
	identities []*url.URL,
) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	usage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	var dnsNames []string
	if server {
		usage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		dnsNames = []string{name}
	}
	serial := sha256.Sum256([]byte(name + time.Now().String()))
	template := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(serial[:16]),
		Subject:      pkix.Name{CommonName: name}, DNSNames: dnsNames, URIs: identities,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage,
	}
	der, err := x509.CreateCertificate(
		rand.Reader, template, authority.certificateValue, &key.PublicKey, authority.key,
	)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, authority.certificateValue.Raw}, PrivateKey: key}
}

func peerContext(state tls.ConnectionState) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: state},
	})
}

func eventually(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition did not become true before deadline")
}
