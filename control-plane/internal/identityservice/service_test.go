package identityservice

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	bonvoyagev1 "github.com/routesphere-global/bonvoyage/api/gen/go/bonvoyage/v1"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/discovery"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestEnrollNodeBindsBoundedRequestAndReturnsCredential(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	backend := &recordingBackend{credential: validCredential(now)}
	service := newTestService(t, now, backend, staticIdentityAuthenticator{
		identity: validIdentity(now, "node-a"),
	})
	response, err := service.EnrollNode(context.Background(), &bonvoyagev1.EnrollNodeRequest{
		NodeId: "node-a", BootstrapToken: "bv1.identifier.secret-value",
		Pkcs10CertificateRequest: []byte("csr"), ObservedAt: timestamppb.New(now),
	})
	if err != nil {
		t.Fatal(err)
	}
	if backend.enrollment.NodeID != "node-a" || backend.enrollment.BootstrapToken == "" ||
		response.GetCredential().GetCredentialGeneration() != "generation-a" ||
		!response.GetCredential().GetServerTime().AsTime().Equal(now) {
		t.Fatalf("enrollment=%#v response=%#v", backend.enrollment, response)
	}
}

func TestEnrollNodeRejectsClockUnknownFieldsAndDeniedToken(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	backend := &recordingBackend{credential: validCredential(now)}
	service := newTestService(t, now, backend, staticIdentityAuthenticator{
		identity: validIdentity(now, "node-a"),
	})
	request := &bonvoyagev1.EnrollNodeRequest{
		NodeId: "node-a", BootstrapToken: "bv1.identifier.secret-value",
		Pkcs10CertificateRequest: []byte("csr"), ObservedAt: timestamppb.New(now.Add(time.Minute)),
	}
	if _, err := service.EnrollNode(context.Background(), request); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("future clock error = %v", err)
	}
	request.ObservedAt = timestamppb.New(now)
	request.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 0x01})
	if _, err := service.EnrollNode(context.Background(), request); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unknown-field error = %v", err)
	}
	request.ProtoReflect().SetUnknown(nil)
	backend.err = ErrEnrollmentDenied
	if _, err := service.EnrollNode(context.Background(), request); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("denied token error = %v", err)
	}
}

func TestEnrollNodeBoundsAggregateBackendWork(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	backend := &blockingEnrollmentBackend{
		credential: validCredential(now), entered: make(chan struct{}, 4), release: make(chan struct{}),
	}
	service, err := New(backend, Options{
		Authenticator: staticIdentityAuthenticator{identity: validIdentity(now, "node-a")},
		MaxClockSkew:  30 * time.Second, MaxObservationAge: time.Minute,
		MaxConcurrentEnrollments: 2, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := func(nodeID string) *bonvoyagev1.EnrollNodeRequest {
		return &bonvoyagev1.EnrollNodeRequest{
			NodeId: nodeID, BootstrapToken: "bv1.identifier.secret-value",
			Pkcs10CertificateRequest: []byte("csr"), ObservedAt: timestamppb.New(now),
		}
	}
	results := make(chan error, 2)
	for _, nodeID := range []string{"node-a", "node-b"} {
		go func() {
			_, enrollErr := service.EnrollNode(context.Background(), request(nodeID))
			results <- enrollErr
		}()
	}
	for index := 0; index < 2; index++ {
		select {
		case <-backend.entered:
		case <-time.After(time.Second):
			t.Fatal("backend did not receive admitted enrollment")
		}
	}
	if _, err := service.RenewNode(context.Background(), &bonvoyagev1.RenewNodeRequest{
		NodeId: "node-a", Pkcs10CertificateRequest: []byte("csr"), ObservedAt: timestamppb.New(now),
	}); err != nil {
		t.Fatalf("renewal was coupled to enrollment capacity: %v", err)
	}
	if _, err := service.EnrollNode(context.Background(), request("node-c")); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("saturated enrollment error = %v", err)
	}
	if backend.calls.Load() != 2 || backend.maximum.Load() != 2 {
		t.Fatalf("backend calls=%d maximum=%d, want 2 and 2", backend.calls.Load(), backend.maximum.Load())
	}
	close(backend.release)
	for index := 0; index < 2; index++ {
		if err := <-results; err != nil {
			t.Fatalf("admitted enrollment error = %v", err)
		}
	}
	if _, err := service.EnrollNode(context.Background(), request("node-d")); err != nil {
		t.Fatalf("enrollment after capacity release = %v", err)
	}
}

func TestRenewNodeRequiresMatchingCurrentIdentity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	backend := &recordingBackend{credential: validCredential(now)}
	authenticator := staticIdentityAuthenticator{identity: validIdentity(now, "node-a")}
	service := newTestService(t, now, backend, authenticator)
	request := &bonvoyagev1.RenewNodeRequest{
		NodeId: "node-b", Pkcs10CertificateRequest: []byte("csr"),
		ObservedAt: timestamppb.New(now),
	}
	if _, err := service.RenewNode(context.Background(), request); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("identity mismatch error = %v", err)
	}
	authenticator.err = discovery.ErrUnauthenticated
	service = newTestService(t, now, backend, authenticator)
	request.NodeId = "node-a"
	if _, err := service.RenewNode(context.Background(), request); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("missing identity error = %v", err)
	}
}

func TestRenewNodeReturnsNewCredentialAndMapsRevocation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	backend := &recordingBackend{credential: validCredential(now)}
	service := newTestService(t, now, backend, staticIdentityAuthenticator{
		identity: validIdentity(now, "node-a"),
	})
	request := &bonvoyagev1.RenewNodeRequest{
		NodeId: "node-a", Pkcs10CertificateRequest: []byte("csr"),
		ObservedAt: timestamppb.New(now),
	}
	response, err := service.RenewNode(context.Background(), request)
	if err != nil || backend.renewal.Identity.NodeID != "node-a" ||
		response.GetCredential().GetCredentialGeneration() != "generation-a" {
		t.Fatalf("renewal=%#v response=%#v err=%v", backend.renewal, response, err)
	}
	backend.err = ErrCredentialRevoked
	if _, err := service.RenewNode(context.Background(), request); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoked renewal error = %v", err)
	}
}

type recordingBackend struct {
	credential Credential
	err        error
	enrollment EnrollmentRequest
	renewal    RenewalRequest
}

type blockingEnrollmentBackend struct {
	credential Credential
	entered    chan struct{}
	release    chan struct{}
	calls      atomic.Int32
	active     atomic.Int32
	maximum    atomic.Int32
}

func (backend *blockingEnrollmentBackend) Enroll(ctx context.Context, _ EnrollmentRequest) (Credential, error) {
	backend.calls.Add(1)
	active := backend.active.Add(1)
	defer backend.active.Add(-1)
	for {
		maximum := backend.maximum.Load()
		if active <= maximum || backend.maximum.CompareAndSwap(maximum, active) {
			break
		}
	}
	backend.entered <- struct{}{}
	select {
	case <-backend.release:
		return backend.credential, nil
	case <-ctx.Done():
		return Credential{}, ctx.Err()
	}
}

func (backend *blockingEnrollmentBackend) Renew(context.Context, RenewalRequest) (Credential, error) {
	return backend.credential, nil
}

func (backend *recordingBackend) Enroll(_ context.Context, request EnrollmentRequest) (Credential, error) {
	backend.enrollment = request
	return backend.credential, backend.err
}

func (backend *recordingBackend) Renew(_ context.Context, request RenewalRequest) (Credential, error) {
	backend.renewal = request
	return backend.credential, backend.err
}

type staticIdentityAuthenticator struct {
	identity discovery.AuthenticatedNode
	err      error
}

func (authenticator staticIdentityAuthenticator) Authenticate(context.Context) (discovery.AuthenticatedNode, error) {
	return authenticator.identity, authenticator.err
}

func (authenticator staticIdentityAuthenticator) ValidateCredential(
	identity discovery.AuthenticatedNode,
	now time.Time,
) error {
	if authenticator.err != nil || now.Before(identity.CredentialNotBefore) || !now.Before(identity.CredentialNotAfter) {
		return discovery.ErrUnauthenticated
	}
	return nil
}

func newTestService(
	t *testing.T,
	now time.Time,
	backend Backend,
	authenticator discovery.Authenticator,
) *Service {
	t.Helper()
	service, err := New(backend, Options{
		Authenticator: authenticator, MaxClockSkew: 30 * time.Second,
		MaxObservationAge: time.Minute, MaxConcurrentEnrollments: 8,
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func validCredential(now time.Time) Credential {
	return Credential{
		Generation: "generation-a", CertificateChain: []byte("certificate"),
		TrustBundle: []byte("trust"), CertificateSHA256: make([]byte, 32),
		IssuerSHA256: make([]byte, 32), SerialNumber: "1",
		NotBefore: now.Add(-time.Minute), RenewAfter: now.Add(time.Hour),
		NotAfter: now.Add(2 * time.Hour),
	}
}

func validIdentity(now time.Time, nodeID string) discovery.AuthenticatedNode {
	return discovery.AuthenticatedNode{
		NodeID: nodeID, CredentialFingerprint: "sha256:credential",
		CredentialSerial: "1", IssuerFingerprint: "sha256:issuer",
		TrustAnchorFingerprint: "sha256:anchor",
		CredentialNotBefore:    now.Add(-time.Minute), CredentialNotAfter: now.Add(time.Hour),
	}
}
