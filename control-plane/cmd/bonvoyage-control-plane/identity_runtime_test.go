package main

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/discovery"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/identity"
)

type lifecycleTransportStub struct {
	err error
}

func (stub lifecycleTransportStub) VerifyClientCertificate(
	certificates []*x509.Certificate,
	_ time.Time,
) ([]*x509.Certificate, error) {
	return certificates, stub.err
}

func (stub lifecycleTransportStub) ValidateCredential(discovery.AuthenticatedNode, time.Time) error {
	return stub.err
}

type lifecycleRepositoryStub struct {
	status    identity.RevocationStatus
	statusErr error
	node      identity.NodeIdentitySummary
	nodeErr   error
}

func (stub lifecycleRepositoryStub) RevocationStatus(
	_ context.Context,
	_ identity.RevocationStatusQuery,
) (identity.RevocationStatus, error) {
	return stub.status, stub.statusErr
}

func (stub lifecycleRepositoryStub) GetNode(
	_ context.Context,
	_ string,
) (identity.NodeIdentitySummary, error) {
	return stub.node, stub.nodeErr
}

func TestRepositoryLifecycleVerifierRejectsNonServingNodeStates(t *testing.T) {
	now := time.Date(2026, 9, 24, 6, 0, 0, 0, time.UTC)
	credential := discovery.AuthenticatedNode{
		NodeID: "node-a", CredentialFingerprint: "sha256:leaf",
		CredentialSerial: "01", IssuerFingerprint: "sha256:issuer",
		CredentialNotBefore: now.Add(-time.Hour), CredentialNotAfter: now.Add(time.Hour),
	}
	tests := []struct {
		name      string
		lifecycle identity.NodeLifecycleState
		enrolled  bool
		wantError bool
	}{
		{name: "ready", lifecycle: identity.NodeLifecycleReady, enrolled: true},
		{name: "draining", lifecycle: identity.NodeLifecycleDraining, enrolled: true},
		{name: "enrolling", lifecycle: identity.NodeLifecycleEnrolling, wantError: true},
		{name: "retired", lifecycle: identity.NodeLifecycleRetired, enrolled: true, wantError: true},
		{name: "revoked", lifecycle: identity.NodeLifecycleRevoked, enrolled: true, wantError: true},
		{name: "not enrolled", lifecycle: identity.NodeLifecycleReady, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier := repositoryLifecycleVerifier{
				transport: lifecycleTransportStub{},
				repository: lifecycleRepositoryStub{node: identity.NodeIdentitySummary{
					Node:     identity.NodeRecord{NodeID: "node-a", Lifecycle: test.lifecycle},
					Enrolled: test.enrolled,
				}},
			}
			err := verifier.ValidateCredential(credential, now)
			if test.wantError && !errors.Is(err, discovery.ErrUnauthenticated) {
				t.Fatalf("ValidateCredential() error = %v, want unauthenticated", err)
			}
			if !test.wantError && err != nil {
				t.Fatalf("ValidateCredential() error = %v", err)
			}
		})
	}
}

func TestRepositoryLifecycleVerifierFailsClosed(t *testing.T) {
	now := time.Date(2026, 9, 24, 6, 0, 0, 0, time.UTC)
	credential := discovery.AuthenticatedNode{NodeID: "node-a"}
	ready := identity.NodeIdentitySummary{
		Node:     identity.NodeRecord{NodeID: "node-a", Lifecycle: identity.NodeLifecycleReady},
		Enrolled: true,
	}
	tests := []struct {
		name      string
		transport error
		status    identity.RevocationStatus
		statusErr error
		nodeErr   error
	}{
		{name: "transport rejection", transport: errors.New("stale trust")},
		{name: "revoked credential", status: identity.RevocationStatus{Revoked: true}},
		{name: "revocation lookup failure", statusErr: errors.New("repository unavailable")},
		{name: "node lookup failure", nodeErr: identity.ErrNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier := repositoryLifecycleVerifier{
				transport: lifecycleTransportStub{err: test.transport},
				repository: lifecycleRepositoryStub{
					status: test.status, statusErr: test.statusErr, node: ready, nodeErr: test.nodeErr,
				},
			}
			if err := verifier.ValidateCredential(credential, now); err == nil {
				t.Fatal("ValidateCredential() succeeded, want fail-closed rejection")
			}
		})
	}
}
