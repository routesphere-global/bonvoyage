package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/identity"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/identityservice"
)

func TestEnrollmentRejectsUnknownTokenBeforeReloadingAuthority(t *testing.T) {
	material := newTestTLSMaterial(t)
	issuerKeyPath := filepath.Join(filepath.Dir(material.caPath), "issuer-key.pem")
	issuerKeyDER, err := x509.MarshalPKCS8PrivateKey(material.caKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		issuerKeyPath,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: issuerKeyDER}),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	repository, err := identity.OpenFileRepository(t.TempDir(), identity.FileRepositoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	backend, err := newRepositoryIdentityBackend(identityBackendOptions{
		repository: repository, issuerCertificate: material.caPath,
		issuerPrivateKey: issuerKeyPath, trustBundle: material.caPath,
		trustDomain: "routesphere.test", nodePathPrefix: "/bonvoyage/nodes/",
		audience: "standalone-test", clock: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(issuerKeyPath); err != nil {
		t.Fatal(err)
	}

	_, err = backend.Enroll(context.Background(), identityservice.EnrollmentRequest{
		NodeID:         "node-a",
		BootstrapToken: "bv1." + strings.Repeat("A", 22) + "." + strings.Repeat("A", 43),
		CSR:            []byte("invalid token must be rejected before CSR or issuer processing"),
	})
	if !errors.Is(err, identityservice.ErrEnrollmentDenied) {
		t.Fatalf("unknown-token error = %v, want enrollment denied", err)
	}
}
