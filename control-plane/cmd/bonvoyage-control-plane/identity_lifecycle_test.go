package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/identity"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/identityservice"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/nodecredentials"
)

func TestIssueEnrollmentTokenRejectsExistingOutputBeforeRepositoryMutation(t *testing.T) {
	identityRoot := filepath.Join(t.TempDir(), "identity")
	output := filepath.Join(t.TempDir(), "node-a.token")
	if err := os.WriteFile(output, []byte("existing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runIssueEnrollmentToken(context.Background(), []string{
		"-identity-repository-root", identityRoot,
		"-node-id", "node-a",
		"-audience", "standalone-test",
		"-token-output", output,
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing token output error = %v", err)
	}
	if _, err := os.Stat(identityRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("identity repository was mutated before output validation: %v", err)
	}
}

func TestClassifyMissingIdentityAsConflict(t *testing.T) {
	err := classifyIdentityError(identity.ErrNotFound)
	if !errors.Is(err, identityservice.ErrIdentityConflict) || !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("classified error = %v", err)
	}
}

func TestIdentityLifecycleEnrollmentRenewalRevocationAndShutdown(t *testing.T) {
	repositoryRoot := filepath.Join(t.TempDir(), "repository")
	sequence := createDiscoveryRepository(t, repositoryRoot)
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

	identityRoot := filepath.Join(t.TempDir(), "identity")
	tokenPath := filepath.Join(t.TempDir(), "node-a.token")
	var tokenOutput bytes.Buffer
	if err := runIssueEnrollmentToken(context.Background(), []string{
		"-identity-repository-root", identityRoot,
		"-node-id", "node-a",
		"-audience", "standalone-test",
		"-token-output", tokenPath,
	}, &tokenOutput, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	tokenBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(tokenOutput.String(), strings.TrimSpace(string(tokenBytes))) {
		t.Fatal("one-time enrollment token leaked to command output")
	}

	revocationPath := filepath.Join(t.TempDir(), "revocations.json")
	if err := runInitializeRevocations([]string{
		"-revocation-file", revocationPath,
		"-valid-for", "24h",
	}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	options := discoveryCommandOptions{
		repositoryRoot:        repositoryRoot,
		rolloutSequence:       sequence,
		listenAddress:         "127.0.0.1:0",
		tlsServerCertificate:  material.serverCertificatePath,
		tlsServerKey:          material.serverKeyPath,
		tlsClientCA:           material.caPath,
		spiffeTrustDomain:     "routesphere.test",
		spiffeNodePathPrefix:  "/bonvoyage/nodes/",
		enrollmentAddress:     "127.0.0.1:0",
		identityRepository:    identityRoot,
		identityAudience:      "standalone-test",
		identityIssuerCert:    material.caPath,
		identityIssuerKey:     issuerKeyPath,
		tlsRevocations:        revocationPath,
		tlsServerName:         "localhost",
		tlsReloadInterval:     10 * time.Millisecond,
		tlsMinimumValidity:    time.Minute,
		identityClockSkew:     time.Minute,
		identityMaxAge:        5 * time.Minute,
		identityMaxConcurrent: 4,
	}
	ctx, cancel := context.WithCancel(context.Background())
	discoveryReady := make(chan net.Addr, 1)
	enrollmentReady := make(chan net.Addr, 1)
	completed := make(chan error, 1)
	runtime := defaultCommandRuntime()
	runtime.listenerReady = func(address net.Addr) { discoveryReady <- address }
	runtime.enrollmentListenerReady = func(address net.Addr) { enrollmentReady <- address }
	runtime.shutdownTimeout = time.Second
	var serverOutput bytes.Buffer
	var serverErrors bytes.Buffer
	go func() {
		completed <- run(ctx, discoveryArgs(options), &serverOutput, &serverErrors, runtime)
	}()
	var discoveryAddress net.Addr
	select {
	case discoveryAddress = <-discoveryReady:
	case err := <-completed:
		t.Fatalf("identity lifecycle server stopped during startup: %v; stderr=%s", err, serverErrors.String())
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatalf("discovery listener did not become ready; stderr=%s", serverErrors.String())
	}
	enrollmentAddress := waitForAddress(t, enrollmentReady)

	credentialRoot := filepath.Join(t.TempDir(), "node-credentials")
	var enrollmentOutput bytes.Buffer
	if err := runEnrollNode(context.Background(), []string{
		"-endpoint", enrollmentAddress.String(),
		"-server-name", "localhost",
		"-server-trust", material.caPath,
		"-credential-root", credentialRoot,
		"-node-id", "node-a",
		"-spiffe-trust-domain", "routesphere.test",
		"-spiffe-node-path-prefix", "/bonvoyage/nodes/",
		"-token-file", tokenPath,
	}, &enrollmentOutput, &bytes.Buffer{}); err != nil {
		cancel()
		t.Fatalf("enroll node: %v", err)
	}
	first, err := nodecredentials.LoadCurrent(credentialRoot)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := runEnrollNode(context.Background(), []string{
		"-endpoint", enrollmentAddress.String(),
		"-server-name", "localhost",
		"-server-trust", material.caPath,
		"-credential-root", credentialRoot,
		"-node-id", "node-a",
		"-spiffe-trust-domain", "routesphere.test",
		"-spiffe-node-path-prefix", "/bonvoyage/nodes/",
		"-token-file", tokenPath,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		cancel()
		t.Fatal("re-enrollment replaced an existing credential")
	}

	if err := runRenewNode(context.Background(), []string{
		"-endpoint", discoveryAddress.String(),
		"-server-name", "localhost",
		"-credential-root", credentialRoot,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		cancel()
		t.Fatalf("renew node: %v", err)
	}
	second, err := nodecredentials.LoadCurrent(credentialRoot)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if first.Manifest().CredentialGeneration == second.Manifest().CredentialGeneration {
		cancel()
		t.Fatal("renewal did not publish a new immutable generation")
	}

	if err := runRevokeNode([]string{
		"-revocation-file", revocationPath,
		"-node-id", "node-a",
		"-reason", "checkpoint-8 test",
	}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		cancel()
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := runRenewNode(context.Background(), []string{
		"-endpoint", discoveryAddress.String(),
		"-server-name", "localhost",
		"-credential-root", credentialRoot,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		cancel()
		t.Fatal("revoked node renewed a credential")
	}
	afterRevocation, err := nodecredentials.LoadCurrent(credentialRoot)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if afterRevocation.Manifest().CredentialGeneration != second.Manifest().CredentialGeneration {
		cancel()
		t.Fatal("failed renewal displaced the last valid generation")
	}

	cancel()
	select {
	case err := <-completed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("identity lifecycle listeners did not stop")
	}
}

func waitForAddress(t *testing.T, ready <-chan net.Addr) net.Addr {
	t.Helper()
	select {
	case address := <-ready:
		return address
	case <-time.After(5 * time.Second):
		t.Fatal("listener did not become ready")
		return nil
	}
}
