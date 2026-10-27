package discovery

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TestTLSLifecycleVerifiesDynamicIdentityAndRetainsLastGoodGeneration(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	directory := t.TempDir()
	authority := newTestAuthority(t)
	paths := writeLifecycleMaterial(t, directory, authority, now, 1, nil)
	lifecycle, err := OpenTLSLifecycle(TLSLifecycleOptions{
		ServerCertificatePath: paths.serverCertificate,
		ServerPrivateKeyPath:  paths.serverKey,
		ClientTrustBundlePath: paths.trustBundle,
		RevocationPath:        paths.revocations,
		ServerName:            "discovery.test", ReloadInterval: time.Second,
		MinimumValidity: time.Minute, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	initial := lifecycle.Status()
	if initial.Generation == "" || initial.TrustGeneration == "" || initial.ReloadSuccesses != 1 {
		t.Fatalf("initial lifecycle status = %#v", initial)
	}

	identityURL, err := url.Parse("spiffe://routesphere.test/bonvoyage/nodes/node-a")
	if err != nil {
		t.Fatal(err)
	}
	client := authority.certificate(t, "node-a", false, []*url.URL{identityURL})
	peerCertificates := parseTLSCertificateChain(t, client)
	verified, err := lifecycle.VerifyClientCertificate(peerCertificates, now)
	if err != nil || len(verified) < 2 {
		t.Fatalf("verify client: chain=%d err=%v", len(verified), err)
	}
	authenticator := MTLSAuthenticator{
		TrustDomain: "routesphere.test", NodePathPrefix: "/bonvoyage/nodes/",
		Verifier: lifecycle, Clock: func() time.Time { return now },
	}
	service, err := NewServer(newRecordingCoordinator(), DefaultOptions(authenticator))
	if err != nil {
		t.Fatal(err)
	}
	grpcServer, err := NewGRPCServer(service, lifecycle.ServerTLSConfig())
	if err != nil {
		t.Fatalf("dynamic TLS server config was rejected: %v", err)
	}
	grpcServer.Stop()
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{
		State: tls.ConnectionState{PeerCertificates: peerCertificates},
	}})
	identity, err := authenticator.Authenticate(ctx)
	if err != nil || identity.NodeID != "node-a" || identity.CredentialSerial == "" ||
		identity.IssuerFingerprint == "" || identity.TrustAnchorFingerprint == "" {
		t.Fatalf("dynamic identity = %#v err=%v", identity, err)
	}

	if err := os.WriteFile(paths.serverKey, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Reload(); err == nil {
		t.Fatal("malformed replacement was accepted")
	}
	afterFailure := lifecycle.Status()
	if afterFailure.Generation != initial.Generation || afterFailure.ReloadFailures != 1 ||
		afterFailure.LastError == "" {
		t.Fatalf("failed reload status = %#v", afterFailure)
	}
	if _, err := lifecycle.VerifyClientCertificate(peerCertificates, now); err != nil {
		t.Fatalf("last valid generation was displaced: %v", err)
	}
}

func TestTLSLifecycleRevocationAndTrustRotation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	directory := t.TempDir()
	oldAuthority := newTestAuthority(t)
	paths := writeLifecycleMaterial(t, directory, oldAuthority, now, 1, nil)
	lifecycle, err := OpenTLSLifecycle(TLSLifecycleOptions{
		ServerCertificatePath: paths.serverCertificate,
		ServerPrivateKeyPath:  paths.serverKey,
		ClientTrustBundlePath: paths.trustBundle,
		RevocationPath:        paths.revocations,
		ServerName:            "discovery.test", ReloadInterval: time.Second,
		MinimumValidity: time.Minute, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	identityURL, _ := url.Parse("spiffe://routesphere.test/bonvoyage/nodes/node-a")
	oldClient := oldAuthority.certificate(t, "node-a", false, []*url.URL{identityURL})
	oldChain := parseTLSCertificateChain(t, oldClient)
	leafFingerprint := certificateFingerprint(oldChain[0])
	issuerFingerprint := certificateFingerprint(oldChain[1])
	revoked := []RevokedCredential{{
		NodeID: "node-a", CredentialFingerprint: leafFingerprint,
		IssuerFingerprint: issuerFingerprint,
		SerialNumber:      oldChain[0].SerialNumber.Text(16), RevokedAt: now,
		Reason: "operator revocation test",
	}}
	writeRevocations(t, paths.revocations, now, 2, revoked)
	if err := lifecycle.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.VerifyClientCertificate(oldChain, now); err == nil {
		t.Fatal("revoked leaf was accepted")
	}
	writeRevocations(t, paths.revocations, now, 1, nil)
	if err := lifecycle.Reload(); err == nil {
		t.Fatal("revocation generation rollback was accepted")
	}
	if _, err := lifecycle.VerifyClientCertificate(oldChain, now); err == nil {
		t.Fatal("revocation rollback displaced the last valid generation")
	}
	writeRevocations(t, paths.revocations, now, 2, nil)
	if err := lifecycle.Reload(); err == nil {
		t.Fatal("changed revocations reused an existing generation")
	}
	if _, err := lifecycle.VerifyClientCertificate(oldChain, now); err == nil {
		t.Fatal("same-generation mutation displaced the last valid generation")
	}

	newAuthority := newTestAuthority(t)
	writeLifecycleMaterial(t, directory, newAuthority, now, 3, nil)
	if err := lifecycle.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.VerifyClientCertificate(oldChain, now); err == nil {
		t.Fatal("old trust anchor remained accepted after rotation")
	}
	newClient := newAuthority.certificate(t, "node-a", false, []*url.URL{identityURL})
	if _, err := lifecycle.VerifyClientCertificate(parseTLSCertificateChain(t, newClient), now); err != nil {
		t.Fatalf("new trust generation rejected: %v", err)
	}
}

func TestTLSLifecycleFailsClosedWhenRevocationSnapshotExpires(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	directory := t.TempDir()
	authority := newTestAuthority(t)
	paths := writeLifecycleMaterial(t, directory, authority, now, 1, nil)
	document := RevocationDocument{
		Version: 1, Generation: 1, UpdatedAt: now,
		ValidUntil: now.Add(30 * time.Minute), Revoked: []RevokedCredential{},
	}
	contents, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, paths.revocations, append(contents, '\n'), 0o644)
	clock := now
	lifecycle, err := OpenTLSLifecycle(TLSLifecycleOptions{
		ServerCertificatePath: paths.serverCertificate,
		ServerPrivateKeyPath:  paths.serverKey,
		ClientTrustBundlePath: paths.trustBundle,
		RevocationPath:        paths.revocations,
		ServerName:            "discovery.test", ReloadInterval: time.Second,
		MinimumValidity: time.Minute, Clock: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	identityURL, _ := url.Parse("spiffe://routesphere.test/bonvoyage/nodes/node-a")
	client := authority.certificate(t, "node-a", false, []*url.URL{identityURL})
	clock = now.Add(31 * time.Minute)
	if _, err := lifecycle.VerifyClientCertificate(parseTLSCertificateChain(t, client), clock); err == nil {
		t.Fatal("expired revocation state did not fail closed")
	}
}

func TestTLSLifecycleRejectsIncoherentPresentedServerChain(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	directory := t.TempDir()
	trustedAuthority := newTestAuthority(t)
	paths := writeLifecycleMaterial(t, directory, trustedAuthority, now, 1, nil)
	lifecycle, err := OpenTLSLifecycle(TLSLifecycleOptions{
		ServerCertificatePath: paths.serverCertificate,
		ServerPrivateKeyPath:  paths.serverKey,
		ClientTrustBundlePath: paths.trustBundle,
		RevocationPath:        paths.revocations,
		ServerName:            "discovery.test", ReloadInterval: time.Second,
		MinimumValidity: time.Minute, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	initial := lifecycle.Status()

	unrelatedAuthority := newTestAuthority(t)
	server := unrelatedAuthority.certificate(t, "discovery.test", true, nil)
	incoherentChain := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate[0]}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: trustedAuthority.certificateValue.Raw})...,
	)
	privateKey := server.PrivateKey.(*ecdsa.PrivateKey)
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, paths.serverCertificate, incoherentChain, 0o644)
	writeTestFile(t, paths.serverKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	if err := lifecycle.Reload(); err == nil {
		t.Fatal("incoherent server certificate chain was accepted")
	}
	afterFailure := lifecycle.Status()
	if afterFailure.Generation != initial.Generation || afterFailure.ReloadFailures != 1 {
		t.Fatalf("failed chain reload status = %#v", afterFailure)
	}
}

func TestRevocationDocumentOperatorLifecycle(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	path := filepath.Join(t.TempDir(), "revocations.json")
	document, err := InitializeRevocationDocument(path, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if document.Generation != 1 || len(document.Revoked) != 0 {
		t.Fatalf("initial document = %#v", document)
	}
	if _, err := InitializeRevocationDocument(path, now, 24*time.Hour); err == nil {
		t.Fatal("initialization replaced an existing revocation document")
	}

	document, err = AddNodeRevocation(path, "node-a", "operator incident", now.Add(time.Minute), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if document.Generation != 2 || len(document.Revoked) != 1 || document.Revoked[0].NodeID != "node-a" {
		t.Fatalf("revoked document = %#v", document)
	}
	document, err = AddNodeRevocation(path, "node-a", "operator incident", now.Add(2*time.Minute), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if document.Generation != 3 || len(document.Revoked) != 1 {
		t.Fatalf("idempotent revoke document = %#v", document)
	}

	refreshTime := document.ValidUntil.Add(time.Minute)
	document, err = RefreshRevocationDocument(path, refreshTime, 24*time.Hour)
	if err != nil {
		t.Fatalf("expired but valid document could not be recovered: %v", err)
	}
	if document.Generation != 4 || !document.ValidUntil.Equal(refreshTime.Add(24*time.Hour)) || len(document.Revoked) != 1 {
		t.Fatalf("refreshed document = %#v", document)
	}
}

type lifecyclePaths struct {
	serverCertificate string
	serverKey         string
	trustBundle       string
	revocations       string
}

func writeLifecycleMaterial(
	t *testing.T,
	directory string,
	authority *testAuthority,
	now time.Time,
	revocationGeneration uint64,
	revoked []RevokedCredential,
) lifecyclePaths {
	t.Helper()
	server := authority.certificate(t, "discovery.test", true, nil)
	paths := lifecyclePaths{
		serverCertificate: filepath.Join(directory, "server.pem"),
		serverKey:         filepath.Join(directory, "server-key.pem"),
		trustBundle:       filepath.Join(directory, "ca.pem"),
		revocations:       filepath.Join(directory, "revocations.json"),
	}
	certificatePEM := make([]byte, 0, 2048)
	for _, der := range server.Certificate {
		certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	privateKey, ok := server.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("server key is not ECDSA")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, paths.serverCertificate, certificatePEM, 0o644)
	writeTestFile(t, paths.serverKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	writeTestFile(t, paths.trustBundle, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: authority.certificateValue.Raw,
	}), 0o644)
	writeRevocations(t, paths.revocations, now, revocationGeneration, revoked)
	return paths
}

func writeRevocations(
	t *testing.T,
	path string,
	now time.Time,
	generation uint64,
	revoked []RevokedCredential,
) {
	t.Helper()
	document := RevocationDocument{
		Version: 1, Generation: generation, UpdatedAt: now,
		ValidUntil: now.Add(24 * time.Hour), Revoked: revoked,
	}
	contents, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, path, append(contents, '\n'), 0o644)
}

func writeTestFile(t *testing.T, path string, contents []byte, mode os.FileMode) {
	t.Helper()
	temporary := path + ".new"
	if err := os.WriteFile(temporary, contents, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(temporary, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, path); err != nil {
		t.Fatal(err)
	}
}

func parseTLSCertificateChain(t *testing.T, certificate tls.Certificate) []*x509.Certificate {
	t.Helper()
	result := make([]*x509.Certificate, 0, len(certificate.Certificate))
	for _, der := range certificate.Certificate {
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, parsed)
	}
	return result
}
