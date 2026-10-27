package main

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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	bonvoyagev1 "github.com/routesphere-global/bonvoyage/api/gen/go/bonvoyage/v1"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/snapshot"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
	"google.golang.org/protobuf/proto"
)

func TestRunValidateOnly(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	missingOutput := filepath.Join(t.TempDir(), "must-not-exist.pb")
	err := run(context.Background(), []string{
		"-input", "../../../config/examples/local.yaml",
		"-output", missingOutput,
		"-validate-only",
	}, &stdout, &stderr, defaultCommandRuntime())
	if err != nil {
		t.Fatalf("run() error = %v, stderr = %s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "configuration valid: snapshot=local-bootstrap generation=1") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if _, err := os.Stat(missingOutput); !os.IsNotExist(err) {
		t.Fatalf("validate-only output exists or stat failed unexpectedly: %v", err)
	}
}

func TestRunWritesProtobufArtifact(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	output := filepath.Join(t.TempDir(), "snapshot.pb")
	err := run(context.Background(), []string{
		"-input", "../../../config/examples/local.yaml",
		"-output", output,
	}, &stdout, &stderr, defaultCommandRuntime())
	if err != nil {
		t.Fatalf("run() error = %v, stderr = %s", err, stderr.String())
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	var compiled bonvoyagev1.Snapshot
	if err := proto.Unmarshal(data, &compiled); err != nil {
		t.Fatalf("proto.Unmarshal() error = %v", err)
	}
	if compiled.GetSnapshotId() != "local-bootstrap" || compiled.GetSchemaVersion() != 1 {
		t.Fatalf("unexpected artifact: %+v", &compiled)
	}
	if !strings.Contains(stdout.String(), "snapshot written:") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunDiscoveryRequiresEveryFlag(t *testing.T) {
	valid := []string{
		"serve-discovery",
		"-repository-root", "/repository",
		"-rollout-sequence", "7",
		"-listen-address", "127.0.0.1:8443",
		"-tls-server-cert", "/tls/server.crt",
		"-tls-server-key", "/tls/server.key",
		"-tls-client-ca", "/tls/client-ca.crt",
		"-spiffe-trust-domain", "routesphere.test",
		"-spiffe-node-path-prefix", "/bonvoyage/nodes/",
	}
	for index := 1; index < len(valid); index += 2 {
		flagName := valid[index]
		args := append([]string(nil), valid[:index]...)
		args = append(args, valid[index+2:]...)
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		err := run(context.Background(), args, &stdout, &stderr, defaultCommandRuntime())
		if err == nil || !strings.Contains(err.Error(), flagName) {
			t.Fatalf("omitting %s: error = %v", flagName, err)
		}
	}
}

func TestRunDiscoveryRejectsInvalidIdentityPolicyAndPositionals(t *testing.T) {
	options := discoveryCommandOptions{
		repositoryRoot: "/repository", rolloutSequence: 7, listenAddress: "127.0.0.1:8443",
		tlsServerCertificate: "/tls/server.crt", tlsServerKey: "/tls/server.key",
		tlsClientCA: "/tls/client-ca.crt", spiffeTrustDomain: "spiffe://routesphere.test",
		spiffeNodePathPrefix: "/bonvoyage/nodes/",
	}
	if err := validateDiscoveryOptions(options); err == nil || !strings.Contains(err.Error(), "trust-domain") {
		t.Fatalf("invalid trust domain error = %v", err)
	}
	options.spiffeTrustDomain = "routesphere.test"
	options.spiffeNodePathPrefix = "bonvoyage/nodes"
	if err := validateDiscoveryOptions(options); err == nil || !strings.Contains(err.Error(), "node-path-prefix") {
		t.Fatalf("invalid node path prefix error = %v", err)
	}

	args := discoveryArgs(options)
	args = append(args, "unexpected")
	err := run(context.Background(), args, &bytes.Buffer{}, &bytes.Buffer{}, defaultCommandRuntime())
	if err == nil || !strings.Contains(err.Error(), "unexpected positional arguments") {
		t.Fatalf("positional argument error = %v", err)
	}
}

func TestValidateDiscoveryOptionsRequiresIsolatedCompleteAdminBoundary(t *testing.T) {
	options := discoveryCommandOptions{
		repositoryRoot: "/repository", rolloutSequence: 7, listenAddress: "127.0.0.1:8443",
		tlsServerCertificate: "/tls/node-server.crt", tlsServerKey: "/tls/node-server.key",
		tlsClientCA: "/tls/node-client-ca.crt", spiffeTrustDomain: "routesphere.test",
		spiffeNodePathPrefix: "/bonvoyage/nodes/", adminListenAddress: "127.0.0.1:9443",
	}
	if err := validateDiscoveryOptions(options); err == nil || !strings.Contains(err.Error(), "Admin API flags are incomplete") {
		t.Fatalf("incomplete Admin boundary error = %v", err)
	}
	options.adminTLSCertificate = "/tls/admin-server.crt"
	options.adminTLSKey = "/tls/admin-server.key"
	options.adminTLSClientCA = "/tls/admin-client-ca.crt"
	options.adminServerName = "admin.routesphere.test"
	options.adminAuthorizations = "/etc/bonvoyage/admin-authorizations.json"
	options.adminTrustDomain = "admin.routesphere.test"
	options.adminOperatorPrefix = "/bonvoyage/operators/"
	options.adminServicePrefix = "/bonvoyage/service-accounts/"
	options.adminMaxConcurrent = 128
	options.policyReconcileInterval = 250 * time.Millisecond
	if err := validateDiscoveryOptions(options); err != nil {
		t.Fatalf("valid Admin boundary error = %v", err)
	}

	options.adminListenAddress = options.listenAddress
	if err := validateDiscoveryOptions(options); err == nil || !strings.Contains(err.Error(), "distinct addresses") {
		t.Fatalf("shared listener error = %v", err)
	}
	options.adminListenAddress = "127.0.0.1:9443"
	options.adminTLSClientCA = options.tlsClientCA
	if err := validateDiscoveryOptions(options); err == nil || !strings.Contains(err.Error(), "TLS files must be distinct") {
		t.Fatalf("shared trust bundle error = %v", err)
	}

	options.adminTLSClientCA = "/tls/admin-client-ca.crt"
	options.listenAddress = "127.0.0.1:0"
	options.adminListenAddress = "127.0.0.1:0"
	if err := validateDiscoveryOptions(options); err != nil {
		t.Fatalf("ephemeral listeners should receive distinct kernel addresses: %v", err)
	}
}

func TestResolveSelectedRolloutPersistsAndResumesAuthority(t *testing.T) {
	repositoryRoot := filepath.Join(t.TempDir(), "repository")
	sequence := createDiscoveryRepository(t, repositoryRoot)
	repository, err := storage.OpenFileRepository(repositoryRoot, storage.FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	options := discoveryCommandOptions{rolloutSequence: sequence, adminListenAddress: "127.0.0.1:9443"}
	selected, err := resolveSelectedRollout(context.Background(), repository, options)
	if err != nil || selected != sequence {
		t.Fatalf("initialize selection = %d, %v", selected, err)
	}
	options.rolloutSequence = sequence + 999
	selected, err = resolveSelectedRollout(context.Background(), repository, options)
	if err != nil || selected != sequence {
		t.Fatalf("resume persisted selection = %d, %v", selected, err)
	}
}

func TestLoadDiscoveryTLSConfig(t *testing.T) {
	material := newTestTLSMaterial(t)
	config, err := loadDiscoveryTLSConfig(material.serverCertificatePath, material.serverKeyPath, material.caPath)
	if err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != tls.VersionTLS13 || config.MaxVersion != tls.VersionTLS13 ||
		config.ClientAuth != tls.RequireAndVerifyClientCert || config.ClientCAs == nil ||
		len(config.Certificates) != 1 || config.Certificates[0].Leaf == nil {
		t.Fatalf("unexpected TLS configuration: %#v", config)
	}

	invalidCA := filepath.Join(t.TempDir(), "invalid-client-ca.pem")
	if err := os.WriteFile(invalidCA, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDiscoveryTLSConfig(material.serverCertificatePath, material.serverKeyPath, invalidCA); err == nil ||
		!strings.Contains(err.Error(), "client CA bundle") {
		t.Fatalf("invalid client CA error = %v", err)
	}
}

func TestRunDiscoveryStartsStopsAndReleasesRepositoryLock(t *testing.T) {
	repositoryRoot := filepath.Join(t.TempDir(), "repository")
	sequence := createDiscoveryRepository(t, repositoryRoot)
	material := newTestTLSMaterial(t)
	options := discoveryCommandOptions{
		repositoryRoot: repositoryRoot, rolloutSequence: sequence, startRollout: true, listenAddress: "127.0.0.1:0",
		tlsServerCertificate: material.serverCertificatePath, tlsServerKey: material.serverKeyPath,
		tlsClientCA: material.caPath, spiffeTrustDomain: "routesphere.test",
		spiffeNodePathPrefix: "/bonvoyage/nodes/",
	}

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan net.Addr, 1)
	completed := make(chan error, 1)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	runtime := defaultCommandRuntime()
	runtime.listenerReady = func(address net.Addr) { ready <- address }
	runtime.shutdownTimeout = time.Second
	go func() {
		completed <- run(ctx, discoveryArgs(options), &stdout, &stderr, runtime)
	}()

	var address net.Addr
	select {
	case address = <-ready:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("discovery listener did not become ready")
	}
	if locked, err := storage.OpenFileRepository(repositoryRoot, storage.FileOptions{}); !errors.Is(err, storage.ErrLocked) {
		if err == nil {
			_ = locked.Close()
		}
		t.Fatalf("second repository open error = %v, want %v", err, storage.ErrLocked)
	}

	connection, err := tls.Dial("tcp", address.String(), material.clientTLSConfig(t))
	if err != nil {
		cancel()
		t.Fatalf("mTLS discovery connection: %v", err)
	}
	if connection.ConnectionState().Version != tls.VersionTLS13 || connection.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatalf("unexpected TLS state: %#v", connection.ConnectionState())
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}

	cancel()
	select {
	case err := <-completed:
		if err != nil {
			t.Fatalf("run() error = %v, stderr = %s", err, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("discovery listener did not stop")
	}
	if !strings.Contains(stdout.String(), "discovery listener ready:") ||
		!strings.Contains(stdout.String(), "discovery listener stopped") {
		t.Fatalf("stdout = %q", stdout.String())
	}

	reopened, err := storage.OpenFileRepository(repositoryRoot, storage.FileOptions{})
	if err != nil {
		t.Fatalf("repository lock was not released: %v", err)
	}
	events, err := reopened.ListRolloutEvents(context.Background(), sequence)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != "START" {
		t.Fatalf("rollout start events = %#v", events)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRunDiscoveryServesSeparateAdminMTLSListener(t *testing.T) {
	repositoryRoot := filepath.Join(t.TempDir(), "repository")
	sequence := createDiscoveryRepository(t, repositoryRoot)
	nodeMaterial := newTestTLSMaterial(t)
	adminMaterial := newTestTLSMaterial(t)
	adminClient := adminMaterial.clientTLSConfigForIdentity(
		t, "spiffe://admin.routesphere.test/bonvoyage/operators/operator-a",
	)
	adminClient.NextProtos = []string{"http/1.1"}
	clientDigest := sha256.Sum256(adminClient.Certificates[0].Certificate[0])
	authorizationsPath := filepath.Join(t.TempDir(), "admin-authorizations.json")
	authorizations, err := json.Marshal(map[string]any{
		"version": 1, "generation": 1,
		"updated_at": time.Now().UTC().Add(-time.Minute), "valid_until": time.Now().UTC().Add(time.Hour),
		"principals": []map[string]any{{
			"spiffe_id":          "spiffe://admin.routesphere.test/bonvoyage/operators/operator-a",
			"certificate_sha256": fmt.Sprintf("sha256:%x", clientDigest),
			"role":               "operator", "source_channel": "gitops",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(authorizationsPath, authorizations, 0o600); err != nil {
		t.Fatal(err)
	}
	options := discoveryCommandOptions{
		repositoryRoot: repositoryRoot, rolloutSequence: sequence, listenAddress: "127.0.0.1:0",
		tlsServerCertificate: nodeMaterial.serverCertificatePath, tlsServerKey: nodeMaterial.serverKeyPath,
		tlsClientCA: nodeMaterial.caPath, spiffeTrustDomain: "routesphere.test",
		spiffeNodePathPrefix: "/bonvoyage/nodes/", adminListenAddress: "127.0.0.1:0",
		adminTLSCertificate: adminMaterial.serverCertificatePath, adminTLSKey: adminMaterial.serverKeyPath,
		adminTLSClientCA: adminMaterial.caPath, adminServerName: "localhost",
		adminAuthorizations: authorizationsPath, adminTrustDomain: "admin.routesphere.test",
		adminOperatorPrefix: "/bonvoyage/operators/", adminServicePrefix: "/bonvoyage/service-accounts/",
		adminMaxConcurrent: 8,
	}

	ctx, cancel := context.WithCancel(context.Background())
	discoveryReady := make(chan net.Addr, 1)
	adminReady := make(chan net.Addr, 1)
	completed := make(chan error, 1)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	runtime := defaultCommandRuntime()
	runtime.listenerReady = func(address net.Addr) { discoveryReady <- address }
	runtime.adminListenerReady = func(address net.Addr) { adminReady <- address }
	runtime.shutdownTimeout = time.Second
	go func() {
		completed <- run(ctx, discoveryArgs(options), &stdout, &stderr, runtime)
	}()

	select {
	case <-discoveryReady:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("discovery listener did not become ready")
	}
	var adminAddress net.Addr
	select {
	case adminAddress = <-adminReady:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatalf("Admin listener did not become ready: stderr=%s", stderr.String())
	}
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: adminClient, DisableKeepAlives: true,
	}}
	request, err := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://"+adminAddress.String()+"/api/v1/rollouts/current", nil,
	)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	request.Host = "localhost"
	response, err := client.Do(request)
	if err != nil {
		cancel()
		t.Fatalf("Admin mTLS request: %v; stderr=%s", err, stderr.String())
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("Admin status = %d", response.StatusCode)
	}
	var status struct {
		Sequence uint64 `json:"sequence"`
		Selected bool   `json:"selected"`
		Phase    string `json:"phase"`
	}
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
		cancel()
		t.Fatal(err)
	}
	if status.Sequence != sequence || !status.Selected || status.Phase != "PREPARING" {
		cancel()
		t.Fatalf("Admin rollout status = %#v", status)
	}

	cancel()
	select {
	case err := <-completed:
		if err != nil {
			t.Fatalf("run() error = %v, stderr = %s", err, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("control-plane listeners did not stop")
	}
	if !strings.Contains(stdout.String(), "Admin API listener ready:") ||
		!strings.Contains(stdout.String(), "rollout_phase=PREPARING") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunDiscoveryReleasesRepositoryLockAfterBindFailure(t *testing.T) {
	repositoryRoot := filepath.Join(t.TempDir(), "repository")
	sequence := createDiscoveryRepository(t, repositoryRoot)
	material := newTestTLSMaterial(t)
	options := discoveryCommandOptions{
		repositoryRoot: repositoryRoot, rolloutSequence: sequence, listenAddress: "127.0.0.1:8443",
		tlsServerCertificate: material.serverCertificatePath, tlsServerKey: material.serverKeyPath,
		tlsClientCA: material.caPath, spiffeTrustDomain: "routesphere.test",
		spiffeNodePathPrefix: "/bonvoyage/nodes/",
	}
	runtime := defaultCommandRuntime()
	runtime.listen = func(string, string) (net.Listener, error) {
		return nil, errors.New("injected bind failure")
	}
	err := run(context.Background(), discoveryArgs(options), &bytes.Buffer{}, &bytes.Buffer{}, runtime)
	if err == nil || !strings.Contains(err.Error(), "injected bind failure") {
		t.Fatalf("bind failure error = %v", err)
	}
	reopened, err := storage.OpenFileRepository(repositoryRoot, storage.FileOptions{})
	if err != nil {
		t.Fatalf("repository lock was not released after bind failure: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func discoveryArgs(options discoveryCommandOptions) []string {
	args := []string{
		"serve-discovery",
		"-repository-root", options.repositoryRoot,
		"-rollout-sequence", big.NewInt(0).SetUint64(options.rolloutSequence).String(),
		"-listen-address", options.listenAddress,
		"-tls-server-cert", options.tlsServerCertificate,
		"-tls-server-key", options.tlsServerKey,
		"-tls-client-ca", options.tlsClientCA,
		"-spiffe-trust-domain", options.spiffeTrustDomain,
		"-spiffe-node-path-prefix", options.spiffeNodePathPrefix,
	}
	if options.startRollout {
		args = append(args, "-start-rollout")
	}
	if options.identityLifecycleEnabled() {
		args = append(args,
			"-enrollment-listen-address", options.enrollmentAddress,
			"-identity-repository-root", options.identityRepository,
			"-identity-audience", options.identityAudience,
			"-identity-issuer-cert", options.identityIssuerCert,
			"-identity-issuer-key", options.identityIssuerKey,
			"-tls-revocations", options.tlsRevocations,
			"-tls-server-name", options.tlsServerName,
			"-tls-reload-interval", options.tlsReloadInterval.String(),
			"-tls-minimum-validity", options.tlsMinimumValidity.String(),
			"-identity-clock-skew", options.identityClockSkew.String(),
			"-identity-observation-max-age", options.identityMaxAge.String(),
			"-identity-max-concurrent-enrollments", strconv.Itoa(options.identityMaxConcurrent),
		)
	}
	if options.adminEnabled() {
		args = append(args,
			"-admin-listen-address", options.adminListenAddress,
			"-admin-tls-server-cert", options.adminTLSCertificate,
			"-admin-tls-server-key", options.adminTLSKey,
			"-admin-tls-client-ca", options.adminTLSClientCA,
			"-admin-tls-server-name", options.adminServerName,
			"-admin-authorizations", options.adminAuthorizations,
			"-admin-spiffe-trust-domain", options.adminTrustDomain,
			"-admin-spiffe-operator-path-prefix", options.adminOperatorPrefix,
			"-admin-spiffe-service-account-path-prefix", options.adminServicePrefix,
			"-admin-max-concurrent", strconv.Itoa(options.adminMaxConcurrent),
		)
	}
	return args
}

func createDiscoveryRepository(t *testing.T, root string) uint64 {
	t.Helper()
	repository, err := storage.OpenFileRepository(root, storage.FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	document, err := os.ReadFile("../../../config/examples/local.yaml")
	if err != nil {
		_ = repository.Close()
		t.Fatal(err)
	}
	desired, err := repository.CreateDesiredRevision(context.Background(), storage.DesiredRevisionInput{
		RequestID: "discovery-command-desired", Document: document, SourceChannel: storage.SourceSystem,
		Actor: "discovery-command-test",
	})
	if err != nil {
		_ = repository.Close()
		t.Fatal(err)
	}
	compiled, err := snapshot.Compile(bytes.NewReader(document))
	if err != nil {
		_ = repository.Close()
		t.Fatal(err)
	}
	artifactBytes, err := snapshot.MarshalDeterministic(compiled)
	if err != nil {
		_ = repository.Close()
		t.Fatal(err)
	}
	artifact, err := repository.CreateSnapshotArtifact(context.Background(), storage.SnapshotArtifactInput{
		DesiredRevisionID: desired.ID, CompilerVersion: "checkpoint-7-test", Bytes: artifactBytes,
	})
	if err != nil {
		_ = repository.Close()
		t.Fatal(err)
	}
	record, err := repository.AllocateRollout(context.Background(), storage.RolloutInput{
		RequestID: "discovery-command-rollout", ArtifactDigest: artifact.Digest,
		DesiredRevisionID: desired.ID, CompilerVersion: "checkpoint-7-test", TargetNodeIDs: []string{"node-a"},
		SourceChannel: storage.SourceSystem, Actor: "discovery-command-test", Reason: "listener lifecycle test",
	})
	if err != nil {
		_ = repository.Close()
		t.Fatal(err)
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}
	return record.Sequence
}

type testTLSMaterial struct {
	serverCertificatePath string
	serverKeyPath         string
	caPath                string
	caCertificate         *x509.Certificate
	caKey                 *ecdsa.PrivateKey
}

func newTestTLSMaterial(t *testing.T) testTLSMaterial {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "BonVoyage command test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	caPath := filepath.Join(directory, "client-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCertificate, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	serverCertificatePath := filepath.Join(directory, "server.pem")
	serverKeyPath := filepath.Join(directory, "server-key.pem")
	serverPEM := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...,
	)
	if err := os.WriteFile(serverCertificatePath, serverPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(serverKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return testTLSMaterial{
		serverCertificatePath: serverCertificatePath, serverKeyPath: serverKeyPath,
		caPath: caPath, caCertificate: caCertificate, caKey: caKey,
	}
}

func (material testTLSMaterial) clientTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	return material.clientTLSConfigForIdentity(t, "spiffe://routesphere.test/bonvoyage/nodes/node-a")
}

func (material testTLSMaterial) clientTLSConfigForIdentity(t *testing.T, identityValue string) *tls.Config {
	t.Helper()
	identity, err := url.Parse(identityValue)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "node-a"}, URIs: []*url.URL{identity},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(
		rand.Reader, clientTemplate, material.caCertificate, &clientKey.PublicKey, material.caKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(material.caCertificate)
	return &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ServerName: "localhost",
		RootCAs: rootCAs, NextProtos: []string{"h2"},
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{clientDER, material.caCertificate.Raw}, PrivateKey: clientKey,
		}},
	}
}
