// Command discoveryfixture creates and verifies the private state used by the
// shipped discovery process acceptance test. It is test tooling, not an
// operator-facing management API.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/rollout"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/rolloutservice"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/snapshot"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
)

const fixtureCompilerVersion = "phase4-checkpoint-7-integration"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "discoveryfixture: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("expected prepare, generate-tls, or verify")
	}
	switch args[0] {
	case "prepare":
		return prepare(args[1:])
	case "generate-tls":
		return generateTLS(args[1:])
	case "issue-client":
		return issueClient(args[1:])
	case "verify":
		return verify(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func issueClient(args []string) error {
	flags := flag.NewFlagSet("discoveryfixture issue-client", flag.ContinueOnError)
	directory := flags.String("tls-directory", "", "existing ephemeral TLS directory")
	nodeID := flags.String("node-id", "", "fixture node identity")
	outputPrefix := flags.String("output-prefix", "", "certificate output basename")
	trustDomain := flags.String("spiffe-trust-domain", "routesphere.test", "client SPIFFE trust domain")
	identityPathPrefix := flags.String("spiffe-path-prefix", "/bonvoyage/nodes/", "client SPIFFE path prefix")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*directory) == "" || strings.TrimSpace(*nodeID) == "" ||
		strings.TrimSpace(*outputPrefix) == "" || filepath.Base(*outputPrefix) != *outputPrefix ||
		strings.TrimSpace(*trustDomain) == "" || !strings.HasPrefix(*identityPathPrefix, "/") ||
		!strings.HasSuffix(*identityPathPrefix, "/") {
		return errors.New("TLS directory, node identity, safe output prefix, trust domain, and absolute path prefix are required")
	}
	caPEM, err := os.ReadFile(filepath.Join(*directory, "issuer.pem"))
	if err != nil {
		return err
	}
	caBlock, trailing := pem.Decode(caPEM)
	if caBlock == nil || caBlock.Type != "CERTIFICATE" || len(strings.TrimSpace(string(trailing))) != 0 {
		return errors.New("issuer certificate is invalid")
	}
	caCertificate, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil || !caCertificate.IsCA {
		return errors.New("issuer certificate is not a CA")
	}
	keyPEM, err := os.ReadFile(filepath.Join(*directory, "issuer-key.pem"))
	if err != nil {
		return err
	}
	keyBlock, keyTrailing := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" || len(strings.TrimSpace(string(keyTrailing))) != 0 {
		return errors.New("issuer private key is invalid")
	}
	caKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}
	return generateClientMaterial(
		*directory, *outputPrefix, *nodeID, *trustDomain, *identityPathPrefix,
		caCertificate, caKey, time.Now().UTC(), nil,
	)
}

func generateTLS(args []string) error {
	flags := flag.NewFlagSet("discoveryfixture generate-tls", flag.ContinueOnError)
	directory := flags.String("tls-directory", "", "new ephemeral TLS output directory")
	nodeID := flags.String("node-id", "node-a", "fixture node identity")
	serverName := flags.String("server-name", "discovery.test", "server certificate DNS identity")
	trustDomain := flags.String("spiffe-trust-domain", "routesphere.test", "client SPIFFE trust domain")
	identityPathPrefix := flags.String("spiffe-path-prefix", "/bonvoyage/nodes/", "client SPIFFE path prefix")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*directory) == "" || strings.TrimSpace(*nodeID) == "" ||
		strings.TrimSpace(*serverName) == "" || strings.TrimSpace(*trustDomain) == "" ||
		!strings.HasPrefix(*identityPathPrefix, "/") || !strings.HasSuffix(*identityPathPrefix, "/") {
		return errors.New("TLS directory, node identity, server name, trust domain, and absolute path prefix are required")
	}
	if err := os.MkdirAll(*directory, 0o700); err != nil {
		return err
	}
	return generateTLSMaterial(
		*directory, *nodeID, *serverName, *trustDomain, *identityPathPrefix,
	)
}

func prepare(args []string) (returnErr error) {
	flags := flag.NewFlagSet("discoveryfixture prepare", flag.ContinueOnError)
	repositoryRoot := flags.String("repository", "", "new repository directory")
	bootstrapConfig := flags.String("bootstrap-config", "", "bootstrap YAML")
	candidateConfig := flags.String("candidate-config", "", "compatible candidate YAML")
	restartConfig := flags.String("restart-config", "", "listener-incompatible YAML")
	bootstrapOutput := flags.String("bootstrap-output", "", "compiled bootstrap output")
	tlsDirectory := flags.String("tls-directory", "", "ephemeral TLS output directory")
	nodeID := flags.String("node-id", "node-a", "target node identity")
	nodeIDs := flags.String("node-ids", "", "optional comma-separated target node identities")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}
	for name, value := range map[string]string{
		"repository":       *repositoryRoot,
		"bootstrap-config": *bootstrapConfig,
		"candidate-config": *candidateConfig,
		"restart-config":   *restartConfig,
		"bootstrap-output": *bootstrapOutput,
		"tls-directory":    *tlsDirectory,
		"node-id":          *nodeID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("-%s is required", name)
		}
	}

	if err := os.MkdirAll(filepath.Dir(*bootstrapOutput), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(*tlsDirectory, 0o700); err != nil {
		return err
	}
	targetNodeIDs := []string{*nodeID}
	if strings.TrimSpace(*nodeIDs) != "" {
		targetNodeIDs = nil
		seen := make(map[string]struct{})
		for _, candidate := range strings.Split(*nodeIDs, ",") {
			candidate = strings.TrimSpace(candidate)
			if candidate == "" {
				return errors.New("node target list contains an empty identity")
			}
			if _, found := seen[candidate]; found {
				return fmt.Errorf("node target list repeats %q", candidate)
			}
			seen[candidate] = struct{}{}
			targetNodeIDs = append(targetNodeIDs, candidate)
		}
		if _, found := seen[*nodeID]; !found {
			return errors.New("primary node identity is absent from the target node list")
		}
	}
	repository, err := storage.OpenFileRepository(*repositoryRoot, storage.FileOptions{})
	if err != nil {
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, repository.Close())
	}()

	bootstrap, bootstrapBytes, err := createArtifact(
		repository, "bootstrap", *bootstrapConfig,
	)
	if err != nil {
		return err
	}
	if err := snapshot.WriteFileAtomic(*bootstrapOutput, bootstrapBytes); err != nil {
		return err
	}
	candidate, _, err := createArtifact(repository, "candidate", *candidateConfig)
	if err != nil {
		return err
	}
	restartRequired, _, err := createArtifact(repository, "restart", *restartConfig)
	if err != nil {
		return err
	}

	ctx := context.Background()
	valid, err := repository.AllocateRollout(ctx, storage.RolloutInput{
		RequestID:              "phase4-checkpoint-7-valid",
		ArtifactDigest:         candidate.artifact.Digest,
		PreviousArtifactDigest: bootstrap.artifact.Digest,
		DesiredRevisionID:      candidate.desired.ID,
		CompilerVersion:        fixtureCompilerVersion,
		TargetNodeIDs:          targetNodeIDs,
		SourceChannel:          storage.SourceSystem,
		Actor:                  "phase4-integration",
		Reason:                 "prove live compatible snapshot activation",
	})
	if err != nil {
		return err
	}
	invalid, err := repository.AllocateRollout(ctx, storage.RolloutInput{
		RequestID:              "phase4-checkpoint-7-listener-restart",
		ArtifactDigest:         restartRequired.artifact.Digest,
		PreviousArtifactDigest: candidate.artifact.Digest,
		DesiredRevisionID:      restartRequired.desired.ID,
		CompilerVersion:        fixtureCompilerVersion,
		TargetNodeIDs:          targetNodeIDs,
		SourceChannel:          storage.SourceSystem,
		Actor:                  "phase4-integration",
		Reason:                 "prove listener topology changes fail closed",
	})
	if err != nil {
		return err
	}
	if err := generateTLSMaterial(
		*tlsDirectory, *nodeID, "discovery.test", "routesphere.test", "/bonvoyage/nodes/",
	); err != nil {
		return err
	}

	fmt.Printf("VALID_SEQUENCE=%d\n", valid.Sequence)
	fmt.Printf("INVALID_SEQUENCE=%d\n", invalid.Sequence)
	fmt.Printf("BOOTSTRAP_SNAPSHOT_ID=%s\n", bootstrap.artifact.SnapshotID)
	fmt.Printf("VALID_SNAPSHOT_ID=%s\n", candidate.artifact.SnapshotID)
	fmt.Printf("INVALID_SNAPSHOT_ID=%s\n", restartRequired.artifact.SnapshotID)
	return nil
}

type compiledArtifact struct {
	desired  storage.DesiredRevision
	artifact storage.SnapshotArtifact
}

func createArtifact(
	repository *storage.FileRepository,
	name string,
	configPath string,
) (compiledArtifact, []byte, error) {
	document, err := os.ReadFile(configPath)
	if err != nil {
		return compiledArtifact{}, nil, err
	}
	desired, err := repository.CreateDesiredRevision(
		context.Background(),
		storage.DesiredRevisionInput{
			RequestID:     "phase4-checkpoint-7-" + name,
			Document:      document,
			SourceChannel: storage.SourceSystem,
			Actor:         "phase4-integration",
		},
	)
	if err != nil {
		return compiledArtifact{}, nil, err
	}
	compiled, err := snapshot.Compile(bytes.NewReader(document))
	if err != nil {
		return compiledArtifact{}, nil, err
	}
	artifactBytes, err := snapshot.MarshalDeterministic(compiled)
	if err != nil {
		return compiledArtifact{}, nil, err
	}
	artifact, err := repository.CreateSnapshotArtifact(
		context.Background(),
		storage.SnapshotArtifactInput{
			DesiredRevisionID: desired.ID,
			CompilerVersion:   fixtureCompilerVersion,
			Bytes:             artifactBytes,
		},
	)
	if err != nil {
		return compiledArtifact{}, nil, err
	}
	return compiledArtifact{desired: desired, artifact: artifact}, artifactBytes, nil
}

func verify(args []string) (returnErr error) {
	flags := flag.NewFlagSet("discoveryfixture verify", flag.ContinueOnError)
	repositoryRoot := flags.String("repository", "", "repository directory")
	sequence := flags.Uint64("sequence", 0, "rollout sequence")
	expectedPhase := flags.String("phase", "", "expected fleet phase")
	nodeID := flags.String("node-id", "node-a", "target node identity")
	expectedNodePhase := flags.String("node-phase", "", "expected node phase")
	minimumEvents := flags.Int("minimum-events", 1, "minimum durable event count")
	requiredIssue := flags.String("require-issue", "", "issue code required in the journal")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *repositoryRoot == "" || *sequence == 0 || *expectedPhase == "" ||
		*expectedNodePhase == "" || *minimumEvents < 1 {
		return errors.New("repository, sequence, phase, node-phase, and positive minimum-events are required")
	}
	repository, err := storage.OpenFileRepository(*repositoryRoot, storage.FileOptions{})
	if err != nil {
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, repository.Close())
	}()
	service, err := rolloutservice.Open(context.Background(), repository, *sequence)
	if err != nil {
		return err
	}
	phase, nodes, err := service.Status()
	if err != nil {
		return err
	}
	if phase != rollout.Phase(*expectedPhase) {
		return fmt.Errorf("phase = %s, want %s", phase, *expectedPhase)
	}
	node, found := nodes[*nodeID]
	if !found {
		return fmt.Errorf("node %q is absent", *nodeID)
	}
	if node.Phase != rollout.NodePhase(*expectedNodePhase) {
		return fmt.Errorf("node phase = %s, want %s", node.Phase, *expectedNodePhase)
	}
	events, err := repository.ListRolloutEvents(context.Background(), *sequence)
	if err != nil {
		return err
	}
	if len(events) < *minimumEvents {
		return fmt.Errorf("event count = %d, want at least %d", len(events), *minimumEvents)
	}
	if *requiredIssue != "" {
		found := false
		for _, event := range events {
			if bytes.Contains(event.Payload, []byte(*requiredIssue)) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("journal does not contain issue %q", *requiredIssue)
		}
	}
	fmt.Printf("PHASE=%s\n", phase)
	fmt.Printf("NODE_PHASE=%s\n", node.Phase)
	fmt.Printf("EVENT_COUNT=%d\n", len(events))
	return nil
}

func generateTLSMaterial(
	directory string,
	nodeID string,
	serverName string,
	trustDomain string,
	identityPathPrefix string,
) error {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "BonVoyage Phase 4 integration CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	if err := writeCertificate(filepath.Join(directory, "ca.pem"), caDER); err != nil {
		return err
	}
	if err := writeCertificate(filepath.Join(directory, "issuer.pem"), caDER); err != nil {
		return err
	}
	if err := writeECKey(filepath.Join(directory, "issuer-key.pem"), caKey); err != nil {
		return err
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serverTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: serverName},
		DNSNames:              []string{serverName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(
		rand.Reader, serverTemplate, caCertificate, &serverKey.PublicKey, caKey,
	)
	if err != nil {
		return err
	}
	if err := writeCertificate(filepath.Join(directory, "server.pem"), serverDER); err != nil {
		return err
	}
	if err := writeECKey(filepath.Join(directory, "server-key.pem"), serverKey); err != nil {
		return err
	}

	return generateClientMaterial(
		directory, "node", nodeID, trustDomain, identityPathPrefix,
		caCertificate, caKey, now, big.NewInt(3),
	)
}

func generateClientMaterial(
	directory string,
	outputPrefix string,
	nodeID string,
	trustDomain string,
	identityPathPrefix string,
	caCertificate *x509.Certificate,
	caKey *ecdsa.PrivateKey,
	now time.Time,
	serial *big.Int,
) error {
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	if serial == nil {
		serial, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
		if err != nil {
			return err
		}
		serial.Add(serial, big.NewInt(4))
	}
	identity, err := url.Parse("spiffe://" + trustDomain + identityPathPrefix + nodeID)
	if err != nil {
		return err
	}
	clientTemplate := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: nodeID},
		URIs:                  []*url.URL{identity},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(
		rand.Reader, clientTemplate, caCertificate, &clientKey.PublicKey, caKey,
	)
	if err != nil {
		return err
	}
	if err := writeCertificate(filepath.Join(directory, outputPrefix+".pem"), clientDER); err != nil {
		return err
	}
	return writeECKey(filepath.Join(directory, outputPrefix+"-key.pem"), clientKey)
}

func writeCertificate(path string, der []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
}

func writeECKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
}
