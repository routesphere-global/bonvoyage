package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	bonvoyagev1 "github.com/routesphere-global/bonvoyage/api/gen/go/bonvoyage/v1"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/nodecredentials"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	defaultIdentityRPCTimeout = 15 * time.Second
	maximumIdentityRPCTimeout = time.Minute
	maximumTokenFileBytes     = 4096
	maximumClientPEMBytes     = 1 << 20
)

type identityClientOptions struct {
	endpoint        string
	serverName      string
	credentialRoot  string
	serverTrustFile string
	nodeID          string
	trustDomain     string
	nodePathPrefix  string
	tokenFile       string
	timeout         time.Duration
	maxClockSkew    time.Duration
}

func runEnrollNode(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("bonvoyage-control-plane enroll-node", flag.ContinueOnError)
	flags.SetOutput(stderr)
	options := identityClientOptions{}
	flags.StringVar(&options.endpoint, "endpoint", "", "enrollment listener host:port")
	flags.StringVar(&options.serverName, "server-name", "", "expected enrollment server DNS identity")
	flags.StringVar(&options.serverTrustFile, "server-trust", "", "PEM server trust bundle path")
	flags.StringVar(&options.credentialRoot, "credential-root", "", "absolute private node credential directory")
	flags.StringVar(&options.nodeID, "node-id", "", "token-bound node ID")
	flags.StringVar(&options.trustDomain, "spiffe-trust-domain", "", "expected SPIFFE trust domain")
	flags.StringVar(&options.nodePathPrefix, "spiffe-node-path-prefix", "", "expected SPIFFE node path prefix")
	flags.StringVar(&options.tokenFile, "token-file", "", "owner-only file containing the one-time enrollment token")
	flags.DurationVar(&options.timeout, "timeout", defaultIdentityRPCTimeout, "bounded enrollment deadline")
	flags.DurationVar(&options.maxClockSkew, "max-clock-skew", time.Minute, "maximum accepted server clock skew")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("enroll-node: unexpected positional arguments: %v", flags.Args())
	}
	if err := validateIdentityClientOptions(options, true); err != nil {
		return fmt.Errorf("enroll-node: %w", err)
	}
	if _, err := nodecredentials.LoadCurrent(options.credentialRoot); err == nil {
		return errors.New("enroll-node: a current credential already exists; use renew-node")
	} else if !errors.Is(err, nodecredentials.ErrNotFound) {
		return fmt.Errorf("enroll-node: inspect credential root: %w", err)
	}
	tokenBytes, err := readRegularFile(options.tokenFile, 0o600, maximumTokenFileBytes)
	if err != nil {
		return fmt.Errorf("enroll-node: read token file: %w", err)
	}
	token := strings.TrimSuffix(string(tokenBytes), "\n")
	if token == "" || token != strings.TrimSpace(token) || strings.ContainsAny(token, "\r\n\t ") {
		return errors.New("enroll-node: token file is malformed")
	}
	request, err := nodecredentials.Generate()
	if err != nil {
		return fmt.Errorf("enroll-node: generate node key: %w", err)
	}
	tlsConfig, err := serverAuthenticatedTLSConfig(options.serverTrustFile, options.serverName)
	if err != nil {
		return fmt.Errorf("enroll-node: load server trust: %w", err)
	}
	connection, err := newIdentityConnection(options.endpoint, tlsConfig)
	if err != nil {
		return fmt.Errorf("enroll-node: construct client: %w", err)
	}
	defer connection.Close()
	rpcContext, cancel := context.WithTimeout(ctx, options.timeout)
	defer cancel()
	response, err := bonvoyagev1.NewNodeIdentityServiceClient(connection).EnrollNode(
		rpcContext,
		&bonvoyagev1.EnrollNodeRequest{
			NodeId:                   options.nodeID,
			BootstrapToken:           token,
			Pkcs10CertificateRequest: request.CSRDER(),
			ObservedAt:               timestamppb.Now(),
		},
	)
	if err != nil {
		return fmt.Errorf("enroll-node: enrollment failed: %w", err)
	}
	if response == nil || len(response.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("enroll-node: enrollment response is malformed")
	}
	generation, err := nodecredentials.Validate(response.GetCredential(), nodecredentials.ValidationOptions{
		ExpectedNodeID:     options.nodeID,
		TrustDomain:        options.trustDomain,
		NodePathPrefix:     options.nodePathPrefix,
		PrivateKeyPEM:      request.PrivateKeyPEM(),
		Clock:              time.Now,
		MaxServerClockSkew: options.maxClockSkew,
	})
	if err != nil {
		return fmt.Errorf("enroll-node: reject issued credential: %w", err)
	}
	if err := nodecredentials.Publish(options.credentialRoot, generation); err != nil {
		return fmt.Errorf("enroll-node: publish credential generation: %w", err)
	}
	return printCredentialStatus(options.credentialRoot, "node enrolled", stdout)
}

func runRenewNode(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("bonvoyage-control-plane renew-node", flag.ContinueOnError)
	flags.SetOutput(stderr)
	options := identityClientOptions{}
	flags.StringVar(&options.endpoint, "endpoint", "", "mTLS discovery listener host:port")
	flags.StringVar(&options.serverName, "server-name", "", "expected discovery server DNS identity")
	flags.StringVar(&options.credentialRoot, "credential-root", "", "absolute private node credential directory")
	flags.DurationVar(&options.timeout, "timeout", defaultIdentityRPCTimeout, "bounded renewal deadline")
	flags.DurationVar(&options.maxClockSkew, "max-clock-skew", time.Minute, "maximum accepted server clock skew")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("renew-node: unexpected positional arguments: %v", flags.Args())
	}
	if err := validateIdentityClientOptions(options, false); err != nil {
		return fmt.Errorf("renew-node: %w", err)
	}
	current, err := nodecredentials.LoadCurrent(options.credentialRoot)
	if err != nil {
		return fmt.Errorf("renew-node: load current credential: %w", err)
	}
	manifest := current.Manifest()
	certificatePEM, err := readRegularFile(
		filepath.Join(options.credentialRoot, "node.pem"), 0o644, maximumClientPEMBytes,
	)
	if err != nil {
		return fmt.Errorf("renew-node: read current certificate: %w", err)
	}
	keyPEM, err := readRegularFile(
		filepath.Join(options.credentialRoot, "node-key.pem"), 0o600, maximumClientPEMBytes,
	)
	if err != nil {
		return fmt.Errorf("renew-node: read current private key: %w", err)
	}
	trustPath := filepath.Join(options.credentialRoot, "ca.pem")
	tlsConfig, err := mutualTLSConfig(certificatePEM, keyPEM, trustPath, options.serverName)
	if err != nil {
		return fmt.Errorf("renew-node: load current mTLS credential: %w", err)
	}
	request, err := nodecredentials.Generate()
	if err != nil {
		return fmt.Errorf("renew-node: generate replacement node key: %w", err)
	}
	connection, err := newIdentityConnection(options.endpoint, tlsConfig)
	if err != nil {
		return fmt.Errorf("renew-node: construct client: %w", err)
	}
	defer connection.Close()
	rpcContext, cancel := context.WithTimeout(ctx, options.timeout)
	defer cancel()
	response, err := bonvoyagev1.NewNodeIdentityServiceClient(connection).RenewNode(
		rpcContext,
		&bonvoyagev1.RenewNodeRequest{
			NodeId:                   manifest.NodeID,
			Pkcs10CertificateRequest: request.CSRDER(),
			ObservedAt:               timestamppb.Now(),
		},
	)
	if err != nil {
		return fmt.Errorf("renew-node: renewal failed; current generation retained: %w", err)
	}
	if response == nil || len(response.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("renew-node: renewal response is malformed; current generation retained")
	}
	generation, err := nodecredentials.Validate(response.GetCredential(), nodecredentials.ValidationOptions{
		ExpectedNodeID:     manifest.NodeID,
		TrustDomain:        manifest.TrustDomain,
		NodePathPrefix:     manifest.NodePathPrefix,
		PrivateKeyPEM:      request.PrivateKeyPEM(),
		Clock:              time.Now,
		MaxServerClockSkew: options.maxClockSkew,
	})
	if err != nil {
		return fmt.Errorf("renew-node: reject replacement credential; current generation retained: %w", err)
	}
	if err := nodecredentials.Publish(options.credentialRoot, generation); err != nil {
		return fmt.Errorf("renew-node: replacement publication failed; current generation restored: %w", err)
	}
	return printCredentialStatus(options.credentialRoot, "node credential renewed", stdout)
}

func validateIdentityClientOptions(options identityClientOptions, enrollment bool) error {
	if strings.TrimSpace(options.endpoint) == "" || strings.TrimSpace(options.serverName) == "" ||
		!filepath.IsAbs(options.credentialRoot) || options.timeout <= 0 ||
		options.timeout > maximumIdentityRPCTimeout || options.maxClockSkew < 0 ||
		options.maxClockSkew > nodecredentials.MaximumServerClockSkew {
		return errors.New("endpoint, server name, absolute credential root, and bounded durations are required")
	}
	if _, _, err := net.SplitHostPort(options.endpoint); err != nil {
		return errors.New("endpoint must be one host:port value")
	}
	if enrollment && (!filepath.IsAbs(options.serverTrustFile) || !filepath.IsAbs(options.tokenFile) ||
		strings.TrimSpace(options.nodeID) == "" || strings.TrimSpace(options.trustDomain) == "" ||
		strings.TrimSpace(options.nodePathPrefix) == "") {
		return errors.New("server trust, token file, node ID, and SPIFFE policy are required for enrollment")
	}
	return nil
}

func newIdentityConnection(endpoint string, tlsConfig *tls.Config) (*grpc.ClientConn, error) {
	return grpc.NewClient(
		endpoint,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallSendMsgSize(32<<10),
			grpc.MaxCallRecvMsgSize(2<<20),
		),
	)
}

func serverAuthenticatedTLSConfig(trustPath, serverName string) (*tls.Config, error) {
	roots, err := loadServerRoots(trustPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: serverName,
	}, nil
}

func mutualTLSConfig(
	certificatePEM []byte,
	keyPEM []byte,
	trustPath string,
	serverName string,
) (*tls.Config, error) {
	config, err := serverAuthenticatedTLSConfig(trustPath, serverName)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return nil, err
	}
	config.Certificates = []tls.Certificate{certificate}
	return config, nil
}

func loadServerRoots(path string) (*x509.CertPool, error) {
	contents, err := readRegularFile(path, 0o644, maximumClientPEMBytes)
	if err != nil {
		return nil, err
	}
	return parseClientCAs(contents)
}

func readRegularFile(path string, expectedMode os.FileMode, maximum int64) ([]byte, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean != path || maximum <= 0 {
		return nil, errors.New("path is not one clean absolute file path")
	}
	before, err := os.Lstat(clean)
	unsafeMode := false
	if err == nil {
		if expectedMode == 0o600 {
			unsafeMode = before.Mode().Perm() != 0o600
		} else {
			unsafeMode = before.Mode().Perm()&0o022 != 0
		}
	}
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || unsafeMode {
		return nil, errors.New("file type or permissions are unsafe")
	}
	file, err := os.Open(clean)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("file changed while it was opened")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if len(contents) == 0 || int64(len(contents)) > maximum {
		return nil, errors.New("file size is outside the accepted bound")
	}
	return contents, nil
}

func printCredentialStatus(root, prefix string, stdout io.Writer) error {
	status, err := nodecredentials.Status(root, time.Now().UTC())
	if err != nil {
		return err
	}
	fmt.Fprintf(
		stdout,
		"%s: node_id=%s generation=%s certificate_sha256=%s not_after=%s renew_after=%s\n",
		prefix,
		status.NodeID,
		status.CredentialGeneration,
		status.CertificateSHA256,
		status.NotAfter.Format(time.RFC3339),
		status.RenewAfter.Format(time.RFC3339),
	)
	return nil
}
