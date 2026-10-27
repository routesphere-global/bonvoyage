package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/adminapi"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/adminservice"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/discovery"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/identityservice"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/rollout"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/rolloutservice"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/snapshot"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
	"google.golang.org/grpc"
)

const (
	discoveryShutdownTimeout                = 10 * time.Second
	defaultIdentityMaxConcurrentEnrollments = 8
)

type discoveryCommandOptions struct {
	repositoryRoot          string
	rolloutSequence         uint64
	startRollout            bool
	listenAddress           string
	tlsServerCertificate    string
	tlsServerKey            string
	tlsClientCA             string
	spiffeTrustDomain       string
	spiffeNodePathPrefix    string
	enrollmentAddress       string
	identityRepository      string
	identityAudience        string
	identityIssuerCert      string
	identityIssuerKey       string
	tlsRevocations          string
	tlsServerName           string
	tlsReloadInterval       time.Duration
	tlsMinimumValidity      time.Duration
	identityClockSkew       time.Duration
	identityMaxAge          time.Duration
	identityMaxConcurrent   int
	adminListenAddress      string
	adminTLSCertificate     string
	adminTLSKey             string
	adminTLSClientCA        string
	adminServerName         string
	adminAuthorizations     string
	adminTrustDomain        string
	adminOperatorPrefix     string
	adminServicePrefix      string
	adminMaxConcurrent      int
	policyReconcileInterval time.Duration
}

type commandRuntime struct {
	listen                  func(string, string) (net.Listener, error)
	listenerReady           func(net.Addr)
	enrollmentListenerReady func(net.Addr)
	adminListenerReady      func(net.Addr)
	shutdownTimeout         time.Duration
}

func main() {
	var ctx context.Context = context.Background()
	stop := func() {}
	if len(os.Args) > 1 && os.Args[1] == "serve-discovery" {
		ctx, stop = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	}
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr, defaultCommandRuntime()); err != nil {
		fmt.Fprintf(os.Stderr, "bonvoyage-control-plane: %v\n", err)
		os.Exit(1)
	}
}

func defaultCommandRuntime() commandRuntime {
	return commandRuntime{listen: net.Listen, shutdownTimeout: discoveryShutdownTimeout}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, runtime commandRuntime) error {
	if len(args) > 0 {
		switch args[0] {
		case "serve-discovery":
			return runDiscovery(ctx, args[1:], stdout, stderr, runtime)
		case "issue-enrollment-token":
			return runIssueEnrollmentToken(ctx, args[1:], stdout, stderr)
		case "enroll-node":
			return runEnrollNode(ctx, args[1:], stdout, stderr)
		case "renew-node":
			return runRenewNode(ctx, args[1:], stdout, stderr)
		case "credential-status":
			return runCredentialStatus(args[1:], stdout, stderr)
		case "revoke-node":
			return runRevokeNode(args[1:], stdout, stderr)
		case "initialize-revocations":
			return runInitializeRevocations(args[1:], stdout, stderr)
		case "refresh-revocations":
			return runRefreshRevocations(args[1:], stdout, stderr)
		}
	}
	return runCompiler(args, stdout, stderr)
}

func runCompiler(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("bonvoyage-control-plane", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("input", "../config/examples/local.yaml", "path to the desired-state YAML file")
	output := flags.String("output", "snapshot.pb", "path for the compiled protobuf snapshot")
	validateOnly := flags.Bool("validate-only", false, "validate configuration without writing an artifact")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}
	if *input == "" {
		return fmt.Errorf("-input must not be empty")
	}

	compiled, err := snapshot.CompileFile(*input)
	if err != nil {
		return err
	}
	if *validateOnly {
		fmt.Fprintf(stdout, "configuration valid: snapshot=%s generation=%d\n", compiled.GetSnapshotId(), compiled.GetGeneration())
		return nil
	}
	if *output == "" {
		return fmt.Errorf("-output must not be empty unless -validate-only is set")
	}
	data, err := snapshot.MarshalDeterministic(compiled)
	if err != nil {
		return err
	}
	if err := snapshot.WriteFileAtomic(*output, data); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "snapshot written: path=%s snapshot=%s generation=%d bytes=%d\n", *output, compiled.GetSnapshotId(), compiled.GetGeneration(), len(data))
	return nil
}

func runDiscovery(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	runtime commandRuntime,
) error {
	flags := flag.NewFlagSet("bonvoyage-control-plane serve-discovery", flag.ContinueOnError)
	flags.SetOutput(stderr)
	options := discoveryCommandOptions{}
	flags.StringVar(&options.repositoryRoot, "repository-root", "", "path to the durable control-plane repository")
	flags.Uint64Var(&options.rolloutSequence, "rollout-sequence", 0, "existing rollout sequence to serve")
	flags.BoolVar(&options.startRollout, "start-rollout", false, "durably start the selected rollout before accepting nodes")
	flags.StringVar(&options.listenAddress, "listen-address", "", "TCP address for the discovery listener")
	flags.StringVar(&options.tlsServerCertificate, "tls-server-cert", "", "PEM server certificate path")
	flags.StringVar(&options.tlsServerKey, "tls-server-key", "", "PEM server private-key path")
	flags.StringVar(&options.tlsClientCA, "tls-client-ca", "", "PEM client certificate-authority bundle path")
	flags.StringVar(&options.spiffeTrustDomain, "spiffe-trust-domain", "", "SPIFFE trust domain for dataplane identities")
	flags.StringVar(&options.spiffeNodePathPrefix, "spiffe-node-path-prefix", "", "SPIFFE path prefix ending in / for dataplane node IDs")
	flags.StringVar(&options.enrollmentAddress, "enrollment-listen-address", "", "separate server-authenticated TCP address for node enrollment")
	flags.StringVar(&options.identityRepository, "identity-repository-root", "", "path to the durable node identity repository")
	flags.StringVar(&options.identityAudience, "identity-audience", "", "exact enrollment-token audience for this installation")
	flags.StringVar(&options.identityIssuerCert, "identity-issuer-cert", "", "PEM node issuing-CA certificate path")
	flags.StringVar(&options.identityIssuerKey, "identity-issuer-key", "", "PEM node issuing-CA private-key path")
	flags.StringVar(&options.tlsRevocations, "tls-revocations", "", "JSON node-certificate revocation snapshot path")
	flags.StringVar(&options.tlsServerName, "tls-server-name", "", "DNS identity required in the discovery and enrollment server certificate")
	flags.DurationVar(&options.tlsReloadInterval, "tls-reload-interval", time.Second, "interval for complete TLS generation reload attempts")
	flags.DurationVar(&options.tlsMinimumValidity, "tls-minimum-validity", time.Minute, "minimum remaining server-certificate validity accepted during reload")
	flags.DurationVar(&options.identityClockSkew, "identity-clock-skew", time.Minute, "maximum node/server clock skew accepted for identity operations")
	flags.DurationVar(&options.identityMaxAge, "identity-observation-max-age", 5*time.Minute, "maximum age of an enrollment or renewal observation")
	flags.IntVar(&options.identityMaxConcurrent, "identity-max-concurrent-enrollments", defaultIdentityMaxConcurrentEnrollments, "maximum concurrent enrollment operations across all connections")
	flags.StringVar(&options.adminListenAddress, "admin-listen-address", "", "separate TLS 1.3 mTLS address for the versioned Admin API")
	flags.StringVar(&options.adminTLSCertificate, "admin-tls-server-cert", "", "PEM Admin server certificate path")
	flags.StringVar(&options.adminTLSKey, "admin-tls-server-key", "", "PEM Admin server private-key path")
	flags.StringVar(&options.adminTLSClientCA, "admin-tls-client-ca", "", "dedicated PEM Admin client certificate-authority bundle")
	flags.StringVar(&options.adminServerName, "admin-tls-server-name", "", "exact DNS identity for the Admin listener")
	flags.StringVar(&options.adminAuthorizations, "admin-authorizations", "", "fresh positive Admin SPIFFE identity and certificate authorization document")
	flags.StringVar(&options.adminTrustDomain, "admin-spiffe-trust-domain", "", "SPIFFE trust domain dedicated to Admin identities")
	flags.StringVar(&options.adminOperatorPrefix, "admin-spiffe-operator-path-prefix", "/bonvoyage/operators/", "Admin operator SPIFFE path prefix ending in /")
	flags.StringVar(&options.adminServicePrefix, "admin-spiffe-service-account-path-prefix", "/bonvoyage/service-accounts/", "Admin service-account SPIFFE path prefix ending in /")
	flags.IntVar(&options.adminMaxConcurrent, "admin-max-concurrent", 128, "maximum concurrent Admin API requests")
	flags.DurationVar(&options.policyReconcileInterval, "rollout-policy-interval", 250*time.Millisecond, "safe rollout policy reconciliation interval")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("serve-discovery: unexpected positional arguments: %v", flags.Args())
	}
	if err := validateDiscoveryOptions(options); err != nil {
		return err
	}
	if ctx == nil {
		return errors.New("serve-discovery: context is nil")
	}
	if runtime.listen == nil || runtime.shutdownTimeout <= 0 {
		return errors.New("serve-discovery: command runtime is invalid")
	}
	return serveDiscovery(ctx, options, stdout, stderr, runtime)
}

func validateDiscoveryOptions(options discoveryCommandOptions) error {
	missing := make([]string, 0, 8)
	required := []struct {
		name  string
		value string
	}{
		{"-repository-root", options.repositoryRoot},
		{"-listen-address", options.listenAddress},
		{"-tls-server-cert", options.tlsServerCertificate},
		{"-tls-server-key", options.tlsServerKey},
		{"-tls-client-ca", options.tlsClientCA},
		{"-spiffe-trust-domain", options.spiffeTrustDomain},
		{"-spiffe-node-path-prefix", options.spiffeNodePathPrefix},
	}
	for _, candidate := range required {
		if strings.TrimSpace(candidate.value) == "" {
			missing = append(missing, candidate.name)
		}
	}
	if options.rolloutSequence == 0 {
		missing = append(missing, "-rollout-sequence")
	}
	if len(missing) != 0 {
		return fmt.Errorf("serve-discovery: required flags are missing: %s", strings.Join(missing, ", "))
	}
	if options.spiffeTrustDomain != strings.TrimSpace(options.spiffeTrustDomain) ||
		strings.ContainsAny(options.spiffeTrustDomain, "/:@?#%") {
		return errors.New("serve-discovery: -spiffe-trust-domain must be a bare URI authority without whitespace, scheme, port, path, query, or fragment")
	}
	if options.spiffeNodePathPrefix != strings.TrimSpace(options.spiffeNodePathPrefix) ||
		!strings.HasPrefix(options.spiffeNodePathPrefix, "/") ||
		!strings.HasSuffix(options.spiffeNodePathPrefix, "/") ||
		strings.ContainsAny(options.spiffeNodePathPrefix, "?#%") {
		return errors.New("serve-discovery: -spiffe-node-path-prefix must be an absolute unescaped path ending in /")
	}
	if !options.identityLifecycleEnabled() {
		return validateAdminOptions(options)
	}
	lifecycleRequired := []struct {
		name  string
		value string
	}{
		{"-enrollment-listen-address", options.enrollmentAddress},
		{"-identity-repository-root", options.identityRepository},
		{"-identity-audience", options.identityAudience},
		{"-identity-issuer-cert", options.identityIssuerCert},
		{"-identity-issuer-key", options.identityIssuerKey},
		{"-tls-revocations", options.tlsRevocations},
		{"-tls-server-name", options.tlsServerName},
	}
	missing = missing[:0]
	for _, candidate := range lifecycleRequired {
		if strings.TrimSpace(candidate.value) == "" {
			missing = append(missing, candidate.name)
		}
	}
	if len(missing) != 0 {
		return fmt.Errorf("serve-discovery: node identity lifecycle flags are incomplete: %s", strings.Join(missing, ", "))
	}
	if fixedListenAddressConflict(options.enrollmentAddress, options.listenAddress) {
		return errors.New("serve-discovery: enrollment and discovery listeners must use distinct addresses")
	}
	if options.identityRepository == options.repositoryRoot {
		return errors.New("serve-discovery: rollout and identity repositories must use distinct roots")
	}
	if options.tlsReloadInterval <= 0 || options.tlsMinimumValidity < 0 ||
		options.identityClockSkew <= 0 || options.identityClockSkew > 5*time.Minute ||
		options.identityMaxAge <= 0 || options.identityMaxConcurrent < 1 ||
		options.identityMaxConcurrent > 128 {
		return errors.New("serve-discovery: identity lifecycle bounds are invalid")
	}
	return validateAdminOptions(options)
}

func validateAdminOptions(options discoveryCommandOptions) error {
	if !options.adminEnabled() {
		return nil
	}
	required := []struct {
		name  string
		value string
	}{
		{"-admin-listen-address", options.adminListenAddress},
		{"-admin-tls-server-cert", options.adminTLSCertificate},
		{"-admin-tls-server-key", options.adminTLSKey},
		{"-admin-tls-client-ca", options.adminTLSClientCA},
		{"-admin-tls-server-name", options.adminServerName},
		{"-admin-authorizations", options.adminAuthorizations},
		{"-admin-spiffe-trust-domain", options.adminTrustDomain},
	}
	missing := make([]string, 0, len(required))
	for _, candidate := range required {
		if strings.TrimSpace(candidate.value) == "" {
			missing = append(missing, candidate.name)
		}
	}
	if len(missing) != 0 {
		return fmt.Errorf("serve-discovery: Admin API flags are incomplete: %s", strings.Join(missing, ", "))
	}
	if fixedListenAddressConflict(options.adminListenAddress, options.listenAddress) ||
		(options.identityLifecycleEnabled() && fixedListenAddressConflict(options.adminListenAddress, options.enrollmentAddress)) {
		return errors.New("serve-discovery: Admin, discovery, and enrollment listeners must use distinct addresses")
	}
	if options.adminTLSCertificate == options.tlsServerCertificate ||
		options.adminTLSKey == options.tlsServerKey || options.adminTLSClientCA == options.tlsClientCA ||
		(options.identityLifecycleEnabled() && options.adminTLSClientCA == options.identityIssuerCert) {
		return errors.New("serve-discovery: Admin and node TLS files must be distinct")
	}
	if options.adminServerName != strings.TrimSpace(options.adminServerName) ||
		strings.ContainsAny(options.adminServerName, "/:@?#%") ||
		options.adminTrustDomain != strings.TrimSpace(options.adminTrustDomain) ||
		strings.ContainsAny(options.adminTrustDomain, "/:@?#%") ||
		!validAdminPathPrefix(options.adminOperatorPrefix) ||
		!validAdminPathPrefix(options.adminServicePrefix) ||
		options.adminOperatorPrefix == options.adminServicePrefix ||
		options.adminMaxConcurrent < 1 || options.adminMaxConcurrent > 1024 ||
		options.policyReconcileInterval < 100*time.Millisecond ||
		options.policyReconcileInterval > 10*time.Second {
		return errors.New("serve-discovery: Admin identity or capacity policy is invalid")
	}
	if options.adminTrustDomain == options.spiffeTrustDomain &&
		(pathPrefixesOverlap(options.adminOperatorPrefix, options.spiffeNodePathPrefix) ||
			pathPrefixesOverlap(options.adminServicePrefix, options.spiffeNodePathPrefix)) {
		return errors.New("serve-discovery: Admin and node SPIFFE namespaces must not overlap")
	}
	return nil
}

func validAdminPathPrefix(value string) bool {
	return value == strings.TrimSpace(value) && strings.HasPrefix(value, "/") &&
		strings.HasSuffix(value, "/") && !strings.ContainsAny(value, "?#%")
}

func fixedListenAddressConflict(left, right string) bool {
	return left == right && !strings.HasSuffix(left, ":0")
}

func pathPrefixesOverlap(left, right string) bool {
	return strings.HasPrefix(left, right) || strings.HasPrefix(right, left)
}

func (options discoveryCommandOptions) identityLifecycleEnabled() bool {
	for _, value := range []string{
		options.enrollmentAddress,
		options.identityRepository,
		options.identityAudience,
		options.identityIssuerCert,
		options.identityIssuerKey,
		options.tlsRevocations,
		options.tlsServerName,
	} {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func (options discoveryCommandOptions) adminEnabled() bool {
	for _, value := range []string{
		options.adminListenAddress,
		options.adminTLSCertificate,
		options.adminTLSKey,
		options.adminTLSClientCA,
		options.adminServerName,
		options.adminAuthorizations,
		options.adminTrustDomain,
	} {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func serveDiscovery(
	ctx context.Context,
	options discoveryCommandOptions,
	stdout io.Writer,
	stderr io.Writer,
	runtime commandRuntime,
) (returnErr error) {
	repository, err := storage.OpenFileRepository(options.repositoryRoot, storage.FileOptions{})
	if err != nil {
		return fmt.Errorf("serve-discovery: open repository %q: %w", options.repositoryRoot, err)
	}
	defer func() {
		if err := repository.Close(); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("serve-discovery: close repository: %w", err))
		}
	}()

	selectedSequence, err := resolveSelectedRollout(ctx, repository, options)
	if err != nil {
		return fmt.Errorf("serve-discovery: resolve selected rollout: %w", err)
	}
	coordinator, err := rolloutservice.Open(ctx, repository, selectedSequence)
	if err != nil {
		return fmt.Errorf("serve-discovery: open rollout sequence %d: %w", selectedSequence, err)
	}
	phase, _, err := coordinator.Status()
	if err != nil {
		return fmt.Errorf("serve-discovery: inspect rollout sequence %d: %w", selectedSequence, err)
	}
	if (options.startRollout || options.adminEnabled()) && phase == rollout.PhasePending {
		eventID := fmt.Sprintf("serve-discovery-start-%d", selectedSequence)
		if _, err := coordinator.Start(ctx, eventID); err != nil {
			return fmt.Errorf("serve-discovery: start rollout sequence %d: %w", selectedSequence, err)
		}
		phase, _, err = coordinator.Status()
		if err != nil {
			return fmt.Errorf("serve-discovery: inspect started rollout sequence %d: %w", selectedSequence, err)
		}
	}
	authenticator := discovery.MTLSAuthenticator{
		TrustDomain: options.spiffeTrustDomain, NodePathPrefix: options.spiffeNodePathPrefix,
	}
	var identityRuntime *checkpoint8IdentityRuntime
	var tlsConfig *tls.Config
	if options.identityLifecycleEnabled() {
		identityRuntime, err = openCheckpoint8IdentityRuntime(options, stderr)
		if err != nil {
			return fmt.Errorf("serve-discovery: initialize node identity lifecycle: %w", err)
		}
		defer func() {
			if err := identityRuntime.close(); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("serve-discovery: close identity repository: %w", err))
			}
		}()
		authenticator = identityRuntime.authenticator
		tlsConfig = identityRuntime.lifecycle.ServerTLSConfig()
	} else {
		tlsConfig, err = loadDiscoveryTLSConfig(
			options.tlsServerCertificate, options.tlsServerKey, options.tlsClientCA,
		)
		if err != nil {
			return fmt.Errorf("serve-discovery: load TLS configuration: %w", err)
		}
	}
	service, err := discovery.NewServer(coordinator, discovery.DefaultOptions(authenticator))
	if err != nil {
		return fmt.Errorf("serve-discovery: construct discovery service: %w", err)
	}
	grpcServer, err := discovery.NewGRPCServer(service, tlsConfig)
	if err != nil {
		return fmt.Errorf("serve-discovery: construct gRPC server: %w", err)
	}
	if identityRuntime != nil {
		if err := identityservice.RegisterRenewalService(grpcServer, identityRuntime.service); err != nil {
			return fmt.Errorf("serve-discovery: register renewal service: %w", err)
		}
	}
	listener, err := runtime.listen("tcp", options.listenAddress)
	if err != nil {
		return fmt.Errorf("serve-discovery: bind %q: %w", options.listenAddress, err)
	}
	defer func() { _ = listener.Close() }()

	endpoints := []grpcServeEndpoint{{name: "discovery", server: grpcServer, listener: listener}}
	httpEndpoints := []httpServeEndpoint(nil)
	enrollmentAdvertiseAddress := options.enrollmentAddress
	var stopIdentityLifecycle context.CancelFunc
	var identityLifecycleDone <-chan struct{}
	if identityRuntime != nil {
		enrollmentServer, err := identityservice.NewEnrollmentGRPCServer(
			identityRuntime.service,
			identityRuntime.lifecycle.EnrollmentTLSConfig(),
		)
		if err != nil {
			return fmt.Errorf("serve-discovery: construct enrollment server: %w", err)
		}
		enrollmentListener, err := runtime.listen("tcp", options.enrollmentAddress)
		if err != nil {
			return fmt.Errorf("serve-discovery: bind enrollment listener %q: %w", options.enrollmentAddress, err)
		}
		defer func() { _ = enrollmentListener.Close() }()
		enrollmentAdvertiseAddress = enrollmentListener.Addr().String()
		endpoints = append(endpoints, grpcServeEndpoint{
			name: "enrollment", server: enrollmentServer, listener: enrollmentListener,
		})
		if runtime.enrollmentListenerReady != nil {
			runtime.enrollmentListenerReady(enrollmentListener.Addr())
		}
		identityContext, cancelIdentityLifecycle := context.WithCancel(ctx)
		identityDone := make(chan struct{})
		stopIdentityLifecycle = cancelIdentityLifecycle
		identityLifecycleDone = identityDone
		go func() {
			defer close(identityDone)
			identityRuntime.run(identityContext)
		}()
		defer func() {
			stopIdentityLifecycle()
			<-identityLifecycleDone
		}()
		fmt.Fprintf(
			stdout,
			"node enrollment listener ready: address=%s audience=%s\n",
			enrollmentListener.Addr(), options.identityAudience,
		)
	}
	if runtime.listenerReady != nil {
		runtime.listenerReady(listener.Addr())
	}
	if options.adminEnabled() {
		serviceOptions := make([]adminservice.Option, 0, 1)
		if identityRuntime != nil {
			serviceOptions = append(serviceOptions, adminservice.WithNodeLifecycle(
				identityRuntime.repository,
				adminservice.NodeLifecycleOptions{
					Audience: options.identityAudience, EnrollmentAddress: enrollmentAdvertiseAddress,
					ServerName: options.tlsServerName, TrustDomain: options.spiffeTrustDomain,
					NodePathPrefix: options.spiffeNodePathPrefix, RevocationPath: options.tlsRevocations,
					RevocationValidFor: defaultRevocationValidity,
				},
			))
		}
		management, err := adminservice.New(repository, service, serviceOptions...)
		if err != nil {
			return fmt.Errorf("serve-discovery: construct Admin service: %w", err)
		}
		policyContext, cancelPolicy := context.WithCancel(ctx)
		policyDone := make(chan struct{})
		go func() {
			defer close(policyDone)
			runRolloutPolicy(policyContext, management, options.policyReconcileInterval, stderr)
		}()
		defer func() {
			cancelPolicy()
			<-policyDone
		}()
		adminTLS, err := adminapi.LoadTLSConfig(
			options.adminTLSCertificate,
			options.adminTLSKey,
			options.adminTLSClientCA,
			options.adminServerName,
			[]string{options.tlsClientCA, options.identityIssuerCert},
			[]string{options.tlsServerCertificate},
		)
		if err != nil {
			return fmt.Errorf("serve-discovery: load Admin TLS configuration: %w", err)
		}
		handler, err := adminapi.NewHandler(adminapi.HandlerOptions{
			Service:     management,
			NodeService: management,
			Authorizer: adminapi.FileAuthorizer{
				Path: options.adminAuthorizations, TrustDomain: options.adminTrustDomain,
				OperatorPathPrefix:       options.adminOperatorPrefix,
				ServiceAccountPathPrefix: options.adminServicePrefix,
			},
			ServerName: options.adminServerName, MaxConcurrent: options.adminMaxConcurrent,
			LogError: func(requestID string, err error) {
				fmt.Fprintf(stderr, "Admin API request failed: request_id=%s error=%v\n", requestID, err)
			},
		})
		if err != nil {
			return fmt.Errorf("serve-discovery: construct Admin HTTP handler: %w", err)
		}
		adminListener, err := runtime.listen("tcp", options.adminListenAddress)
		if err != nil {
			return fmt.Errorf("serve-discovery: bind Admin listener %q: %w", options.adminListenAddress, err)
		}
		defer func() { _ = adminListener.Close() }()
		secureAdminListener := tls.NewListener(adminListener, adminTLS)
		adminServer := &http.Server{
			Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
			WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10,
			ErrorLog:     log.New(stderr, "Admin API: ", log.LstdFlags),
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		}
		httpEndpoints = append(httpEndpoints, httpServeEndpoint{
			name: "admin", server: adminServer, listener: secureAdminListener,
		})
		if runtime.adminListenerReady != nil {
			runtime.adminListenerReady(adminListener.Addr())
		}
		fmt.Fprintf(
			stdout,
			"Admin API listener ready: address=%s selected_rollout_sequence=%d\n",
			adminListener.Addr(), selectedSequence,
		)
	}
	fmt.Fprintf(
		stdout,
		"discovery listener ready: address=%s rollout_sequence=%d rollout_phase=%s\n",
		listener.Addr(), selectedSequence, phase,
	)
	serveErr := serveControlPlaneEndpoints(ctx, endpoints, httpEndpoints, runtime.shutdownTimeout, stderr)
	if serveErr != nil {
		return fmt.Errorf("serve-discovery: %w", serveErr)
	}
	fmt.Fprintln(stdout, "discovery listener stopped")
	return nil
}

func runRolloutPolicy(
	ctx context.Context,
	management *adminservice.Service,
	interval time.Duration,
	stderr io.Writer,
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case observedAt := <-ticker.C:
			result, err := management.ReconcilePolicy(ctx, observedAt.UTC())
			if errors.Is(err, adminservice.ErrPolicyAwaitingReconciliation) {
				continue
			}
			if err != nil {
				fmt.Fprintf(stderr, "safe rollout policy reconciliation failed: %v\n", err)
				continue
			}
			if result.Evaluation.Changed {
				fmt.Fprintf(
					stderr,
					"safe rollout policy decision: sequence=%d decision=%s phase=%s reason=%s\n",
					result.Evaluation.Sequence, result.Evaluation.Decision,
					result.Evaluation.Phase, result.Evaluation.Reason,
				)
			}
			if result.AutomaticRollback != nil {
				fmt.Fprintf(
					stderr,
					"automatic exact rollback selected: sequence=%d target=%d\n",
					result.AutomaticRollback.Status.Sequence,
					result.AutomaticRollback.Status.RollbackTargetSequence,
				)
			}
		}
	}
}

func resolveSelectedRollout(
	ctx context.Context,
	repository storage.Repository,
	options discoveryCommandOptions,
) (uint64, error) {
	if !options.adminEnabled() {
		return options.rolloutSequence, nil
	}
	selected, err := repository.GetSelectedRollout(ctx)
	if err == nil {
		return selected.Sequence, nil
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return 0, err
	}
	selected, err = repository.InitializeSelectedRollout(ctx, options.rolloutSequence)
	if err != nil {
		return 0, err
	}
	return selected.Sequence, nil
}

func loadDiscoveryTLSConfig(certificatePath, keyPath, clientCAPath string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load server certificate and key: %w", err)
	}
	if len(certificate.Certificate) == 0 {
		return nil, errors.New("server certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse server leaf certificate: %w", err)
	}
	certificate.Leaf = leaf

	clientCABytes, err := os.ReadFile(clientCAPath)
	if err != nil {
		return nil, fmt.Errorf("read client CA bundle: %w", err)
	}
	clientCAs, err := parseClientCAs(clientCABytes)
	if err != nil {
		return nil, fmt.Errorf("parse client CA bundle: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}, nil
}

func parseClientCAs(contents []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	remaining := contents
	count := 0
	for len(remaining) != 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			if len(strings.TrimSpace(string(remaining))) != 0 {
				return nil, errors.New("bundle contains non-PEM data")
			}
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, fmt.Errorf("bundle contains unsupported PEM block %q", block.Type)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate %d: %w", count+1, err)
		}
		if !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, fmt.Errorf("certificate %d is not a certificate authority", count+1)
		}
		pool.AddCert(certificate)
		count++
		remaining = rest
	}
	if count == 0 {
		return nil, errors.New("bundle contains no certificate authorities")
	}
	return pool, nil
}

type grpcServeEndpoint struct {
	name     string
	server   *grpc.Server
	listener net.Listener
}

type grpcServeResult struct {
	name string
	err  error
}

type httpServeEndpoint struct {
	name     string
	server   *http.Server
	listener net.Listener
}

func serveControlPlaneEndpoints(
	ctx context.Context,
	endpoints []grpcServeEndpoint,
	httpEndpoints []httpServeEndpoint,
	shutdownTimeout time.Duration,
	stderr io.Writer,
) error {
	total := len(endpoints) + len(httpEndpoints)
	results := make(chan grpcServeResult, total)
	for _, endpoint := range endpoints {
		endpoint := endpoint
		go func() {
			results <- grpcServeResult{name: endpoint.name, err: endpoint.server.Serve(endpoint.listener)}
		}()
	}
	for _, endpoint := range httpEndpoints {
		endpoint := endpoint
		go func() {
			results <- grpcServeResult{name: endpoint.name, err: endpoint.server.Serve(endpoint.listener)}
		}()
	}
	select {
	case result := <-results:
		stopControlPlaneEndpoints(endpoints, httpEndpoints, shutdownTimeout)
		for range total - 1 {
			<-results
		}
		if result.err == nil {
			return fmt.Errorf("%s server stopped unexpectedly", result.name)
		}
		return fmt.Errorf("%s server stopped unexpectedly: %w", result.name, result.err)
	case <-ctx.Done():
		if !stopControlPlaneEndpoints(endpoints, httpEndpoints, shutdownTimeout) {
			fmt.Fprintf(stderr, "serve-discovery: graceful shutdown exceeded %s; active requests or streams were stopped\n", shutdownTimeout)
		}
		for range total {
			result := <-results
			if result.err != nil && !errors.Is(result.err, grpc.ErrServerStopped) &&
				!errors.Is(result.err, http.ErrServerClosed) {
				return fmt.Errorf("stop %s server: %w", result.name, result.err)
			}
		}
		return nil
	}
}

func stopControlPlaneEndpoints(
	grpcEndpoints []grpcServeEndpoint,
	httpEndpoints []httpServeEndpoint,
	timeout time.Duration,
) bool {
	stopped := make(chan bool, len(grpcEndpoints)+len(httpEndpoints))
	for _, endpoint := range grpcEndpoints {
		endpoint := endpoint
		go func() { stopped <- stopGRPCServer(endpoint.server, timeout) }()
	}
	for _, endpoint := range httpEndpoints {
		endpoint := endpoint
		go func() { stopped <- stopHTTPServer(endpoint.server, timeout) }()
	}
	graceful := true
	for range len(grpcEndpoints) + len(httpEndpoints) {
		graceful = <-stopped && graceful
	}
	return graceful
}

func stopHTTPServer(server *http.Server, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		_ = server.Close()
		return false
	}
	return true
}

func stopGRPCServer(server *grpc.Server, timeout time.Duration) bool {
	stopped := make(chan struct{})
	go func() {
		server.GracefulStop()
		close(stopped)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-stopped:
		return true
	case <-timer.C:
		server.Stop()
		<-stopped
		return false
	}
}
