package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/discovery"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/identity"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/identityservice"
)

type checkpoint8IdentityRuntime struct {
	lifecycle     *discovery.TLSLifecycle
	authenticator discovery.MTLSAuthenticator
	service       *identityservice.Service
	repository    identity.Repository
}

// repositoryLifecycleVerifier composes the fresh transport trust/revocation
// snapshot with the durable node lifecycle. A retired or revoked identity can
// neither establish a new stream nor survive the periodic credential check.
type repositoryLifecycleVerifier struct {
	transport  lifecycleTransportVerifier
	repository lifecycleIdentityRepository
}

type lifecycleTransportVerifier interface {
	discovery.CertificateVerifier
	discovery.CredentialValidator
}

type lifecycleIdentityRepository interface {
	RevocationStatus(context.Context, identity.RevocationStatusQuery) (identity.RevocationStatus, error)
	GetNode(context.Context, string) (identity.NodeIdentitySummary, error)
}

func (verifier repositoryLifecycleVerifier) VerifyClientCertificate(
	peerCertificates []*x509.Certificate,
	now time.Time,
) ([]*x509.Certificate, error) {
	return verifier.transport.VerifyClientCertificate(peerCertificates, now)
}

func (verifier repositoryLifecycleVerifier) ValidateCredential(
	credential discovery.AuthenticatedNode,
	now time.Time,
) error {
	if err := verifier.transport.ValidateCredential(credential, now); err != nil {
		return err
	}
	status, err := verifier.repository.RevocationStatus(context.Background(), identity.RevocationStatusQuery{
		NodeID: credential.NodeID, IssuerFingerprint: credential.IssuerFingerprint,
		Serial: credential.CredentialSerial, LeafFingerprint: credential.CredentialFingerprint,
	})
	if err != nil || status.Revoked {
		return discovery.ErrUnauthenticated
	}
	node, err := verifier.repository.GetNode(context.Background(), credential.NodeID)
	if err != nil || !node.Enrolled || node.Node.Lifecycle == identity.NodeLifecycleRetired ||
		node.Node.Lifecycle == identity.NodeLifecycleRevoked ||
		node.Node.Lifecycle == identity.NodeLifecycleEnrolling {
		return discovery.ErrUnauthenticated
	}
	return nil
}

func openCheckpoint8IdentityRuntime(
	options discoveryCommandOptions,
	statusWriter io.Writer,
) (_ *checkpoint8IdentityRuntime, returnErr error) {
	var statusMu sync.Mutex
	var lastGeneration string
	var lastFailureCount uint64
	lifecycle, err := discovery.OpenTLSLifecycle(discovery.TLSLifecycleOptions{
		ServerCertificatePath: options.tlsServerCertificate,
		ServerPrivateKeyPath:  options.tlsServerKey,
		ClientTrustBundlePath: options.tlsClientCA,
		RevocationPath:        options.tlsRevocations,
		ServerName:            options.tlsServerName,
		ReloadInterval:        options.tlsReloadInterval,
		MinimumValidity:       options.tlsMinimumValidity,
		Clock:                 time.Now,
		OnReload: func(status discovery.TLSLifecycleStatus) {
			statusMu.Lock()
			defer statusMu.Unlock()
			if status.LastError != "" {
				if status.ReloadFailures == lastFailureCount {
					return
				}
				lastFailureCount = status.ReloadFailures
				fmt.Fprintf(
					statusWriter,
					"identity TLS reload rejected: failures=%d last_error=%q\n",
					status.ReloadFailures,
					status.LastError,
				)
				return
			}
			if status.Generation == lastGeneration {
				return
			}
			lastGeneration = status.Generation
			fmt.Fprintf(
				statusWriter,
				"identity TLS generation active: generation=%s trust_generation=%s revocation_generation=%d server_expiry=%s\n",
				status.Generation,
				status.TrustGeneration,
				status.RevocationGeneration,
				status.ServerCertificateExpiry.Format(time.RFC3339),
			)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("open dynamic TLS lifecycle: %w", err)
	}
	repository, err := identity.OpenFileRepository(
		options.identityRepository,
		identity.FileRepositoryOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("open identity repository: %w", err)
	}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, repository.Close())
		}
	}()
	backend, err := newRepositoryIdentityBackend(identityBackendOptions{
		repository:        repository,
		issuerCertificate: options.identityIssuerCert,
		issuerPrivateKey:  options.identityIssuerKey,
		trustBundle:       options.tlsClientCA,
		trustDomain:       options.spiffeTrustDomain,
		nodePathPrefix:    options.spiffeNodePathPrefix,
		audience:          options.identityAudience,
		clock:             time.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("construct identity issuer: %w", err)
	}
	verifier := repositoryLifecycleVerifier{transport: lifecycle, repository: repository}
	authenticator := discovery.MTLSAuthenticator{
		TrustDomain:    options.spiffeTrustDomain,
		NodePathPrefix: options.spiffeNodePathPrefix,
		Verifier:       verifier,
		Clock:          time.Now,
	}
	service, err := identityservice.New(backend, identityservice.Options{
		Authenticator:            authenticator,
		MaxClockSkew:             options.identityClockSkew,
		MaxObservationAge:        options.identityMaxAge,
		MaxConcurrentEnrollments: options.identityMaxConcurrent,
		Clock:                    time.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("construct node identity service: %w", err)
	}
	return &checkpoint8IdentityRuntime{
		lifecycle:     lifecycle,
		authenticator: authenticator,
		service:       service,
		repository:    repository,
	}, nil
}

func (runtime *checkpoint8IdentityRuntime) run(ctx context.Context) {
	if runtime != nil && runtime.lifecycle != nil {
		runtime.lifecycle.Run(ctx)
	}
}

func (runtime *checkpoint8IdentityRuntime) close() error {
	if runtime == nil || runtime.repository == nil {
		return nil
	}
	return runtime.repository.Close()
}
