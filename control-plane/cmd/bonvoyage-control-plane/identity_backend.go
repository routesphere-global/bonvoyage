package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/identity"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/identityservice"
)

type identityBackendOptions struct {
	repository        identity.Repository
	issuerCertificate string
	issuerPrivateKey  string
	trustBundle       string
	trustDomain       string
	nodePathPrefix    string
	audience          string
	clock             func() time.Time
}

type repositoryIdentityBackend struct {
	options identityBackendOptions
}

func newRepositoryIdentityBackend(options identityBackendOptions) (*repositoryIdentityBackend, error) {
	if options.repository == nil || strings.TrimSpace(options.issuerCertificate) == "" ||
		strings.TrimSpace(options.issuerPrivateKey) == "" || strings.TrimSpace(options.trustBundle) == "" ||
		strings.TrimSpace(options.trustDomain) == "" || strings.TrimSpace(options.nodePathPrefix) == "" ||
		strings.TrimSpace(options.audience) == "" || options.clock == nil {
		return nil, errors.New("identity backend options are incomplete")
	}
	backend := &repositoryIdentityBackend{options: options}
	if _, err := backend.loadAuthority(); err != nil {
		return nil, err
	}
	return backend, nil
}

func (backend *repositoryIdentityBackend) Enroll(
	ctx context.Context,
	request identityservice.EnrollmentRequest,
) (identityservice.Credential, error) {
	var authorityLoadError error
	record, err := backend.options.repository.Enroll(ctx, func() (*identity.Authority, error) {
		authority, loadErr := backend.loadAuthority()
		authorityLoadError = loadErr
		return authority, loadErr
	}, identity.EnrollmentRequest{
		Token: request.BootstrapToken, NodeID: request.NodeID,
		Audience: backend.options.audience, CSRDER: request.CSR,
	})
	if err != nil {
		if authorityLoadError != nil {
			return identityservice.Credential{}, errors.Join(identityservice.ErrIdentityUnavailable, authorityLoadError)
		}
		return identityservice.Credential{}, classifyIdentityError(err)
	}
	return serviceCredential(record.Bundle)
}

func (backend *repositoryIdentityBackend) Renew(
	ctx context.Context,
	request identityservice.RenewalRequest,
) (identityservice.Credential, error) {
	status, err := backend.options.repository.RevocationStatus(ctx, identity.RevocationStatusQuery{
		NodeID: request.NodeID, IssuerFingerprint: request.Identity.IssuerFingerprint,
		Serial:          request.Identity.CredentialSerial,
		LeafFingerprint: request.Identity.CredentialFingerprint,
	})
	if err != nil {
		return identityservice.Credential{}, classifyIdentityError(err)
	}
	if status.Revoked {
		return identityservice.Credential{}, identityservice.ErrCredentialRevoked
	}
	current, err := backend.options.repository.CurrentCredential(ctx, request.NodeID)
	if err != nil {
		return identityservice.Credential{}, classifyIdentityError(err)
	}
	if current.Bundle.LeafFingerprint != request.Identity.CredentialFingerprint ||
		current.Bundle.IssuerFingerprint != request.Identity.IssuerFingerprint ||
		current.Bundle.Serial != request.Identity.CredentialSerial {
		return identityservice.Credential{}, identityservice.ErrIdentityConflict
	}
	authority, err := backend.loadAuthority()
	if err != nil {
		return identityservice.Credential{}, errors.Join(identityservice.ErrIdentityUnavailable, err)
	}
	record, err := backend.options.repository.RotateCredential(ctx, authority, identity.RotationRequest{
		NodeID: request.NodeID, CSRDER: request.CSR,
	})
	if err != nil {
		return identityservice.Credential{}, classifyIdentityError(err)
	}
	return serviceCredential(record.Bundle)
}

func (backend *repositoryIdentityBackend) loadAuthority() (*identity.Authority, error) {
	return identity.LoadAuthority(identity.AuthorityOptions{
		CertificatePath: backend.options.issuerCertificate,
		PrivateKeyPath:  backend.options.issuerPrivateKey,
		TrustBundlePath: backend.options.trustBundle,
		TrustDomain:     backend.options.trustDomain,
		NodePathPrefix:  backend.options.nodePathPrefix,
		Clock:           backend.options.clock,
	})
}

func serviceCredential(bundle identity.CredentialBundle) (identityservice.Credential, error) {
	leafDigest, err := decodeFingerprint(bundle.LeafFingerprint)
	if err != nil {
		return identityservice.Credential{}, fmt.Errorf("decode leaf fingerprint: %w", err)
	}
	issuerDigest, err := decodeFingerprint(bundle.IssuerFingerprint)
	if err != nil {
		return identityservice.Credential{}, fmt.Errorf("decode issuer fingerprint: %w", err)
	}
	return identityservice.Credential{
		Generation:       bundle.GenerationID,
		CertificateChain: []byte(bundle.ChainPEM), TrustBundle: []byte(bundle.TrustBundlePEM),
		CertificateSHA256: leafDigest, IssuerSHA256: issuerDigest,
		SerialNumber: bundle.Serial, NotBefore: bundle.NotBefore,
		NotAfter: bundle.NotAfter, RenewAfter: bundle.RenewAfter,
	}, nil
}

func decodeFingerprint(value string) ([]byte, error) {
	if !strings.HasPrefix(value, "sha256:") || len(value) != 71 {
		return nil, errors.New("fingerprint is not canonical SHA-256")
	}
	digest, err := hex.DecodeString(value[7:])
	if err != nil || len(digest) != 32 {
		return nil, errors.New("fingerprint is not canonical SHA-256")
	}
	return digest, nil
}

func classifyIdentityError(err error) error {
	switch {
	case errors.Is(err, identity.ErrEnrollmentRejected):
		return errors.Join(identityservice.ErrEnrollmentDenied, err)
	case errors.Is(err, identity.ErrRevoked):
		return errors.Join(identityservice.ErrCredentialRevoked, err)
	case errors.Is(err, identity.ErrInvalid):
		return errors.Join(identityservice.ErrInvalidCSR, err)
	case errors.Is(err, identity.ErrConflict):
		return errors.Join(identityservice.ErrIdentityConflict, err)
	case errors.Is(err, identity.ErrNotFound):
		return errors.Join(identityservice.ErrIdentityConflict, err)
	case errors.Is(err, identity.ErrClosed), errors.Is(err, identity.ErrCorrupt),
		errors.Is(err, identity.ErrLocked), errors.Is(err, identity.ErrUnsupportedPlatform):
		return errors.Join(identityservice.ErrIdentityUnavailable, err)
	default:
		return err
	}
}
