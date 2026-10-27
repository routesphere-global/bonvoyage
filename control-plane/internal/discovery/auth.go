package discovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// MTLSAuthenticator binds a verified client certificate URI SAN to node_id.
// The expected identity is spiffe://<trust-domain><node-path-prefix><node-id>.
type MTLSAuthenticator struct {
	TrustDomain    string
	NodePathPrefix string
	Verifier       CertificateVerifier
	Clock          func() time.Time
}

// Authenticate rejects plaintext, unverified certificates, ambiguous URI
// identities, and node IDs outside the control-plane identifier contract.
func (authenticator MTLSAuthenticator) Authenticate(ctx context.Context) (AuthenticatedNode, error) {
	if strings.TrimSpace(authenticator.TrustDomain) == "" ||
		!strings.HasPrefix(authenticator.NodePathPrefix, "/") ||
		!strings.HasSuffix(authenticator.NodePathPrefix, "/") {
		return AuthenticatedNode{}, fmt.Errorf("invalid mTLS identity policy: %w", ErrInvalidOptions)
	}
	remote, ok := peer.FromContext(ctx)
	if !ok || remote.AuthInfo == nil {
		return AuthenticatedNode{}, ErrUnauthenticated
	}
	state, ok := tlsConnectionState(remote.AuthInfo)
	if !ok || len(state.State.PeerCertificates) == 0 {
		return AuthenticatedNode{}, ErrUnauthenticated
	}
	chain, err := authenticator.verifiedChain(state.State.PeerCertificates, state.State.VerifiedChains)
	if err != nil || len(chain) == 0 {
		return AuthenticatedNode{}, ErrUnauthenticated
	}
	certificate := chain[0]
	if !bytes.Equal(certificate.Raw, state.State.PeerCertificates[0].Raw) {
		return AuthenticatedNode{}, ErrUnauthenticated
	}
	var nodeID string
	matchCount := 0
	for _, identity := range certificate.URIs {
		candidate, matches := authenticator.nodeID(identity)
		if matches {
			matchCount++
			nodeID = candidate
		}
	}
	if matchCount != 1 {
		return AuthenticatedNode{}, fmt.Errorf("client certificate has %d matching node identities: %w", matchCount, ErrUnauthenticated)
	}
	if certificate.SerialNumber == nil || certificate.SerialNumber.Sign() <= 0 {
		return AuthenticatedNode{}, ErrUnauthenticated
	}
	digest := sha256.Sum256(certificate.Raw)
	issuer := certificate
	if len(chain) > 1 {
		issuer = chain[1]
	}
	issuerDigest := sha256.Sum256(issuer.Raw)
	anchorDigest := sha256.Sum256(chain[len(chain)-1].Raw)
	validFrom := certificate.NotBefore.UTC()
	validUntil := certificate.NotAfter.UTC()
	for _, member := range chain[1:] {
		if member.NotBefore.After(validFrom) {
			validFrom = member.NotBefore.UTC()
		}
		if member.NotAfter.Before(validUntil) {
			validUntil = member.NotAfter.UTC()
		}
	}
	identity := AuthenticatedNode{
		NodeID: nodeID, CredentialFingerprint: fmt.Sprintf("sha256:%x", digest),
		CredentialSerial:       strings.ToLower(certificate.SerialNumber.Text(16)),
		IssuerFingerprint:      fmt.Sprintf("sha256:%x", issuerDigest),
		TrustAnchorFingerprint: fmt.Sprintf("sha256:%x", anchorDigest),
		CredentialNotBefore:    validFrom, CredentialNotAfter: validUntil,
	}
	if err := authenticator.ValidateCredential(identity, authenticator.now()); err != nil {
		return AuthenticatedNode{}, ErrUnauthenticated
	}
	return identity, nil
}

func (authenticator MTLSAuthenticator) verifiedChain(
	peerCertificates []*x509.Certificate,
	verifiedChains [][]*x509.Certificate,
) ([]*x509.Certificate, error) {
	if authenticator.Verifier != nil {
		return authenticator.Verifier.VerifyClientCertificate(peerCertificates, authenticator.now())
	}
	if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
		return nil, ErrUnauthenticated
	}
	return verifiedChains[0], nil
}

func (authenticator MTLSAuthenticator) now() time.Time {
	if authenticator.Clock != nil {
		return authenticator.Clock().UTC()
	}
	return time.Now().UTC()
}

// ValidateCredential enforces certificate time and, when configured, current
// trust and revocation state for an already established stream.
func (authenticator MTLSAuthenticator) ValidateCredential(identity AuthenticatedNode, now time.Time) error {
	if identity.CredentialNotBefore.IsZero() || identity.CredentialNotAfter.IsZero() ||
		now.Before(identity.CredentialNotBefore) || !now.Before(identity.CredentialNotAfter) {
		return ErrUnauthenticated
	}
	validator, ok := authenticator.Verifier.(CredentialValidator)
	if ok {
		if err := validator.ValidateCredential(identity, now); err != nil {
			return ErrUnauthenticated
		}
	}
	return nil
}

func tlsConnectionState(authInfo credentials.AuthInfo) (state credentials.TLSInfo, ok bool) {
	switch typed := authInfo.(type) {
	case credentials.TLSInfo:
		return typed, true
	case *credentials.TLSInfo:
		if typed != nil {
			return *typed, true
		}
	}
	return credentials.TLSInfo{}, false
}

func (authenticator MTLSAuthenticator) nodeID(identity *url.URL) (string, bool) {
	if identity == nil || identity.Scheme != "spiffe" || identity.Host != authenticator.TrustDomain ||
		identity.RawQuery != "" || identity.Fragment != "" ||
		!strings.HasPrefix(identity.Path, authenticator.NodePathPrefix) {
		return "", false
	}
	nodeID := strings.TrimPrefix(identity.Path, authenticator.NodePathPrefix)
	if strings.Contains(nodeID, "/") || validateIdentifier("certificate node ID", nodeID) != nil {
		return "", false
	}
	return nodeID, true
}
