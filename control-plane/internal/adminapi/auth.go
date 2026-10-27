// Package adminapi exposes the standalone Admin service through a bounded,
// TLS-client-certificate-authenticated HTTP/1.1 API.
package adminapi

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/adminservice"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
)

const maxAuthorizationBytes = 256 << 10

const (
	consoleActorHeader   = "X-BonVoyage-Console-Actor"
	consoleRoleHeader    = "X-BonVoyage-Console-Role"
	consoleSessionHeader = "X-BonVoyage-Console-Session"
)

var ErrUnauthenticated = errors.New("admin client is not authenticated")

type authorizationDocument struct {
	Version    uint32                   `json:"version"`
	Generation uint64                   `json:"generation"`
	UpdatedAt  time.Time                `json:"updated_at"`
	ValidUntil time.Time                `json:"valid_until"`
	Principals []authorizationPrincipal `json:"principals"`
}

type authorizationPrincipal struct {
	SPIFFEID               string                `json:"spiffe_id"`
	CertificateSHA256      string                `json:"certificate_sha256"`
	Role                   adminservice.Role     `json:"role"`
	SourceChannel          storage.SourceChannel `json:"source_channel"`
	AllowConsoleDelegation bool                  `json:"allow_console_delegation,omitempty"`
}

// FileAuthorizer reloads one positive authorization snapshot for every
// request. Removal or fingerprint rotation therefore takes effect without a
// long-lived authorization cache; unreadable, malformed, or stale state fails
// closed.
type FileAuthorizer struct {
	Path                     string
	TrustDomain              string
	OperatorPathPrefix       string
	ServiceAccountPathPrefix string
	Clock                    func() time.Time
}

func (authorizer FileAuthorizer) Authorize(request *http.Request) (adminservice.Principal, error) {
	if request == nil || request.TLS == nil || len(request.TLS.PeerCertificates) == 0 ||
		len(request.TLS.VerifiedChains) == 0 || len(request.TLS.VerifiedChains[0]) == 0 {
		return adminservice.Principal{}, ErrUnauthenticated
	}
	if strings.TrimSpace(authorizer.TrustDomain) == "" ||
		!validPathPrefix(authorizer.OperatorPathPrefix) ||
		!validPathPrefix(authorizer.ServiceAccountPathPrefix) ||
		authorizer.OperatorPathPrefix == authorizer.ServiceAccountPathPrefix {
		return adminservice.Principal{}, ErrUnauthenticated
	}
	leaf := request.TLS.PeerCertificates[0]
	if leaf.IsCA || len(leaf.URIs) != 1 || !permitsClientAuth(leaf) {
		return adminservice.Principal{}, ErrUnauthenticated
	}
	identity := leaf.URIs[0]
	if !authorizer.validIdentity(identity) {
		return adminservice.Principal{}, ErrUnauthenticated
	}
	digest := sha256.Sum256(leaf.Raw)
	fingerprint := fmt.Sprintf("sha256:%x", digest)
	document, err := authorizer.load()
	if err != nil {
		return adminservice.Principal{}, ErrUnauthenticated
	}
	identityString := identity.String()
	for _, candidate := range document.Principals {
		if candidate.SPIFFEID != identityString {
			continue
		}
		if candidate.CertificateSHA256 != fingerprint {
			return adminservice.Principal{}, ErrUnauthenticated
		}
		return authorizePrincipal(request, candidate, identityString)
	}
	return adminservice.Principal{}, ErrUnauthenticated
}

func (authorizer FileAuthorizer) load() (authorizationDocument, error) {
	if !filepath.IsAbs(authorizer.Path) || filepath.Clean(authorizer.Path) != authorizer.Path {
		return authorizationDocument{}, errors.New("authorization path is not canonical and absolute")
	}
	info, err := os.Lstat(authorizer.Path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 || info.Size() <= 0 || info.Size() > maxAuthorizationBytes {
		return authorizationDocument{}, errors.New("authorization file is unavailable or unsafe")
	}
	contents, err := os.ReadFile(authorizer.Path)
	if err != nil {
		return authorizationDocument{}, err
	}
	var document authorizationDocument
	if err := decodeStrictJSONBytes(contents, &document, 16); err != nil {
		return authorizationDocument{}, err
	}
	now := authorizer.now()
	if document.Version != 1 || document.Generation == 0 || document.UpdatedAt.IsZero() ||
		document.ValidUntil.IsZero() || document.UpdatedAt.After(now.Add(time.Minute)) ||
		!now.Before(document.ValidUntil) || document.ValidUntil.Sub(document.UpdatedAt) > 90*24*time.Hour ||
		len(document.Principals) == 0 || len(document.Principals) > 1_000 {
		return authorizationDocument{}, errors.New("authorization document header is invalid or stale")
	}
	seenIdentity := make(map[string]struct{}, len(document.Principals))
	seenFingerprint := make(map[string]struct{}, len(document.Principals))
	for _, principal := range document.Principals {
		identity, err := url.Parse(principal.SPIFFEID)
		if err != nil || !authorizer.validIdentity(identity) || identity.String() != principal.SPIFFEID ||
			!canonicalFingerprint(principal.CertificateSHA256) {
			return authorizationDocument{}, errors.New("authorization principal identity is invalid")
		}
		switch principal.Role {
		case adminservice.RoleAuditor, adminservice.RoleViewer, adminservice.RoleOperator,
			adminservice.RoleAdministrator:
		default:
			return authorizationDocument{}, errors.New("authorization principal role is invalid")
		}
		switch principal.SourceChannel {
		case storage.SourceAPI, storage.SourceCLI, storage.SourceConsole, storage.SourceGitOps:
		default:
			return authorizationDocument{}, errors.New("authorization principal source channel is invalid")
		}
		if principal.AllowConsoleDelegation &&
			(principal.SourceChannel != storage.SourceConsole ||
				principal.Role != adminservice.RoleAdministrator) {
			return authorizationDocument{}, errors.New("Console delegation requires a Console administrator principal")
		}
		if _, exists := seenIdentity[principal.SPIFFEID]; exists {
			return authorizationDocument{}, errors.New("authorization principal identity is duplicated")
		}
		if _, exists := seenFingerprint[principal.CertificateSHA256]; exists {
			return authorizationDocument{}, errors.New("authorization certificate fingerprint is duplicated")
		}
		seenIdentity[principal.SPIFFEID] = struct{}{}
		seenFingerprint[principal.CertificateSHA256] = struct{}{}
	}
	return document, nil
}

func authorizePrincipal(
	request *http.Request,
	candidate authorizationPrincipal,
	machineActor string,
) (adminservice.Principal, error) {
	actor, actorPresent := singleHeader(request.Header, consoleActorHeader)
	roleText, rolePresent := singleHeader(request.Header, consoleRoleHeader)
	session, sessionPresent := singleHeader(request.Header, consoleSessionHeader)
	delegationPresent := len(request.Header.Values(consoleActorHeader)) != 0 ||
		len(request.Header.Values(consoleRoleHeader)) != 0 ||
		len(request.Header.Values(consoleSessionHeader)) != 0
	if !candidate.AllowConsoleDelegation {
		if delegationPresent {
			return adminservice.Principal{}, ErrUnauthenticated
		}
		return adminservice.Principal{
			Actor: machineActor, Role: candidate.Role, SourceChannel: candidate.SourceChannel,
		}, nil
	}
	if !actorPresent || !rolePresent || !sessionPresent ||
		!validConsoleActor(actor) || !canonicalFingerprint(session) {
		return adminservice.Principal{}, ErrUnauthenticated
	}
	role := adminservice.Role(roleText)
	switch role {
	case adminservice.RoleAuditor, adminservice.RoleOperator, adminservice.RoleAdministrator:
	default:
		return adminservice.Principal{}, ErrUnauthenticated
	}
	return adminservice.Principal{
		Actor: actor, Role: role, SourceChannel: storage.SourceConsole,
	}, nil
}

func singleHeader(headers http.Header, name string) (string, bool) {
	values := headers.Values(name)
	if len(values) != 1 || values[0] == "" || strings.TrimSpace(values[0]) != values[0] {
		return "", false
	}
	return values[0], true
}

func validConsoleActor(value string) bool {
	const prefix = "local:"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	identifier := strings.TrimPrefix(value, prefix)
	if len(identifier) < 1 || len(identifier) > 64 || strings.ToLower(identifier) != identifier {
		return false
	}
	for index, char := range identifier {
		valid := char >= 'a' && char <= 'z' || char >= '0' && char <= '9' ||
			char == '.' || char == '_' || char == '-'
		if !valid || index == 0 && (char == '.' || char == '_' || char == '-') {
			return false
		}
	}
	return true
}

func (authorizer FileAuthorizer) validIdentity(identity *url.URL) bool {
	if identity == nil || identity.Scheme != "spiffe" || identity.Host != authorizer.TrustDomain ||
		identity.RawQuery != "" || identity.Fragment != "" || identity.RawPath != "" {
		return false
	}
	for _, prefix := range []string{authorizer.OperatorPathPrefix, authorizer.ServiceAccountPathPrefix} {
		if strings.HasPrefix(identity.Path, prefix) {
			name := strings.TrimPrefix(identity.Path, prefix)
			return name != "" && !strings.Contains(name, "/") && validIdentifier(name)
		}
	}
	return false
}

func (authorizer FileAuthorizer) now() time.Time {
	if authorizer.Clock != nil {
		return authorizer.Clock().UTC()
	}
	return time.Now().UTC()
}

func permitsClientAuth(certificate *x509.Certificate) bool {
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func validPathPrefix(value string) bool {
	return strings.HasPrefix(value, "/") && strings.HasSuffix(value, "/") &&
		!strings.ContainsAny(value, "?#%")
}

func validIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, char := range value {
		valid := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' ||
			char >= '0' && char <= '9' || char == '.' || char == '_' || char == ':' || char == '-'
		if !valid || index == 0 && (char == '.' || char == ':' || char == '-') {
			return false
		}
	}
	return true
}

func canonicalFingerprint(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+sha256.Size*2 {
		return false
	}
	for _, char := range strings.TrimPrefix(value, "sha256:") {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}
