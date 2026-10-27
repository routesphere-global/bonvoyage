package discovery

import (
	"crypto/tls"
	"errors"
	"time"

	bonvoyagev1 "github.com/routesphere-global/bonvoyage/api/gen/go/bonvoyage/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

const (
	maxNodeMessageBytes  = 1 << 20
	maxArtifactBytes     = 65 << 20
	maxConcurrentStreams = 1024
)

// NewGRPCServer constructs the production transport boundary. It refuses
// plaintext, optional client certificates, TLS versions below 1.3, and an
// unbounded message surface. Dynamic trust is accepted only when the TLS
// layer still requires a certificate and supplies an explicit verifier.
func NewGRPCServer(service *Server, tlsConfig *tls.Config) (*grpc.Server, error) {
	if service == nil || tlsConfig == nil {
		return nil, ErrInvalidOptions
	}
	staticVerification := tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert && tlsConfig.ClientCAs != nil
	dynamicVerification := tlsConfig.ClientAuth == tls.RequireAnyClientCert && tlsConfig.VerifyConnection != nil
	if tlsConfig.MinVersion < tls.VersionTLS13 ||
		(tlsConfig.MaxVersion != 0 && tlsConfig.MaxVersion < tls.VersionTLS13) ||
		(!staticVerification && !dynamicVerification) ||
		tlsConfig.GetConfigForClient != nil {
		return nil, errors.Join(ErrInvalidOptions, errors.New("TLS 1.3 with verified client certificates is required"))
	}
	if len(tlsConfig.Certificates) == 0 && tlsConfig.GetCertificate == nil {
		return nil, errors.Join(ErrInvalidOptions, errors.New("a server certificate is required"))
	}
	secureConfig := tlsConfig.Clone()
	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(secureConfig)),
		grpc.MaxRecvMsgSize(maxNodeMessageBytes),
		grpc.MaxSendMsgSize(maxArtifactBytes),
		grpc.MaxConcurrentStreams(maxConcurrentStreams),
		grpc.ConnectionTimeout(10*time.Second),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time: 2 * time.Minute, Timeout: 20 * time.Second,
			MaxConnectionAge: 15 * time.Minute, MaxConnectionAgeGrace: 30 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime: 10 * time.Second, PermitWithoutStream: false,
		}),
	)
	bonvoyagev1.RegisterSnapshotDiscoveryServiceServer(server, service)
	return server, nil
}
