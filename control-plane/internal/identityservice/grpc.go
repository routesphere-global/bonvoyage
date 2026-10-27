package identityservice

import (
	"context"
	"crypto/tls"
	"errors"
	"time"

	bonvoyagev1 "github.com/routesphere-global/bonvoyage/api/gen/go/bonvoyage/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	maximumEnrollmentRequestBytes  = 32 << 10
	maximumEnrollmentResponseBytes = 2 << 20
	maximumConcurrentEnrollments   = 128
)

// NewEnrollmentGRPCServer constructs the server-authenticated bootstrap
// listener. It intentionally forbids client-certificate authentication here;
// the discovery listener separately requires verified mTLS for renewal.
func NewEnrollmentGRPCServer(service *Service, tlsConfig *tls.Config) (*grpc.Server, error) {
	if service == nil || tlsConfig == nil || tlsConfig.MinVersion < tls.VersionTLS13 ||
		(tlsConfig.MaxVersion != 0 && tlsConfig.MaxVersion < tls.VersionTLS13) ||
		tlsConfig.ClientAuth != tls.NoClientCert || tlsConfig.GetConfigForClient != nil ||
		(len(tlsConfig.Certificates) == 0 && tlsConfig.GetCertificate == nil) {
		return nil, errors.New("invalid TLS 1.3 enrollment transport configuration")
	}
	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig.Clone())),
		grpc.MaxRecvMsgSize(maximumEnrollmentRequestBytes),
		grpc.MaxSendMsgSize(maximumEnrollmentResponseBytes),
		grpc.MaxConcurrentStreams(maximumConcurrentEnrollments),
		grpc.ConnectionTimeout(10*time.Second),
	)
	bonvoyagev1.RegisterNodeIdentityServiceServer(server, enrollmentOnlyServer{service: service})
	return server, nil
}

// RegisterRenewalService adds authenticated renewal to the mTLS discovery
// server. It must be called before Serve.
func RegisterRenewalService(server *grpc.Server, service *Service) error {
	if server == nil || service == nil {
		return errors.New("renewal server and service are required")
	}
	bonvoyagev1.RegisterNodeIdentityServiceServer(server, renewalOnlyServer{service: service})
	return nil
}

type enrollmentOnlyServer struct {
	bonvoyagev1.UnimplementedNodeIdentityServiceServer
	service *Service
}

func (server enrollmentOnlyServer) EnrollNode(
	ctx context.Context,
	request *bonvoyagev1.EnrollNodeRequest,
) (*bonvoyagev1.EnrollNodeResponse, error) {
	return server.service.EnrollNode(ctx, request)
}

type renewalOnlyServer struct {
	bonvoyagev1.UnimplementedNodeIdentityServiceServer
	service *Service
}

func (server renewalOnlyServer) RenewNode(
	ctx context.Context,
	request *bonvoyagev1.RenewNodeRequest,
) (*bonvoyagev1.RenewNodeResponse, error) {
	return server.service.RenewNode(ctx, request)
}
