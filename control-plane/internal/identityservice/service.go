// Package identityservice exposes bounded node enrollment and renewal over the
// generated Phase 4 gRPC contract. Issuance and durable token state remain in
// an injected backend so transport cannot silently become an identity store.
package identityservice

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	bonvoyagev1 "github.com/routesphere-global/bonvoyage/api/gen/go/bonvoyage/v1"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/discovery"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	maximumNodeIDBytes           = 128
	maximumTokenBytes            = 512
	maximumCSRBytes              = 16 << 10
	maximumCertificateChainBytes = 256 << 10
	maximumTrustBundleBytes      = 1 << 20
)

var (
	ErrEnrollmentDenied    = errors.New("node enrollment was denied")
	ErrCredentialRevoked   = errors.New("node credential was revoked")
	ErrInvalidCSR          = errors.New("node certificate request is invalid")
	ErrIdentityConflict    = errors.New("node identity state conflicts with the request")
	ErrIdentityUnavailable = errors.New("node identity service is unavailable")
)

// Credential is the immutable public result of one issuance operation.
type Credential struct {
	Generation        string
	CertificateChain  []byte
	TrustBundle       []byte
	CertificateSHA256 []byte
	IssuerSHA256      []byte
	SerialNumber      string
	NotBefore         time.Time
	NotAfter          time.Time
	RenewAfter        time.Time
}

// EnrollmentRequest is already bounded and clock-checked by Service.
type EnrollmentRequest struct {
	NodeID         string
	BootstrapToken string
	CSR            []byte
	ObservedAt     time.Time
	ReceivedAt     time.Time
}

// RenewalRequest carries the current certificate-bound identity. Backends
// must preserve node identity and reject revoked credentials.
type RenewalRequest struct {
	Identity   discovery.AuthenticatedNode
	NodeID     string
	CSR        []byte
	ObservedAt time.Time
	ReceivedAt time.Time
}

// Backend consumes enrollment tokens and signs constrained node credentials.
type Backend interface {
	Enroll(context.Context, EnrollmentRequest) (Credential, error)
	Renew(context.Context, RenewalRequest) (Credential, error)
}

// Options bounds clock and payload behavior.
type Options struct {
	Authenticator            discovery.Authenticator
	MaxClockSkew             time.Duration
	MaxObservationAge        time.Duration
	MaxConcurrentEnrollments int
	Clock                    func() time.Time
}

// Service implements the generated node identity contract.
type Service struct {
	bonvoyagev1.UnimplementedNodeIdentityServiceServer
	backend           Backend
	authenticator     discovery.Authenticator
	maxClockSkew      time.Duration
	maxObservationAge time.Duration
	enrollmentSem     chan struct{}
	clock             func() time.Time
}

// New validates and copies all issuance transport bounds.
func New(backend Backend, options Options) (*Service, error) {
	if backend == nil || options.Authenticator == nil || options.MaxClockSkew <= 0 ||
		options.MaxObservationAge <= 0 || options.MaxConcurrentEnrollments < 1 ||
		options.MaxConcurrentEnrollments > maximumConcurrentEnrollments || options.Clock == nil {
		return nil, errors.New("invalid node identity service options")
	}
	return &Service{
		backend: backend, authenticator: options.Authenticator,
		maxClockSkew: options.MaxClockSkew, maxObservationAge: options.MaxObservationAge,
		enrollmentSem: make(chan struct{}, options.MaxConcurrentEnrollments), clock: options.Clock,
	}, nil
}

// EnrollNode consumes one short-lived token and returns a certificate for the
// token-bound node. CSR identity extensions are never an identity authority.
func (service *Service) EnrollNode(
	ctx context.Context,
	request *bonvoyagev1.EnrollNodeRequest,
) (*bonvoyagev1.EnrollNodeResponse, error) {
	now := service.clock().UTC()
	nodeID, observedAt, err := service.validateRequest(
		request.GetNodeId(), request.GetPkcs10CertificateRequest(), request.GetObservedAt(),
	)
	if err != nil {
		return nil, err
	}
	if request == nil || len(request.ProtoReflect().GetUnknown()) != 0 ||
		strings.TrimSpace(request.GetBootstrapToken()) != request.GetBootstrapToken() ||
		len(request.GetBootstrapToken()) < 16 || len(request.GetBootstrapToken()) > maximumTokenBytes {
		return nil, status.Error(codes.InvalidArgument, "enrollment request is malformed")
	}
	select {
	case service.enrollmentSem <- struct{}{}:
		defer func() { <-service.enrollmentSem }()
	case <-ctx.Done():
		return nil, status.FromContextError(ctx.Err()).Err()
	default:
		return nil, status.Error(codes.ResourceExhausted, "enrollment work capacity is exhausted")
	}
	credential, err := service.backend.Enroll(ctx, EnrollmentRequest{
		NodeID: nodeID, BootstrapToken: request.GetBootstrapToken(),
		CSR:        append([]byte(nil), request.GetPkcs10CertificateRequest()...),
		ObservedAt: observedAt, ReceivedAt: now,
	})
	if err != nil {
		return nil, backendStatus(err)
	}
	wire, err := wireCredential(credential, now)
	if err != nil {
		return nil, status.Error(codes.Internal, "issuer returned an invalid credential")
	}
	return &bonvoyagev1.EnrollNodeResponse{Credential: wire}, nil
}

// RenewNode requires the current mTLS node identity and cannot rename a node.
func (service *Service) RenewNode(
	ctx context.Context,
	request *bonvoyagev1.RenewNodeRequest,
) (*bonvoyagev1.RenewNodeResponse, error) {
	now := service.clock().UTC()
	nodeID, observedAt, err := service.validateRequest(
		request.GetNodeId(), request.GetPkcs10CertificateRequest(), request.GetObservedAt(),
	)
	if err != nil {
		return nil, err
	}
	if request == nil || len(request.ProtoReflect().GetUnknown()) != 0 {
		return nil, status.Error(codes.InvalidArgument, "renewal request is malformed")
	}
	identity, err := service.authenticator.Authenticate(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "a current verified node credential is required")
	}
	if identity.NodeID != nodeID {
		return nil, status.Error(codes.PermissionDenied, "renewal node ID does not match the authenticated identity")
	}
	if validator, ok := service.authenticator.(discovery.CredentialValidator); ok {
		if err := validator.ValidateCredential(identity, now); err != nil {
			return nil, status.Error(codes.PermissionDenied, "the current node credential is not renewable")
		}
	}
	credential, err := service.backend.Renew(ctx, RenewalRequest{
		Identity: identity, NodeID: nodeID,
		CSR:        append([]byte(nil), request.GetPkcs10CertificateRequest()...),
		ObservedAt: observedAt, ReceivedAt: now,
	})
	if err != nil {
		return nil, backendStatus(err)
	}
	wire, err := wireCredential(credential, now)
	if err != nil {
		return nil, status.Error(codes.Internal, "issuer returned an invalid credential")
	}
	return &bonvoyagev1.RenewNodeResponse{Credential: wire}, nil
}

func (service *Service) validateRequest(
	nodeID string,
	csr []byte,
	observed *timestamppb.Timestamp,
) (string, time.Time, error) {
	if !validNodeID(nodeID) || len(csr) == 0 || len(csr) > maximumCSRBytes || observed == nil {
		return "", time.Time{}, status.Error(codes.InvalidArgument, "node identity request is malformed")
	}
	if err := observed.CheckValid(); err != nil {
		return "", time.Time{}, status.Error(codes.InvalidArgument, "node observation time is invalid")
	}
	observedAt := observed.AsTime().UTC()
	now := service.clock().UTC()
	if observedAt.After(now.Add(service.maxClockSkew)) || observedAt.Before(now.Add(-service.maxObservationAge)) {
		return "", time.Time{}, status.Error(codes.FailedPrecondition, "node clock is outside the accepted enrollment window")
	}
	return nodeID, observedAt, nil
}

func wireCredential(credential Credential, serverTime time.Time) (*bonvoyagev1.NodeCredentialBundle, error) {
	if strings.TrimSpace(credential.Generation) == "" || len(credential.Generation) > 128 ||
		len(credential.CertificateChain) == 0 || len(credential.CertificateChain) > maximumCertificateChainBytes ||
		len(credential.TrustBundle) == 0 || len(credential.TrustBundle) > maximumTrustBundleBytes ||
		len(credential.CertificateSHA256) != 32 || len(credential.IssuerSHA256) != 32 ||
		strings.TrimSpace(credential.SerialNumber) == "" || credential.NotBefore.IsZero() ||
		credential.NotAfter.IsZero() || credential.RenewAfter.IsZero() ||
		credential.NotAfter.Before(credential.RenewAfter) || credential.RenewAfter.Before(credential.NotBefore) {
		return nil, errors.New("credential metadata is invalid")
	}
	result := &bonvoyagev1.NodeCredentialBundle{
		CredentialGeneration: credential.Generation,
		CertificateChainPem:  append([]byte(nil), credential.CertificateChain...),
		TrustBundlePem:       append([]byte(nil), credential.TrustBundle...),
		CertificateSha256:    append([]byte(nil), credential.CertificateSHA256...),
		IssuerSha256:         append([]byte(nil), credential.IssuerSHA256...),
		SerialNumber:         credential.SerialNumber,
		NotBefore:            timestamppb.New(credential.NotBefore.UTC()),
		NotAfter:             timestamppb.New(credential.NotAfter.UTC()),
		RenewAfter:           timestamppb.New(credential.RenewAfter.UTC()),
		ServerTime:           timestamppb.New(serverTime.UTC()),
	}
	for _, timestamp := range []*timestamppb.Timestamp{
		result.NotBefore, result.NotAfter, result.RenewAfter, result.ServerTime,
	} {
		if err := timestamp.CheckValid(); err != nil {
			return nil, fmt.Errorf("credential timestamp: %w", err)
		}
	}
	return result, nil
}

func backendStatus(err error) error {
	switch {
	case errors.Is(err, ErrEnrollmentDenied):
		return status.Error(codes.PermissionDenied, "node enrollment was denied")
	case errors.Is(err, ErrCredentialRevoked):
		return status.Error(codes.PermissionDenied, "node credential is revoked")
	case errors.Is(err, ErrInvalidCSR):
		return status.Error(codes.InvalidArgument, "node certificate request is invalid")
	case errors.Is(err, ErrIdentityConflict):
		return status.Error(codes.Aborted, "node identity state conflicts with the request")
	case errors.Is(err, ErrIdentityUnavailable):
		return status.Error(codes.Unavailable, "node identity service is unavailable")
	default:
		return status.Error(codes.Internal, "node identity operation failed")
	}
}

func validNodeID(value string) bool {
	if value == "" || len(value) > maximumNodeIDBytes || value != strings.TrimSpace(value) {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			(index > 0 && (character == '-' || character == '.' || character == '_')) {
			continue
		}
		return false
	}
	return true
}
