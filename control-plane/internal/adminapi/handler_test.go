package adminapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/adminservice"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/rollout"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
)

func TestHandlerEnforcesStrictMachineBoundaryAndJSON(t *testing.T) {
	service := &recordingManagementService{telemetry: adminservice.OperationalTelemetry{
		Ready: true, RuntimeAuthorityMatch: true, SelectedSequence: 42,
		RolloutPhase: rollout.PhaseActive, RolloutKind: storage.RolloutKindApply,
		PolicyStrategy: "DISABLED", ProcessStartedAt: time.Unix(1_000, 0),
	}}
	handler, err := NewHandler(HandlerOptions{
		Service: service, Authorizer: staticAuthorizer{principal: testPrincipal()},
		ServerName: "admin.test", MaxConcurrent: 4,
		Random: bytes.NewReader(bytes.Repeat([]byte{0x42}, 1_024)),
	})
	if err != nil {
		t.Fatal(err)
	}

	valid := `{"document":"server: {}\n"}`
	response := performAdminRequest(handler, http.MethodPost, "/api/v1/configurations/validate", valid, nil)
	if response.Code != http.StatusOK || service.validateCalls != 1 {
		t.Fatalf("valid response = %d %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("X-Content-Type-Options") != "nosniff" ||
		response.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("security headers = %#v", response.Header())
	}

	for name, body := range map[string]string{
		"duplicate": `{"document":"one","document":"two"}`,
		"unknown":   `{"document":"one","extra":true}`,
		"null":      `{"document":null}`,
		"trailing":  `{"document":"one"}{"document":"two"}`,
	} {
		t.Run(name, func(t *testing.T) {
			result := performAdminRequest(handler, http.MethodPost, "/api/v1/configurations/validate", body, nil)
			if result.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s", result.Code, result.Body.String())
			}
		})
	}

	for name, header := range map[string]http.Header{
		"origin":          {"Origin": {"https://admin.test"}},
		"cookie":          {"Cookie": {"session=secret"}},
		"bearer":          {"Authorization": {"Bearer secret"}},
		"method override": {"X-HTTP-Method-Override": {"DELETE"}},
	} {
		t.Run(name, func(t *testing.T) {
			result := performAdminRequest(handler, http.MethodPost, "/api/v1/configurations/validate", valid, header)
			if result.Code != http.StatusForbidden {
				t.Fatalf("status = %d body=%s", result.Code, result.Body.String())
			}
		})
	}

	wrongMethod := performAdminRequest(handler, http.MethodGet, "/api/v1/configurations/validate", "", nil)
	if wrongMethod.Code != http.StatusMethodNotAllowed || wrongMethod.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("wrong method = %d allow=%q", wrongMethod.Code, wrongMethod.Header().Get("Allow"))
	}
	mutation := performAdminRequest(handler, http.MethodPost, "/api/v1/rollouts", `{}`, nil)
	if mutation.Code != http.StatusBadRequest || !strings.Contains(mutation.Body.String(), "INVALID_IDEMPOTENCY_KEY") {
		t.Fatalf("missing idempotency response = %d %s", mutation.Code, mutation.Body.String())
	}
	previewBody := `{"document":"server: {}\n","baseline_rollout_sequence":7,"target_node_ids":["node-a","node-b"],"policy":{"strategy":"CANARY","canary_node_ids":["node-a"],"minimum_healthy_canary_percent":100,"canary_observation_seconds":30,"prepare_timeout_seconds":20,"activation_timeout_seconds":30,"heartbeat_stale_after_seconds":10,"automatic_rollback":true}}`
	previewResponse := performAdminRequest(
		handler, http.MethodPost, "/api/v1/configurations/preview", previewBody, nil,
	)
	if previewResponse.Code != http.StatusOK || service.previewInput.Policy.Strategy != storage.RolloutStrategyCanary ||
		!service.previewInput.Policy.AutomaticRollback {
		t.Fatalf("policy preview = %d %s input=%#v", previewResponse.Code, previewResponse.Body.String(), service.previewInput)
	}
	cancelHeaders := http.Header{"Idempotency-Key": {"cancel-operation-0001"}}
	cancelResponse := performAdminRequest(
		handler, http.MethodPost, "/api/v1/rollouts/42/cancel",
		`{"reason":"operator stopped rollout"}`, cancelHeaders,
	)
	if cancelResponse.Code != http.StatusAccepted || service.cancelInput.Sequence != 42 ||
		service.cancelInput.Reason != "operator stopped rollout" || service.cancelInput.RequestID == "" {
		t.Fatalf("cancel response = %d %s input=%#v", cancelResponse.Code, cancelResponse.Body.String(), service.cancelInput)
	}
	auditResponse := performAdminRequest(
		handler, http.MethodGet, "/api/v1/rollouts/42/audit?after_index=7&limit=25", "", nil,
	)
	if auditResponse.Code != http.StatusOK || service.auditSequence != 42 ||
		service.auditAfterIndex != 7 || service.auditLimit != 25 {
		t.Fatalf("audit response = %d %s", auditResponse.Code, auditResponse.Body.String())
	}
	desiredResponse := performAdminRequest(
		handler, http.MethodGet, "/api/v1/rollouts/42/desired-state", "", nil,
	)
	if desiredResponse.Code != http.StatusOK || service.desiredSequence != 42 ||
		!strings.Contains(desiredResponse.Body.String(), "desired-test") {
		t.Fatalf("desired-state response = %d %s", desiredResponse.Code, desiredResponse.Body.String())
	}
	reorderedAudit := performAdminRequest(
		handler, http.MethodGet, "/api/v1/rollouts/42/audit?limit=50&after_index=9", "", nil,
	)
	if reorderedAudit.Code != http.StatusOK || service.auditAfterIndex != 9 ||
		service.auditLimit != 50 {
		t.Fatalf("reordered audit response = %d %s", reorderedAudit.Code, reorderedAudit.Body.String())
	}
	invalidAudit := performAdminRequest(
		handler, http.MethodGet, "/api/v1/rollouts/42/audit?limit=0", "", nil,
	)
	if invalidAudit.Code != http.StatusBadRequest {
		t.Fatalf("invalid audit status = %d body=%s", invalidAudit.Code, invalidAudit.Body.String())
	}
	encodedAudit := performAdminRequest(
		handler, http.MethodGet, "/api/v1/rollouts/42/audit?after_index=%37", "", nil,
	)
	if encodedAudit.Code != http.StatusBadRequest {
		t.Fatalf("encoded audit status = %d body=%s", encodedAudit.Code, encodedAudit.Body.String())
	}
	routeDigest := strings.Repeat("a", 64)
	routesResponse := performAdminRequest(
		handler, http.MethodGet,
		"/api/v1/configurations/current/routes?artifact_sha256="+routeDigest+"&offset=500&limit=250&query=payments",
		"", nil,
	)
	if routesResponse.Code != http.StatusOK ||
		service.routeQuery.ExpectedArtifactSHA256 != routeDigest || service.routeQuery.Offset != 500 ||
		service.routeQuery.Limit != 250 || service.routeQuery.Query != "payments" {
		t.Fatalf("route response = %d %s query=%#v", routesResponse.Code, routesResponse.Body.String(), service.routeQuery)
	}
	for _, path := range []string{
		"/api/v1/configurations/current/routes",
		"/api/v1/configurations/current/routes?artifact_sha256=" + routeDigest + "&limit=501",
		"/api/v1/configurations/current/routes?artifact_sha256=" + routeDigest + "&unknown=1",
		"/api/v1/configurations/current/routes?artifact_sha256=" + routeDigest + "&offset=01",
	} {
		result := performAdminRequest(handler, http.MethodGet, path, "", nil)
		if result.Code != http.StatusBadRequest {
			t.Fatalf("invalid route query %q status = %d body=%s", path, result.Code, result.Body.String())
		}
	}
	metrics := performAdminRequest(handler, http.MethodGet, "/metrics", "", nil)
	if metrics.Code != http.StatusOK ||
		metrics.Header().Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" ||
		!strings.Contains(metrics.Body.String(), "bonvoyage_control_plane_ready 1") ||
		strings.Contains(metrics.Body.String(), testPrincipal().Actor) {
		t.Fatalf("metrics response = %d %s", metrics.Code, metrics.Body.String())
	}
}

func TestFileAuthorizerPinsSPIFFEIdentityCertificateAndFreshAuthorization(t *testing.T) {
	now := time.Date(2026, time.September, 23, 10, 0, 0, 0, time.UTC)
	identity, err := url.Parse("spiffe://admin.test/bonvoyage/service-accounts/gitops")
	if err != nil {
		t.Fatal(err)
	}
	certificate := testClientCertificate(t, now, []*url.URL{identity})
	fingerprint := fmt.Sprintf("sha256:%x", sha256.Sum256(certificate.Raw))
	path := filepath.Join(t.TempDir(), "authorizations.json")
	document := authorizationDocument{
		Version: 1, Generation: 1, UpdatedAt: now.Add(-time.Minute), ValidUntil: now.Add(time.Hour),
		Principals: []authorizationPrincipal{{
			SPIFFEID: identity.String(), CertificateSHA256: fingerprint,
			Role: adminservice.RoleOperator, SourceChannel: storage.SourceGitOps,
		}},
	}
	writeAuthorizationTestFile(t, path, document)
	authorizer := FileAuthorizer{
		Path: path, TrustDomain: "admin.test",
		OperatorPathPrefix:       "/bonvoyage/operators/",
		ServiceAccountPathPrefix: "/bonvoyage/service-accounts/",
		Clock:                    func() time.Time { return now },
	}
	request := &http.Request{TLS: &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{certificate},
		VerifiedChains:   [][]*x509.Certificate{{certificate}},
	}}
	principal, err := authorizer.Authorize(request)
	if err != nil || principal.Actor != identity.String() ||
		principal.Role != adminservice.RoleOperator || principal.SourceChannel != storage.SourceGitOps {
		t.Fatalf("principal = %#v, err=%v", principal, err)
	}

	document.Principals[0].CertificateSHA256 = "sha256:" + strings.Repeat("0", 64)
	writeAuthorizationTestFile(t, path, document)
	if _, err := authorizer.Authorize(request); err == nil {
		t.Fatal("changed certificate fingerprint was accepted")
	}
	document.Principals[0].CertificateSHA256 = fingerprint
	document.ValidUntil = now
	writeAuthorizationTestFile(t, path, document)
	if _, err := authorizer.Authorize(request); err == nil {
		t.Fatal("stale authorization document was accepted")
	}
	ambiguous := testClientCertificate(t, now, []*url.URL{identity, identity})
	request.TLS.PeerCertificates = []*x509.Certificate{ambiguous}
	request.TLS.VerifiedChains = [][]*x509.Certificate{{ambiguous}}
	if _, err := authorizer.Authorize(request); err == nil {
		t.Fatal("ambiguous URI identity was accepted")
	}
}

func TestFileAuthorizerBindsConsoleDelegationToAnAuthorizedMachineIdentity(t *testing.T) {
	now := time.Date(2026, time.September, 24, 10, 0, 0, 0, time.UTC)
	identity, err := url.Parse("spiffe://admin.test/bonvoyage/service-accounts/console")
	if err != nil {
		t.Fatal(err)
	}
	certificate := testClientCertificate(t, now, []*url.URL{identity})
	fingerprint := fmt.Sprintf("sha256:%x", sha256.Sum256(certificate.Raw))
	path := filepath.Join(t.TempDir(), "authorizations.json")
	document := authorizationDocument{
		Version: 1, Generation: 1, UpdatedAt: now.Add(-time.Minute), ValidUntil: now.Add(time.Hour),
		Principals: []authorizationPrincipal{{
			SPIFFEID: identity.String(), CertificateSHA256: fingerprint,
			Role: adminservice.RoleAdministrator, SourceChannel: storage.SourceConsole,
			AllowConsoleDelegation: true,
		}},
	}
	writeAuthorizationTestFile(t, path, document)
	authorizer := FileAuthorizer{
		Path: path, TrustDomain: "admin.test",
		OperatorPathPrefix:       "/bonvoyage/operators/",
		ServiceAccountPathPrefix: "/bonvoyage/service-accounts/",
		Clock:                    func() time.Time { return now },
	}
	request := &http.Request{
		Header: make(http.Header),
		TLS: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{certificate},
			VerifiedChains:   [][]*x509.Certificate{{certificate}},
		},
	}
	if _, err := authorizer.Authorize(request); err == nil {
		t.Fatal("Console machine identity was accepted without browser delegation")
	}
	request.Header.Set(consoleActorHeader, "local:alice")
	request.Header.Set(consoleRoleHeader, string(adminservice.RoleOperator))
	request.Header.Set(consoleSessionHeader, "sha256:"+strings.Repeat("a", 64))
	principal, err := authorizer.Authorize(request)
	if err != nil || principal.Actor != "local:alice" || principal.Role != adminservice.RoleOperator ||
		principal.SourceChannel != storage.SourceConsole {
		t.Fatalf("delegated principal = %#v, err=%v", principal, err)
	}

	request.Header.Set(consoleRoleHeader, string(adminservice.RoleViewer))
	if _, err := authorizer.Authorize(request); err == nil {
		t.Fatal("legacy viewer role was accepted as a new Console delegation")
	}
	request.Header.Set(consoleRoleHeader, string(adminservice.RoleAuditor))
	request.Header.Add(consoleActorHeader, "local:mallory")
	if _, err := authorizer.Authorize(request); err == nil {
		t.Fatal("ambiguous delegated actor was accepted")
	}

	document.Principals[0].AllowConsoleDelegation = false
	writeAuthorizationTestFile(t, path, document)
	request.Header = make(http.Header)
	request.Header.Set(consoleActorHeader, "local:alice")
	request.Header.Set(consoleRoleHeader, string(adminservice.RoleAuditor))
	request.Header.Set(consoleSessionHeader, "sha256:"+strings.Repeat("a", 64))
	if _, err := authorizer.Authorize(request); err == nil {
		t.Fatal("delegation headers were accepted for an ordinary machine principal")
	}
}

func performAdminRequest(
	handler http.Handler,
	method string,
	path string,
	body string,
	headers http.Header,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://admin.test"+path, strings.NewReader(body))
	request.Host = "admin.test"
	request.URL.Scheme = ""
	request.URL.Host = ""
	request.Proto = "HTTP/1.1"
	request.ProtoMajor = 1
	request.ProtoMinor = 1
	request.TLS = &tls.ConnectionState{ServerName: "admin.test"}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

type staticAuthorizer struct {
	principal adminservice.Principal
}

func (authorizer staticAuthorizer) Authorize(*http.Request) (adminservice.Principal, error) {
	return authorizer.principal, nil
}

func testPrincipal() adminservice.Principal {
	return adminservice.Principal{
		Actor: "spiffe://admin.test/service-accounts/gitops",
		Role:  adminservice.RoleOperator, SourceChannel: storage.SourceGitOps,
	}
}

type recordingManagementService struct {
	validateCalls   int
	previewInput    adminservice.PreviewInput
	cancelInput     adminservice.CancelInput
	auditSequence   uint64
	auditAfterIndex uint64
	auditLimit      int
	desiredSequence uint64
	routeQuery      adminservice.RouteCatalogQuery
	telemetry       adminservice.OperationalTelemetry
}

func (service *recordingManagementService) Validate(
	context.Context,
	adminservice.Principal,
	adminservice.ValidateInput,
) (adminservice.ValidationResult, error) {
	service.validateCalls++
	return adminservice.ValidationResult{APIVersion: adminservice.APIVersion, Valid: true}, nil
}

func (service *recordingManagementService) Preview(
	_ context.Context, _ adminservice.Principal, input adminservice.PreviewInput,
) (adminservice.PreviewResult, error) {
	service.previewInput = input
	return adminservice.PreviewResult{}, nil
}

func (*recordingManagementService) PreviewRollback(
	context.Context, adminservice.Principal, adminservice.RollbackPreviewInput,
) (adminservice.PreviewResult, error) {
	return adminservice.PreviewResult{}, nil
}

func (*recordingManagementService) Apply(
	context.Context, adminservice.Principal, adminservice.ApplyInput,
) (adminservice.MutationResult, error) {
	return adminservice.MutationResult{}, nil
}

func (service *recordingManagementService) Cancel(
	_ context.Context, _ adminservice.Principal, input adminservice.CancelInput,
) (adminservice.MutationResult, error) {
	service.cancelInput = input
	return adminservice.MutationResult{}, nil
}

func (*recordingManagementService) Rollback(
	context.Context, adminservice.Principal, adminservice.RollbackInput,
) (adminservice.MutationResult, error) {
	return adminservice.MutationResult{}, nil
}

func (*recordingManagementService) GetStatus(
	context.Context, adminservice.Principal, uint64,
) (adminservice.RolloutStatus, error) {
	return adminservice.RolloutStatus{}, nil
}

func (service *recordingManagementService) GetDesiredState(
	_ context.Context, _ adminservice.Principal, sequence uint64,
) (adminservice.DesiredStateResult, error) {
	service.desiredSequence = sequence
	return adminservice.DesiredStateResult{
		APIVersion: adminservice.APIVersion, RolloutSequence: sequence,
		DesiredRevisionID: "desired-test", Document: "snapshot: {}\n",
		SourceChannel: storage.SourceConsole, Actor: "operator-a",
		CreatedAt: time.Unix(1_000, 0).UTC(), SnapshotID: "snapshot-test",
		ArtifactSHA256: strings.Repeat("a", 64),
	}, nil
}

func (*recordingManagementService) GetDiagnostics(
	context.Context, adminservice.Principal, uint64,
) (adminservice.DiagnosticsResult, error) {
	return adminservice.DiagnosticsResult{}, nil
}

func (service *recordingManagementService) GetAudit(
	_ context.Context,
	_ adminservice.Principal,
	sequence uint64,
	afterIndex uint64,
	limit int,
) (adminservice.AuditResult, error) {
	service.auditSequence = sequence
	service.auditAfterIndex = afterIndex
	service.auditLimit = limit
	return adminservice.AuditResult{}, nil
}

func (service *recordingManagementService) GetOperationalTelemetry(
	context.Context,
	adminservice.Principal,
) (adminservice.OperationalTelemetry, error) {
	return service.telemetry, nil
}

func (service *recordingManagementService) ListCurrentRoutes(
	_ context.Context,
	_ adminservice.Principal,
	query adminservice.RouteCatalogQuery,
) (adminservice.RouteCatalogPage, error) {
	service.routeQuery = query
	return adminservice.RouteCatalogPage{
		APIVersion: adminservice.APIVersion, ArtifactSHA256: query.ExpectedArtifactSHA256,
		Limit: query.Limit, Offset: query.Offset, Routes: []adminservice.RouteCatalogEntry{},
	}, nil
}

func testClientCertificate(t *testing.T, now time.Time, identities []*url.URL) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ignored"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: identities,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func writeAuthorizationTestFile(t *testing.T, path string, document authorizationDocument) {
	t.Helper()
	contents, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}
