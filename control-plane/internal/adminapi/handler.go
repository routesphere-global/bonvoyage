package adminapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/adminservice"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/discovery"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/identity"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/rollout"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/rolloutservice"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
)

const (
	maxConfigEnvelopeBytes = 4 << 20
	maxMutationBodyBytes   = 16 << 10
	maxURLBytes            = 4 << 10
	maxHeaderCount         = 64
	maxHeaderValueBytes    = 8 << 10
	maxJSONDepth           = 32
)

type managementService interface {
	Validate(context.Context, adminservice.Principal, adminservice.ValidateInput) (adminservice.ValidationResult, error)
	Preview(context.Context, adminservice.Principal, adminservice.PreviewInput) (adminservice.PreviewResult, error)
	PreviewRollback(context.Context, adminservice.Principal, adminservice.RollbackPreviewInput) (adminservice.PreviewResult, error)
	Apply(context.Context, adminservice.Principal, adminservice.ApplyInput) (adminservice.MutationResult, error)
	Cancel(context.Context, adminservice.Principal, adminservice.CancelInput) (adminservice.MutationResult, error)
	Rollback(context.Context, adminservice.Principal, adminservice.RollbackInput) (adminservice.MutationResult, error)
	GetStatus(context.Context, adminservice.Principal, uint64) (adminservice.RolloutStatus, error)
	GetDesiredState(context.Context, adminservice.Principal, uint64) (adminservice.DesiredStateResult, error)
	GetDiagnostics(context.Context, adminservice.Principal, uint64) (adminservice.DiagnosticsResult, error)
	GetAudit(context.Context, adminservice.Principal, uint64, uint64, int) (adminservice.AuditResult, error)
	GetOperationalTelemetry(context.Context, adminservice.Principal) (adminservice.OperationalTelemetry, error)
	ListCurrentRoutes(context.Context, adminservice.Principal, adminservice.RouteCatalogQuery) (adminservice.RouteCatalogPage, error)
}

type nodeManagementService interface {
	ListNodes(context.Context, adminservice.Principal) (adminservice.NodeListResult, error)
	GetNode(context.Context, adminservice.Principal, string) (adminservice.NodeView, error)
	ListNodeEvents(context.Context, adminservice.Principal, string, uint64, int) (adminservice.NodeEventsResult, error)
	CreateNode(context.Context, adminservice.Principal, adminservice.CreateNodeInput) (adminservice.NodeEnrollmentResult, error)
	ReissueNode(context.Context, adminservice.Principal, adminservice.ReissueNodeInput) (adminservice.NodeEnrollmentResult, error)
	ReplaceNode(context.Context, adminservice.Principal, adminservice.ReplaceNodeInput) (adminservice.NodeEnrollmentResult, error)
	UpdateNode(context.Context, adminservice.Principal, adminservice.UpdateNodeInput) (adminservice.NodeMutationResult, error)
	DrainNode(context.Context, adminservice.Principal, adminservice.TransitionNodeInput) (adminservice.NodeMutationResult, error)
	RetireNode(context.Context, adminservice.Principal, adminservice.TransitionNodeInput) (adminservice.NodeMutationResult, error)
	RevokeNode(context.Context, adminservice.Principal, adminservice.TransitionNodeInput) (adminservice.NodeMutationResult, error)
}

type Authorizer interface {
	Authorize(*http.Request) (adminservice.Principal, error)
}

type HandlerOptions struct {
	Service       managementService
	NodeService   nodeManagementService
	Authorizer    Authorizer
	ServerName    string
	MaxConcurrent int
	Random        io.Reader
	LogError      func(string, error)
}

type Handler struct {
	service    managementService
	nodes      nodeManagementService
	authorizer Authorizer
	serverName string
	sem        chan struct{}
	random     io.Reader
	logError   func(string, error)
}

func NewHandler(options HandlerOptions) (*Handler, error) {
	if options.Service == nil || options.Authorizer == nil ||
		strings.TrimSpace(options.ServerName) == "" || strings.ContainsAny(options.ServerName, "/:@?#%") ||
		options.MaxConcurrent < 1 || options.MaxConcurrent > 1_024 {
		return nil, errors.New("admin HTTP handler options are invalid")
	}
	randomSource := options.Random
	if randomSource == nil {
		randomSource = rand.Reader
	}
	return &Handler{
		service: options.Service, nodes: options.NodeService, authorizer: options.Authorizer,
		serverName: options.ServerName, sem: make(chan struct{}, options.MaxConcurrent),
		random: randomSource, logError: options.LogError,
	}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	requestID, err := handler.newRequestID()
	if err != nil {
		writeProblem(response, "INTERNAL", http.StatusInternalServerError, "request identity unavailable", "unavailable")
		return
	}
	secureResponseHeaders(response, requestID)
	if err := handler.validateRequestBoundary(request); err != nil {
		handler.problem(response, requestID, err)
		return
	}
	select {
	case handler.sem <- struct{}{}:
		defer func() { <-handler.sem }()
	default:
		handler.problem(response, requestID, errSaturated)
		return
	}
	principal, err := handler.authorizer.Authorize(request)
	if err != nil {
		handler.problem(response, requestID, ErrUnauthenticated)
		return
	}

	switch {
	case request.URL.Path == "/metrics":
		handler.handleMetrics(response, request, requestID, principal)
	case request.URL.Path == "/api/v1/configurations/validate":
		handler.handleValidate(response, request, requestID, principal)
	case request.URL.Path == "/api/v1/configurations/preview":
		handler.handlePreview(response, request, requestID, principal)
	case request.URL.Path == "/api/v1/configurations/current/routes":
		handler.handleCurrentRoutes(response, request, requestID, principal)
	case request.URL.Path == "/api/v1/rollouts":
		handler.handleApply(response, request, requestID, principal)
	case request.URL.Path == "/api/v1/rollbacks/preview":
		handler.handleRollbackPreview(response, request, requestID, principal)
	case request.URL.Path == "/api/v1/rollbacks":
		handler.handleRollback(response, request, requestID, principal)
	case request.URL.Path == "/api/v1/nodes":
		handler.handleNodes(response, request, requestID, principal)
	case strings.HasPrefix(request.URL.Path, "/api/v1/nodes/"):
		handler.handleNodeResource(response, request, requestID, principal)
	case strings.HasPrefix(request.URL.Path, "/api/v1/rollouts/") &&
		strings.HasSuffix(request.URL.Path, "/cancel"):
		handler.handleCancel(response, request, requestID, principal)
	case strings.HasPrefix(request.URL.Path, "/api/v1/rollouts/"):
		handler.handleRolloutRead(response, request, requestID, principal)
	default:
		handler.problem(response, requestID, storage.ErrNotFound)
	}
}

func (handler *Handler) handleValidate(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
	principal adminservice.Principal,
) {
	if !handler.requireMethod(response, requestID, request, http.MethodPost) {
		return
	}
	var body configurationRequest
	if err := decodeRequest(request, &body, maxConfigEnvelopeBytes); err != nil {
		handler.problem(response, requestID, err)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	result, err := handler.service.Validate(ctx, principal, adminservice.ValidateInput{Document: []byte(body.Document)})
	if err != nil {
		var validation *adminservice.ConfigurationValidationError
		if errors.As(err, &validation) {
			writeConfigurationValidationProblem(response, requestID, validation)
			return
		}
		handler.problem(response, requestID, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (handler *Handler) handlePreview(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
	principal adminservice.Principal,
) {
	if !handler.requireMethod(response, requestID, request, http.MethodPost) {
		return
	}
	var body previewRequest
	if err := decodeRequest(request, &body, maxConfigEnvelopeBytes); err != nil {
		handler.problem(response, requestID, err)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	result, err := handler.service.Preview(ctx, principal, adminservice.PreviewInput{
		Document: []byte(body.Document), BaselineRolloutSequence: body.BaselineRolloutSequence,
		TargetNodeIDs: body.TargetNodeIDs, Policy: policyInput(body.Policy),
	})
	if err != nil {
		handler.problem(response, requestID, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (handler *Handler) handleApply(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
	principal adminservice.Principal,
) {
	if !handler.requireMethod(response, requestID, request, http.MethodPost) {
		return
	}
	operationID, err := operationID(request, principal)
	if err != nil {
		handler.problem(response, requestID, err)
		return
	}
	var body applyRequest
	if err := decodeRequest(request, &body, maxConfigEnvelopeBytes); err != nil {
		handler.problem(response, requestID, err)
		return
	}
	expected, err := storage.ParseDigest(body.ExpectedActiveArtifactSHA256)
	if err != nil || expected.String() != body.ExpectedActiveArtifactSHA256 {
		handler.problem(response, requestID, errInvalidRequest)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 20*time.Second)
	defer cancel()
	result, err := handler.service.Apply(ctx, principal, adminservice.ApplyInput{
		RequestID: operationID, Document: []byte(body.Document),
		SourceRevision: body.SourceRevision, Reason: body.Reason,
		TargetNodeIDs:                   body.TargetNodeIDs,
		ExpectedSelectedRolloutSequence: body.ExpectedSelectedRolloutSequence,
		ExpectedActiveArtifact:          expected,
		PreviewFingerprintSHA256:        body.PreviewFingerprintSHA256,
		Policy:                          policyInput(body.Policy),
	})
	if err != nil {
		handler.problem(response, requestID, err)
		return
	}
	writeJSON(response, http.StatusAccepted, result)
}

func (handler *Handler) handleCancel(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
	principal adminservice.Principal,
) {
	if !handler.requireMethod(response, requestID, request, http.MethodPost) {
		return
	}
	operationID, err := operationID(request, principal)
	if err != nil {
		handler.problem(response, requestID, err)
		return
	}
	path := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, "/api/v1/rollouts/"), "/cancel")
	sequence, err := parseSequence(path)
	if err != nil || sequence == 0 {
		handler.problem(response, requestID, storage.ErrNotFound)
		return
	}
	var body cancelRequest
	if err := decodeRequest(request, &body, maxMutationBodyBytes); err != nil {
		handler.problem(response, requestID, err)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	result, err := handler.service.Cancel(ctx, principal, adminservice.CancelInput{
		RequestID: operationID, Sequence: sequence, Reason: body.Reason,
	})
	if err != nil {
		handler.problem(response, requestID, err)
		return
	}
	writeJSON(response, http.StatusAccepted, result)
}

func (handler *Handler) handleRollbackPreview(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
	principal adminservice.Principal,
) {
	if !handler.requireMethod(response, requestID, request, http.MethodPost) {
		return
	}
	var body rollbackPreviewRequest
	if err := decodeRequest(request, &body, maxMutationBodyBytes); err != nil {
		handler.problem(response, requestID, err)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	result, err := handler.service.PreviewRollback(ctx, principal, adminservice.RollbackPreviewInput{
		CurrentRolloutSequence: body.CurrentRolloutSequence,
		TargetRolloutSequence:  body.TargetRolloutSequence,
		TargetNodeIDs:          body.TargetNodeIDs,
	})
	if err != nil {
		handler.problem(response, requestID, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (handler *Handler) handleRollback(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
	principal adminservice.Principal,
) {
	if !handler.requireMethod(response, requestID, request, http.MethodPost) {
		return
	}
	operationID, err := operationID(request, principal)
	if err != nil {
		handler.problem(response, requestID, err)
		return
	}
	var body rollbackRequest
	if err := decodeRequest(request, &body, maxMutationBodyBytes); err != nil {
		handler.problem(response, requestID, err)
		return
	}
	expected, err := storage.ParseDigest(body.ExpectedActiveArtifactSHA256)
	if err != nil || expected.String() != body.ExpectedActiveArtifactSHA256 {
		handler.problem(response, requestID, errInvalidRequest)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 20*time.Second)
	defer cancel()
	result, err := handler.service.Rollback(ctx, principal, adminservice.RollbackInput{
		RequestID: operationID, Reason: body.Reason, TargetNodeIDs: body.TargetNodeIDs,
		ExpectedSelectedRolloutSequence: body.ExpectedSelectedRolloutSequence,
		ExpectedActiveArtifact:          expected,
		RollbackTargetSequence:          body.RollbackTargetSequence,
		PreviewFingerprintSHA256:        body.PreviewFingerprintSHA256,
	})
	if err != nil {
		handler.problem(response, requestID, err)
		return
	}
	writeJSON(response, http.StatusAccepted, result)
}

func (handler *Handler) handleRolloutRead(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
	principal adminservice.Principal,
) {
	if !handler.requireMethod(response, requestID, request, http.MethodGet) {
		return
	}
	if request.ContentLength > 0 || len(request.TransferEncoding) != 0 {
		handler.problem(response, requestID, errInvalidRequest)
		return
	}
	path := strings.TrimPrefix(request.URL.Path, "/api/v1/rollouts/")
	diagnostics := strings.HasSuffix(path, "/diagnostics")
	audit := strings.HasSuffix(path, "/audit")
	desiredState := strings.HasSuffix(path, "/desired-state")
	if diagnostics {
		path = strings.TrimSuffix(path, "/diagnostics")
	} else if audit {
		path = strings.TrimSuffix(path, "/audit")
	} else if desiredState {
		path = strings.TrimSuffix(path, "/desired-state")
	}
	sequence, err := parseSequence(path)
	if err != nil {
		handler.problem(response, requestID, err)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 3*time.Second)
	defer cancel()
	if audit {
		afterIndex, limit, err := parseAuditWindow(request.URL.RawQuery)
		if err != nil {
			handler.problem(response, requestID, err)
			return
		}
		result, err := handler.service.GetAudit(ctx, principal, sequence, afterIndex, limit)
		if err != nil {
			handler.problem(response, requestID, err)
			return
		}
		writeJSON(response, http.StatusOK, result)
		return
	}
	if diagnostics {
		result, err := handler.service.GetDiagnostics(ctx, principal, sequence)
		if err != nil {
			handler.problem(response, requestID, err)
			return
		}
		writeJSON(response, http.StatusOK, result)
		return
	}
	if desiredState {
		result, err := handler.service.GetDesiredState(ctx, principal, sequence)
		if err != nil {
			handler.problem(response, requestID, err)
			return
		}
		writeJSON(response, http.StatusOK, result)
		return
	}
	result, err := handler.service.GetStatus(ctx, principal, sequence)
	if err != nil {
		handler.problem(response, requestID, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (handler *Handler) handleMetrics(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
	principal adminservice.Principal,
) {
	if !handler.requireMethod(response, requestID, request, http.MethodGet) {
		return
	}
	if request.ContentLength > 0 || len(request.TransferEncoding) != 0 {
		handler.problem(response, requestID, errInvalidRequest)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 3*time.Second)
	defer cancel()
	telemetry, err := handler.service.GetOperationalTelemetry(ctx, principal)
	if err != nil {
		handler.problem(response, requestID, err)
		return
	}
	writePrometheus(response, telemetry)
}

func (handler *Handler) handleCurrentRoutes(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
	principal adminservice.Principal,
) {
	if !handler.requireMethod(response, requestID, request, http.MethodGet) {
		return
	}
	if request.ContentLength > 0 || len(request.TransferEncoding) != 0 {
		handler.problem(response, requestID, errInvalidRequest)
		return
	}
	query, err := parseRouteCatalogQuery(request.URL.RawQuery)
	if err != nil {
		handler.problem(response, requestID, err)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer cancel()
	result, err := handler.service.ListCurrentRoutes(ctx, principal, query)
	if err != nil {
		handler.problem(response, requestID, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (handler *Handler) validateRequestBoundary(request *http.Request) error {
	if request == nil || request.ProtoMajor != 1 || request.ProtoMinor != 1 ||
		request.URL == nil || request.URL.IsAbs() || request.URL.RawPath != "" ||
		len(request.RequestURI) > maxURLBytes ||
		(request.URL.RawQuery != "" && !isQueryPath(request.URL.Path)) ||
		request.URL.ForceQuery || request.URL.Fragment != "" {
		return errInvalidRequest
	}
	host := request.Host
	if parsedHost, _, err := net.SplitHostPort(request.Host); err == nil {
		host = parsedHost
	}
	if !strings.EqualFold(host, handler.serverName) || request.TLS == nil ||
		!strings.EqualFold(request.TLS.ServerName, handler.serverName) {
		return ErrUnauthenticated
	}
	if request.Header.Get("Origin") != "" || request.Header.Get("Sec-Fetch-Site") != "" ||
		request.Header.Get("Cookie") != "" || request.Header.Get("Authorization") != "" ||
		request.Header.Get("X-HTTP-Method-Override") != "" || request.Header.Get("Content-Encoding") != "" {
		return errForbiddenBoundary
	}
	if len(request.Header) > maxHeaderCount {
		return errHeadersTooLarge
	}
	for _, values := range request.Header {
		for _, value := range values {
			if len(value) > maxHeaderValueBytes {
				return errHeadersTooLarge
			}
		}
	}
	return nil
}

func isQueryPath(path string) bool {
	return (strings.HasPrefix(path, "/api/v1/rollouts/") && strings.HasSuffix(path, "/audit")) ||
		(strings.HasPrefix(path, "/api/v1/nodes/") && strings.HasSuffix(path, "/events")) ||
		path == "/api/v1/configurations/current/routes"
}

func parseRouteCatalogQuery(rawQuery string) (adminservice.RouteCatalogQuery, error) {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return adminservice.RouteCatalogQuery{}, errInvalidRequest
	}
	for name, entries := range values {
		if len(entries) != 1 || (name != "artifact_sha256" && name != "offset" && name != "limit" && name != "query") {
			return adminservice.RouteCatalogQuery{}, errInvalidRequest
		}
	}
	artifactValues, present := values["artifact_sha256"]
	if !present || len(artifactValues) != 1 || artifactValues[0] == "" {
		return adminservice.RouteCatalogQuery{}, errInvalidRequest
	}
	result := adminservice.RouteCatalogQuery{
		ExpectedArtifactSHA256: artifactValues[0],
		Limit:                  adminservice.DefaultRoutePageSize,
	}
	if entries, ok := values["offset"]; ok {
		parsed, parseErr := strconv.Atoi(entries[0])
		if parseErr != nil || strconv.Itoa(parsed) != entries[0] || parsed < 0 || parsed > adminservice.MaxRouteOffset {
			return adminservice.RouteCatalogQuery{}, errInvalidRequest
		}
		result.Offset = parsed
	}
	if entries, ok := values["limit"]; ok {
		parsed, parseErr := strconv.Atoi(entries[0])
		if parseErr != nil || strconv.Itoa(parsed) != entries[0] || parsed < 1 || parsed > adminservice.MaxRoutePageSize {
			return adminservice.RouteCatalogQuery{}, errInvalidRequest
		}
		result.Limit = parsed
	}
	if entries, ok := values["query"]; ok {
		if entries[0] == "" || len(entries[0]) > adminservice.MaxRouteSearchBytes {
			return adminservice.RouteCatalogQuery{}, errInvalidRequest
		}
		result.Query = entries[0]
	}
	return result, nil
}

func parseAuditWindow(rawQuery string) (uint64, int, error) {
	if rawQuery == "" {
		return 0, adminservice.DefaultAuditPageSize, nil
	}
	afterIndex := uint64(0)
	limit := adminservice.DefaultAuditPageSize
	seenAfterIndex := false
	seenLimit := false
	for _, parameter := range strings.Split(rawQuery, "&") {
		name, value, found := strings.Cut(parameter, "=")
		if !found || value == "" {
			return 0, 0, errInvalidRequest
		}
		switch name {
		case "after_index":
			if seenAfterIndex {
				return 0, 0, errInvalidRequest
			}
			parsed, parseErr := strconv.ParseUint(value, 10, 64)
			if parseErr != nil || strconv.FormatUint(parsed, 10) != value {
				return 0, 0, errInvalidRequest
			}
			afterIndex = parsed
			seenAfterIndex = true
		case "limit":
			if seenLimit {
				return 0, 0, errInvalidRequest
			}
			parsed, parseErr := strconv.Atoi(value)
			if parseErr != nil || strconv.Itoa(parsed) != value ||
				parsed < 1 || parsed > adminservice.MaxAuditPageSize {
				return 0, 0, errInvalidRequest
			}
			limit = parsed
			seenLimit = true
		default:
			return 0, 0, errInvalidRequest
		}
	}
	return afterIndex, limit, nil
}

func (handler *Handler) requireMethod(
	response http.ResponseWriter,
	requestID string,
	request *http.Request,
	want string,
) bool {
	if request.Method == want {
		return true
	}
	response.Header().Set("Allow", want)
	handler.problem(response, requestID, errMethodNotAllowed)
	return false
}

func decodeRequest(request *http.Request, destination any, limit int64) error {
	contentTypes := request.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return errUnsupportedMedia
	}
	mediaType, parameters, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" {
		return errUnsupportedMedia
	}
	if len(parameters) != 0 && (len(parameters) != 1 || !strings.EqualFold(parameters["charset"], "utf-8")) {
		return errUnsupportedMedia
	}
	if request.ContentLength > limit {
		return errBodyTooLarge
	}
	contents, err := io.ReadAll(io.LimitReader(request.Body, limit+1))
	if err != nil {
		return errInvalidRequest
	}
	if int64(len(contents)) > limit {
		return errBodyTooLarge
	}
	if err := decodeStrictJSONBytes(contents, destination, maxJSONDepth); err != nil {
		return errInvalidRequest
	}
	return nil
}

func operationID(request *http.Request, principal adminservice.Principal) (string, error) {
	values := request.Header.Values("Idempotency-Key")
	if len(values) != 1 || len(values[0]) < 16 || len(values[0]) > 128 {
		return "", errInvalidIdempotencyKey
	}
	for _, char := range values[0] {
		if char < 0x21 || char > 0x7e {
			return "", errInvalidIdempotencyKey
		}
	}
	digest := sha256.Sum256([]byte(principal.Actor + "\x00" + request.Method + "\x00" + request.URL.Path + "\x00" + values[0]))
	return "op_" + hex.EncodeToString(digest[:]), nil
}

func parseSequence(value string) (uint64, error) {
	if value == "current" {
		return 0, nil
	}
	if value == "" || strings.Contains(value, "/") {
		return 0, storage.ErrNotFound
	}
	sequence, err := strconv.ParseUint(value, 10, 64)
	if err != nil || sequence == 0 || strconv.FormatUint(sequence, 10) != value {
		return 0, storage.ErrNotFound
	}
	return sequence, nil
}

func (handler *Handler) newRequestID() (string, error) {
	var bytes [16]byte
	if _, err := io.ReadFull(handler.random, bytes[:]); err != nil {
		return "", err
	}
	return "req_" + hex.EncodeToString(bytes[:]), nil
}

func (handler *Handler) problem(response http.ResponseWriter, requestID string, err error) {
	code, status, detail := problemForError(err)
	if status >= 500 && handler.logError != nil {
		handler.logError(requestID, err)
	}
	writeProblem(response, code, status, detail, requestID)
}

type problemDocument struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Code      string `json:"code"`
	Detail    string `json:"detail"`
	RequestID string `json:"request_id"`
}

type configurationValidationProblemDocument struct {
	problemDocument
	Diagnostics          []adminservice.ConfigurationDiagnostic `json:"diagnostics"`
	DiagnosticsTruncated bool                                   `json:"diagnostics_truncated"`
}

func writeProblem(response http.ResponseWriter, code string, status int, detail, requestID string) {
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(problemDocument{
		Type:  "urn:routesphere:bonvoyage:problem:" + strings.ToLower(code),
		Title: http.StatusText(status), Status: status, Code: code, Detail: detail, RequestID: requestID,
	})
}

func writeConfigurationValidationProblem(
	response http.ResponseWriter,
	requestID string,
	validation *adminservice.ConfigurationValidationError,
) {
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(http.StatusUnprocessableEntity)
	_ = json.NewEncoder(response).Encode(configurationValidationProblemDocument{
		problemDocument: problemDocument{
			Type:      "urn:routesphere:bonvoyage:problem:invalid_configuration",
			Title:     http.StatusText(http.StatusUnprocessableEntity),
			Status:    http.StatusUnprocessableEntity,
			Code:      "INVALID_CONFIGURATION",
			Detail:    "the desired state failed strict server-side validation",
			RequestID: requestID,
		},
		Diagnostics:          validation.Diagnostics,
		DiagnosticsTruncated: validation.DiagnosticsTruncated,
	})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func secureResponseHeaders(response http.ResponseWriter, requestID string) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Pragma", "no-cache")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("X-Frame-Options", "DENY")
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("X-Request-ID", requestID)
}

var (
	errInvalidRequest        = errors.New("admin request is invalid")
	errForbiddenBoundary     = errors.New("browser or alternate authentication state is forbidden")
	errUnsupportedMedia      = errors.New("admin request media type is unsupported")
	errBodyTooLarge          = errors.New("admin request body is too large")
	errHeadersTooLarge       = errors.New("admin request headers are too large")
	errMethodNotAllowed      = errors.New("admin request method is not allowed")
	errInvalidIdempotencyKey = errors.New("idempotency key is invalid")
	errSaturated             = errors.New("admin request capacity is exhausted")
)

func problemForError(err error) (string, int, string) {
	switch {
	case errors.Is(err, ErrUnauthenticated):
		return "UNAUTHENTICATED", http.StatusUnauthorized, "a valid Admin client certificate and authorization are required"
	case errors.Is(err, adminservice.ErrForbidden), errors.Is(err, errForbiddenBoundary):
		return "FORBIDDEN", http.StatusForbidden, "the authenticated principal may not perform this operation"
	case errors.Is(err, storage.ErrNotFound), errors.Is(err, identity.ErrNotFound):
		return "NOT_FOUND", http.StatusNotFound, "the requested resource was not found"
	case errors.Is(err, errMethodNotAllowed):
		return "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed, "the HTTP method is not supported for this resource"
	case errors.Is(err, errUnsupportedMedia):
		return "UNSUPPORTED_MEDIA_TYPE", http.StatusUnsupportedMediaType, "Content-Type must be application/json with optional UTF-8 charset"
	case errors.Is(err, errBodyTooLarge):
		return "REQUEST_TOO_LARGE", http.StatusRequestEntityTooLarge, "the request exceeds the bounded Admin API envelope"
	case errors.Is(err, errHeadersTooLarge):
		return "HEADERS_TOO_LARGE", http.StatusRequestHeaderFieldsTooLarge, "the request headers exceed the Admin API bounds"
	case errors.Is(err, errInvalidIdempotencyKey):
		return "INVALID_IDEMPOTENCY_KEY", http.StatusBadRequest, "a 16-128 byte printable Idempotency-Key is required"
	case errors.Is(err, adminservice.ErrInvalidConfiguration):
		return "INVALID_CONFIGURATION", http.StatusUnprocessableEntity, "the desired state failed strict server-side validation"
	case errors.Is(err, adminservice.ErrInvalidInput), errors.Is(err, storage.ErrInvalid), errors.Is(err, identity.ErrInvalid),
		errors.Is(err, errInvalidRequest):
		return "INVALID_REQUEST", http.StatusBadRequest, "the request does not satisfy the versioned Admin API contract"
	case errors.Is(err, adminservice.ErrNoChange):
		return "NO_CHANGE", http.StatusConflict, "the proposed operation does not change the active artifact"
	case errors.Is(err, adminservice.ErrPrecondition), errors.Is(err, storage.ErrConflict),
		errors.Is(err, identity.ErrConflict), errors.Is(err, identity.ErrRevoked),
		errors.Is(err, discovery.ErrRolloutInProgress), errors.Is(err, discovery.ErrRolloutSuperseded),
		errors.Is(err, discovery.ErrRollbackRequired), errors.Is(err, rollout.ErrRequiresRollback),
		errors.Is(err, rollout.ErrStateTransition),
		errors.Is(err, adminservice.ErrPolicyAwaitingReconciliation):
		return "CONFLICT", http.StatusConflict, "the selected rollout or preview precondition no longer permits this operation"
	case errors.Is(err, errSaturated):
		return "SATURATED", http.StatusServiceUnavailable, "the bounded Admin API request capacity is exhausted"
	case errors.Is(err, context.DeadlineExceeded):
		return "DEADLINE_EXCEEDED", http.StatusGatewayTimeout, "the Admin operation exceeded its bounded deadline"
	case errors.Is(err, context.Canceled):
		return "CANCELED", http.StatusRequestTimeout, "the Admin operation was canceled"
	case errors.Is(err, adminservice.ErrAuthorityMismatch), errors.Is(err, storage.ErrClosed), errors.Is(err, identity.ErrClosed),
		errors.Is(err, storage.ErrLocked), errors.Is(err, rolloutservice.ErrServicePoisoned),
		errors.Is(err, rolloutservice.ErrDurabilityUncertain):
		return "UNAVAILABLE", http.StatusServiceUnavailable, "the authoritative control-plane state is unavailable"
	case errors.Is(err, storage.ErrCorrupt), errors.Is(err, identity.ErrCorrupt), errors.Is(err, rolloutservice.ErrReplayMismatch):
		return "DATA_LOSS", http.StatusInternalServerError, "durable control-plane state failed integrity verification"
	default:
		return "INTERNAL", http.StatusInternalServerError, "the Admin operation failed without exposing internal state"
	}
}

type configurationRequest struct {
	Document string `json:"document"`
}

type previewRequest struct {
	Document                string                `json:"document"`
	BaselineRolloutSequence uint64                `json:"baseline_rollout_sequence"`
	TargetNodeIDs           []string              `json:"target_node_ids"`
	Policy                  *rolloutPolicyRequest `json:"policy,omitempty"`
}

type applyRequest struct {
	Document                        string                `json:"document"`
	SourceRevision                  string                `json:"source_revision"`
	Reason                          string                `json:"reason"`
	TargetNodeIDs                   []string              `json:"target_node_ids"`
	ExpectedSelectedRolloutSequence uint64                `json:"expected_selected_rollout_sequence"`
	ExpectedActiveArtifactSHA256    string                `json:"expected_active_artifact_sha256"`
	PreviewFingerprintSHA256        string                `json:"preview_fingerprint_sha256"`
	Policy                          *rolloutPolicyRequest `json:"policy,omitempty"`
}

type rolloutPolicyRequest struct {
	Strategy                    storage.RolloutStrategy `json:"strategy"`
	CanaryNodeIDs               []string                `json:"canary_node_ids,omitempty"`
	MinimumHealthyCanaryPercent uint32                  `json:"minimum_healthy_canary_percent,omitempty"`
	CanaryObservationSeconds    uint32                  `json:"canary_observation_seconds,omitempty"`
	PrepareTimeoutSeconds       uint32                  `json:"prepare_timeout_seconds"`
	ActivationTimeoutSeconds    uint32                  `json:"activation_timeout_seconds"`
	HeartbeatStaleAfterSeconds  uint32                  `json:"heartbeat_stale_after_seconds,omitempty"`
	AutomaticRollback           bool                    `json:"automatic_rollback"`
}

type cancelRequest struct {
	Reason string `json:"reason"`
}

type rollbackPreviewRequest struct {
	CurrentRolloutSequence uint64   `json:"current_rollout_sequence"`
	TargetRolloutSequence  uint64   `json:"target_rollout_sequence"`
	TargetNodeIDs          []string `json:"target_node_ids"`
}

type rollbackRequest struct {
	Reason                          string   `json:"reason"`
	TargetNodeIDs                   []string `json:"target_node_ids"`
	ExpectedSelectedRolloutSequence uint64   `json:"expected_selected_rollout_sequence"`
	ExpectedActiveArtifactSHA256    string   `json:"expected_active_artifact_sha256"`
	RollbackTargetSequence          uint64   `json:"rollback_target_sequence"`
	PreviewFingerprintSHA256        string   `json:"preview_fingerprint_sha256"`
}

func policyInput(value *rolloutPolicyRequest) adminservice.RolloutPolicyInput {
	if value == nil {
		return adminservice.RolloutPolicyInput{}
	}
	return adminservice.RolloutPolicyInput{
		Enabled: true, Strategy: value.Strategy,
		CanaryNodeIDs:               append([]string(nil), value.CanaryNodeIDs...),
		MinimumHealthyCanaryPercent: value.MinimumHealthyCanaryPercent,
		CanaryObservationSeconds:    value.CanaryObservationSeconds,
		PrepareTimeoutSeconds:       value.PrepareTimeoutSeconds,
		ActivationTimeoutSeconds:    value.ActivationTimeoutSeconds,
		HeartbeatStaleAfterSeconds:  value.HeartbeatStaleAfterSeconds,
		AutomaticRollback:           value.AutomaticRollback,
	}
}
