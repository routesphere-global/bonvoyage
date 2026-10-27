package adminapi

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/adminservice"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
)

type nodeMetadataRequest struct {
	DisplayName string            `json:"display_name"`
	Group       string            `json:"group"`
	Labels      map[string]string `json:"labels,omitempty"`
}

type createNodeRequest struct {
	NodeID     string              `json:"node_id"`
	Metadata   nodeMetadataRequest `json:"metadata"`
	Reason     string              `json:"reason"`
	TTLSeconds uint32              `json:"ttl_seconds,omitempty"`
}

type updateNodeRequest struct {
	ExpectedVersion uint64              `json:"expected_version"`
	Metadata        nodeMetadataRequest `json:"metadata"`
	Reason          string              `json:"reason"`
}

type nodeTransitionRequest struct {
	ExpectedVersion uint64 `json:"expected_version"`
	Reason          string `json:"reason"`
}

type reissueNodeRequest struct {
	ExpectedVersion uint64 `json:"expected_version"`
	Reason          string `json:"reason"`
	TTLSeconds      uint32 `json:"ttl_seconds,omitempty"`
}

type replaceNodeRequest struct {
	ExpectedVersion   uint64              `json:"expected_version"`
	ReplacementNodeID string              `json:"replacement_node_id"`
	Metadata          nodeMetadataRequest `json:"metadata"`
	Reason            string              `json:"reason"`
	TTLSeconds        uint32              `json:"ttl_seconds,omitempty"`
}

func (handler *Handler) handleNodes(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
	principal adminservice.Principal,
) {
	if handler.nodes == nil {
		handler.problem(response, requestID, storage.ErrNotFound)
		return
	}
	switch request.Method {
	case http.MethodGet:
		ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
		defer cancel()
		result, err := handler.nodes.ListNodes(ctx, principal)
		if err != nil {
			handler.problem(response, requestID, err)
			return
		}
		writeJSON(response, http.StatusOK, result)
	case http.MethodPost:
		operationID, err := operationID(request, principal)
		if err != nil {
			handler.problem(response, requestID, err)
			return
		}
		var body createNodeRequest
		if err := decodeRequest(request, &body, maxMutationBodyBytes); err != nil {
			handler.problem(response, requestID, err)
			return
		}
		ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
		defer cancel()
		result, err := handler.nodes.CreateNode(ctx, principal, adminservice.CreateNodeInput{
			RequestID: operationID, Reason: body.Reason, NodeID: body.NodeID,
			Metadata: nodeMetadataInput(body.Metadata), TTLSeconds: body.TTLSeconds,
		})
		if err != nil {
			handler.problem(response, requestID, err)
			return
		}
		writeJSON(response, http.StatusCreated, result)
	default:
		handler.problem(response, requestID, errMethodNotAllowed)
	}
}

func (handler *Handler) handleNodeResource(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
	principal adminservice.Principal,
) {
	if handler.nodes == nil {
		handler.problem(response, requestID, storage.ErrNotFound)
		return
	}
	nodeID, action, err := parseNodeResourcePath(request.URL.Path)
	if err != nil {
		handler.problem(response, requestID, storage.ErrNotFound)
		return
	}
	switch action {
	case "":
		handler.handleNode(response, request, requestID, principal, nodeID)
	case "events":
		handler.handleNodeEvents(response, request, requestID, principal, nodeID)
	case "enrollment-token":
		handler.handleNodeReissue(response, request, requestID, principal, nodeID)
	case "replacements":
		handler.handleNodeReplacement(response, request, requestID, principal, nodeID)
	case "drain", "retire", "revoke":
		handler.handleNodeTransition(response, request, requestID, principal, nodeID, action)
	default:
		handler.problem(response, requestID, storage.ErrNotFound)
	}
}

func (handler *Handler) handleNode(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
	principal adminservice.Principal,
	nodeID string,
) {
	switch request.Method {
	case http.MethodGet:
		ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
		defer cancel()
		result, err := handler.nodes.GetNode(ctx, principal, nodeID)
		if err != nil {
			handler.problem(response, requestID, err)
			return
		}
		writeJSON(response, http.StatusOK, result)
	case http.MethodPatch:
		operationID, err := operationID(request, principal)
		if err != nil {
			handler.problem(response, requestID, err)
			return
		}
		var body updateNodeRequest
		if err := decodeRequest(request, &body, maxMutationBodyBytes); err != nil {
			handler.problem(response, requestID, err)
			return
		}
		ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
		defer cancel()
		result, err := handler.nodes.UpdateNode(ctx, principal, adminservice.UpdateNodeInput{
			RequestID: operationID, Reason: body.Reason, NodeID: nodeID,
			ExpectedVersion: body.ExpectedVersion, Metadata: nodeMetadataInput(body.Metadata),
		})
		if err != nil {
			handler.problem(response, requestID, err)
			return
		}
		writeJSON(response, http.StatusOK, result)
	default:
		handler.problem(response, requestID, errMethodNotAllowed)
	}
}

func (handler *Handler) handleNodeEvents(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
	principal adminservice.Principal,
	nodeID string,
) {
	if !handler.requireMethod(response, requestID, request, http.MethodGet) {
		return
	}
	afterIndex, limit, err := parseNodeEventWindow(request.URL.RawQuery)
	if err != nil {
		handler.problem(response, requestID, err)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer cancel()
	result, err := handler.nodes.ListNodeEvents(ctx, principal, nodeID, afterIndex, limit)
	if err != nil {
		handler.problem(response, requestID, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func parseNodeEventWindow(rawQuery string) (uint64, int, error) {
	if rawQuery == "" {
		return 0, adminservice.DefaultNodeEventPageSize, nil
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return 0, 0, errInvalidRequest
	}
	for name, entries := range values {
		if len(entries) != 1 || (name != "after_index" && name != "limit") {
			return 0, 0, errInvalidRequest
		}
	}
	afterIndex := uint64(0)
	limit := adminservice.DefaultNodeEventPageSize
	if entries, ok := values["after_index"]; ok {
		parsed, parseErr := strconv.ParseUint(entries[0], 10, 64)
		if parseErr != nil || strconv.FormatUint(parsed, 10) != entries[0] {
			return 0, 0, errInvalidRequest
		}
		afterIndex = parsed
	}
	if entries, ok := values["limit"]; ok {
		parsed, parseErr := strconv.Atoi(entries[0])
		if parseErr != nil || strconv.Itoa(parsed) != entries[0] ||
			parsed < 1 || parsed > adminservice.MaxNodeEventPageSize {
			return 0, 0, errInvalidRequest
		}
		limit = parsed
	}
	return afterIndex, limit, nil
}

func (handler *Handler) handleNodeReissue(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
	principal adminservice.Principal,
	nodeID string,
) {
	if !handler.requireMethod(response, requestID, request, http.MethodPost) {
		return
	}
	operationID, err := operationID(request, principal)
	if err != nil {
		handler.problem(response, requestID, err)
		return
	}
	var body reissueNodeRequest
	if err := decodeRequest(request, &body, maxMutationBodyBytes); err != nil {
		handler.problem(response, requestID, err)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	result, err := handler.nodes.ReissueNode(ctx, principal, adminservice.ReissueNodeInput{
		RequestID: operationID, Reason: body.Reason, NodeID: nodeID,
		ExpectedVersion: body.ExpectedVersion, TTLSeconds: body.TTLSeconds,
	})
	if err != nil {
		handler.problem(response, requestID, err)
		return
	}
	writeJSON(response, http.StatusCreated, result)
}

func (handler *Handler) handleNodeReplacement(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
	principal adminservice.Principal,
	nodeID string,
) {
	if !handler.requireMethod(response, requestID, request, http.MethodPost) {
		return
	}
	if request.Header.Get("X-BonVoyage-Node-Confirm") != "replace:"+nodeID {
		handler.problem(response, requestID, adminservice.ErrPrecondition)
		return
	}
	operationID, err := operationID(request, principal)
	if err != nil {
		handler.problem(response, requestID, err)
		return
	}
	var body replaceNodeRequest
	if err := decodeRequest(request, &body, maxMutationBodyBytes); err != nil {
		handler.problem(response, requestID, err)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	result, err := handler.nodes.ReplaceNode(ctx, principal, adminservice.ReplaceNodeInput{
		RequestID: operationID, Reason: body.Reason, PredecessorNodeID: nodeID,
		ExpectedVersion: body.ExpectedVersion, ReplacementNodeID: body.ReplacementNodeID,
		Metadata: nodeMetadataInput(body.Metadata), TTLSeconds: body.TTLSeconds,
	})
	if err != nil {
		handler.problem(response, requestID, err)
		return
	}
	writeJSON(response, http.StatusCreated, result)
}

func (handler *Handler) handleNodeTransition(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
	principal adminservice.Principal,
	nodeID string,
	action string,
) {
	if !handler.requireMethod(response, requestID, request, http.MethodPost) {
		return
	}
	if action != "drain" && request.Header.Get("X-BonVoyage-Node-Confirm") != action+":"+nodeID {
		handler.problem(response, requestID, adminservice.ErrPrecondition)
		return
	}
	operationID, err := operationID(request, principal)
	if err != nil {
		handler.problem(response, requestID, err)
		return
	}
	var body nodeTransitionRequest
	if err := decodeRequest(request, &body, maxMutationBodyBytes); err != nil {
		handler.problem(response, requestID, err)
		return
	}
	input := adminservice.TransitionNodeInput{
		RequestID: operationID, Reason: body.Reason, NodeID: nodeID, ExpectedVersion: body.ExpectedVersion,
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	var result adminservice.NodeMutationResult
	switch action {
	case "drain":
		result, err = handler.nodes.DrainNode(ctx, principal, input)
	case "retire":
		result, err = handler.nodes.RetireNode(ctx, principal, input)
	case "revoke":
		result, err = handler.nodes.RevokeNode(ctx, principal, input)
	}
	if err != nil {
		handler.problem(response, requestID, err)
		return
	}
	status := http.StatusOK
	if action == "drain" {
		status = http.StatusAccepted
	}
	writeJSON(response, status, result)
}

func parseNodeResourcePath(path string) (string, string, error) {
	trimmed := strings.TrimPrefix(path, "/api/v1/nodes/")
	parts := strings.Split(trimmed, "/")
	if trimmed == path || len(parts) == 0 || len(parts) > 2 || parts[0] == "" {
		return "", "", storage.ErrNotFound
	}
	if len(parts) == 1 {
		return parts[0], "", nil
	}
	if parts[1] == "" {
		return "", "", storage.ErrNotFound
	}
	return parts[0], parts[1], nil
}

func nodeMetadataInput(input nodeMetadataRequest) adminservice.NodeMetadataInput {
	return adminservice.NodeMetadataInput{
		DisplayName: input.DisplayName, Group: input.Group, Labels: input.Labels,
	}
}
