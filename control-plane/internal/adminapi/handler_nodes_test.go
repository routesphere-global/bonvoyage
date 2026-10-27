package adminapi

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/adminservice"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
)

func TestNodeHandlerRoutesBoundedMutationsAndRequiresTerminalConfirmation(t *testing.T) {
	management := &recordingManagementService{}
	nodes := &recordingNodeManagementService{}
	principal := testPrincipal()
	principal.Role = adminservice.RoleAdministrator
	principal.SourceChannel = storage.SourceConsole
	handler, err := NewHandler(HandlerOptions{
		Service: management, NodeService: nodes,
		Authorizer: staticAuthorizer{principal: principal},
		ServerName: "admin.test", MaxConcurrent: 4,
		Random: bytes.NewReader(bytes.Repeat([]byte{0x71}, 4_096)),
	})
	if err != nil {
		t.Fatal(err)
	}

	listed := performAdminRequest(handler, http.MethodGet, "/api/v1/nodes", "", nil)
	if listed.Code != http.StatusOK || nodes.listCalls != 1 {
		t.Fatalf("list nodes = %d %s", listed.Code, listed.Body.String())
	}
	events := performAdminRequest(handler, http.MethodGet, "/api/v1/nodes/node-a/events?after_index=7&limit=25", "", nil)
	if events.Code != http.StatusOK || nodes.eventsAfterIndex != 7 || nodes.eventsLimit != 25 {
		t.Fatalf("list events = %d %s cursor=%d limit=%d", events.Code, events.Body.String(), nodes.eventsAfterIndex, nodes.eventsLimit)
	}
	invalidEvents := performAdminRequest(handler, http.MethodGet, "/api/v1/nodes/node-a/events?limit=251", "", nil)
	if invalidEvents.Code != http.StatusBadRequest {
		t.Fatalf("invalid event window = %d %s", invalidEvents.Code, invalidEvents.Body.String())
	}
	created := performAdminRequest(
		handler, http.MethodPost, "/api/v1/nodes",
		`{"node_id":"node-a","metadata":{"display_name":"Singapore A","group":"edge","labels":{"zone":"sin-a"}},"reason":"add node","ttl_seconds":600}`,
		http.Header{"Idempotency-Key": {"create-node-a-0001"}},
	)
	if created.Code != http.StatusCreated || nodes.createInput.NodeID != "node-a" ||
		nodes.createInput.Metadata.Labels["zone"] != "sin-a" || nodes.createInput.RequestID == "" {
		t.Fatalf("create node = %d %s input=%#v", created.Code, created.Body.String(), nodes.createInput)
	}
	updated := performAdminRequest(
		handler, http.MethodPatch, "/api/v1/nodes/node-a",
		`{"expected_version":2,"metadata":{"display_name":"Payments A","group":"payments","labels":{}},"reason":"change placement"}`,
		http.Header{"Idempotency-Key": {"update-node-a-0001"}},
	)
	if updated.Code != http.StatusOK || nodes.updateInput.NodeID != "node-a" ||
		nodes.updateInput.ExpectedVersion != 2 || nodes.updateInput.Metadata.Group != "payments" {
		t.Fatalf("update node = %d %s input=%#v", updated.Code, updated.Body.String(), nodes.updateInput)
	}
	drained := performAdminRequest(
		handler, http.MethodPost, "/api/v1/nodes/node-a/drain",
		`{"expected_version":3,"reason":"maintenance"}`,
		http.Header{"Idempotency-Key": {"drain-node-a-0001"}},
	)
	if drained.Code != http.StatusAccepted || nodes.drainInput.NodeID != "node-a" ||
		nodes.drainInput.ExpectedVersion != 3 {
		t.Fatalf("drain node = %d %s input=%#v", drained.Code, drained.Body.String(), nodes.drainInput)
	}
	missingConfirmation := performAdminRequest(
		handler, http.MethodPost, "/api/v1/nodes/node-a/retire",
		`{"expected_version":4,"reason":"complete retirement"}`,
		http.Header{"Idempotency-Key": {"retire-node-a-0001"}},
	)
	if missingConfirmation.Code != http.StatusConflict || nodes.retireCalls != 0 {
		t.Fatalf("unconfirmed retirement = %d %s", missingConfirmation.Code, missingConfirmation.Body.String())
	}
	retired := performAdminRequest(
		handler, http.MethodPost, "/api/v1/nodes/node-a/retire",
		`{"expected_version":4,"reason":"complete retirement"}`,
		http.Header{
			"Idempotency-Key":          {"retire-node-a-0001"},
			"X-BonVoyage-Node-Confirm": {"retire:node-a"},
		},
	)
	if retired.Code != http.StatusOK || nodes.retireCalls != 1 || nodes.retireInput.NodeID != "node-a" {
		t.Fatalf("retire node = %d %s input=%#v", retired.Code, retired.Body.String(), nodes.retireInput)
	}
	replaced := performAdminRequest(
		handler, http.MethodPost, "/api/v1/nodes/node-a/replacements",
		`{"expected_version":4,"replacement_node_id":"node-b","metadata":{"display_name":"Singapore B","group":"edge","labels":{}},"reason":"replace hardware","ttl_seconds":600}`,
		http.Header{
			"Idempotency-Key":          {"replace-node-a-0001"},
			"X-BonVoyage-Node-Confirm": {"replace:node-a"},
		},
	)
	if replaced.Code != http.StatusCreated || nodes.replaceInput.PredecessorNodeID != "node-a" ||
		nodes.replaceInput.ReplacementNodeID != "node-b" {
		t.Fatalf("replace node = %d %s input=%#v", replaced.Code, replaced.Body.String(), nodes.replaceInput)
	}
	invalidPath := performAdminRequest(handler, http.MethodGet, "/api/v1/nodes/node-a/events/extra", "", nil)
	if invalidPath.Code != http.StatusNotFound {
		t.Fatalf("invalid node path = %d %s", invalidPath.Code, invalidPath.Body.String())
	}
	missingKey := performAdminRequest(
		handler, http.MethodPost, "/api/v1/nodes", `{"node_id":"node-z"}`, nil,
	)
	if missingKey.Code != http.StatusBadRequest || !strings.Contains(missingKey.Body.String(), "INVALID_IDEMPOTENCY_KEY") {
		t.Fatalf("missing idempotency key = %d %s", missingKey.Code, missingKey.Body.String())
	}
}

type recordingNodeManagementService struct {
	listCalls        int
	retireCalls      int
	createInput      adminservice.CreateNodeInput
	updateInput      adminservice.UpdateNodeInput
	drainInput       adminservice.TransitionNodeInput
	retireInput      adminservice.TransitionNodeInput
	replaceInput     adminservice.ReplaceNodeInput
	eventsAfterIndex uint64
	eventsLimit      int
}

func (service *recordingNodeManagementService) ListNodes(
	context.Context, adminservice.Principal,
) (adminservice.NodeListResult, error) {
	service.listCalls++
	return adminservice.NodeListResult{APIVersion: adminservice.APIVersion, Nodes: []adminservice.NodeView{}}, nil
}

func (*recordingNodeManagementService) GetNode(
	context.Context, adminservice.Principal, string,
) (adminservice.NodeView, error) {
	return adminservice.NodeView{}, nil
}

func (service *recordingNodeManagementService) ListNodeEvents(
	_ context.Context, _ adminservice.Principal, _ string, afterIndex uint64, limit int,
) (adminservice.NodeEventsResult, error) {
	service.eventsAfterIndex = afterIndex
	service.eventsLimit = limit
	return adminservice.NodeEventsResult{}, nil
}

func (service *recordingNodeManagementService) CreateNode(
	_ context.Context, _ adminservice.Principal, input adminservice.CreateNodeInput,
) (adminservice.NodeEnrollmentResult, error) {
	service.createInput = input
	return adminservice.NodeEnrollmentResult{APIVersion: adminservice.APIVersion}, nil
}

func (*recordingNodeManagementService) ReissueNode(
	context.Context, adminservice.Principal, adminservice.ReissueNodeInput,
) (adminservice.NodeEnrollmentResult, error) {
	return adminservice.NodeEnrollmentResult{}, nil
}

func (service *recordingNodeManagementService) ReplaceNode(
	_ context.Context, _ adminservice.Principal, input adminservice.ReplaceNodeInput,
) (adminservice.NodeEnrollmentResult, error) {
	service.replaceInput = input
	return adminservice.NodeEnrollmentResult{APIVersion: adminservice.APIVersion}, nil
}

func (service *recordingNodeManagementService) UpdateNode(
	_ context.Context, _ adminservice.Principal, input adminservice.UpdateNodeInput,
) (adminservice.NodeMutationResult, error) {
	service.updateInput = input
	return adminservice.NodeMutationResult{APIVersion: adminservice.APIVersion}, nil
}

func (service *recordingNodeManagementService) DrainNode(
	_ context.Context, _ adminservice.Principal, input adminservice.TransitionNodeInput,
) (adminservice.NodeMutationResult, error) {
	service.drainInput = input
	return adminservice.NodeMutationResult{APIVersion: adminservice.APIVersion}, nil
}

func (service *recordingNodeManagementService) RetireNode(
	_ context.Context, _ adminservice.Principal, input adminservice.TransitionNodeInput,
) (adminservice.NodeMutationResult, error) {
	service.retireCalls++
	service.retireInput = input
	return adminservice.NodeMutationResult{APIVersion: adminservice.APIVersion}, nil
}

func (*recordingNodeManagementService) RevokeNode(
	context.Context, adminservice.Principal, adminservice.TransitionNodeInput,
) (adminservice.NodeMutationResult, error) {
	return adminservice.NodeMutationResult{}, nil
}
