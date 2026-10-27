package configauthoring

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	bonvoyagev1 "github.com/routesphere-global/bonvoyage/api/gen/go/bonvoyage/v1"
)

func TestDiffReadersIgnoresSourceOnlyPresentationChanges(t *testing.T) {
	proposed := strings.Replace(
		"# reviewed proposal\n"+validConfiguration,
		"    virtual_hosts: [default]",
		"    virtual_hosts:\n      - default",
		1,
	)
	response := DiffReaders(
		strings.NewReader(validConfiguration), "baseline.yaml",
		strings.NewReader(proposed), "proposed.yaml",
		Requirements{},
	)
	result := requireDiffResult(t, response)
	if response.Status != "accepted" || response.ExitCode != ExitAccepted ||
		response.FailureKind != "none" || len(response.Inputs) != 2 {
		t.Fatalf("unexpected response: %+v", response)
	}
	if len(result.Changes) != 0 {
		t.Fatalf("presentation-only diff = %+v, want none", result.Changes)
	}
	if result.BaselineArtifactSHA256 != result.ProposedArtifactSHA256 {
		t.Fatalf("artifact identities differ: %+v", result)
	}
	if response.Inputs[0].SHA256 == response.Inputs[1].SHA256 {
		t.Fatal("source identities should retain the presentation difference")
	}
}

func TestDiffReadersIgnoresExplicitCompilerDefault(t *testing.T) {
	proposed := strings.Replace(
		validConfiguration,
		"    load_balancing_policy: round_robin\n",
		"    load_balancing_policy: round_robin\n    connect_timeout_ms: 1000\n",
		1,
	)
	result := requireDiffResult(t, DiffReaders(
		strings.NewReader(validConfiguration), "baseline.yaml",
		strings.NewReader(proposed), "proposed.yaml",
		Requirements{},
	))
	if len(result.Changes) != 0 || result.BaselineArtifactSHA256 != result.ProposedArtifactSHA256 {
		t.Fatalf("explicit compiler default changed semantics: %+v", result)
	}
}

func TestDiffReadersReportsCompiledPathsWithoutValues(t *testing.T) {
	proposed := strings.Replace(validConfiguration, "port: 8080", "port: 8443", 1)
	response := DiffReaders(
		strings.NewReader(validConfiguration), "baseline.yaml",
		strings.NewReader(proposed), "proposed.yaml",
		Requirements{},
	)
	result := requireDiffResult(t, response)
	want := []Change{{Path: "/listeners/0/port", Kind: "changed"}}
	if !changesEqual(result.Changes, want) {
		t.Fatalf("changes = %+v, want %+v", result.Changes, want)
	}
	encoded, _ := json.Marshal(response)
	if bytes.Contains(encoded, []byte("8443")) {
		t.Fatalf("diff leaked changed scalar: %s", encoded)
	}
}

func TestDiffReadersReportsIndexedResourceAddition(t *testing.T) {
	proposed := strings.Replace(
		validConfiguration,
		"        port: 8081\n",
		"        port: 8081\n      - name: backend-2\n        address: upstream-2\n        port: 8082\n",
		1,
	)
	result := requireDiffResult(t, DiffReaders(
		strings.NewReader(validConfiguration), "baseline.yaml",
		strings.NewReader(proposed), "proposed.yaml",
		Requirements{},
	))
	want := []Change{{Path: "/clusters/0/endpoints/1", Kind: "added"}}
	if !changesEqual(result.Changes, want) {
		t.Fatalf("changes = %+v, want %+v", result.Changes, want)
	}
}

func TestDiffReadersReportsExclusiveActionReplacement(t *testing.T) {
	proposed := strings.Replace(
		validConfiguration,
		"        cluster: backend",
		"        fixed_response:\n          status_code: 204",
		1,
	)
	result := requireDiffResult(t, DiffReaders(
		strings.NewReader(validConfiguration), "baseline.yaml",
		strings.NewReader(proposed), "proposed.yaml",
		Requirements{},
	))
	want := []Change{
		{Path: "/virtual_hosts/0/routes/0/cluster", Kind: "changed"},
		{Path: "/virtual_hosts/0/routes/0/fixed_response", Kind: "added"},
	}
	if !changesEqual(result.Changes, want) {
		t.Fatalf("changes = %+v, want %+v", result.Changes, want)
	}
}

func TestDiffReadersReportsOneofBranchReplacement(t *testing.T) {
	proposed := strings.Replace(
		validConfiguration,
		"          path_prefix: /api",
		"          path_exact: /api",
		1,
	)
	result := requireDiffResult(t, DiffReaders(
		strings.NewReader(validConfiguration), "baseline.yaml",
		strings.NewReader(proposed), "proposed.yaml",
		Requirements{},
	))
	want := []Change{
		{Path: "/virtual_hosts/0/routes/0/match/path_exact", Kind: "added"},
		{Path: "/virtual_hosts/0/routes/0/match/path_prefix", Kind: "removed"},
	}
	if !changesEqual(result.Changes, want) {
		t.Fatalf("changes = %+v, want %+v", result.Changes, want)
	}
}

func TestDiffReadersDoesNotExposeSecretReferences(t *testing.T) {
	baselineSecret := "tenant-a-private-key.pem"
	proposedSecret := "tenant-b-private-key.pem"
	withTLS := func(secret string) string {
		return strings.Replace(
			validConfiguration,
			"    virtual_hosts: [default]\n",
			"    virtual_hosts: [default]\n    downstream_tls:\n      certificate_chain_secret: server-chain.pem\n      private_key_secret: "+secret+"\n",
			1,
		)
	}
	response := DiffReaders(
		strings.NewReader(withTLS(baselineSecret)), "baseline.yaml",
		strings.NewReader(withTLS(proposedSecret)), "proposed.yaml",
		Requirements{},
	)
	result := requireDiffResult(t, response)
	want := []Change{{Path: "/listeners/0/downstream_tls/private_key_secret", Kind: "changed"}}
	if !changesEqual(result.Changes, want) {
		t.Fatalf("changes = %+v, want %+v", result.Changes, want)
	}
	encoded, _ := json.Marshal(response)
	for _, secret := range []string{baselineSecret, proposedSecret} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatalf("diff leaked secret reference %q: %s", secret, encoded)
		}
	}
}

func TestDiffReadersIgnoresNodeLocalServerChanges(t *testing.T) {
	proposed := strings.Replace(validConfiguration, "node_id: node-1", "node_id: node-2", 1)
	response := DiffReaders(
		strings.NewReader(validConfiguration), "baseline.yaml",
		strings.NewReader(proposed), "proposed.yaml",
		Requirements{},
	)
	result := requireDiffResult(t, response)
	if len(result.Changes) != 0 || result.BaselineArtifactSHA256 != result.ProposedArtifactSHA256 {
		t.Fatalf("node-local server metadata changed dataplane semantics: %+v", result)
	}
}

func TestDiffReadersIdentifiesInvalidSideAndRetainsBothInputs(t *testing.T) {
	for _, test := range []struct {
		name       string
		baseline   string
		proposed   string
		wantPath   string
		wantSource string
	}{
		{"baseline", "server: [\n", validConfiguration, "/baseline", "baseline.yaml"},
		{"proposed", validConfiguration, "server: [\n", "/proposed", "proposed.yaml"},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := DiffReaders(
				strings.NewReader(test.baseline), "baseline.yaml",
				strings.NewReader(test.proposed), "proposed.yaml",
				Requirements{},
			)
			if response.Status != "rejected" || response.ExitCode != ExitRejected ||
				response.Result != nil || len(response.Inputs) != 2 || len(response.Diagnostics) != 2 {
				t.Fatalf("unexpected response: %+v", response)
			}
			if response.Diagnostics[0].Code != "BV_CFG_DIFF_INPUT_INVALID" ||
				response.Diagnostics[0].Path != test.wantPath ||
				response.Diagnostics[1].Code != "BV_CFG_YAML_SYNTAX" {
				t.Fatalf("unexpected diagnostics: %+v", response.Diagnostics)
			}
			if response.Diagnostics[1].Source == nil ||
				response.Diagnostics[1].Source.SourceID != test.wantSource {
				t.Fatalf("unexpected source: %+v", response.Diagnostics[1].Source)
			}
		})
	}
}

func TestDiffReadersRefusesVersionMismatch(t *testing.T) {
	response := DiffReaders(
		strings.NewReader(validConfiguration), "baseline.yaml",
		strings.NewReader(validConfiguration), "proposed.yaml",
		Requirements{ProductVersion: "9.9.9"},
	)
	if response.Status != "refused" || response.ExitCode != ExitRefused ||
		response.Result != nil || len(response.Inputs) != 2 ||
		len(response.Diagnostics) != 2 ||
		response.Diagnostics[0].Code != "BV_CFG_DIFF_INPUT_INVALID" ||
		response.Diagnostics[0].Path != "/baseline" ||
		response.Diagnostics[1].Code != "BV_CFG_VERSION_MISMATCH" {
		t.Fatalf("unexpected refusal: %+v", response)
	}
}

func TestSemanticChangesFailClosedAtOutputLimit(t *testing.T) {
	baseline := &bonvoyagev1.Snapshot{}
	bounded := &bonvoyagev1.Snapshot{Listeners: make([]*bonvoyagev1.Listener, maxDiffChanges)}
	for index := range bounded.Listeners {
		bounded.Listeners[index] = &bonvoyagev1.Listener{}
	}
	changes, err := semanticChanges(baseline, bounded)
	if err != nil || len(changes) != maxDiffChanges {
		t.Fatalf("bounded semanticChanges() = %d changes, %v", len(changes), err)
	}

	proposed := &bonvoyagev1.Snapshot{Listeners: make([]*bonvoyagev1.Listener, maxDiffChanges+1)}
	for index := range proposed.Listeners {
		proposed.Listeners[index] = &bonvoyagev1.Listener{}
	}
	_, err = semanticChanges(baseline, proposed)
	if !errors.Is(err, errDiffOutputLimit) {
		t.Fatalf("semanticChanges() error = %v, want output limit", err)
	}
	collector := diffCollector{}
	if err := collector.add("/"+strings.Repeat("x", maxDiffPathLen), "changed"); !errors.Is(err, errDiffOutputLimit) {
		t.Fatalf("oversized path error = %v, want output limit", err)
	}
}

func TestSemanticChangesSortsDeterministically(t *testing.T) {
	baseline := &bonvoyagev1.Snapshot{
		SnapshotId: "baseline", Generation: 1,
		Listeners: []*bonvoyagev1.Listener{{Port: 8080}},
	}
	proposed := &bonvoyagev1.Snapshot{
		SnapshotId: "proposed", Generation: 2,
		Listeners: []*bonvoyagev1.Listener{{Port: 8443}},
	}
	changes, err := semanticChanges(baseline, proposed)
	if err != nil {
		t.Fatal(err)
	}
	want := []Change{
		{Path: "/generation", Kind: "changed"},
		{Path: "/listeners/0/port", Kind: "changed"},
		{Path: "/snapshot_id", Kind: "changed"},
	}
	if !changesEqual(changes, want) {
		t.Fatalf("changes = %+v, want %+v", changes, want)
	}
}

func TestSemanticChangesUsesPublicConfigurationFieldNames(t *testing.T) {
	baseline := &bonvoyagev1.Snapshot{
		Listeners: []*bonvoyagev1.Listener{{VirtualHostNames: []string{"baseline"}}},
		VirtualHosts: []*bonvoyagev1.VirtualHost{{Routes: []*bonvoyagev1.Route{{
			ClusterName:      "baseline",
			WeightedClusters: []*bonvoyagev1.WeightedCluster{{ClusterName: "baseline"}},
		}}}},
	}
	proposed := &bonvoyagev1.Snapshot{
		Listeners: []*bonvoyagev1.Listener{{VirtualHostNames: []string{"proposed"}}},
		VirtualHosts: []*bonvoyagev1.VirtualHost{{Routes: []*bonvoyagev1.Route{{
			ClusterName:      "proposed",
			WeightedClusters: []*bonvoyagev1.WeightedCluster{{ClusterName: "proposed"}},
		}}}},
	}
	changes, err := semanticChanges(baseline, proposed)
	if err != nil {
		t.Fatal(err)
	}
	want := []Change{
		{Path: "/listeners/0/virtual_hosts/0", Kind: "changed"},
		{Path: "/virtual_hosts/0/routes/0/cluster", Kind: "changed"},
		{Path: "/virtual_hosts/0/routes/0/weighted_clusters/0/cluster", Kind: "changed"},
	}
	if !changesEqual(changes, want) {
		t.Fatalf("changes = %+v, want %+v", changes, want)
	}
}

func requireDiffResult(t *testing.T, response Response) *DiffResult {
	t.Helper()
	result, ok := response.Result.(*DiffResult)
	if !ok || result == nil {
		t.Fatalf("diff result has unexpected type: %#v; response=%+v", response.Result, response)
	}
	return result
}

func changesEqual(left, right []Change) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
