package configauthoring

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreviewReaderReturnsDeterministicPostDefaultArtifactAndCounts(t *testing.T) {
	first := PreviewReader(strings.NewReader(validConfiguration), "proposal.yaml", Requirements{})
	second := PreviewReader(strings.NewReader(validConfiguration), "proposal.yaml", Requirements{})
	result := requirePreviewResult(t, first)
	validated := requireValidationResult(t, ValidateReader(
		strings.NewReader(validConfiguration), "proposal.yaml", Requirements{},
	))

	if first.Status != "accepted" || first.ExitCode != ExitAccepted ||
		first.FailureKind != "none" || len(first.Inputs) != 1 {
		t.Fatalf("unexpected response: %+v", first)
	}
	if result.Artifact != *validated.Artifact {
		t.Fatalf("preview artifact = %+v, validation artifact = %+v", result.Artifact, validated.Artifact)
	}
	wantCounts := ResourceCounts{
		Listeners: 1, VirtualHosts: 1, Routes: 1, Clusters: 1, Endpoints: 1,
	}
	if result.Counts != wantCounts || result.BaselineArtifactSHA256 != "" || len(result.Changes) != 0 {
		t.Fatalf("unexpected preview result: %+v", result)
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("machine results differ:\n%s\n%s", firstJSON, secondJSON)
	}
	if bytes.Contains(firstJSON, []byte("baseline_artifact_sha256")) {
		t.Fatalf("preview without a baseline emitted a baseline identity: %s", firstJSON)
	}
}

func TestPreviewReaderWithBaselineReportsOnlyCompiledChangePaths(t *testing.T) {
	baselinePath := writePreviewInput(t, "baseline.yaml", validConfiguration)
	proposed := strings.Replace(validConfiguration, "port: 8080", "port: 8443", 1)
	response := PreviewReaderWithBaseline(
		strings.NewReader(proposed), "proposal.yaml", baselinePath, Requirements{},
	)
	result := requirePreviewResult(t, response)
	wantChanges := []Change{{Path: "/listeners/0/port", Kind: "changed"}}
	if len(response.Inputs) != 2 || result.BaselineArtifactSHA256 == "" ||
		!changesEqual(result.Changes, wantChanges) {
		t.Fatalf("unexpected response: %+v", response)
	}
	encoded, _ := json.Marshal(response)
	if bytes.Contains(encoded, []byte("8443")) {
		t.Fatalf("preview leaked changed scalar: %s", encoded)
	}
}

func TestPreviewBaselineComparisonUsesPostDefaultSemantics(t *testing.T) {
	baselinePath := writePreviewInput(t, "baseline.yaml", validConfiguration)
	proposed := strings.Replace(
		validConfiguration,
		"    load_balancing_policy: round_robin\n",
		"    load_balancing_policy: round_robin\n    connect_timeout_ms: 1000\n",
		1,
	)
	result := requirePreviewResult(t, PreviewReaderWithBaseline(
		strings.NewReader(proposed), "proposal.yaml", baselinePath, Requirements{},
	))
	if result.BaselineArtifactSHA256 != result.Artifact.SHA256 || len(result.Changes) != 0 {
		t.Fatalf("explicit compiler default changed preview semantics: %+v", result)
	}
}

func TestPreviewIdentifiesInvalidInputWithoutEcho(t *testing.T) {
	validPath := writePreviewInput(t, "valid.yaml", validConfiguration)
	invalidPath := writePreviewInput(t, "invalid.yaml", "server:\n  private_customer_token: do-not-echo\n")
	tests := []struct {
		name       string
		response   Response
		wantPath   string
		wantSource string
	}{
		{
			name: "document",
			response: PreviewReaderWithBaseline(
				strings.NewReader("server: [\n"), "proposal.yaml", validPath, Requirements{},
			),
			wantPath: "/document", wantSource: "proposal.yaml",
		},
		{
			name: "baseline",
			response: PreviewReaderWithBaseline(
				strings.NewReader(validConfiguration), "proposal.yaml", invalidPath, Requirements{},
			),
			wantPath: "/baseline", wantSource: invalidPath,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := test.response
			if response.Status != "rejected" || response.Result != nil ||
				len(response.Inputs) != 2 || len(response.Diagnostics) < 2 ||
				response.Diagnostics[0].Code != "BV_CFG_PREVIEW_INPUT_INVALID" ||
				response.Diagnostics[0].Path != test.wantPath {
				t.Fatalf("unexpected response: %+v", response)
			}
			last := response.Diagnostics[len(response.Diagnostics)-1]
			if last.Source != nil && last.Source.SourceID != test.wantSource {
				t.Fatalf("unexpected source: %+v", last.Source)
			}
			encoded, _ := json.Marshal(response)
			if bytes.Contains(encoded, []byte("do-not-echo")) {
				t.Fatalf("preview leaked rejected scalar: %s", encoded)
			}
		})
	}
}

func TestCountResourcesHandlesNilAndMultipleResources(t *testing.T) {
	if got := countResources(nil); got != (ResourceCounts{}) {
		t.Fatalf("nil counts = %+v", got)
	}
	proposed := strings.Replace(
		validConfiguration,
		"        port: 8081\n",
		"        port: 8081\n      - name: backend-2\n        address: upstream-2\n        port: 8082\n",
		1,
	)
	result := requirePreviewResult(t, PreviewReader(
		strings.NewReader(proposed), "proposal.yaml", Requirements{},
	))
	if result.Counts.Endpoints != 2 || result.Counts.Routes != 1 {
		t.Fatalf("unexpected counts: %+v", result.Counts)
	}
}

func writePreviewInput(t *testing.T, name, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func requirePreviewResult(t *testing.T, response Response) *PreviewResult {
	t.Helper()
	result, ok := response.Result.(*PreviewResult)
	if !ok {
		t.Fatalf("result type = %T, response = %+v", response.Result, response)
	}
	return result
}
