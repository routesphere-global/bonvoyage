package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/configauthoring"
)

const commandValidConfig = `server:
  node_id: node-1
  admin_addr: 127.0.0.1:9901
  metrics_addr: 127.0.0.1:9090
snapshot:
  schema_version: 1
  snapshot_id: command-test
  generation: 1
listeners:
  - name: http
    address: 0.0.0.0
    port: 8080
    protocol: http1
    virtual_hosts: [default]
virtual_hosts:
  - name: default
    domains: ["*"]
    routes:
      - name: ready
        match:
          path_exact: /ready
        fixed_response:
          status_code: 200
clusters:
  - name: unused
    load_balancing_policy: round_robin
    endpoints:
      - name: upstream
        address: 127.0.0.1
        port: 8081
`

func TestRunValidatesExplicitStandardInput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := run(
		[]string{"validate", "--stdin", "--source-id", "test.yaml"},
		strings.NewReader(commandValidConfig), &stdout, &stderr,
	)
	if exitCode != configauthoring.ExitAccepted {
		t.Fatalf("run() exit = %d, stderr = %q", exitCode, stderr.String())
	}
	var response struct {
		Status string `json:"status"`
		Result struct {
			Valid bool `json:"valid"`
		} `json:"result"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if response.Status != "accepted" || !response.Result.Valid {
		t.Fatalf("unexpected response: %+v", response)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunRequiresOneExplicitInput(t *testing.T) {
	for _, args := range [][]string{
		{"validate"},
		{"validate", "--stdin", "--input", "config.yaml"},
		{"validate", "--stdin", "--require-configuration-schema-version", "0"},
		{"preview"},
		{"preview", "--stdin", "--input", "config.yaml"},
		{"preview", "--input", "config.yaml", "--source-id", "proposal.yaml"},
		{"format", "--stdin", "--in-place"},
		{"explain"},
		{"explain", "--stdin", "--path", "/server"},
		{"validate", "--stdin", "--path", "/server"},
		{"diff"},
		{"diff", "--baseline-stdin", "--proposed-stdin"},
		{"diff", "--baseline", "baseline.yaml", "--baseline-source-id", "baseline"},
		{"diff", "--baseline", "baseline.yaml", "--proposed", "proposed.yaml", "--proposed-source-id", "proposed"},
		{"migrate", "--stdin"},
		{"migrate", "--stdin", "--from-schema-version", "1"},
		{"migrate", "--stdin", "--from-schema-version", "0", "--to-schema-version", "1"},
		{"migrate", "--stdin", "--from-schema-version", "1", "--to-schema-version", "4294967296"},
		{"migrate", "--stdin", "--in-place", "--from-schema-version", "1", "--to-schema-version", "1"},
	} {
		var stdout, stderr bytes.Buffer
		if exitCode := run(args, strings.NewReader(commandValidConfig), &stdout, &stderr); exitCode != configauthoring.ExitInternal {
			t.Fatalf("run(%v) exit = %d, want %d", args, exitCode, configauthoring.ExitInternal)
		}
		if stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("run(%v) stdout=%q stderr=%q", args, stdout.String(), stderr.String())
		}
	}
}

func TestRunPreviewsExplicitInputWithOptionalLocalBaseline(t *testing.T) {
	directory := t.TempDir()
	baselinePath := filepath.Join(directory, "baseline.yaml")
	proposedPath := filepath.Join(directory, "proposed.yaml")
	if err := os.WriteFile(baselinePath, []byte(commandValidConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	proposed := strings.Replace(commandValidConfig, "port: 8080", "port: 8443", 1)
	if err := os.WriteFile(proposedPath, []byte(proposed), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	exitCode := run(
		[]string{"preview", "--input", proposedPath, "--baseline", baselinePath},
		strings.NewReader("ignored"), &stdout, &stderr,
	)
	if exitCode != configauthoring.ExitAccepted || stderr.Len() != 0 {
		t.Fatalf("run() exit = %d, stderr = %q", exitCode, stderr.String())
	}
	var response struct {
		Operation string `json:"operation"`
		Inputs    []any  `json:"inputs"`
		Result    struct {
			Kind     string                         `json:"kind"`
			Artifact configauthoring.Artifact       `json:"artifact"`
			Counts   configauthoring.ResourceCounts `json:"counts"`
			Changes  []configauthoring.Change       `json:"changes"`
		} `json:"result"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Operation != "preview" || len(response.Inputs) != 2 ||
		response.Result.Kind != "preview" || response.Result.Artifact.SHA256 == "" ||
		response.Result.Counts.Listeners != 1 || response.Result.Counts.Routes != 1 ||
		len(response.Result.Changes) != 1 ||
		response.Result.Changes[0].Path != "/listeners/0/port" {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestRunPreviewsExplicitStandardInputWithoutBaseline(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := run(
		[]string{"preview", "--stdin", "--source-id", "proposal.yaml"},
		strings.NewReader(commandValidConfig), &stdout, &stderr,
	)
	if exitCode != configauthoring.ExitAccepted || stderr.Len() != 0 {
		t.Fatalf("run() exit = %d, stderr = %q", exitCode, stderr.String())
	}
	var response struct {
		Status string `json:"status"`
		Inputs []any  `json:"inputs"`
		Result struct {
			Kind                   string `json:"kind"`
			BaselineArtifactSHA256 string `json:"baseline_artifact_sha256"`
		} `json:"result"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Status != "accepted" || len(response.Inputs) != 1 ||
		response.Result.Kind != "preview" || response.Result.BaselineArtifactSHA256 != "" {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestRunMigratesExplicitPathWithoutReplacingNoChangeInput(t *testing.T) {
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "configuration.yaml")
	source := "# preserve this presentation exactly\n" + commandValidConfig
	if err := os.WriteFile(inputPath, []byte(source), 0o640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(inputPath)
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	exitCode := run(
		[]string{
			"migrate", "--input", inputPath, "--in-place",
			"--from-schema-version", "1", "--to-schema-version", "1",
		},
		strings.NewReader("ignored"), &stdout, &stderr,
	)
	if exitCode != configauthoring.ExitAccepted || stderr.Len() != 0 {
		t.Fatalf("run() exit = %d, stderr = %q", exitCode, stderr.String())
	}
	var response struct {
		Operation string `json:"operation"`
		Status    string `json:"status"`
		Result    struct {
			Kind              string `json:"kind"`
			FromSchemaVersion uint32 `json:"from_schema_version"`
			ToSchemaVersion   uint32 `json:"to_schema_version"`
			Changed           bool   `json:"changed"`
			Document          string `json:"document"`
		} `json:"result"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Operation != "migrate" || response.Status != "accepted" ||
		response.Result.Kind != "migration" || response.Result.FromSchemaVersion != 1 ||
		response.Result.ToSchemaVersion != 1 || response.Result.Changed ||
		response.Result.Document != source {
		t.Fatalf("unexpected response: %+v", response)
	}
	after, err := os.Stat(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || after.Mode().Perm() != 0o640 {
		t.Fatal("no-change in-place migration replaced or modified its input")
	}
}

func TestRunMigratesExplicitStandardInputWithoutSemanticCompilation(t *testing.T) {
	source := strings.Replace(commandValidConfig, "virtual_hosts: [default]", "virtual_hosts: [missing]", 1)
	var stdout, stderr bytes.Buffer
	exitCode := run(
		[]string{
			"migrate", "--stdin", "--source-id", "legacy.yaml",
			"--from-schema-version", "1", "--to-schema-version", "1",
		},
		strings.NewReader(source), &stdout, &stderr,
	)
	if exitCode != configauthoring.ExitAccepted || stderr.Len() != 0 {
		t.Fatalf("run() exit = %d, stderr = %q", exitCode, stderr.String())
	}
	var response struct {
		Status string `json:"status"`
		Result struct {
			Changed  bool   `json:"changed"`
			Document string `json:"document"`
		} `json:"result"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Status != "accepted" || response.Result.Changed || response.Result.Document != source {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestRunMigrationRefusesUnshippedPair(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := run(
		[]string{
			"migrate", "--stdin", "--source-id", "legacy.yaml",
			"--from-schema-version", "1", "--to-schema-version", "2",
		},
		strings.NewReader(commandValidConfig), &stdout, &stderr,
	)
	if exitCode != configauthoring.ExitRefused || stderr.Len() != 0 {
		t.Fatalf("run() exit = %d, stderr = %q", exitCode, stderr.String())
	}
	var response struct {
		Status      string `json:"status"`
		FailureKind string `json:"failure_kind"`
		Diagnostics []struct {
			Code string `json:"code"`
		} `json:"diagnostics"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Status != "refused" || response.FailureKind != "compatibility" ||
		len(response.Diagnostics) != 1 ||
		response.Diagnostics[0].Code != "BV_CFG_MIGRATION_UNSUPPORTED" {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestRunDiffsTwoExplicitPaths(t *testing.T) {
	directory := t.TempDir()
	baselinePath := filepath.Join(directory, "baseline.yaml")
	proposedPath := filepath.Join(directory, "proposed.yaml")
	if err := os.WriteFile(baselinePath, []byte(commandValidConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	proposed := strings.Replace(commandValidConfig, "port: 8080", "port: 8443", 1)
	if err := os.WriteFile(proposedPath, []byte(proposed), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	exitCode := run(
		[]string{"diff", "--baseline", baselinePath, "--proposed", proposedPath},
		strings.NewReader("ignored"), &stdout, &stderr,
	)
	if exitCode != configauthoring.ExitAccepted || stderr.Len() != 0 {
		t.Fatalf("run() exit = %d, stderr = %q", exitCode, stderr.String())
	}
	var response struct {
		Operation string `json:"operation"`
		Inputs    []any  `json:"inputs"`
		Result    struct {
			Kind    string `json:"kind"`
			Changes []struct {
				Path string `json:"path"`
				Kind string `json:"kind"`
			} `json:"changes"`
		} `json:"result"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Operation != "diff" || len(response.Inputs) != 2 ||
		response.Result.Kind != "semantic-diff" || len(response.Result.Changes) != 1 ||
		response.Result.Changes[0].Path != "/listeners/0/port" ||
		response.Result.Changes[0].Kind != "changed" {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestRunDiffAcceptsExactlyOneStandardInputSide(t *testing.T) {
	directory := t.TempDir()
	baselinePath := filepath.Join(directory, "baseline.yaml")
	proposedPath := filepath.Join(directory, "proposed.yaml")
	if err := os.WriteFile(baselinePath, []byte(commandValidConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	proposed := strings.Replace(commandValidConfig, "generation: 1", "generation: 2", 1)
	if err := os.WriteFile(proposedPath, []byte(proposed), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name  string
		args  []string
		stdin string
	}{
		{
			name: "baseline",
			args: []string{
				"diff", "--baseline-stdin", "--baseline-source-id", "baseline-stdin.yaml",
				"--proposed", proposedPath,
			},
			stdin: commandValidConfig,
		},
		{
			name: "proposed",
			args: []string{
				"diff", "--baseline", baselinePath,
				"--proposed-stdin", "--proposed-source-id", "proposed-stdin.yaml",
			},
			stdin: proposed,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			exitCode := run(test.args, strings.NewReader(test.stdin), &stdout, &stderr)
			if exitCode != configauthoring.ExitAccepted || stderr.Len() != 0 {
				t.Fatalf("run() exit = %d, stderr = %q", exitCode, stderr.String())
			}
			var response struct {
				Status string `json:"status"`
				Result struct {
					Changes []struct {
						Path string `json:"path"`
					} `json:"changes"`
				} `json:"result"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response.Status != "accepted" || len(response.Result.Changes) != 1 ||
				response.Result.Changes[0].Path != "/generation" {
				t.Fatalf("unexpected response: %+v", response)
			}
		})
	}
}

func TestRunExplainsStaticFieldWithoutDocumentInput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := run(
		[]string{"explain", "--path", "/listeners/0/port"},
		strings.NewReader("ignored"), &stdout, &stderr,
	)
	if exitCode != configauthoring.ExitAccepted {
		t.Fatalf("run() exit = %d, stderr = %q", exitCode, stderr.String())
	}
	var response struct {
		Operation string `json:"operation"`
		Inputs    []any  `json:"inputs"`
		Result    struct {
			Kind string `json:"kind"`
			Path string `json:"path"`
		} `json:"result"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Operation != "explain" || len(response.Inputs) != 0 ||
		response.Result.Kind != "field-explanation" || response.Result.Path != "/listeners/0/port" {
		t.Fatalf("unexpected response: %+v", response)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}
