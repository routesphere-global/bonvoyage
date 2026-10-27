package configauthoring

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/snapshot"
)

const validConfiguration = `server:
  node_id: node-1
  admin_addr: 127.0.0.1:9901
  metrics_addr: 127.0.0.1:9090
snapshot:
  schema_version: 1
  snapshot_id: authoring-test
  generation: 7
  minimum_dataplane_version: 0.2.0
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
      - name: api
        match:
          path_prefix: /api
        cluster: backend
clusters:
  - name: backend
    load_balancing_policy: round_robin
    endpoints:
      - name: backend-1
        address: upstream
        port: 8081
`

func TestValidateReaderAcceptsDeterministicArtifact(t *testing.T) {
	first := ValidateReader(strings.NewReader(validConfiguration), "bonvoyage.yaml", Requirements{})
	second := ValidateReader(strings.NewReader(validConfiguration), "bonvoyage.yaml", Requirements{})
	if first.Status != "accepted" || first.ExitCode != ExitAccepted || first.FailureKind != "none" {
		t.Fatalf("unexpected status: %+v", first)
	}
	result := requireValidationResult(t, first)
	if !result.Valid || result.Artifact == nil {
		t.Fatalf("accepted result is incomplete: %+v", result)
	}
	if result.Artifact.SnapshotID != "authoring-test" ||
		result.Artifact.SchemaVersion != 1 ||
		result.Artifact.MinimumDataplaneVersion != "0.2.0" {
		t.Fatalf("unexpected artifact: %+v", result.Artifact)
	}
	if first.Versions.CompilerVersion != snapshot.CompilerVersion ||
		first.Versions.InputConfigurationSchemaVersion == nil ||
		*first.Versions.InputConfigurationSchemaVersion != 1 {
		t.Fatalf("unexpected versions: %+v", first.Versions)
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("machine results differ:\n%s\n%s", firstJSON, secondJSON)
	}
	inputDigest := sha256.Sum256([]byte(validConfiguration))
	if first.Inputs[0].SHA256 != fmt.Sprintf("%x", inputDigest) ||
		first.Inputs[0].Bytes != len(validConfiguration) {
		t.Fatalf("unexpected input identity: %+v", first.Inputs[0])
	}
}

func TestValidateReaderClassifiesCompilerFailuresWithoutEcho(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		code       string
		path       string
		forbidden  string
		wantSource bool
	}{
		{
			name:  "missing schema version",
			input: strings.Replace(validConfiguration, "  schema_version: 1\n", "", 1),
			code:  "BV_CFG_SCHEMA_VERSION_REQUIRED", path: "/snapshot/schema_version",
		},
		{
			name:  "unsupported schema version",
			input: strings.Replace(validConfiguration, "schema_version: 1", "schema_version: 99", 1),
			code:  "BV_CFG_SCHEMA_VERSION_UNSUPPORTED", path: "/snapshot/schema_version", wantSource: true,
		},
		{
			name:  "missing reference",
			input: strings.Replace(validConfiguration, "cluster: backend", "cluster: private-customer-upstream", 1),
			code:  "BV_CFG_REFERENCE_MISSING", path: "/virtual_hosts/0/routes/0/cluster",
			forbidden: "private-customer-upstream", wantSource: true,
		},
		{
			name:  "unknown field",
			input: strings.Replace(validConfiguration, "  node_id: node-1", "  private_token: top-secret-value\n  node_id: node-1", 1),
			code:  "BV_CFG_SCHEMA_UNKNOWN_FIELD", forbidden: "top-secret-value", wantSource: true,
		},
		{
			name:  "wrong type",
			input: strings.Replace(validConfiguration, "port: 8080", "port: [secret-value]", 1),
			code:  "BV_CFG_SCHEMA_TYPE", forbidden: "secret-value", wantSource: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := ValidateReader(strings.NewReader(test.input), "test.yaml", Requirements{})
			assertRejected(t, response, test.code)
			diagnostic := response.Diagnostics[0]
			if diagnostic.Path != test.path {
				t.Fatalf("path = %q, want %q", diagnostic.Path, test.path)
			}
			if test.wantSource && diagnostic.Source == nil {
				t.Fatal("expected a proven source location")
			}
			encoded, _ := json.Marshal(response)
			if test.forbidden != "" && bytes.Contains(encoded, []byte(test.forbidden)) {
				t.Fatalf("result leaked source scalar %q: %s", test.forbidden, encoded)
			}
		})
	}
}

func TestValidateReaderRejectsYAMLSafetyCases(t *testing.T) {
	alias := `server: &server
  node_id: node-1
snapshot:
  schema_version: 1
copy: *server
`
	multiple := validConfiguration + "\n---\nserver: {}\n"
	for _, test := range []struct {
		name  string
		input string
		code  string
	}{
		{"empty", " \n\t", "BV_CFG_YAML_EMPTY"},
		{"syntax", "server: [\n", "BV_CFG_YAML_SYNTAX"},
		{"alias", alias, "BV_CFG_YAML_ALIAS_UNSUPPORTED"},
		{"multiple", multiple, "BV_CFG_YAML_MULTIPLE_DOCUMENTS"},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertRejected(t, ValidateReader(strings.NewReader(test.input), "test.yaml", Requirements{}), test.code)
		})
	}
}

func TestValidateReaderAppliesCompilerStructuralLimitBeforeLocationIndex(t *testing.T) {
	var input strings.Builder
	input.WriteString("server:\n")
	for depth := 0; depth < 70; depth++ {
		input.WriteString(strings.Repeat("  ", depth+1))
		input.WriteString("nested:\n")
	}
	assertRejected(
		t,
		ValidateReader(strings.NewReader(input.String()), "deep.yaml", Requirements{}),
		"BV_CFG_YAML_LIMIT_EXCEEDED",
	)
}

func TestValidateReaderRejectsInvalidUTF8AndBoundsObservation(t *testing.T) {
	invalid := ValidateReader(bytes.NewReader([]byte{0xff, 0xfe}), "invalid.yaml", Requirements{})
	assertRejected(t, invalid, "BV_CFG_INPUT_ENCODING")

	oversizedData := bytes.Repeat([]byte("x"), int(snapshot.MaxConfigBytes)+1)
	oversized := ValidateReader(bytes.NewReader(oversizedData), "large.yaml", Requirements{})
	assertRejected(t, oversized, "BV_CFG_INPUT_TOO_LARGE")
	if oversized.Inputs[0].Bytes != int(snapshot.MaxConfigBytes) {
		t.Fatalf("observed bytes = %d, want %d", oversized.Inputs[0].Bytes, snapshot.MaxConfigBytes)
	}
	digest := sha256.Sum256(oversizedData[:snapshot.MaxConfigBytes])
	if oversized.Inputs[0].SHA256 != fmt.Sprintf("%x", digest) {
		t.Fatalf("bounded observation digest = %s, want %x", oversized.Inputs[0].SHA256, digest)
	}
}

func TestValidateReaderReportsPartialReadWithoutSourceEcho(t *testing.T) {
	reader := &failingReader{data: []byte("private-prefix"), err: errors.New("sensitive storage detail")}
	response := ValidateReader(reader, "broken.yaml", Requirements{})
	if response.Status != "failed" || response.ExitCode != ExitInputOutput || response.FailureKind != "io" {
		t.Fatalf("unexpected response: %+v", response)
	}
	if response.Diagnostics[0].Code != "BV_CFG_INPUT_UNREADABLE" ||
		strings.Contains(response.Diagnostics[0].Message, "sensitive") {
		t.Fatalf("unsafe diagnostic: %+v", response.Diagnostics[0])
	}
}

func TestValidateReaderRefusesExactVersionMismatch(t *testing.T) {
	requiredSchema := uint32(2)
	for _, requirements := range []Requirements{
		{ProductVersion: "9.9.9"},
		{CompilerVersion: "different-compiler"},
		{ConfigurationSchemaVersion: &requiredSchema},
	} {
		response := ValidateReader(strings.NewReader(validConfiguration), "test.yaml", requirements)
		if response.Status != "refused" || response.ExitCode != ExitRefused ||
			response.FailureKind != "compatibility" || response.Result != nil ||
			response.Diagnostics[0].Code != "BV_CFG_VERSION_MISMATCH" {
			t.Fatalf("unexpected refusal: %+v", response)
		}
	}
}

func TestValidatePathResolvesReadOnlySymlinkAndRejectsOtherInputs(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.yaml")
	if err := os.WriteFile(target, []byte(validConfiguration), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "projected.YML")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if response := ValidatePath(link, Requirements{}); response.Status != "accepted" {
		t.Fatalf("symlink validation failed: %+v", response)
	}
	assertRejected(t, ValidatePath(filepath.Join(directory, "config.txt"), Requirements{}), "BV_CFG_FILE_TYPE_UNSUPPORTED")
	notRegular := ValidatePath(directory+".yaml", Requirements{})
	if notRegular.Status != "failed" || notRegular.Diagnostics[0].Code != "BV_CFG_INPUT_UNREADABLE" {
		// The suffixed path does not exist, so this is intentionally an unreadable input.
		t.Fatalf("unexpected missing input response: %+v", notRegular)
	}
	directoryPath := filepath.Join(directory, "directory.yaml")
	if err := os.Mkdir(directoryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	notRegular = ValidatePath(directoryPath, Requirements{})
	if notRegular.Status != "failed" || notRegular.Diagnostics[0].Code != "BV_CFG_INPUT_NOT_REGULAR" {
		t.Fatalf("unexpected non-regular response: %+v", notRegular)
	}
}

func TestValidateReaderRejectsPEMWithoutEcho(t *testing.T) {
	pemBegin := "-----BEGIN " + "PRIVATE KEY-----"
	pemBody := "private-key-" + "material"
	pemEnd := "-----END " + "PRIVATE KEY-----"
	input := strings.Replace(
		validConfiguration,
		"        cluster: backend\n",
		fmt.Sprintf(
			"        cluster: backend\n        api_key_auth:\n          credentials_secret: |\n            %s\n            %s\n            %s\n",
			pemBegin,
			pemBody,
			pemEnd,
		),
		1,
	)
	response := ValidateReader(strings.NewReader(input), "secret.yaml", Requirements{})
	assertRejected(t, response, "BV_CFG_SECRET_LITERAL_FORBIDDEN")
	encoded, _ := json.Marshal(response)
	for _, forbidden := range []string{pemBegin, pemBody, pemEnd} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("result leaked PEM content %q: %s", forbidden, encoded)
		}
	}
}

func TestCompilerPathUsesRFC6901(t *testing.T) {
	for input, want := range map[string]string{
		"listeners[2].virtual_hosts[7]: failure":               "/listeners/2/virtual_hosts/7",
		"virtual_hosts[0].routes[1].match.path_exact: failure": "/virtual_hosts/0/routes/1/match/path_exact",
		"parse YAML: failure":                                  "",
		"private_customer_value: failure":                      "",
	} {
		if got := compilerPath(input); got != want {
			t.Fatalf("compilerPath(%q) = %q, want %q", input, got, want)
		}
	}
}

func assertRejected(t *testing.T, response Response, code string) {
	t.Helper()
	result := requireValidationResult(t, response)
	if response.Status != "rejected" || response.ExitCode != ExitRejected ||
		response.FailureKind != "validation" || result.Valid || result.Artifact != nil ||
		len(response.Diagnostics) != 1 || response.Diagnostics[0].Code != code {
		t.Fatalf("unexpected rejection for %s: %+v", code, response)
	}
}

func requireValidationResult(t *testing.T, response Response) *ValidationResult {
	t.Helper()
	result, ok := response.Result.(*ValidationResult)
	if !ok || result == nil {
		t.Fatalf("validation result has unexpected type: %#v", response.Result)
	}
	return result
}

type failingReader struct {
	data []byte
	err  error
	done bool
}

func (reader *failingReader) Read(destination []byte) (int, error) {
	if reader.done {
		return 0, reader.err
	}
	reader.done = true
	return copy(destination, reader.data), reader.err
}
