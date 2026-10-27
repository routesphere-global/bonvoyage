package configauthoring

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrateReaderPreservesNoChangeDocumentExactly(t *testing.T) {
	source := strings.Replace(validConfiguration, "cluster: backend", "cluster: missing", 1)
	source = strings.Replace(source, "server:\n", "# migration intent\nserver:\n", 1)
	source = strings.ReplaceAll(source, "\n", "\r\n")
	input := append(append([]byte(nil), utf8BOM...), []byte(source)...)

	first := MigrateReader(bytes.NewReader(input), "legacy.yaml", 1, 1, Requirements{})
	second := MigrateReader(bytes.NewReader(input), "legacy.yaml", 1, 1, Requirements{})
	result := requireMigrationResult(t, first)
	if first.Status != "accepted" || first.ExitCode != ExitAccepted ||
		first.FailureKind != "none" || result.Changed ||
		result.FromSchemaVersion != 1 || result.ToSchemaVersion != 1 ||
		!bytes.Equal([]byte(result.Document), input) {
		t.Fatalf("unexpected migration response: %+v", first)
	}
	if first.Versions.InputConfigurationSchemaVersion == nil ||
		*first.Versions.InputConfigurationSchemaVersion != 1 {
		t.Fatalf("unexpected input version: %+v", first.Versions)
	}
	digest := sha256.Sum256(input)
	if result.DocumentSHA256 != fmt.Sprintf("%x", digest) ||
		result.DocumentSHA256 != first.Inputs[0].SHA256 {
		t.Fatalf("unexpected document identity: result=%s input=%+v", result.DocumentSHA256, first.Inputs[0])
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("migration result is not deterministic:\n%s\n%s", firstJSON, secondJSON)
	}
}

func TestMigrateReaderRefusesUnshippedPairsAndVersionMismatch(t *testing.T) {
	tests := []struct {
		name  string
		input string
		from  uint32
		to    uint32
		code  string
		path  string
	}{
		{name: "target unsupported", input: validConfiguration, from: 1, to: 2, code: "BV_CFG_MIGRATION_UNSUPPORTED"},
		{name: "declared source mismatch", input: validConfiguration, from: 2, to: 1, code: "BV_CFG_VERSION_MISMATCH", path: "/snapshot/schema_version"},
		{
			name:  "source pair unsupported",
			input: strings.Replace(validConfiguration, "schema_version: 1", "schema_version: 2", 1),
			from:  2, to: 1, code: "BV_CFG_MIGRATION_UNSUPPORTED",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := MigrateReader(strings.NewReader(test.input), "input.yaml", test.from, test.to, Requirements{})
			if response.Status != "refused" || response.ExitCode != ExitRefused ||
				response.FailureKind != "compatibility" || response.Result != nil ||
				len(response.Diagnostics) != 1 || response.Diagnostics[0].Code != test.code ||
				response.Diagnostics[0].Path != test.path {
				t.Fatalf("unexpected refusal: %+v", response)
			}
		})
	}
}

func TestMigrateReaderRejectsUnsafeInputWithoutEcho(t *testing.T) {
	missingVersion := strings.Replace(validConfiguration, "  schema_version: 1\n", "", 1)
	zeroVersion := strings.Replace(validConfiguration, "schema_version: 1", "schema_version: 0", 1)
	alias := strings.Replace(validConfiguration, "domains: [\"*\"]", "domains: &domains [\"*\"]", 1) +
		"alias: *domains\n"
	for name, test := range map[string]struct {
		input string
		code  string
	}{
		"syntax":          {input: "server: [", code: "BV_CFG_YAML_SYNTAX"},
		"multiple":        {input: validConfiguration + "---\n{}\n", code: "BV_CFG_YAML_MULTIPLE_DOCUMENTS"},
		"alias":           {input: alias, code: "BV_CFG_YAML_ALIAS_UNSUPPORTED"},
		"missing version": {input: missingVersion, code: "BV_CFG_SCHEMA_VERSION_REQUIRED"},
		"zero version":    {input: zeroVersion, code: "BV_CFG_SCHEMA_VERSION_UNSUPPORTED"},
	} {
		t.Run(name, func(t *testing.T) {
			response := MigrateReader(strings.NewReader(test.input), name+".yaml", 1, 1, Requirements{})
			if response.Status != "rejected" || response.Result != nil ||
				len(response.Diagnostics) != 1 || response.Diagnostics[0].Code != test.code {
				t.Fatalf("unexpected rejection: %+v", response)
			}
		})
	}

	begin := strings.Join([]string{"-----", "BEGIN ", "PRIVATE KEY", "-----"}, "")
	end := strings.Join([]string{"-----", "END ", "PRIVATE KEY", "-----"}, "")
	secret := begin + "\nprivate-material-must-not-echo\n" + end
	input := strings.Replace(
		validConfiguration,
		"    virtual_hosts: [default]\n",
		"    virtual_hosts: [default]\n    downstream_tls:\n      certificate_chain_secret: server-chain.pem\n      private_key_secret: |\n        "+strings.ReplaceAll(secret, "\n", "\n        ")+"\n",
		1,
	)
	response := MigrateReader(strings.NewReader(input), "secret.yaml", 1, 1, Requirements{})
	encoded, _ := json.Marshal(response)
	if response.Status != "rejected" || response.Result != nil ||
		len(response.Diagnostics) != 1 ||
		response.Diagnostics[0].Code != "BV_CFG_SECRET_LITERAL_FORBIDDEN" ||
		response.Diagnostics[0].Path != "/listeners/0/downstream_tls/private_key_secret" ||
		!response.Diagnostics[0].Redacted || bytes.Contains(encoded, []byte("private-material-must-not-echo")) {
		t.Fatalf("unexpected secret rejection: %s", encoded)
	}
}

func TestMigrateReaderRefusesExactInstalledVersionMismatch(t *testing.T) {
	schemaVersion := uint32(2)
	for _, requirements := range []Requirements{
		{ProductVersion: "9.9.9"},
		{CompilerVersion: "different-compiler"},
		{ConfigurationSchemaVersion: &schemaVersion},
	} {
		response := MigrateReader(strings.NewReader(validConfiguration), "input.yaml", 1, 1, requirements)
		if response.Status != "refused" || response.Result != nil ||
			len(response.Diagnostics) != 1 || response.Diagnostics[0].Code != "BV_CFG_VERSION_MISMATCH" {
			t.Fatalf("unexpected version refusal: %+v", response)
		}
	}
}

func TestMigratePathIsNonMutatingAndRejectsInPlaceSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.yaml")
	if err := os.WriteFile(target, []byte(validConfiguration), 0o640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	response := MigratePath(target, 1, 1, Requirements{}, true)
	result := requireMigrationResult(t, response)
	after, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed || !os.SameFile(before, after) || after.Mode().Perm() != 0o640 {
		t.Fatal("no-change in-place migration replaced or modified its source")
	}

	link := filepath.Join(directory, "projected.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if response := MigratePath(link, 1, 1, Requirements{}, false); response.Status != "accepted" {
		t.Fatalf("read-only migration rejected a regular-file symlink: %+v", response)
	}
	response = MigratePath(link, 1, 1, Requirements{}, true)
	if response.Status != "rejected" || response.Result != nil ||
		len(response.Diagnostics) != 1 || response.Diagnostics[0].Code != "BV_CFG_INPUT_SYMLINK" {
		t.Fatalf("unexpected in-place symlink response: %+v", response)
	}
}

func requireMigrationResult(t *testing.T, response Response) *MigrationResult {
	t.Helper()
	result, ok := response.Result.(*MigrationResult)
	if !ok || result == nil {
		t.Fatalf("migration result has unexpected type: %#v", response.Result)
	}
	return result
}
