package configauthoring

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestExplainReturnsDeterministicStaticHelp(t *testing.T) {
	first := Explain("/virtual_hosts/0/routes/7/jwt_auth/jwks_secret", Requirements{})
	second := Explain("/virtual_hosts/0/routes/7/jwt_auth/jwks_secret", Requirements{})
	if first.Status != "accepted" || first.ExitCode != ExitAccepted || len(first.Inputs) != 0 {
		t.Fatalf("unexpected response: %+v", first)
	}
	result := requireExplanationResult(t, first)
	if result.Path != "/virtual_hosts/0/routes/7/jwt_auth/jwks_secret" ||
		result.Title != "JWKS secret" || !strings.Contains(result.Summary, "filename") {
		t.Fatalf("unexpected explanation: %+v", result)
	}
	if first.Versions.InputConfigurationSchemaVersion == nil ||
		*first.Versions.InputConfigurationSchemaVersion != 1 {
		t.Fatalf("unexpected versions: %+v", first.Versions)
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("machine results differ:\n%s\n%s", firstJSON, secondJSON)
	}
}

func TestExplainAcceptsCatalogAndConcreteArrayPaths(t *testing.T) {
	for _, path := range []string{"", "/listeners/*/port", "/listeners/0/port", "/clusters/42/endpoints/7/address"} {
		response := Explain(path, Requirements{})
		if response.Status != "accepted" {
			t.Fatalf("Explain(%q) = %+v", path, response)
		}
		if result := requireExplanationResult(t, response); result.Path != path {
			t.Fatalf("path = %q, want %q", result.Path, path)
		}
	}
}

func TestExplainRejectsUnknownOrMalformedPathWithoutEcho(t *testing.T) {
	for _, path := range []string{
		"not-a-pointer",
		"/listeners/01/port",
		"/listeners/0/private-customer-secret",
		"/listeners/0/bad~2token",
		"/" + strings.Repeat("x", maximumExplanationPathRunes+1),
	} {
		response := Explain(path, Requirements{})
		if response.Status != "rejected" || response.ExitCode != ExitRejected ||
			response.FailureKind != "validation" || len(response.Diagnostics) != 1 ||
			response.Diagnostics[0].Code != "BV_CFG_EXPLAIN_PATH_UNKNOWN" ||
			response.Result != nil || len(response.Inputs) != 0 {
			t.Fatalf("unexpected rejected response: %+v", response)
		}
		encoded, _ := json.Marshal(response)
		if bytes.Contains(encoded, []byte(path)) {
			t.Fatalf("rejection echoed unreviewed path %q: %s", path, encoded)
		}
	}
}

func TestExplainRefusesExactVersionMismatch(t *testing.T) {
	schemaVersion := uint32(2)
	for _, requirements := range []Requirements{
		{ProductVersion: "9.9.9"},
		{CompilerVersion: "different-compiler"},
		{ConfigurationSchemaVersion: &schemaVersion},
	} {
		response := Explain("/server/node_id", requirements)
		if response.Status != "refused" || response.ExitCode != ExitRefused ||
			response.Diagnostics[0].Code != "BV_CFG_VERSION_MISMATCH" || response.Result != nil {
			t.Fatalf("unexpected refusal: %+v", response)
		}
	}
}

func TestExplanationCatalogIsInternallyValid(t *testing.T) {
	catalog, err := loadExplanationCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Entries) != 160 {
		t.Fatalf("catalog entries = %d, want 160", len(catalog.Entries))
	}
}

func TestExplanationCatalogDecoderRejectsUnknownAndTrailingContent(t *testing.T) {
	for _, contents := range []string{
		`{"schema_version":1,"unknown":true}`,
		`{"schema_version":1} {}`,
	} {
		if _, err := decodeExplanationCatalog([]byte(contents)); err == nil {
			t.Fatalf("decodeExplanationCatalog(%q) unexpectedly passed", contents)
		}
	}
}

func requireExplanationResult(t *testing.T, response Response) *ExplanationResult {
	t.Helper()
	result, ok := response.Result.(*ExplanationResult)
	if !ok || result == nil {
		t.Fatalf("result type = %T, want *ExplanationResult", response.Result)
	}
	return result
}
