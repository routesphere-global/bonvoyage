package adminapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/adminservice"
)

type apiValidationCorpusManifest struct {
	Cases []struct {
		ID                      string   `json:"id"`
		Document                string   `json:"document"`
		ForbiddenOutputLiterals []string `json:"forbidden_output_literals"`
		Expected                struct {
			Status   string `json:"status"`
			Artifact *struct {
				SHA256                  string `json:"sha256"`
				Bytes                   int    `json:"bytes"`
				SnapshotID              string `json:"snapshot_id"`
				SchemaVersion           uint32 `json:"schema_version"`
				MinimumDataplaneVersion string `json:"minimum_dataplane_version"`
			} `json:"artifact"`
			Diagnostic *struct {
				Code   string  `json:"code"`
				Path   *string `json:"path"`
				Source *struct {
					Start adminservice.ConfigurationPosition `json:"start"`
					End   adminservice.ConfigurationPosition `json:"end"`
				} `json:"source"`
				Redacted bool `json:"redacted"`
			} `json:"diagnostic"`
		} `json:"expected"`
	} `json:"cases"`
}

type apiConfigurationValidationProblem struct {
	problemDocument
	Diagnostics          []adminservice.ConfigurationDiagnostic `json:"diagnostics"`
	DiagnosticsTruncated bool                                   `json:"diagnostics_truncated"`
}

func TestAuthenticatedValidationAPIReplaysSharedCorpus(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	manifestBytes, err := os.ReadFile(filepath.Join(
		root, "config", "authoring", "corpus", "v1", "manifest.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	var manifest apiValidationCorpusManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Cases) != 11 {
		t.Fatalf("corpus cases = %d, want 11", len(manifest.Cases))
	}

	handler, err := NewHandler(HandlerOptions{
		Service:    &adminservice.Service{},
		Authorizer: staticAuthorizer{principal: testPrincipal()},
		ServerName: "admin.test", MaxConcurrent: 4,
		Random: bytes.NewReader(bytes.Repeat([]byte{0x42}, 4_096)),
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, corpusCase := range manifest.Cases {
		t.Run(corpusCase.ID, func(t *testing.T) {
			document, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(corpusCase.Document)))
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := json.Marshal(configurationRequest{Document: string(document)})
			if err != nil {
				t.Fatal(err)
			}
			response := performAdminRequest(
				handler, http.MethodPost, "/api/v1/configurations/validate", string(envelope), nil,
			)

			if corpusCase.Expected.Status == "accepted" {
				if response.Code != http.StatusOK ||
					response.Header().Get("Content-Type") != "application/json; charset=utf-8" {
					t.Fatalf("accepted response = %d %s", response.Code, response.Body.String())
				}
				var result adminservice.ValidationResult
				if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				artifact := corpusCase.Expected.Artifact
				if artifact == nil || !result.Valid || result.ArtifactSHA256 != artifact.SHA256 ||
					result.ArtifactBytes != artifact.Bytes || result.SnapshotID != artifact.SnapshotID ||
					result.SchemaVersion != artifact.SchemaVersion ||
					result.MinimumDataplaneVersion != artifact.MinimumDataplaneVersion {
					t.Fatalf("accepted projection = %+v, expected = %+v", result, artifact)
				}
			} else {
				if response.Code != http.StatusUnprocessableEntity ||
					response.Header().Get("Content-Type") != "application/problem+json" {
					t.Fatalf("rejected response = %d %s", response.Code, response.Body.String())
				}
				var problem apiConfigurationValidationProblem
				if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
					t.Fatal(err)
				}
				if problem.Code != "INVALID_CONFIGURATION" || problem.Status != 422 ||
					problem.DiagnosticsTruncated || len(problem.Diagnostics) != 1 ||
					corpusCase.Expected.Diagnostic == nil {
					t.Fatalf("problem projection = %+v", problem)
				}
				diagnostic := problem.Diagnostics[0]
				expected := corpusCase.Expected.Diagnostic
				expectedPath := ""
				if expected.Path != nil {
					expectedPath = *expected.Path
				}
				if diagnostic.Code != expected.Code || diagnostic.Path != expectedPath ||
					diagnostic.Redacted != expected.Redacted {
					t.Fatalf("diagnostic = %+v, expected = %+v", diagnostic, expected)
				}
				if expected.Source == nil && diagnostic.Source != nil {
					t.Fatalf("unexpected source range: %+v", diagnostic.Source)
				}
				if expected.Source != nil && (diagnostic.Source == nil ||
					diagnostic.Source.Start != expected.Source.Start ||
					diagnostic.Source.End != expected.Source.End) {
					t.Fatalf("source range = %+v, expected = %+v", diagnostic.Source, expected.Source)
				}
			}

			for _, forbidden := range corpusCase.ForbiddenOutputLiterals {
				if strings.Contains(response.Body.String(), forbidden) {
					t.Fatalf("response leaked forbidden literal %q: %s", forbidden, response.Body.String())
				}
			}
		})
	}
}
