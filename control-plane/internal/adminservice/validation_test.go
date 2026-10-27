package adminservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
)

type validationCorpusManifest struct {
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
				Code     string  `json:"code"`
				Severity string  `json:"severity"`
				Path     *string `json:"path"`
				Source   *struct {
					Start ConfigurationPosition `json:"start"`
					End   ConfigurationPosition `json:"end"`
				} `json:"source"`
				Redacted bool `json:"redacted"`
			} `json:"diagnostic"`
		} `json:"expected"`
	} `json:"cases"`
}

func TestValidatePreservesSharedCorpusProjection(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	manifestBytes, err := os.ReadFile(filepath.Join(
		root, "config", "authoring", "corpus", "v1", "manifest.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	var manifest validationCorpusManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Cases) != 11 {
		t.Fatalf("corpus cases = %d, want 11", len(manifest.Cases))
	}

	service := &Service{}
	principal := Principal{
		Actor: "spiffe://admin.test/service-accounts/console",
		Role:  RoleOperator, SourceChannel: storage.SourceConsole,
	}
	for _, corpusCase := range manifest.Cases {
		t.Run(corpusCase.ID, func(t *testing.T) {
			document, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(corpusCase.Document)))
			if err != nil {
				t.Fatal(err)
			}
			result, validationErr := service.Validate(
				context.Background(), principal, ValidateInput{Document: document},
			)
			if corpusCase.Expected.Status == "accepted" {
				if validationErr != nil {
					t.Fatal(validationErr)
				}
				artifact := corpusCase.Expected.Artifact
				if artifact == nil || !result.Valid || result.APIVersion != APIVersion ||
					result.ArtifactSHA256 != artifact.SHA256 || result.ArtifactBytes != artifact.Bytes ||
					result.SnapshotID != artifact.SnapshotID || result.SchemaVersion != artifact.SchemaVersion ||
					result.MinimumDataplaneVersion != artifact.MinimumDataplaneVersion {
					t.Fatalf("accepted projection = %+v, expected = %+v", result, artifact)
				}
				return
			}

			var rejected *ConfigurationValidationError
			if !errors.As(validationErr, &rejected) || !errors.Is(validationErr, ErrInvalidConfiguration) {
				t.Fatalf("rejection error = %v", validationErr)
			}
			if rejected.DiagnosticsTruncated || len(rejected.Diagnostics) != 1 ||
				corpusCase.Expected.Diagnostic == nil {
				t.Fatalf("rejected projection = %+v", rejected)
			}
			diagnostic := rejected.Diagnostics[0]
			expected := corpusCase.Expected.Diagnostic
			if diagnostic.Code != expected.Code || diagnostic.Severity != expected.Severity ||
				diagnostic.Redacted != expected.Redacted {
				t.Fatalf("diagnostic = %+v, expected = %+v", diagnostic, expected)
			}
			expectedPath := ""
			if expected.Path != nil {
				expectedPath = *expected.Path
			}
			if diagnostic.Path != expectedPath {
				t.Fatalf("diagnostic path = %q, want %q", diagnostic.Path, expectedPath)
			}
			if expected.Source == nil && diagnostic.Source != nil {
				t.Fatalf("unexpected source range: %+v", diagnostic.Source)
			}
			if expected.Source != nil && (diagnostic.Source == nil ||
				diagnostic.Source.Start != expected.Source.Start ||
				diagnostic.Source.End != expected.Source.End) {
				t.Fatalf("source range = %+v, expected = %+v", diagnostic.Source, expected.Source)
			}
			encoded, err := json.Marshal(rejected)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range corpusCase.ForbiddenOutputLiterals {
				if bytes.Contains(encoded, []byte(forbidden)) {
					t.Fatalf("rejection leaked forbidden literal %q: %s", forbidden, encoded)
				}
			}
		})
	}
}

func TestValidateKeepsAuthorizationAndCancellationAheadOfCompilation(t *testing.T) {
	service := &Service{}
	input := ValidateInput{Document: []byte("private-value")}
	_, err := service.Validate(context.Background(), Principal{
		Actor: "auditor", Role: RoleAuditor, SourceChannel: storage.SourceConsole,
	}, input)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("auditor error = %v, want forbidden", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = service.Validate(ctx, Principal{
		Actor: "operator", Role: RoleOperator, SourceChannel: storage.SourceConsole,
	}, input)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled error = %v, want context cancellation", err)
	}
}
