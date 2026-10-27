package configauthoring

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/snapshot"
)

func TestFormatReaderPreservesCommentsBOMCRLFAndSemantics(t *testing.T) {
	source := strings.Replace(validConfiguration, "server:\n", "# gateway document\nserver: # server block\n", 1)
	source = strings.Replace(source, "  node_id: node-1\n", "  node_id:    node-1 # stable identity\n", 1)
	source = strings.Replace(source, "snapshot:\n", "# snapshot intent\nsnapshot:\n", 1)
	source = strings.ReplaceAll(source, "\n", "\r\n")
	input := append(append([]byte(nil), utf8BOM...), []byte(source)...)

	response := FormatReader(bytes.NewReader(input), "commented.yaml", Requirements{})
	result := requireDocumentResult(t, response)
	if response.Status != "accepted" || !result.Changed {
		t.Fatalf("unexpected format response: %+v", response)
	}
	formatted := []byte(result.Document)
	if !bytes.HasPrefix(formatted, utf8BOM) {
		t.Fatal("UTF-8 BOM was not preserved")
	}
	for _, comment := range []string{"# gateway document", "# server block", "# stable identity", "# snapshot intent"} {
		if !bytes.Contains(formatted, []byte(comment)) {
			t.Fatalf("formatted document lost %q", comment)
		}
	}
	if bytes.Contains(formatted, []byte("runtime_limits:")) {
		t.Fatal("formatter materialized a compiler default into source YAML")
	}
	serverOffset := bytes.Index(formatted, []byte("server:"))
	snapshotOffset := bytes.Index(formatted, []byte("snapshot:"))
	listenerOffset := bytes.Index(formatted, []byte("listeners:"))
	if serverOffset < 0 || snapshotOffset <= serverOffset || listenerOffset <= snapshotOffset {
		t.Fatal("formatter changed source field order")
	}
	if hasLoneLF(formatted) {
		t.Fatal("formatted document did not preserve CRLF line endings")
	}
	if !bytes.HasSuffix(formatted, []byte("\r\n")) {
		t.Fatal("formatted document did not preserve the terminal newline")
	}
	digest := sha256.Sum256(formatted)
	if result.DocumentSHA256 != fmt.Sprintf("%x", digest) {
		t.Fatalf("document digest = %s, want %x", result.DocumentSHA256, digest)
	}
	assertSameCompiledArtifact(t, input, formatted)

	second := FormatReader(bytes.NewReader(formatted), "commented.yaml", Requirements{})
	secondResult := requireDocumentResult(t, second)
	if secondResult.Changed || secondResult.Document != result.Document ||
		secondResult.DocumentSHA256 != result.DocumentSHA256 {
		t.Fatalf("formatter is not idempotent:\nfirst=%+v\nsecond=%+v", result, secondResult)
	}
}

func TestFormatReaderPreservesMissingTerminalNewline(t *testing.T) {
	input := strings.TrimSuffix(validConfiguration, "\n")
	response := FormatReader(strings.NewReader(input), "no-newline.yaml", Requirements{})
	result := requireDocumentResult(t, response)
	if strings.HasSuffix(result.Document, "\n") {
		t.Fatal("formatter added a terminal newline")
	}
	assertSameCompiledArtifact(t, []byte(input), []byte(result.Document))
}

func TestFormatReaderRejectsMixedAndLoneCarriageReturn(t *testing.T) {
	for name, input := range map[string]string{
		"mixed": strings.Replace(validConfiguration, "server:\n", "server:\r\n", 1),
		"lone":  strings.Replace(validConfiguration, "server:\n", "server:\r", 1),
	} {
		t.Run(name, func(t *testing.T) {
			response := FormatReader(strings.NewReader(input), name+".yaml", Requirements{})
			assertFormatRejected(t, response, "BV_CFG_FORMAT_UNSAFE")
		})
	}
}

func TestFormatReaderRequiresCompilerAcceptance(t *testing.T) {
	input := strings.Replace(validConfiguration, "cluster: backend", "cluster: missing", 1)
	response := FormatReader(strings.NewReader(input), "invalid.yaml", Requirements{})
	assertFormatRejected(t, response, "BV_CFG_REFERENCE_MISSING")
}

func TestFormatPathIsNonMutatingByDefaultAndAtomicWhenExplicit(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "bonvoyage.yaml")
	input := strings.Replace(validConfiguration, "  node_id: node-1\n", "  node_id:    node-1\n", 1)
	if err := os.WriteFile(path, []byte(input), 0o640); err != nil {
		t.Fatal(err)
	}

	separate := FormatPath(path, Requirements{}, false)
	separateResult := requireDocumentResult(t, separate)
	unchanged, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged) != input || !separateResult.Changed {
		t.Fatal("default format operation modified its source or reported no change")
	}

	inPlace := FormatPath(path, Requirements{}, true)
	inPlaceResult := requireDocumentResult(t, inPlace)
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(written) != inPlaceResult.Document || inPlaceResult.Document != separateResult.Document {
		t.Fatal("in-place replacement did not write the accepted formatted result")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %o, want 640", info.Mode().Perm())
	}
	beforeNoOp := info
	noOp := FormatPath(path, Requirements{}, true)
	noOpResult := requireDocumentResult(t, noOp)
	afterNoOp, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if noOpResult.Changed || !os.SameFile(beforeNoOp, afterNoOp) {
		t.Fatal("unchanged in-place format replaced the source file")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "bonvoyage.yaml" {
		t.Fatalf("unexpected files after atomic replacement: %+v", entries)
	}
}

func TestFormatPathAllowsReadOnlySymlinkAndRejectsInPlaceSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.yaml")
	input := strings.Replace(validConfiguration, "  node_id: node-1\n", "  node_id:    node-1\n", 1)
	if err := os.WriteFile(target, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "projected.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if response := FormatPath(link, Requirements{}, false); response.Status != "accepted" {
		t.Fatalf("read-only format rejected a regular-file symlink: %+v", response)
	}
	response := FormatPath(link, Requirements{}, true)
	assertFormatRejected(t, response, "BV_CFG_INPUT_SYMLINK")
	written, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(written) != input {
		t.Fatal("rejected in-place symlink operation changed its target")
	}
}

func TestFormattedOutputLimitIsBounded(t *testing.T) {
	if err := checkFormattedOutputSize(make([]byte, snapshot.MaxConfigBytes)); err != nil {
		t.Fatalf("maximum-size output rejected: %v", err)
	}
	if !errors.Is(checkFormattedOutputSize(make([]byte, snapshot.MaxConfigBytes+1)), errOutputLimit) {
		t.Fatal("oversized formatted output did not return the output-limit error")
	}
}

func requireDocumentResult(t *testing.T, response Response) *DocumentResult {
	t.Helper()
	result, ok := response.Result.(*DocumentResult)
	if !ok || result == nil {
		t.Fatalf("document result has unexpected type: %#v", response.Result)
	}
	return result
}

func assertFormatRejected(t *testing.T, response Response, code string) {
	t.Helper()
	if response.Operation != OperationFormat || response.Status != "rejected" ||
		response.ExitCode != ExitRejected || response.FailureKind != "validation" ||
		response.Result != nil || len(response.Diagnostics) != 1 || response.Diagnostics[0].Code != code {
		t.Fatalf("unexpected format rejection for %s: %+v", code, response)
	}
}

func assertSameCompiledArtifact(t *testing.T, first, second []byte) {
	t.Helper()
	firstSnapshot, err := snapshot.Compile(bytes.NewReader(first))
	if err != nil {
		t.Fatal(err)
	}
	secondSnapshot, err := snapshot.Compile(bytes.NewReader(second))
	if err != nil {
		t.Fatal(err)
	}
	firstArtifact, err := snapshot.MarshalDeterministic(firstSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	secondArtifact, err := snapshot.MarshalDeterministic(secondSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstArtifact, secondArtifact) {
		t.Fatal("formatted document changed compiled semantics")
	}
}

func hasLoneLF(data []byte) bool {
	for index, value := range data {
		if value == '\n' && (index == 0 || data[index-1] != '\r') {
			return true
		}
	}
	return false
}
