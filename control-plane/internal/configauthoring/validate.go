package configauthoring

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	bonvoyagev1 "github.com/routesphere-global/bonvoyage/api/gen/go/bonvoyage/v1"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/snapshot"
)

var supportedConfigurationSchemaVersions = []uint32{1}

// ValidatePath validates one explicitly selected YAML file. Read-only
// validation follows symlinks only when the resolved target is a regular file.
func ValidatePath(path string, requirements Requirements) Response {
	return validateLoaded(loadPath(path, snapshot.MaxConfigBytes), requirements)
}

// ValidateReader validates explicitly selected standard input or another
// caller-owned reader. The source identifier is metadata only and is never
// interpreted as a path.
func ValidateReader(reader io.Reader, sourceID string, requirements Requirements) Response {
	return validateLoaded(loadReader(reader, sourceID, snapshot.MaxConfigBytes), requirements)
}

func validateLoaded(input loadedInput, requirements Requirements) Response {
	compiled, response, ok := compileLoaded(input, requirements, OperationValidate)
	if !ok {
		return response
	}
	response.Status = "accepted"
	response.ExitCode = ExitAccepted
	response.FailureKind = "none"
	response.Result = &ValidationResult{
		Kind:     "validation",
		Valid:    true,
		Artifact: artifactFromCompiled(compiled),
	}
	return response
}

func artifactFromCompiled(compiled compiledInput) *Artifact {
	return &Artifact{
		SHA256:                  fmt.Sprintf("%x", sha256.Sum256(compiled.artifactBytes)),
		Bytes:                   len(compiled.artifactBytes),
		SnapshotID:              compiled.snapshotID,
		SchemaVersion:           compiled.schemaVersion,
		MinimumDataplaneVersion: compiled.minimumDataplaneVersion,
	}
}

type compiledInput struct {
	snapshot                *bonvoyagev1.Snapshot
	artifactBytes           []byte
	snapshotID              string
	schemaVersion           uint32
	minimumDataplaneVersion string
}

func compileLoaded(
	input loadedInput,
	requirements Requirements,
	operation string,
) (compiledInput, Response, bool) {
	response := baseResponse(input, operation)
	if input.readErr != nil {
		code := "BV_CFG_INPUT_UNREADABLE"
		if errors.Is(input.readErr, errUnsupportedFileType) {
			code = "BV_CFG_FILE_TYPE_UNSUPPORTED"
			return compiledInput{}, reject(response, inputDiagnostic(code)), false
		}
		if errors.Is(input.readErr, errInputSymlink) {
			code = "BV_CFG_INPUT_SYMLINK"
			return compiledInput{}, reject(response, inputDiagnostic(code)), false
		}
		if errors.Is(input.readErr, errInputNotRegular) {
			code = "BV_CFG_INPUT_NOT_REGULAR"
		}
		return compiledInput{}, failInputOutput(response, inputDiagnostic(code)), false
	}
	if input.tooLarge {
		return compiledInput{}, reject(response, inputDiagnostic("BV_CFG_INPUT_TOO_LARGE")), false
	}
	if !utf8.Valid(input.data) {
		return compiledInput{}, reject(response, inputDiagnostic("BV_CFG_INPUT_ENCODING")), false
	}
	if mismatchPath := versionMismatch(response.Versions, requirements); mismatchPath != "" {
		return compiledInput{}, refuse(response, inputDiagnostic("BV_CFG_VERSION_MISMATCH")), false
	}

	compiled, compileErr := snapshot.Compile(bytes.NewReader(input.data))
	index := emptySourceIndex(input.sourceID, input.data)
	if compileErr == nil || sourceIndexAllowedAfter(compileErr) {
		index = buildSourceIndex(input.sourceID, input.data)
	}
	response.Versions.InputConfigurationSchemaVersion = index.configurationSchemaVersion()
	if mismatchPath := versionMismatch(response.Versions, requirements); mismatchPath != "" {
		diagnostic := inputDiagnostic("BV_CFG_VERSION_MISMATCH")
		if mismatchPath != "installed" {
			diagnostic.Path = mismatchPath
			diagnostic.Source = index.sourceForPath(mismatchPath)
		}
		return compiledInput{}, refuse(response, diagnostic), false
	}
	if compileErr != nil {
		return compiledInput{}, reject(response, compileDiagnostic(compileErr, index)), false
	}
	artifactBytes, err := snapshot.MarshalDeterministic(compiled)
	if err != nil {
		return compiledInput{}, failInternal(response), false
	}
	return compiledInput{
		snapshot: compiled, artifactBytes: artifactBytes, snapshotID: compiled.GetSnapshotId(),
		schemaVersion:           compiled.GetSchemaVersion(),
		minimumDataplaneVersion: compiled.GetMinimumDataplaneVersion(),
	}, response, true
}

func sourceIndexAllowedAfter(err error) bool {
	message := err.Error()
	if !strings.Contains(message, "parse YAML") {
		return true
	}
	return strings.Contains(message, "cannot unmarshal") ||
		(strings.Contains(message, "field ") && strings.Contains(message, "not found in type"))
}

func baseResponse(input loadedInput, operation string) Response {
	response := baseStaticResponse(operation, nil)
	response.Inputs = []Input{inputRecord(input)}
	return response
}

func baseStaticResponse(operation string, schemaVersion *uint32) Response {
	return Response{
		ContractVersion: ContractVersion,
		Operation:       operation,
		Status:          "failed",
		ExitCode:        ExitInternal,
		FailureKind:     "internal",
		Versions: Versions{
			ProductVersion:  ProductVersion,
			CompilerVersion: snapshot.CompilerVersion,
			SupportedConfigurationSchemaVersions: append(
				[]uint32(nil), supportedConfigurationSchemaVersions...),
			InputConfigurationSchemaVersion: schemaVersion,
		},
		Inputs:      []Input{},
		Diagnostics: []Diagnostic{},
	}
}

func versionMismatch(installed Versions, required Requirements) string {
	if required.ProductVersion != "" && required.ProductVersion != installed.ProductVersion {
		return "installed"
	}
	if required.CompilerVersion != "" && required.CompilerVersion != installed.CompilerVersion {
		return "installed"
	}
	if required.ConfigurationSchemaVersion != nil &&
		installed.InputConfigurationSchemaVersion != nil &&
		*required.ConfigurationSchemaVersion != *installed.InputConfigurationSchemaVersion {
		return "/snapshot/schema_version"
	}
	return ""
}

func reject(response Response, diagnostic Diagnostic) Response {
	response.Status = "rejected"
	response.ExitCode = ExitRejected
	response.FailureKind = "validation"
	response.Diagnostics = []Diagnostic{diagnostic}
	if response.Operation == OperationValidate {
		response.Result = &ValidationResult{Kind: "validation", Valid: false, Artifact: nil}
	} else {
		response.Result = nil
	}
	return response
}

func refuse(response Response, diagnostic Diagnostic) Response {
	response.Status = "refused"
	response.ExitCode = ExitRefused
	response.FailureKind = "compatibility"
	response.Diagnostics = []Diagnostic{diagnostic}
	response.Result = nil
	return response
}

func failInputOutput(response Response, diagnostic Diagnostic) Response {
	response.Status = "failed"
	response.ExitCode = ExitInputOutput
	response.FailureKind = "io"
	response.Diagnostics = []Diagnostic{diagnostic}
	response.Result = nil
	return response
}

func failInternal(response Response) Response {
	response.Status = "failed"
	response.ExitCode = ExitInternal
	response.FailureKind = "internal"
	response.Diagnostics = []Diagnostic{inputDiagnostic("BV_CFG_INTERNAL")}
	response.Result = nil
	return response
}
