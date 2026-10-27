package configauthoring

import (
	"bytes"
	"errors"
	"io"
	"unicode/utf8"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/snapshot"
)

// MigratePath applies one explicit, release-shipped schema migration to a
// selected YAML file. The only contract-v1 pair is 1 to 1, so in-place mode
// validates the mutation boundary but does not replace the unchanged file.
func MigratePath(
	path string,
	fromSchemaVersion uint32,
	toSchemaVersion uint32,
	requirements Requirements,
	inPlace bool,
) Response {
	if !inPlace {
		return migrateLoaded(
			loadPath(path, snapshot.MaxConfigBytes),
			fromSchemaVersion,
			toSchemaVersion,
			requirements,
		)
	}
	input, _ := loadInPlacePath(path, snapshot.MaxConfigBytes)
	return migrateLoaded(input, fromSchemaVersion, toSchemaVersion, requirements)
}

// MigrateReader applies one explicit migration to caller-owned input and
// returns the complete resulting document only as the primary result.
func MigrateReader(
	reader io.Reader,
	sourceID string,
	fromSchemaVersion uint32,
	toSchemaVersion uint32,
	requirements Requirements,
) Response {
	return migrateLoaded(
		loadReader(reader, sourceID, snapshot.MaxConfigBytes),
		fromSchemaVersion,
		toSchemaVersion,
		requirements,
	)
}

func migrateLoaded(
	input loadedInput,
	fromSchemaVersion uint32,
	toSchemaVersion uint32,
	requirements Requirements,
) Response {
	response := baseResponse(input, OperationMigrate)
	if input.readErr != nil {
		code := "BV_CFG_INPUT_UNREADABLE"
		if errors.Is(input.readErr, errUnsupportedFileType) {
			return reject(response, inputDiagnostic("BV_CFG_FILE_TYPE_UNSUPPORTED"))
		}
		if errors.Is(input.readErr, errInputSymlink) {
			return reject(response, inputDiagnostic("BV_CFG_INPUT_SYMLINK"))
		}
		if errors.Is(input.readErr, errInputNotRegular) {
			code = "BV_CFG_INPUT_NOT_REGULAR"
		}
		return failInputOutput(response, inputDiagnostic(code))
	}
	if input.tooLarge {
		return reject(response, inputDiagnostic("BV_CFG_INPUT_TOO_LARGE"))
	}
	if !utf8.Valid(input.data) {
		return reject(response, inputDiagnostic("BV_CFG_INPUT_ENCODING"))
	}
	if versionMismatch(response.Versions, requirements) != "" {
		return refuse(response, inputDiagnostic("BV_CFG_VERSION_MISMATCH"))
	}

	declaredVersion, inspectErr := snapshot.InspectSchemaVersion(bytes.NewReader(input.data))
	index := emptySourceIndex(input.sourceID, input.data)
	if inspectErr == nil || sourceIndexAllowedAfter(inspectErr) {
		index = buildSourceIndex(input.sourceID, input.data)
	}
	if inspectErr != nil {
		return reject(response, compileDiagnostic(inspectErr, index))
	}
	if declaredVersion == nil {
		return reject(response, compileDiagnostic(
			errors.New("snapshot.schema_version: required"), index,
		))
	}
	response.Versions.InputConfigurationSchemaVersion = declaredVersion
	if *declaredVersion == 0 {
		return reject(response, compileDiagnostic(
			errors.New("snapshot.schema_version: got 0, only version 1 is supported"), index,
		))
	}
	if mismatchPath := versionMismatch(response.Versions, requirements); mismatchPath != "" {
		diagnostic := inputDiagnostic("BV_CFG_VERSION_MISMATCH")
		diagnostic.Path = mismatchPath
		diagnostic.Source = index.sourceForPath(mismatchPath)
		return refuse(response, diagnostic)
	}
	if *declaredVersion != fromSchemaVersion {
		diagnostic := inputDiagnostic("BV_CFG_VERSION_MISMATCH")
		diagnostic.Path = "/snapshot/schema_version"
		diagnostic.Source = index.sourceForPath(diagnostic.Path)
		return refuse(response, diagnostic)
	}
	if fromSchemaVersion != 1 || toSchemaVersion != 1 {
		return refuse(response, inputDiagnostic("BV_CFG_MIGRATION_UNSUPPORTED"))
	}
	if path := index.firstPEMLiteralPath(); path != "" {
		diagnostic := inputDiagnostic("BV_CFG_SECRET_LITERAL_FORBIDDEN")
		diagnostic.Path = path
		diagnostic.Source = index.sourceForPath(path)
		diagnostic.Redacted = true
		return reject(response, diagnostic)
	}

	response.Status = "accepted"
	response.ExitCode = ExitAccepted
	response.FailureKind = "none"
	response.Result = &MigrationResult{
		Kind:              "migration",
		FromSchemaVersion: fromSchemaVersion,
		ToSchemaVersion:   toSchemaVersion,
		Changed:           false,
		Document:          string(input.data),
		DocumentSHA256:    response.Inputs[0].SHA256,
	}
	return response
}
