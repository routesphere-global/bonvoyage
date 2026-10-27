// Package configauthoring exposes the versioned, offline configuration
// authoring result contract without adding a second semantic validator.
package configauthoring

const (
	ContractVersion   = "bonvoyage.configuration-authoring.v1"
	OperationValidate = "validate"
	OperationFormat   = "format"
	OperationExplain  = "explain"
	OperationDiff     = "diff"
	OperationMigrate  = "migrate"
	OperationPreview  = "preview"

	ExitAccepted    = 0
	ExitRejected    = 2
	ExitRefused     = 3
	ExitInputOutput = 4
	ExitInternal    = 70

	maxSourceIDRunes = 1024
)

// ProductVersion is injected by release builds. The development default must
// remain a valid semantic version so local results satisfy the public schema.
var ProductVersion = "0.2.0"

type Requirements struct {
	ProductVersion             string
	CompilerVersion            string
	ConfigurationSchemaVersion *uint32
}

type Response struct {
	ContractVersion      string       `json:"contract_version"`
	Operation            string       `json:"operation"`
	Status               string       `json:"status"`
	ExitCode             int          `json:"exit_code"`
	FailureKind          string       `json:"failure_kind"`
	Versions             Versions     `json:"versions"`
	Inputs               []Input      `json:"inputs"`
	Diagnostics          []Diagnostic `json:"diagnostics"`
	DiagnosticsTruncated bool         `json:"diagnostics_truncated"`
	Result               any          `json:"result"`
}

type Versions struct {
	ProductVersion                       string   `json:"product_version"`
	CompilerVersion                      string   `json:"compiler_version"`
	SupportedConfigurationSchemaVersions []uint32 `json:"supported_configuration_schema_versions"`
	InputConfigurationSchemaVersion      *uint32  `json:"input_configuration_schema_version"`
}

type Input struct {
	SourceID string `json:"source_id"`
	Bytes    int    `json:"bytes"`
	SHA256   string `json:"sha256"`
}

type Diagnostic struct {
	Code     string       `json:"code"`
	Severity string       `json:"severity"`
	Message  string       `json:"message"`
	Path     string       `json:"path,omitempty"`
	Source   *SourceRange `json:"source,omitempty"`
	Redacted bool         `json:"redacted"`
}

type SourceRange struct {
	SourceID string   `json:"source_id"`
	Start    Position `json:"start"`
	End      Position `json:"end"`
}

type Position struct {
	Line       int `json:"line"`
	Column     int `json:"column"`
	ByteOffset int `json:"byte_offset"`
}

type ValidationResult struct {
	Kind     string    `json:"kind"`
	Valid    bool      `json:"valid"`
	Artifact *Artifact `json:"artifact"`
}

type DocumentResult struct {
	Kind           string `json:"kind"`
	Changed        bool   `json:"changed"`
	Document       string `json:"document"`
	DocumentSHA256 string `json:"document_sha256"`
}

type ExplanationResult struct {
	Kind    string `json:"kind"`
	Path    string `json:"path"`
	Title   string `json:"title"`
	Summary string `json:"summary"`
}

type DiffResult struct {
	Kind                   string   `json:"kind"`
	BaselineArtifactSHA256 string   `json:"baseline_artifact_sha256"`
	ProposedArtifactSHA256 string   `json:"proposed_artifact_sha256"`
	Changes                []Change `json:"changes"`
}

type MigrationResult struct {
	Kind              string `json:"kind"`
	FromSchemaVersion uint32 `json:"from_schema_version"`
	ToSchemaVersion   uint32 `json:"to_schema_version"`
	Changed           bool   `json:"changed"`
	Document          string `json:"document"`
	DocumentSHA256    string `json:"document_sha256"`
}

type PreviewResult struct {
	Kind                   string         `json:"kind"`
	Artifact               Artifact       `json:"artifact"`
	Counts                 ResourceCounts `json:"counts"`
	BaselineArtifactSHA256 string         `json:"baseline_artifact_sha256,omitempty"`
	Changes                []Change       `json:"changes"`
}

type ResourceCounts struct {
	Listeners    int `json:"listeners"`
	VirtualHosts int `json:"virtual_hosts"`
	Routes       int `json:"routes"`
	Clusters     int `json:"clusters"`
	Endpoints    int `json:"endpoints"`
}

type Change struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
}

type Artifact struct {
	SHA256                  string `json:"sha256"`
	Bytes                   int    `json:"bytes"`
	SnapshotID              string `json:"snapshot_id"`
	SchemaVersion           uint32 `json:"schema_version"`
	MinimumDataplaneVersion string `json:"minimum_dataplane_version"`
}
