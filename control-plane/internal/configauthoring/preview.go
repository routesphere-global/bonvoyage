package configauthoring

import (
	"bytes"
	"errors"
	"io"

	bonvoyagev1 "github.com/routesphere-global/bonvoyage/api/gen/go/bonvoyage/v1"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/snapshot"
)

// PreviewPath compiles one explicitly selected YAML file and summarizes its
// immutable data-plane artifact without contacting a gateway.
func PreviewPath(path string, requirements Requirements) Response {
	return previewLoaded(
		loadPath(path, snapshot.MaxConfigBytes), nil, requirements,
	)
}

// PreviewPathWithBaseline compiles a proposal and one explicitly selected
// local baseline. The baseline is comparison input only and is never fetched
// from runtime state.
func PreviewPathWithBaseline(
	path string,
	baselinePath string,
	requirements Requirements,
) Response {
	baseline := loadPath(baselinePath, snapshot.MaxConfigBytes)
	return previewLoaded(
		loadPath(path, snapshot.MaxConfigBytes), &baseline, requirements,
	)
}

// PreviewReader compiles caller-owned input. The source identifier is metadata
// only and is never interpreted as a path.
func PreviewReader(
	reader io.Reader,
	sourceID string,
	requirements Requirements,
) Response {
	return previewLoaded(
		loadReader(reader, sourceID, snapshot.MaxConfigBytes), nil, requirements,
	)
}

// PreviewReaderWithBaseline compiles caller-owned proposal input and compares
// it with one explicitly selected local baseline file.
func PreviewReaderWithBaseline(
	reader io.Reader,
	sourceID string,
	baselinePath string,
	requirements Requirements,
) Response {
	baseline := loadPath(baselinePath, snapshot.MaxConfigBytes)
	return previewLoaded(
		loadReader(reader, sourceID, snapshot.MaxConfigBytes), &baseline, requirements,
	)
}

func previewLoaded(
	proposed loadedInput,
	baseline *loadedInput,
	requirements Requirements,
) Response {
	inputs := []Input{inputRecord(proposed)}
	if baseline != nil {
		inputs = append(inputs, inputRecord(*baseline))
	}

	proposedCompiled, response, ok := compileLoaded(proposed, requirements, OperationPreview)
	response.Inputs = inputs
	if !ok {
		return identifyInvalidPreviewInput(response, "/document")
	}

	changes := make([]Change, 0)
	baselineDigest := ""
	if baseline != nil {
		baselineCompiled, baselineResponse, baselineOK := compileLoaded(
			*baseline, requirements, OperationPreview,
		)
		baselineResponse.Inputs = inputs
		if !baselineOK {
			return identifyInvalidPreviewInput(baselineResponse, "/baseline")
		}
		baselineDigest = artifactSHA256(baselineCompiled.artifactBytes)
		if !bytes.Equal(baselineCompiled.artifactBytes, proposedCompiled.artifactBytes) {
			var err error
			changes, err = semanticChanges(baselineCompiled.snapshot, proposedCompiled.snapshot)
			if err != nil {
				if errors.Is(err, errDiffOutputLimit) {
					return reject(response, inputDiagnostic("BV_CFG_OUTPUT_LIMIT_EXCEEDED"))
				}
				return failInternal(response)
			}
			if len(changes) == 0 {
				return failInternal(response)
			}
		}
	}

	artifact := artifactFromCompiled(proposedCompiled)
	response.Status = "accepted"
	response.ExitCode = ExitAccepted
	response.FailureKind = "none"
	response.Result = &PreviewResult{
		Kind:                   "preview",
		Artifact:               *artifact,
		Counts:                 countResources(proposedCompiled.snapshot),
		BaselineArtifactSHA256: baselineDigest,
		Changes:                changes,
	}
	return response
}

func identifyInvalidPreviewInput(response Response, path string) Response {
	if response.FailureKind == "internal" {
		return response
	}
	diagnostic := inputDiagnostic("BV_CFG_PREVIEW_INPUT_INVALID")
	diagnostic.Path = path
	response.Diagnostics = append([]Diagnostic{diagnostic}, response.Diagnostics...)
	return response
}

func countResources(compiled *bonvoyagev1.Snapshot) ResourceCounts {
	counts := ResourceCounts{}
	if compiled == nil {
		return counts
	}
	counts.Listeners = len(compiled.GetListeners())
	counts.VirtualHosts = len(compiled.GetVirtualHosts())
	counts.Clusters = len(compiled.GetClusters())
	for _, virtualHost := range compiled.GetVirtualHosts() {
		counts.Routes += len(virtualHost.GetRoutes())
	}
	for _, cluster := range compiled.GetClusters() {
		counts.Endpoints += len(cluster.GetEndpoints())
	}
	return counts
}
