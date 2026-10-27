package configauthoring

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"

	bonvoyagev1 "github.com/routesphere-global/bonvoyage/api/gen/go/bonvoyage/v1"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/snapshot"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	maxDiffChanges = 10_000
	maxDiffPathLen = 4_096
)

var errDiffOutputLimit = errors.New("semantic diff output exceeds its limit")

var compiledFieldPathNames = map[protoreflect.FullName]string{
	"bonvoyage.v1.Listener.virtual_host_names":  "virtual_hosts",
	"bonvoyage.v1.Route.cluster_name":           "cluster",
	"bonvoyage.v1.WeightedCluster.cluster_name": "cluster",
}

// DiffPaths compares two explicitly selected YAML files after both pass the
// authoritative configuration compiler.
func DiffPaths(baselinePath, proposedPath string, requirements Requirements) Response {
	return diffLoaded(
		loadPath(baselinePath, snapshot.MaxConfigBytes),
		loadPath(proposedPath, snapshot.MaxConfigBytes),
		requirements,
	)
}

// DiffReaders compares two caller-owned readers. Source identifiers are
// metadata only and are never interpreted as paths.
func DiffReaders(
	baseline io.Reader,
	baselineSourceID string,
	proposed io.Reader,
	proposedSourceID string,
	requirements Requirements,
) Response {
	return diffLoaded(
		loadReader(baseline, baselineSourceID, snapshot.MaxConfigBytes),
		loadReader(proposed, proposedSourceID, snapshot.MaxConfigBytes),
		requirements,
	)
}

// DiffBaselineReader compares an explicit baseline reader with a proposed
// configuration file.
func DiffBaselineReader(
	baseline io.Reader,
	baselineSourceID string,
	proposedPath string,
	requirements Requirements,
) Response {
	return diffLoaded(
		loadReader(baseline, baselineSourceID, snapshot.MaxConfigBytes),
		loadPath(proposedPath, snapshot.MaxConfigBytes),
		requirements,
	)
}

// DiffProposedReader compares a baseline configuration file with an explicit
// proposed reader.
func DiffProposedReader(
	baselinePath string,
	proposed io.Reader,
	proposedSourceID string,
	requirements Requirements,
) Response {
	return diffLoaded(
		loadPath(baselinePath, snapshot.MaxConfigBytes),
		loadReader(proposed, proposedSourceID, snapshot.MaxConfigBytes),
		requirements,
	)
}

func diffLoaded(baseline, proposed loadedInput, requirements Requirements) Response {
	inputs := []Input{inputRecord(baseline), inputRecord(proposed)}

	baselineCompiled, response, ok := compileLoaded(baseline, requirements, OperationDiff)
	response.Inputs = inputs
	if !ok {
		return identifyInvalidDiffInput(response, "/baseline")
	}

	proposedCompiled, response, ok := compileLoaded(proposed, requirements, OperationDiff)
	response.Inputs = inputs
	if !ok {
		return identifyInvalidDiffInput(response, "/proposed")
	}

	changes := make([]Change, 0)
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
	response.Status = "accepted"
	response.ExitCode = ExitAccepted
	response.FailureKind = "none"
	response.Result = &DiffResult{
		Kind:                   "semantic-diff",
		BaselineArtifactSHA256: artifactSHA256(baselineCompiled.artifactBytes),
		ProposedArtifactSHA256: artifactSHA256(proposedCompiled.artifactBytes),
		Changes:                changes,
	}
	return response
}

func identifyInvalidDiffInput(response Response, path string) Response {
	if response.FailureKind == "internal" {
		return response
	}
	diagnostic := inputDiagnostic("BV_CFG_DIFF_INPUT_INVALID")
	diagnostic.Path = path
	response.Diagnostics = append([]Diagnostic{diagnostic}, response.Diagnostics...)
	return response
}

func artifactSHA256(data []byte) string {
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest)
}

func semanticChanges(baseline, proposed *bonvoyagev1.Snapshot) ([]Change, error) {
	if baseline == nil || proposed == nil {
		return nil, errors.New("compiled snapshot is nil")
	}
	collector := diffCollector{changes: make([]Change, 0)}
	if err := collector.compareMessage("", baseline.ProtoReflect(), proposed.ProtoReflect()); err != nil {
		return nil, err
	}
	sort.Slice(collector.changes, func(left, right int) bool {
		if collector.changes[left].Path == collector.changes[right].Path {
			return collector.changes[left].Kind < collector.changes[right].Kind
		}
		return collector.changes[left].Path < collector.changes[right].Path
	})
	return collector.changes, nil
}

type diffCollector struct {
	changes []Change
}

func (collector *diffCollector) compareMessage(
	path string,
	baseline protoreflect.Message,
	proposed protoreflect.Message,
) error {
	fields := baseline.Descriptor().Fields()
	if proposed.Descriptor().FullName() != baseline.Descriptor().FullName() {
		return errors.New("compiled snapshot message types differ")
	}
	for index := 0; index < fields.Len(); index++ {
		field := fields.Get(index)
		fieldPath := path + "/" + escapePointerToken(publicFieldPathName(field))
		baselineHas := baseline.Has(field)
		proposedHas := proposed.Has(field)

		if field.IsList() {
			if err := collector.compareList(fieldPath, field, baseline.Get(field).List(), proposed.Get(field).List()); err != nil {
				return err
			}
			continue
		}
		if field.IsMap() {
			if !mapEqual(field, baseline.Get(field).Map(), proposed.Get(field).Map()) {
				if err := collector.add(fieldPath, "changed"); err != nil {
					return err
				}
			}
			continue
		}

		hasSemanticPresence := field.HasPresence()
		switch {
		case hasSemanticPresence && baselineHas && !proposedHas:
			if err := collector.add(fieldPath, "removed"); err != nil {
				return err
			}
		case hasSemanticPresence && !baselineHas && proposedHas:
			if err := collector.add(fieldPath, "added"); err != nil {
				return err
			}
		case field.Message() != nil && !baselineHas:
			continue
		case field.Message() != nil:
			if err := collector.compareMessage(
				fieldPath,
				baseline.Get(field).Message(),
				proposed.Get(field).Message(),
			); err != nil {
				return err
			}
		case !scalarEqual(field.Kind(), baseline.Get(field), proposed.Get(field)):
			if err := collector.add(fieldPath, "changed"); err != nil {
				return err
			}
		}
	}
	return nil
}

func publicFieldPathName(field protoreflect.FieldDescriptor) string {
	if name, ok := compiledFieldPathNames[field.FullName()]; ok {
		return name
	}
	return string(field.Name())
}

func (collector *diffCollector) compareList(
	path string,
	field protoreflect.FieldDescriptor,
	baseline protoreflect.List,
	proposed protoreflect.List,
) error {
	common := min(baseline.Len(), proposed.Len())
	for index := 0; index < common; index++ {
		itemPath := path + "/" + strconv.Itoa(index)
		if field.Message() != nil {
			if err := collector.compareMessage(
				itemPath,
				baseline.Get(index).Message(),
				proposed.Get(index).Message(),
			); err != nil {
				return err
			}
			continue
		}
		if !scalarEqual(field.Kind(), baseline.Get(index), proposed.Get(index)) {
			if err := collector.add(itemPath, "changed"); err != nil {
				return err
			}
		}
	}
	for index := common; index < baseline.Len(); index++ {
		if err := collector.add(path+"/"+strconv.Itoa(index), "removed"); err != nil {
			return err
		}
	}
	for index := common; index < proposed.Len(); index++ {
		if err := collector.add(path+"/"+strconv.Itoa(index), "added"); err != nil {
			return err
		}
	}
	return nil
}

func (collector *diffCollector) add(path, kind string) error {
	if len(path) > maxDiffPathLen || len(collector.changes) >= maxDiffChanges {
		return errDiffOutputLimit
	}
	collector.changes = append(collector.changes, Change{Path: path, Kind: kind})
	return nil
}

func mapEqual(
	field protoreflect.FieldDescriptor,
	baseline protoreflect.Map,
	proposed protoreflect.Map,
) bool {
	if baseline.Len() != proposed.Len() {
		return false
	}
	equal := true
	baseline.Range(func(key protoreflect.MapKey, value protoreflect.Value) bool {
		if !proposed.Has(key) || !mapValueEqual(field.MapValue(), value, proposed.Get(key)) {
			equal = false
			return false
		}
		return true
	})
	return equal
}

func mapValueEqual(
	descriptor protoreflect.FieldDescriptor,
	baseline protoreflect.Value,
	proposed protoreflect.Value,
) bool {
	if descriptor.Message() != nil {
		return proto.Equal(baseline.Message().Interface(), proposed.Message().Interface())
	}
	return scalarEqual(descriptor.Kind(), baseline, proposed)
}

func scalarEqual(
	kind protoreflect.Kind,
	baseline protoreflect.Value,
	proposed protoreflect.Value,
) bool {
	switch kind {
	case protoreflect.BytesKind:
		return bytes.Equal(baseline.Bytes(), proposed.Bytes())
	case protoreflect.FloatKind:
		return math.Float32bits(float32(baseline.Float())) == math.Float32bits(float32(proposed.Float()))
	case protoreflect.DoubleKind:
		return math.Float64bits(baseline.Float()) == math.Float64bits(proposed.Float())
	default:
		return baseline.Interface() == proposed.Interface()
	}
}
