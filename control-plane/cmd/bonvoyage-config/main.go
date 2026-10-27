package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"unicode/utf8"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/configauthoring"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 ||
		(args[0] != configauthoring.OperationValidate &&
			args[0] != configauthoring.OperationFormat &&
			args[0] != configauthoring.OperationExplain &&
			args[0] != configauthoring.OperationDiff &&
			args[0] != configauthoring.OperationMigrate &&
			args[0] != configauthoring.OperationPreview) {
		printUsage(stderr)
		return configauthoring.ExitInternal
	}
	operation := args[0]

	flags := flag.NewFlagSet("bonvoyage-config "+operation, flag.ContinueOnError)
	flags.SetOutput(stderr)
	var inputPath, sourceID *string
	var readStdin *bool
	if operation != configauthoring.OperationExplain && operation != configauthoring.OperationDiff {
		inputPath = flags.String("input", "", "read one YAML configuration from PATH")
		readStdin = flags.Bool("stdin", false, "read one YAML configuration from standard input")
		sourceID = flags.String("source-id", "stdin", "source identifier reported for explicit standard input")
	}
	var fieldPath *string
	if operation == configauthoring.OperationExplain {
		fieldPath = flags.String("path", "", "explain one RFC 6901 configuration field path")
	}
	var baselinePath, proposedPath, baselineSourceID, proposedSourceID *string
	var baselineStdin, proposedStdin *bool
	if operation == configauthoring.OperationDiff {
		baselinePath = flags.String("baseline", "", "read the baseline YAML configuration from PATH")
		proposedPath = flags.String("proposed", "", "read the proposed YAML configuration from PATH")
		baselineStdin = flags.Bool("baseline-stdin", false, "read the baseline YAML configuration from standard input")
		proposedStdin = flags.Bool("proposed-stdin", false, "read the proposed YAML configuration from standard input")
		baselineSourceID = flags.String("baseline-source-id", "baseline-stdin", "source identifier for a baseline read from standard input")
		proposedSourceID = flags.String("proposed-source-id", "proposed-stdin", "source identifier for a proposal read from standard input")
	} else if operation == configauthoring.OperationPreview {
		baselinePath = flags.String("baseline", "", "optionally compare with a local baseline YAML configuration at PATH")
	}
	var inPlace *bool
	if operation == configauthoring.OperationFormat || operation == configauthoring.OperationMigrate {
		inPlace = flags.Bool("in-place", false, "atomically replace the selected regular input file")
	}
	var fromSchemaVersion, toSchemaVersion *uint64
	if operation == configauthoring.OperationMigrate {
		fromSchemaVersion = flags.Uint64("from-schema-version", 0, "declare the exact input configuration schema version")
		toSchemaVersion = flags.Uint64("to-schema-version", 0, "select the exact target configuration schema version")
	}
	requiredProduct := flags.String("require-product-version", "", "require the exact installed product version")
	requiredCompiler := flags.String("require-compiler-version", "", "require the exact compiler identity")
	requiredSchema := flags.Uint64("require-configuration-schema-version", 0, "require the exact input schema version")
	if err := flags.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return configauthoring.ExitAccepted
		}
		return configauthoring.ExitInternal
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "unexpected positional arguments")
		return configauthoring.ExitInternal
	}
	sourceIDWasSet := false
	requiredSchemaWasSet := false
	fieldPathWasSet := false
	baselineSourceIDWasSet := false
	proposedSourceIDWasSet := false
	fromSchemaVersionWasSet := false
	toSchemaVersionWasSet := false
	flags.Visit(func(value *flag.Flag) {
		switch value.Name {
		case "baseline-source-id":
			baselineSourceIDWasSet = true
		case "source-id":
			sourceIDWasSet = true
		case "proposed-source-id":
			proposedSourceIDWasSet = true
		case "path":
			fieldPathWasSet = true
		case "from-schema-version":
			fromSchemaVersionWasSet = true
		case "require-configuration-schema-version":
			requiredSchemaWasSet = true
		case "to-schema-version":
			toSchemaVersionWasSet = true
		}
	})
	if operation == configauthoring.OperationExplain {
		if !fieldPathWasSet {
			fmt.Fprintln(stderr, "--path is required for explain")
			return configauthoring.ExitInternal
		}
	} else if operation == configauthoring.OperationDiff {
		if (*baselinePath != "") == *baselineStdin {
			fmt.Fprintln(stderr, "exactly one of --baseline or --baseline-stdin is required")
			return configauthoring.ExitInternal
		}
		if (*proposedPath != "") == *proposedStdin {
			fmt.Fprintln(stderr, "exactly one of --proposed or --proposed-stdin is required")
			return configauthoring.ExitInternal
		}
		if *baselineStdin && *proposedStdin {
			fmt.Fprintln(stderr, "baseline and proposed configurations cannot both use standard input")
			return configauthoring.ExitInternal
		}
		if *baselinePath != "" && baselineSourceIDWasSet {
			fmt.Fprintln(stderr, "--baseline-source-id is valid only with --baseline-stdin")
			return configauthoring.ExitInternal
		}
		if *proposedPath != "" && proposedSourceIDWasSet {
			fmt.Fprintln(stderr, "--proposed-source-id is valid only with --proposed-stdin")
			return configauthoring.ExitInternal
		}
		if *baselineStdin && (*baselineSourceID == "" || utf8.RuneCountInString(*baselineSourceID) > 1024) {
			fmt.Fprintln(stderr, "--baseline-source-id must contain between 1 and 1024 Unicode characters")
			return configauthoring.ExitInternal
		}
		if *proposedStdin && (*proposedSourceID == "" || utf8.RuneCountInString(*proposedSourceID) > 1024) {
			fmt.Fprintln(stderr, "--proposed-source-id must contain between 1 and 1024 Unicode characters")
			return configauthoring.ExitInternal
		}
	} else {
		if (*inputPath != "") == *readStdin {
			fmt.Fprintln(stderr, "exactly one of --input or --stdin is required")
			return configauthoring.ExitInternal
		}
		if *inputPath != "" && sourceIDWasSet {
			fmt.Fprintln(stderr, "--source-id is valid only with --stdin")
			return configauthoring.ExitInternal
		}
		if inPlace != nil && *inPlace && *readStdin {
			fmt.Fprintln(stderr, "--in-place requires --input and cannot be used with --stdin")
			return configauthoring.ExitInternal
		}
		if *readStdin && (*sourceID == "" || utf8.RuneCountInString(*sourceID) > 1024) {
			fmt.Fprintln(stderr, "--source-id must contain between 1 and 1024 Unicode characters")
			return configauthoring.ExitInternal
		}
		if operation == configauthoring.OperationMigrate &&
			(!fromSchemaVersionWasSet || !toSchemaVersionWasSet ||
				*fromSchemaVersion == 0 || *fromSchemaVersion > math.MaxUint32 ||
				*toSchemaVersion == 0 || *toSchemaVersion > math.MaxUint32) {
			fmt.Fprintln(stderr, "migrate requires explicit nonzero 32-bit --from-schema-version and --to-schema-version values")
			return configauthoring.ExitInternal
		}
	}

	requirements := configauthoring.Requirements{
		ProductVersion:  *requiredProduct,
		CompilerVersion: *requiredCompiler,
	}
	if requiredSchemaWasSet && (*requiredSchema == 0 || *requiredSchema > math.MaxUint32) {
		fmt.Fprintln(stderr, "--require-configuration-schema-version is outside the supported integer range")
		return configauthoring.ExitInternal
	}
	if *requiredSchema != 0 {
		value := uint32(*requiredSchema)
		requirements.ConfigurationSchemaVersion = &value
	}

	var response configauthoring.Response
	switch operation {
	case configauthoring.OperationValidate:
		if *readStdin {
			response = configauthoring.ValidateReader(stdin, *sourceID, requirements)
		} else {
			response = configauthoring.ValidatePath(*inputPath, requirements)
		}
	case configauthoring.OperationFormat:
		if *readStdin {
			response = configauthoring.FormatReader(stdin, *sourceID, requirements)
		} else {
			response = configauthoring.FormatPath(*inputPath, requirements, *inPlace)
		}
	case configauthoring.OperationExplain:
		response = configauthoring.Explain(*fieldPath, requirements)
	case configauthoring.OperationDiff:
		switch {
		case *baselineStdin:
			response = configauthoring.DiffBaselineReader(
				stdin, *baselineSourceID, *proposedPath, requirements,
			)
		case *proposedStdin:
			response = configauthoring.DiffProposedReader(
				*baselinePath, stdin, *proposedSourceID, requirements,
			)
		default:
			response = configauthoring.DiffPaths(*baselinePath, *proposedPath, requirements)
		}
	case configauthoring.OperationMigrate:
		from := uint32(*fromSchemaVersion)
		to := uint32(*toSchemaVersion)
		if *readStdin {
			response = configauthoring.MigrateReader(stdin, *sourceID, from, to, requirements)
		} else {
			response = configauthoring.MigratePath(*inputPath, from, to, requirements, *inPlace)
		}
	case configauthoring.OperationPreview:
		switch {
		case *readStdin && *baselinePath != "":
			response = configauthoring.PreviewReaderWithBaseline(
				stdin, *sourceID, *baselinePath, requirements,
			)
		case *readStdin:
			response = configauthoring.PreviewReader(stdin, *sourceID, requirements)
		case *baselinePath != "":
			response = configauthoring.PreviewPathWithBaseline(
				*inputPath, *baselinePath, requirements,
			)
		default:
			response = configauthoring.PreviewPath(*inputPath, requirements)
		}
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(response); err != nil {
		fmt.Fprintln(stderr, "could not write the machine result")
		return configauthoring.ExitInputOutput
	}
	return response.ExitCode
}

func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: bonvoyage-config <validate|format|explain|diff|migrate|preview> [operation options]")
}
