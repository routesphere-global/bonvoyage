package configauthoring

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/snapshot"
	"gopkg.in/yaml.v3"
)

var (
	errFormatUnsafe = errors.New("format preservation could not be proven")
	errOutputLimit  = errors.New("formatted output exceeds the size limit")
)

var utf8BOM = []byte{0xef, 0xbb, 0xbf}

// FormatPath formats one explicitly selected YAML file. The source remains
// untouched unless inPlace is true; in-place formatting rejects symlinks and
// uses a same-directory atomic replacement.
func FormatPath(path string, requirements Requirements, inPlace bool) Response {
	if !inPlace {
		return formatLoaded(loadPath(path, snapshot.MaxConfigBytes), requirements)
	}
	input, state := loadInPlacePath(path, snapshot.MaxConfigBytes)
	response := formatLoaded(input, requirements)
	if response.Status != "accepted" {
		return response
	}
	result, ok := response.Result.(*DocumentResult)
	if !ok || result == nil {
		return failInternal(response)
	}
	if !result.Changed {
		return response
	}
	if state == nil || atomicReplaceRegularFile(state, []byte(result.Document)) != nil {
		return failInputOutput(response, inputDiagnostic("BV_CFG_FORMAT_UNSAFE"))
	}
	return response
}

// FormatReader formats explicitly selected standard input or another
// caller-owned reader and always returns the formatted document separately.
func FormatReader(reader io.Reader, sourceID string, requirements Requirements) Response {
	return formatLoaded(loadReader(reader, sourceID, snapshot.MaxConfigBytes), requirements)
}

func formatLoaded(input loadedInput, requirements Requirements) Response {
	original, response, ok := compileLoaded(input, requirements, OperationFormat)
	if !ok {
		return response
	}

	formatted, err := formatDocument(input.data)
	if err != nil {
		code := "BV_CFG_FORMAT_UNSAFE"
		if errors.Is(err, errOutputLimit) {
			code = "BV_CFG_OUTPUT_LIMIT_EXCEEDED"
		}
		return reject(response, inputDiagnostic(code))
	}
	compiled, err := snapshot.Compile(bytes.NewReader(formatted))
	if err != nil {
		return reject(response, inputDiagnostic("BV_CFG_FORMAT_UNSAFE"))
	}
	artifactBytes, err := snapshot.MarshalDeterministic(compiled)
	if err != nil {
		return failInternal(response)
	}
	if !bytes.Equal(original.artifactBytes, artifactBytes) {
		return reject(response, inputDiagnostic("BV_CFG_FORMAT_UNSAFE"))
	}

	digest := sha256.Sum256(formatted)
	response.Status = "accepted"
	response.ExitCode = ExitAccepted
	response.FailureKind = "none"
	response.Result = &DocumentResult{
		Kind: "formatted-document", Changed: !bytes.Equal(input.data, formatted),
		Document: string(formatted), DocumentSHA256: fmt.Sprintf("%x", digest),
	}
	return response
}

type presentationStyle struct {
	bom             bool
	crlf            bool
	terminalNewline bool
}

func formatDocument(input []byte) ([]byte, error) {
	style, err := inspectPresentation(input)
	if err != nil {
		return nil, err
	}
	originalRoot, err := decodePresentation(input, style)
	if err != nil {
		return nil, errFormatUnsafe
	}
	originalComments := collectComments(&originalRoot, "")

	formatted, err := encodePresentation(&originalRoot, style)
	if err != nil {
		return nil, errFormatUnsafe
	}
	if err := checkFormattedOutputSize(formatted); err != nil {
		return nil, errOutputLimit
	}
	formattedRoot, err := decodePresentation(formatted, style)
	if err != nil || !reflect.DeepEqual(originalComments, collectComments(&formattedRoot, "")) {
		return nil, errFormatUnsafe
	}

	secondPass, err := encodePresentation(&formattedRoot, style)
	if err != nil || !bytes.Equal(formatted, secondPass) {
		return nil, errFormatUnsafe
	}
	return formatted, nil
}

func checkFormattedOutputSize(formatted []byte) error {
	if int64(len(formatted)) > snapshot.MaxConfigBytes {
		return errOutputLimit
	}
	return nil
}

func inspectPresentation(input []byte) (presentationStyle, error) {
	style := presentationStyle{bom: bytes.HasPrefix(input, utf8BOM)}
	hasLF := false
	hasCRLF := false
	for position := 0; position < len(input); position++ {
		switch input[position] {
		case '\r':
			if position+1 >= len(input) || input[position+1] != '\n' {
				return presentationStyle{}, errFormatUnsafe
			}
		case '\n':
			if position > 0 && input[position-1] == '\r' {
				hasCRLF = true
			} else {
				hasLF = true
			}
		}
	}
	if hasLF && hasCRLF {
		return presentationStyle{}, errFormatUnsafe
	}
	style.crlf = hasCRLF
	if style.crlf {
		style.terminalNewline = bytes.HasSuffix(input, []byte("\r\n"))
	} else {
		style.terminalNewline = bytes.HasSuffix(input, []byte("\n"))
	}
	return style, nil
}

func decodePresentation(input []byte, style presentationStyle) (yaml.Node, error) {
	if style.bom {
		if !bytes.HasPrefix(input, utf8BOM) {
			return yaml.Node{}, errFormatUnsafe
		}
		input = input[len(utf8BOM):]
	}
	decoder := yaml.NewDecoder(bytes.NewReader(input))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil || len(root.Content) == 0 {
		return yaml.Node{}, errFormatUnsafe
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return yaml.Node{}, errFormatUnsafe
	}
	return root, nil
}

func encodePresentation(root *yaml.Node, style presentationStyle) ([]byte, error) {
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(root); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	formatted := output.Bytes()
	if !style.terminalNewline {
		formatted = bytes.TrimSuffix(formatted, []byte("\n"))
	}
	if style.crlf {
		formatted = bytes.ReplaceAll(formatted, []byte("\n"), []byte("\r\n"))
	}
	if style.bom {
		formatted = append(append([]byte(nil), utf8BOM...), formatted...)
	} else {
		formatted = append([]byte(nil), formatted...)
	}
	return formatted, nil
}

type commentRecord struct {
	Path string
	Kind string
	Text string
}

func collectComments(node *yaml.Node, path string) []commentRecord {
	if node == nil {
		return nil
	}
	comments := make([]commentRecord, 0)
	for _, comment := range []struct {
		kind string
		text string
	}{
		{kind: "head", text: node.HeadComment},
		{kind: "line", text: node.LineComment},
		{kind: "foot", text: node.FootComment},
	} {
		if comment.text != "" {
			comments = append(comments, commentRecord{Path: path, Kind: comment.kind, Text: comment.text})
		}
	}
	for index, child := range node.Content {
		childPath := fmt.Sprintf("%s/%d", path, index)
		comments = append(comments, collectComments(child, childPath)...)
	}
	return comments
}

type inPlaceFile struct {
	path string
	info os.FileInfo
	mode os.FileMode
}

func loadInPlacePath(path string, maximum int64) (loadedInput, *inPlaceFile) {
	sourceID := boundedSourceID(path)
	extension := strings.ToLower(filepath.Ext(path))
	if extension != ".yaml" && extension != ".yml" {
		return loadedInput{sourceID: sourceID, readErr: errUnsupportedFileType}, nil
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return loadedInput{sourceID: sourceID, readErr: fmt.Errorf("inspect input: %w", err)}, nil
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 {
		return loadedInput{sourceID: sourceID, readErr: errInputSymlink}, nil
	}
	if !pathInfo.Mode().IsRegular() {
		return loadedInput{sourceID: sourceID, readErr: errInputNotRegular}, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return loadedInput{sourceID: sourceID, readErr: fmt.Errorf("open input: %w", err)}, nil
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		return loadedInput{sourceID: sourceID, readErr: errInputNotRegular}, nil
	}
	return loadReader(file, sourceID, maximum), &inPlaceFile{
		path: path, info: openedInfo, mode: openedInfo.Mode().Perm(),
	}
}

func atomicReplaceRegularFile(state *inPlaceFile, content []byte) (resultErr error) {
	current, err := os.Lstat(state.path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() ||
		!os.SameFile(state.info, current) {
		return errFormatUnsafe
	}

	directory := filepath.Dir(state.path)
	temporary, err := os.CreateTemp(directory, ".bonvoyage-format-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		if temporary != nil {
			_ = temporary.Close()
		}
		if temporaryPath != "" {
			_ = os.Remove(temporaryPath)
		}
	}()

	if _, err := temporary.Write(content); err != nil {
		return err
	}
	// Keep the temporary file owner-only while it contains partial output.
	// Restore source ownership and permissions only after the complete document
	// is present; either metadata failure aborts before the rename.
	if err := preserveFileOwnership(temporary, state.info); err != nil {
		return err
	}
	if err := temporary.Chmod(state.mode); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	temporary = nil

	current, err = os.Lstat(state.path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() ||
		!os.SameFile(state.info, current) {
		return errFormatUnsafe
	}
	if err := os.Rename(temporaryPath, state.path); err != nil {
		return err
	}
	temporaryPath = ""
	return nil
}
