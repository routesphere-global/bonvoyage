package configauthoring

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

var knownRootFields = map[string]struct{}{
	"server": {}, "snapshot": {}, "listeners": {}, "virtual_hosts": {},
	"clusters": {}, "runtime_limits": {},
}

type loadedInput struct {
	sourceID string
	data     []byte
	readErr  error
	tooLarge bool
}

func loadPath(path string, maximum int64) loadedInput {
	sourceID := boundedSourceID(path)
	extension := strings.ToLower(filepath.Ext(path))
	if extension != ".yaml" && extension != ".yml" {
		return loadedInput{sourceID: sourceID, readErr: errUnsupportedFileType}
	}

	info, err := os.Stat(path)
	if err != nil {
		return loadedInput{sourceID: sourceID, readErr: fmt.Errorf("stat input: %w", err)}
	}
	if !info.Mode().IsRegular() {
		return loadedInput{sourceID: sourceID, readErr: errInputNotRegular}
	}

	file, err := os.Open(path)
	if err != nil {
		return loadedInput{sourceID: sourceID, readErr: fmt.Errorf("open input: %w", err)}
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return loadedInput{sourceID: sourceID, readErr: fmt.Errorf("inspect input: %w", err)}
	}
	if !openedInfo.Mode().IsRegular() {
		return loadedInput{sourceID: sourceID, readErr: errInputNotRegular}
	}
	return loadReader(file, sourceID, maximum)
}

func loadReader(reader io.Reader, sourceID string, maximum int64) loadedInput {
	sourceID = boundedSourceID(sourceID)
	if reader == nil {
		return loadedInput{sourceID: sourceID, readErr: fmt.Errorf("read input: reader is nil")}
	}
	data, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	observed := data
	tooLarge := int64(len(data)) > maximum
	if tooLarge {
		observed = data[:maximum]
	}
	return loadedInput{sourceID: sourceID, data: observed, readErr: err, tooLarge: tooLarge}
}

func boundedSourceID(value string) string {
	if value == "" {
		return "input"
	}
	if utf8.RuneCountInString(value) <= maxSourceIDRunes {
		return value
	}
	return "input"
}

func inputRecord(input loadedInput) Input {
	digest := sha256.Sum256(input.data)
	return Input{
		SourceID: input.sourceID,
		Bytes:    len(input.data),
		SHA256:   fmt.Sprintf("%x", digest),
	}
}

type sourceIndex struct {
	sourceID string
	data     []byte
	nodes    map[string]*yaml.Node
}

func emptySourceIndex(sourceID string, data []byte) *sourceIndex {
	return &sourceIndex{sourceID: sourceID, data: data, nodes: make(map[string]*yaml.Node)}
}

func buildSourceIndex(sourceID string, data []byte) *sourceIndex {
	index := emptySourceIndex(sourceID, data)
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil || len(root.Content) == 0 {
		return index
	}
	index.walk(root.Content[0], "")
	return index
}

func (index *sourceIndex) walk(node *yaml.Node, path string) {
	if node == nil {
		return
	}
	if _, exists := index.nodes[path]; !exists {
		index.nodes[path] = node
	}
	switch node.Kind {
	case yaml.MappingNode:
		for position := 0; position+1 < len(node.Content); position += 2 {
			key := node.Content[position]
			value := node.Content[position+1]
			childPath := path + "/" + escapePointerToken(key.Value)
			index.nodes[childPath] = value
			index.walk(value, childPath)
		}
	case yaml.SequenceNode:
		for position, child := range node.Content {
			index.walk(child, path+"/"+strconv.Itoa(position))
		}
	}
}

func (index *sourceIndex) configurationSchemaVersion() *uint32 {
	node := index.nodes["/snapshot/schema_version"]
	if node == nil || node.Kind != yaml.ScalarNode {
		return nil
	}
	parsed, err := strconv.ParseUint(strings.TrimSpace(node.Value), 10, 32)
	if err != nil || parsed == 0 {
		return nil
	}
	value := uint32(parsed)
	return &value
}

func (index *sourceIndex) containsPEMLiteralAt(path string) bool {
	node := index.nodes[path]
	if node == nil || node.Kind != yaml.ScalarNode || !isSecretReferencePath(path) {
		return false
	}
	value := strings.ToUpper(node.Value)
	return strings.Contains(value, "-----BEGIN ") && strings.Contains(value, "-----")
}

func (index *sourceIndex) firstPEMLiteralPath() string {
	selected := ""
	for path := range index.nodes {
		if index.containsPEMLiteralAt(path) && (selected == "" || path < selected) {
			selected = path
		}
	}
	return selected
}

func (index *sourceIndex) sourceForPath(path string) *SourceRange {
	node := index.nodes[path]
	if node == nil || node.Line < 1 || node.Column < 1 {
		return nil
	}
	position, ok := index.position(node.Line, node.Column)
	if !ok {
		return nil
	}
	return &SourceRange{SourceID: index.sourceID, Start: position, End: position}
}

func (index *sourceIndex) sourceForLine(line int) *SourceRange {
	if line < 1 {
		return nil
	}
	start, end, ok := lineBounds(index.data, line)
	if !ok {
		return nil
	}
	position := start
	for position < end {
		r, width := utf8.DecodeRune(index.data[position:end])
		if r != ' ' && r != '\t' && r != '\ufeff' {
			break
		}
		position += width
	}
	column := 1 + utf8.RuneCount(index.data[start:position])
	if line == 1 && bytes.HasPrefix(index.data[start:position], []byte{0xef, 0xbb, 0xbf}) {
		column--
	}
	point := Position{Line: line, Column: column, ByteOffset: position}
	return &SourceRange{SourceID: index.sourceID, Start: point, End: point}
}

func (index *sourceIndex) position(line, column int) (Position, bool) {
	start, end, ok := lineBounds(index.data, line)
	if !ok {
		return Position{}, false
	}
	position := start
	if line == 1 && bytes.HasPrefix(index.data, []byte{0xef, 0xbb, 0xbf}) {
		position += 3
	}
	for current := 1; current < column; current++ {
		if position >= end {
			return Position{}, false
		}
		_, width := utf8.DecodeRune(index.data[position:end])
		position += width
	}
	return Position{Line: line, Column: column, ByteOffset: position}, true
}

func lineBounds(data []byte, requested int) (int, int, bool) {
	line := 1
	start := 0
	for position, value := range data {
		if line == requested && value == '\n' {
			end := position
			if end > start && data[end-1] == '\r' {
				end--
			}
			return start, end, true
		}
		if value == '\n' {
			line++
			start = position + 1
		}
	}
	if line == requested {
		return start, len(data), true
	}
	return 0, 0, false
}

func escapePointerToken(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

func isSecretReferencePath(path string) bool {
	for _, suffix := range []string{
		"/certificate_chain_secret", "/credentials_secret", "/jwks_secret",
		"/private_key_secret", "/trust_bundle_secret",
	} {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}
