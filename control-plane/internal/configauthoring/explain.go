package configauthoring

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"
)

const (
	maximumExplanationPathRunes      = 4096
	explanationCatalogClassification = "routesphere-bonvoyage-field-explanations"
)

//go:embed catalog/bonvoyage-field-explanations-v1.json
var explanationCatalogJSON []byte

type explanationCatalog struct {
	SchemaVersion              uint32                    `json:"schema_version"`
	Classification             string                    `json:"classification"`
	ContractVersion            string                    `json:"contract_version"`
	ConfigurationSchemaVersion uint32                    `json:"configuration_schema_version"`
	Entries                    []explanationCatalogEntry `json:"entries"`
}

type explanationCatalogEntry struct {
	Path    string `json:"path"`
	Title   string `json:"title"`
	Summary string `json:"summary"`
}

var (
	explanationCatalogOnce sync.Once
	loadedCatalog          explanationCatalog
	loadedCatalogErr       error
)

// Explain returns reviewed release-matched help for one RFC 6901 field path.
// It does not read a configuration document or inspect caller-owned values.
func Explain(path string, requirements Requirements) Response {
	catalog, err := loadExplanationCatalog()
	if err != nil {
		return failInternal(baseStaticResponse(OperationExplain, nil))
	}
	selectedSchemaVersion := catalog.ConfigurationSchemaVersion
	response := baseStaticResponse(OperationExplain, &selectedSchemaVersion)
	if versionMismatch(response.Versions, requirements) != "" {
		return refuse(response, inputDiagnostic("BV_CFG_VERSION_MISMATCH"))
	}
	requestedTokens, ok := parseExplanationPath(path)
	if !ok {
		return reject(response, inputDiagnostic("BV_CFG_EXPLAIN_PATH_UNKNOWN"))
	}
	for _, entry := range catalog.Entries {
		patternTokens, _ := parseExplanationPath(entry.Path)
		if explanationPathMatches(patternTokens, requestedTokens) {
			response.Status = "accepted"
			response.ExitCode = ExitAccepted
			response.FailureKind = "none"
			response.Result = &ExplanationResult{
				Kind: "field-explanation", Path: path,
				Title: entry.Title, Summary: entry.Summary,
			}
			return response
		}
	}
	return reject(response, inputDiagnostic("BV_CFG_EXPLAIN_PATH_UNKNOWN"))
}

func loadExplanationCatalog() (explanationCatalog, error) {
	explanationCatalogOnce.Do(func() {
		var err error
		loadedCatalog, err = decodeExplanationCatalog(explanationCatalogJSON)
		if err != nil {
			loadedCatalogErr = err
			return
		}
		if loadedCatalog.SchemaVersion != 1 ||
			loadedCatalog.Classification != explanationCatalogClassification ||
			loadedCatalog.ContractVersion != ContractVersion ||
			loadedCatalog.ConfigurationSchemaVersion != 1 || len(loadedCatalog.Entries) == 0 {
			loadedCatalogErr = errors.New("explanation catalog identity is invalid")
			return
		}
		previous := ""
		for index, entry := range loadedCatalog.Entries {
			if _, ok := parseExplanationPath(entry.Path); !ok ||
				entry.Title == "" || utf8.RuneCountInString(entry.Title) > 256 ||
				entry.Summary == "" || utf8.RuneCountInString(entry.Summary) > 4096 ||
				(index > 0 && entry.Path <= previous) {
				loadedCatalogErr = errors.New("explanation catalog entry is invalid")
				return
			}
			previous = entry.Path
		}
		paths := make([]string, len(loadedCatalog.Entries))
		for index, entry := range loadedCatalog.Entries {
			paths[index] = entry.Path
		}
		if !sort.StringsAreSorted(paths) {
			loadedCatalogErr = errors.New("explanation catalog is not sorted")
		}
	})
	return loadedCatalog, loadedCatalogErr
}

func decodeExplanationCatalog(contents []byte) (explanationCatalog, error) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var catalog explanationCatalog
	if err := decoder.Decode(&catalog); err != nil {
		return explanationCatalog{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return explanationCatalog{}, errors.New("explanation catalog has trailing content")
	}
	return catalog, nil
}

func parseExplanationPath(path string) ([]string, bool) {
	if !utf8.ValidString(path) || utf8.RuneCountInString(path) > maximumExplanationPathRunes {
		return nil, false
	}
	if path == "" {
		return []string{}, true
	}
	if !strings.HasPrefix(path, "/") {
		return nil, false
	}
	rawTokens := strings.Split(path[1:], "/")
	tokens := make([]string, 0, len(rawTokens))
	for _, raw := range rawTokens {
		var decoded strings.Builder
		for index := 0; index < len(raw); index++ {
			if raw[index] != '~' {
				decoded.WriteByte(raw[index])
				continue
			}
			if index+1 >= len(raw) || raw[index+1] != '0' && raw[index+1] != '1' {
				return nil, false
			}
			index++
			if raw[index] == '0' {
				decoded.WriteByte('~')
			} else {
				decoded.WriteByte('/')
			}
		}
		tokens = append(tokens, decoded.String())
	}
	return tokens, true
}

func explanationPathMatches(pattern, requested []string) bool {
	if len(pattern) != len(requested) {
		return false
	}
	for index := range pattern {
		if pattern[index] == requested[index] {
			continue
		}
		if pattern[index] != "*" || !canonicalArrayIndex(requested[index]) {
			return false
		}
	}
	return true
}

func canonicalArrayIndex(value string) bool {
	if value == "*" {
		return true
	}
	if value == "0" {
		return true
	}
	if value == "" || value[0] < '1' || value[0] > '9' {
		return false
	}
	for index := 1; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}
