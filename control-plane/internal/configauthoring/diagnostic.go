package configauthoring

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

var (
	errUnsupportedFileType = errors.New("input filename does not have a supported extension")
	errInputNotRegular     = errors.New("input does not resolve to a regular file")
	errInputSymlink        = errors.New("in-place input is a symbolic link")
	yamlLinePattern        = regexp.MustCompile(`(?:^|[ :])line ([0-9]+)(?::|$)`)
)

func inputDiagnostic(code string) Diagnostic {
	messages := map[string]string{
		"BV_CFG_DIFF_INPUT_INVALID":       "The selected diff input is not an accepted configuration.",
		"BV_CFG_EXPLAIN_PATH_UNKNOWN":     "The field path is not present in the explanation catalog for this release.",
		"BV_CFG_FILE_TYPE_UNSUPPORTED":    "The input filename does not use a supported YAML extension.",
		"BV_CFG_FORMAT_UNSAFE":            "The document could not be formatted while preserving every required source and semantic invariant.",
		"BV_CFG_INPUT_ENCODING":           "The input is not valid UTF-8.",
		"BV_CFG_INPUT_NOT_REGULAR":        "The input path does not resolve to a regular file.",
		"BV_CFG_INPUT_SYMLINK":            "A symbolic link cannot be replaced by an in-place operation.",
		"BV_CFG_INPUT_TOO_LARGE":          "The input exceeds the maximum supported configuration size.",
		"BV_CFG_INPUT_UNREADABLE":         "The input could not be read.",
		"BV_CFG_INTERNAL":                 "The configuration operation failed internally.",
		"BV_CFG_MIGRATION_UNSUPPORTED":    "The requested configuration schema migration is not available in this release.",
		"BV_CFG_OUTPUT_LIMIT_EXCEEDED":    "The operation result exceeds the maximum supported output size.",
		"BV_CFG_PREVIEW_INPUT_INVALID":    "The selected preview input is not an accepted configuration.",
		"BV_CFG_SECRET_LITERAL_FORBIDDEN": "Secret contents are forbidden; configure a deployment-secret filename instead.",
		"BV_CFG_VERSION_MISMATCH":         "The input does not match the required installed version identities.",
	}
	return Diagnostic{Code: code, Severity: "error", Message: messages[code], Redacted: false}
}

func compileDiagnostic(err error, index *sourceIndex) Diagnostic {
	raw := err.Error()
	path := compilerPath(raw)
	code := "BV_CFG_SEMANTIC_INVALID"
	message := "The configuration is not semantically valid."

	switch {
	case strings.Contains(raw, "document is empty"):
		code, message = "BV_CFG_YAML_EMPTY", "The YAML document is empty."
	case strings.Contains(raw, "aliases and merge keys"):
		code, message = "BV_CFG_YAML_ALIAS_UNSUPPORTED", "YAML aliases and merge keys are not supported."
	case strings.Contains(raw, "multiple documents"):
		code, message = "BV_CFG_YAML_MULTIPLE_DOCUMENTS", "Only one YAML document is supported."
	case strings.Contains(raw, "node limit") || strings.Contains(raw, "nesting limit"):
		code, message = "BV_CFG_YAML_LIMIT_EXCEEDED", "The YAML document exceeds a structural safety limit."
	case strings.Contains(raw, "field ") && strings.Contains(raw, "not found in type"):
		code, message = "BV_CFG_SCHEMA_UNKNOWN_FIELD", "The document contains a field that is not supported by this release."
	case strings.Contains(raw, "cannot unmarshal"):
		code, message = "BV_CFG_SCHEMA_TYPE", "A field has a value of the wrong type."
	case strings.Contains(raw, "snapshot.schema_version: required"):
		code, message = "BV_CFG_SCHEMA_VERSION_REQUIRED", "The configuration schema version is required."
	case strings.Contains(raw, "snapshot.schema_version:") && strings.Contains(raw, "only version"):
		code, message = "BV_CFG_SCHEMA_VERSION_UNSUPPORTED", "The configuration schema version is not supported by this release."
	case path != "" && index.containsPEMLiteralAt(path):
		code, message = "BV_CFG_SECRET_LITERAL_FORBIDDEN", "Secret contents are forbidden; configure a deployment-secret filename instead."
	case strings.Contains(raw, "references unknown"):
		code, message = "BV_CFG_REFERENCE_MISSING", "A configuration reference does not resolve to a declared resource."
	case strings.Contains(raw, "duplicate") || strings.Contains(raw, "already owned"):
		code, message = "BV_CFG_REFERENCE_DUPLICATE", "A configuration resource, binding, or reference is duplicated."
	case strings.Contains(raw, "required") || strings.Contains(raw, "at least one") || strings.Contains(raw, "exactly one"):
		code, message = "BV_CFG_SCHEMA_REQUIRED_FIELD", "A required field, collection, or exclusive choice is missing."
	case strings.Contains(raw, "parse YAML"):
		code, message = "BV_CFG_YAML_SYNTAX", "The YAML document is not syntactically valid."
	case strings.Contains(raw, "must ") || strings.Contains(raw, "unsupported") ||
		strings.Contains(raw, "between ") || strings.Contains(raw, "exceed"):
		code, message = "BV_CFG_SCHEMA_CONSTRAINT", "A field violates a configuration constraint."
	}

	diagnostic := Diagnostic{
		Code: code, Severity: "error", Message: message, Path: path, Redacted: true,
	}
	if path != "" {
		diagnostic.Source = index.sourceForPath(path)
	} else if line := yamlErrorLine(raw); line > 0 {
		diagnostic.Source = index.sourceForLine(line)
	}
	return diagnostic
}

func compilerPath(message string) string {
	prefix, _, found := strings.Cut(message, ":")
	if !found || strings.ContainsAny(prefix, " \n\r\t") {
		return ""
	}
	segments := strings.Split(prefix, ".")
	if len(segments) == 0 {
		return ""
	}
	root, indexes, ok := pathSegment(segments[0])
	if !ok {
		return ""
	}
	if _, known := knownRootFields[root]; !known {
		return ""
	}
	result := "/" + escapePointerToken(root)
	for _, index := range indexes {
		result += "/" + index
	}
	for _, segment := range segments[1:] {
		name, indexes, ok := pathSegment(segment)
		if !ok {
			return ""
		}
		result += "/" + escapePointerToken(name)
		for _, index := range indexes {
			result += "/" + index
		}
	}
	return result
}

func pathSegment(segment string) (string, []string, bool) {
	nameEnd := strings.IndexByte(segment, '[')
	if nameEnd < 0 {
		nameEnd = len(segment)
	}
	name := segment[:nameEnd]
	if name == "" {
		return "", nil, false
	}
	for _, r := range name {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return "", nil, false
		}
	}
	remainder := segment[nameEnd:]
	var indexes []string
	for remainder != "" {
		if remainder[0] != '[' {
			return "", nil, false
		}
		end := strings.IndexByte(remainder, ']')
		if end < 2 {
			return "", nil, false
		}
		index := remainder[1:end]
		if _, err := strconv.ParseUint(index, 10, 32); err != nil {
			return "", nil, false
		}
		indexes = append(indexes, index)
		remainder = remainder[end+1:]
	}
	return name, indexes, true
}

func yamlErrorLine(message string) int {
	match := yamlLinePattern.FindStringSubmatch(message)
	if len(match) != 2 {
		return 0
	}
	line, err := strconv.Atoi(match[1])
	if err != nil {
		return 0
	}
	return line
}
