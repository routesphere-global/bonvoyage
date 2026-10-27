package adminapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

func decodeStrictJSONBytes(contents []byte, destination any, maxDepth int) error {
	if len(contents) == 0 || !utf8.Valid(contents) {
		return errors.New("JSON body is empty or not valid UTF-8")
	}
	shape := json.NewDecoder(bytes.NewReader(contents))
	shape.UseNumber()
	first, err := shape.Token()
	if err != nil {
		return fmt.Errorf("decode JSON token: %w", err)
	}
	if err := consumeJSONValue(shape, first, 1, maxDepth); err != nil {
		return err
	}
	if token, err := shape.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("JSON body has trailing token %v", token)
		}
		return fmt.Errorf("decode JSON tail: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON object: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON body has a trailing value")
		}
		return fmt.Errorf("decode JSON object tail: %w", err)
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, token json.Token, depth, maxDepth int) error {
	if token == nil {
		return errors.New("JSON null values are not accepted")
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	if depth > maxDepth {
		return fmt.Errorf("JSON depth exceeds %d", maxDepth)
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode JSON object key: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, exists := keys[key]; exists {
				return fmt.Errorf("JSON object contains duplicate member %q", key)
			}
			keys[key] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode JSON object value: %w", err)
			}
			if err := consumeJSONValue(decoder, value, depth+1, maxDepth); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("JSON object is not closed")
		}
	case '[':
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode JSON array value: %w", err)
			}
			if err := consumeJSONValue(decoder, value, depth+1, maxDepth); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("JSON array is not closed")
		}
	default:
		return errors.New("unexpected JSON closing delimiter")
	}
	return nil
}
