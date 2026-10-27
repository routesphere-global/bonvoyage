package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

const maximumSSELineBytes = 64 << 10

type sseEvent struct {
	Event     string   `json:"event"`
	Data      []string `json:"data,omitempty"`
	ID        string   `json:"id,omitempty"`
	Heartbeat bool     `json:"heartbeat"`
	RawBytes  int      `json:"raw_bytes"`
}

func parseSSE(stream io.Reader, visit func(sseEvent) error) error {
	reader := bufio.NewReaderSize(stream, 16<<10)
	current := sseEvent{}
	hasFields := false
	dispatch := func() error {
		if !hasFields && !current.Heartbeat {
			return nil
		}
		if current.Event == "" && !current.Heartbeat {
			current.Event = "message"
		}
		if err := visit(current); err != nil {
			return err
		}
		current = sseEvent{}
		hasFields = false
		return nil
	}

	for {
		line, err := reader.ReadString('\n')
		if len(line) > maximumSSELineBytes {
			return errors.New("SSE line exceeds the fixture limit")
		}
		current.RawBytes += len(line)
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			if dispatchErr := dispatch(); dispatchErr != nil {
				return dispatchErr
			}
		} else if strings.HasPrefix(line, ":") {
			current.Heartbeat = true
		} else {
			name, value, found := strings.Cut(line, ":")
			if found && strings.HasPrefix(value, " ") {
				value = value[1:]
			}
			switch name {
			case "event":
				current.Event = value
				hasFields = true
			case "data":
				current.Data = append(current.Data, value)
				hasFields = true
			case "id":
				if strings.ContainsRune(value, '\x00') {
					return errors.New("SSE id contains NUL")
				}
				current.ID = value
				hasFields = true
			case "retry":
				// Retrying is a client concern; preserve framing without acting on it.
			default:
				// Unknown fields are ignored by the SSE processing model.
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if dispatchErr := dispatch(); dispatchErr != nil {
					return dispatchErr
				}
				return nil
			}
			return fmt.Errorf("read SSE stream: %w", err)
		}
	}
}

func formatSSE(event, id, data string) string {
	var output strings.Builder
	if id != "" {
		fmt.Fprintf(&output, "id: %s\n", id)
	}
	if event != "" {
		fmt.Fprintf(&output, "event: %s\n", event)
	}
	for _, line := range strings.Split(data, "\n") {
		fmt.Fprintf(&output, "data: %s\n", line)
	}
	output.WriteByte('\n')
	return output.String()
}
