package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type tuningJournalEntry struct {
	Sequence       int             `json:"sequence"`
	PreviousSHA256 string          `json:"previous_sha256"`
	Kind           string          `json:"kind"`
	Data           json.RawMessage `json:"data"`
}
type tuningJournalEnvelope struct {
	SHA256 string          `json:"sha256"`
	Entry  json.RawMessage `json:"entry"`
}
type fileTuningJournal struct {
	directory string
	sequence  int
	previous  string
	mu        sync.Mutex
}

func syncTuningDirectory(directory string) error {
	f, err := os.Open(directory)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

func newTuningJournal(directory string) (*fileTuningJournal, error) {
	// Never adopt an existing attempt, including a symlink or partial journal.
	if err := os.Mkdir(directory, 0o700); err != nil {
		return nil, err
	}
	if err := syncTuningDirectory(filepath.Dir(directory)); err != nil {
		return nil, err
	}
	return &fileTuningJournal{directory: directory}, nil
}

func validTuningEvent(kind string) bool {
	switch kind {
	case "prepared", "write-intent", "rollback-intent", "runtime-verified", "applied", "rolled-back", "recovery-required",
		"recovery-prepared", "recovery-write-intent", "recovery-restored":
		return true
	}
	return false
}

// Record does not return success until both the record and its directory entry
// have been synchronized. Failure leaves an incomplete attempt, never a reusable
// journal. Hash chaining detects mutation/reordering, not malicious re-signing.
func (j *fileTuningJournal) Record(kind string, data any) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !validTuningEvent(kind) {
		return errors.New("unknown tuning journal event")
	}
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}
	entry, err := json.Marshal(tuningJournalEntry{j.sequence + 1, j.previous, kind, payload})
	if err != nil {
		return err
	}
	hash := digest(entry)
	encoded, err := json.Marshal(tuningJournalEnvelope{hash, entry})
	if err != nil {
		return err
	}
	if len(encoded) > 1024*1024 {
		return errors.New("tuning journal record exceeds one MiB")
	}
	name := filepath.Join(j.directory, fmt.Sprintf("%06d.json", j.sequence+1))
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(append(encoded, '\n'))
	syncErr := f.Sync()
	closeErr := f.Close()
	if err = errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if err = syncTuningDirectory(j.directory); err != nil {
		return err
	}
	j.sequence++
	j.previous = hash
	return nil
}

func decodeTuningJSON(data []byte, target any) error {
	if err := rejectDuplicateTuningKeys(json.NewDecoder(bytes.NewReader(data)), 0); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing journal JSON")
	}
	return nil
}

// encoding/json otherwise accepts duplicate keys and overwrites earlier values.
func rejectDuplicateTuningKeys(d *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting limit")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim == '{' {
		keys := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || keys[strings.ToLower(name)] {
				return errors.New("duplicate JSON key")
			}
			keys[strings.ToLower(name)] = true
			if err := rejectDuplicateTuningKeys(d, depth+1); err != nil {
				return err
			}
		}
	} else if delim == '[' {
		for d.More() {
			if err := rejectDuplicateTuningKeys(d, depth+1); err != nil {
				return err
			}
		}
	} else {
		return errors.New("unexpected JSON delimiter")
	}
	_, err = d.Token()
	return err
}

// Integrity verification is diagnostic only. It neither replays changes nor
// grants rollback/measurement permission; interrupted attempts need reconciliation.
func verifyTuningJournal(directory string) ([]tuningJournalEntry, error) {
	files, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 || len(files) > 1024 {
		return nil, errors.New("invalid journal length")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name() < files[j].Name() })
	previous := ""
	entries := make([]tuningJournalEntry, 0, len(files))
	for i, file := range files {
		if file.Name() != fmt.Sprintf("%06d.json", i+1) || !file.Type().IsRegular() {
			return nil, errors.New("journal sequence gap or non-regular entry")
		}
		info, err := file.Info()
		if err != nil {
			return nil, err
		}
		if info.Size() > 1024*1024+1 || info.Mode().Perm() != 0o600 {
			return nil, errors.New("journal record exceeds bounds or is not private")
		}
		data, err := os.ReadFile(filepath.Join(directory, file.Name()))
		if err != nil {
			return nil, err
		}
		var envelope tuningJournalEnvelope
		if err := decodeTuningJSON(data, &envelope); err != nil {
			return nil, err
		}
		if digest(envelope.Entry) != envelope.SHA256 {
			return nil, errors.New("journal checksum mismatch")
		}
		var entry tuningJournalEntry
		if err := decodeTuningJSON(envelope.Entry, &entry); err != nil {
			return nil, err
		}
		if entry.Sequence != i+1 || entry.PreviousSHA256 != previous || !validTuningEvent(entry.Kind) {
			return nil, errors.New("journal chain mismatch")
		}
		entries = append(entries, entry)
		previous = envelope.SHA256
	}
	last := entries[len(entries)-1].Kind
	if (entries[0].Kind != "prepared" && entries[0].Kind != "recovery-prepared") ||
		(last != "applied" && last != "rolled-back" && last != "recovery-required" && last != "recovery-restored") {
		return entries, errors.New("journal is incomplete; operator reconciliation required")
	}
	return entries, nil
}
