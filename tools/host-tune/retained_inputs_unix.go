//go:build linux || darwin

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

type verifiedTuningInputs struct {
	transaction    tuningTransaction
	manifestSHA256 string
	inventory      hostInventory
}

var retainedInputNames = []string{
	"README.txt", "bonvoyage-resources.conf", "bonvoyage-runtime-arguments.txt",
	"execution.json", "inventory.json", "irq-affinity.plan.tsv", "irqbalance.env",
	"policy.yaml", "tuning-plan.json",
}

// The private directory is pinned by descriptor. Leaf names are never paths;
// no-follow, ownership and link checks apply to every captured file.
func readPrivateTuningDirectory(directory string, maximumFiles int) (map[string][]byte, error) {
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), directory)
	defer dir.Close()
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&0o7777 != 0o700 {
		return nil, errors.New("retained directory must be private and owned by caller")
	}
	entries, err := dir.ReadDir(maximumFiles + 1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) == 0 || len(entries) > maximumFiles {
		return nil, errors.New("retained file count exceeds bounds")
	}
	result := make(map[string][]byte, len(entries))
	total := 0
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return nil, errors.New("non-regular retained entry")
		}
		fileFD, err := unix.Openat(fd, entry.Name(), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		file := os.NewFile(uintptr(fileFD), entry.Name())
		var s unix.Stat_t
		err = unix.Fstat(fileFD, &s)
		if err != nil {
			file.Close()
			return nil, err
		}
		if s.Mode&unix.S_IFMT != unix.S_IFREG || s.Nlink != 1 || s.Uid != uint32(os.Geteuid()) ||
			s.Mode&0o7777 != 0o600 || s.Size > 1024*1024 {
			file.Close()
			return nil, errors.New("unsafe retained file metadata or size")
		}
		data, err := io.ReadAll(io.LimitReader(file, 1024*1024+1))
		file.Close()
		if err != nil {
			return nil, err
		}
		total += len(data)
		if len(data) > 1024*1024 || total > 16*1024*1024 {
			return nil, errors.New("retained byte limit")
		}
		result[entry.Name()] = data
	}
	return result, nil
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func tuningFileManifest(files map[string][]byte) []byte {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		fmt.Fprintf(&b, "%s  %s\n", digest(files[name]), name)
	}
	return []byte(b.String())
}

// expectedManifest comes from an independently reviewed transfer/approval record,
// never from the same directory's self-authored checksums alone.
func loadRetainedTuningInputs(directory, expectedManifest string) (verifiedTuningInputs, error) {
	rejected := verifiedTuningInputs{}
	if !validSHA256(expectedManifest) {
		return rejected, errors.New("reviewed manifest digest required")
	}
	files, err := readPrivateTuningDirectory(directory, len(retainedInputNames)+1)
	if err != nil {
		return rejected, err
	}
	manifest, ok := files["checksums.sha256"]
	if !ok || digest(manifest) != expectedManifest {
		return rejected, errors.New("retained manifest binding mismatch")
	}
	delete(files, "checksums.sha256")
	if len(files) != len(retainedInputNames) {
		return rejected, errors.New("incomplete retained inputs")
	}
	for _, name := range retainedInputNames {
		if _, ok := files[name]; !ok {
			return rejected, fmt.Errorf("missing input %s", name)
		}
	}
	if !bytes.Equal(manifest, tuningFileManifest(files)) {
		return rejected, errors.New("retained content/manifest mismatch")
	}
	policy, err := decodeTuningPolicy(files["policy.yaml"])
	if err != nil {
		return rejected, err
	}
	var inventory hostInventory
	var plan tuningPlan
	var execution tuningExecutionBinding
	for _, item := range []struct {
		name   string
		target any
	}{
		{"inventory.json", &inventory}, {"tuning-plan.json", &plan}, {"execution.json", &execution},
	} {
		if err := decodeTuningJSON(files[item.name], item.target); err != nil {
			return rejected, err
		}
	}
	current, err := runningTuningExecution()
	if err != nil || execution != current {
		return rejected, errors.New("retained execution identity does not match running utility")
	}
	tx, err := prepareTuningTransaction(policy, digest(files["policy.yaml"]), inventory, digest(files["inventory.json"]), plan)
	if err != nil {
		return rejected, err
	}
	expected, err := renderPlanArtifacts(plan)
	if err != nil {
		return rejected, err
	}
	for name, want := range expected {
		if !bytes.Equal(files[name], want) {
			return rejected, fmt.Errorf("non-regenerated plan artifact: %s", name)
		}
	}
	tx.Execution = &execution
	tx.IntentSHA256 = tuningIntentDigest(tx)
	return verifiedTuningInputs{tx, expectedManifest, inventory}, nil
}

func validateRetainedTransaction(inputs verifiedTuningInputs, tx tuningTransaction) error {
	if !validSHA256(inputs.manifestSHA256) || tx.Execution == nil ||
		inputs.transaction.Execution == nil {
		return errors.New("verified execution-bound inputs required")
	}
	current, err := runningTuningExecution()
	if err != nil || *tx.Execution != current {
		return errors.New("stale recovery utility or service contract")
	}
	a, b := tx, inputs.transaction
	a.RuntimeBefore = nil
	for i := range a.Changes {
		if !validTuningValue(a.Changes[i].Before) {
			return errors.New("invalid recovery before-image")
		}
	}
	a.Changes = append([]tuningChange(nil), a.Changes...)
	for i := range a.Changes {
		a.Changes[i].Before = tuningValue{}
	}
	encodedA, _ := json.Marshal(a)
	encodedB, _ := json.Marshal(b)
	if !bytes.Equal(encodedA, encodedB) {
		return errors.New("journal transaction differs from verified retained inputs")
	}
	return nil
}
