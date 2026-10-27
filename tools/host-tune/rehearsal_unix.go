//go:build linux || darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

const nativeRehearsalBase = "/var/lib/bonvoyage-host-tune/rehearsals"

type rehearsalDependencies struct {
	host          func(verifiedTuningInputs, string) (tuningRecoveryBackend, func() error, error)
	evidenceClass string
}
type rehearsalReceipt struct {
	SchemaVersion            int                     `json:"schema_version"`
	Command                  string                  `json:"command"`
	Scope                    string                  `json:"scope,omitempty"`
	NICVerification          string                  `json:"nic_irq_verification,omitempty"`
	Purpose                  string                  `json:"purpose,omitempty"`
	Status                   string                  `json:"status"`
	EvidenceClass            string                  `json:"evidence_class"`
	InputManifestSHA256      string                  `json:"input_manifest_sha256,omitempty"`
	IntentSHA256             string                  `json:"intent_sha256,omitempty"`
	Execution                *tuningExecutionBinding `json:"execution,omitempty"`
	Identity                 *tuningIdentity         `json:"identity,omitempty"`
	JournalSHA256            string                  `json:"journal_sha256,omitempty"`
	JournalEntries           int                     `json:"journal_entries"`
	Review                   *tuningRecoveryReview   `json:"review,omitempty"`
	Reason                   string                  `json:"reason,omitempty"`
	MeasurementAuthorized    bool                    `json:"measurement_authorized"`
	NativeReadinessQualified bool                    `json:"native_readiness_qualified"`
}

func runRehearsal(arguments []string) error {
	deps := rehearsalDependencies{
		evidenceClass: "ubuntu-native-rehearsal-unqualified",
		host: func(inputs verifiedTuningInputs, output string) (tuningRecoveryBackend, func() error, error) {
			if err := validateNativeRehearsalOutput(output); err != nil {
				return nil, nil, err
			}
			b, err := newNativeServiceBackendForScope(inputs.inventory, inputs.transaction.Plan.Scope)
			if err != nil {
				return nil, nil, err
			}
			return b, b.Close, nil
		},
	}
	return runRehearsalWith(context.Background(), arguments, deps, os.Stdout)
}

func validateNativeRehearsalOutput(output string) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("native rehearsal requires Linux and root")
	}
	if err := validateNativeRehearsalPath(output); err != nil {
		return err
	}
	files, err := openNativeTuningFiles("/", 0)
	if err != nil {
		return err
	}
	defer files.root.Close()
	parent, _, err := files.parent(output)
	if err != nil {
		return err
	}
	defer parent.Close()
	st, err := parent.Stat()
	if err != nil {
		return err
	}
	if st.Mode().Perm() != 0o700 {
		return errors.New("native rehearsal evidence parent must have mode 0700")
	}
	return nil
}

func validateNativeRehearsalPath(output string) error {
	if output != filepath.Clean(output) || filepath.Dir(output) != nativeRehearsalBase ||
		!regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`).MatchString(filepath.Base(output)) {
		return errors.New("native evidence output must be a new named attempt under " + nativeRehearsalBase)
	}
	return nil
}

func readRehearsalInput(name string) ([]byte, error) {
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > 1024*1024 {
		return nil, errors.New("rehearsal input must be a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1024*1024 {
		return nil, errors.New("rehearsal input exceeds one MiB")
	}
	return data, nil
}

func runRehearsalWith(parent context.Context, arguments []string, deps rehearsalDependencies, stdout io.Writer) (resultErr error) {
	if len(arguments) == 0 || arguments[0] == "--help" || arguments[0] == "help" {
		_, err := fmt.Fprintln(stdout, "Usage: bonvoyage-host-tune rehearsal stage|check|snapshot|apply|review|restore [flags]\n"+
			"stage: --policy FILE --inventory FILE --plan DIRECTORY --plan-manifest SHA256 --output DIRECTORY\n"+
			"check: --inputs DIRECTORY --manifest SHA256 --output DIRECTORY\n"+
			"snapshot: --journal DIRECTORY --output DIRECTORY\n"+
			"apply: --inputs DIRECTORY --manifest SHA256 --approve INTENT --lab --maintenance --output DIRECTORY\n"+
			"review: --inputs DIRECTORY --manifest SHA256 --journal DIRECTORY --journal-sha256 SHA256 --purpose interrupted|rollback --lab --output DIRECTORY\n"+
			"restore: review flags plus --approve REVIEW_DIGEST --maintenance\n"+
			"Host operations accept --timeout DURATION (default 2m, maximum 10m).\n"+
			"Every command except snapshot accepts --scope full-host|vm-cpu-memory (default full-host); selection must match the retained plan.\n"+
			"VM scope requires a fixed-core plan and defers NIC affinity qualification; it never authorizes measurements.\n"+
			"Native host operations require Ubuntu 24.04/root and new evidence attempts under "+nativeRehearsalBase+".\n"+
			"Experimental lab commands restart BonVoyage and irqbalance. Results do not authorize measurements.")
		return err
	}
	command := arguments[0]
	if command != "stage" && command != "check" && command != "snapshot" && command != "apply" && command != "review" && command != "restore" {
		return fmt.Errorf("unknown rehearsal command %q", command)
	}
	flags := flag.NewFlagSet("rehearsal "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var output, inputsDir, manifest, policyPath, inventoryPath, planDir, planManifest, journalDir, journalSHA, purpose, approval string
	var lab, maintenance bool
	scope := tuningScopeFullHost
	timeout := 2 * time.Minute
	flags.StringVar(&output, "output", "", "new private evidence directory")
	if command != "snapshot" {
		flags.StringVar(&scope, "scope", scope, "verification scope matching the retained plan")
	}
	if command == "stage" {
		flags.StringVar(&policyPath, "policy", "", "policy YAML")
		flags.StringVar(&inventoryPath, "inventory", "", "inventory JSON")
		flags.StringVar(&planDir, "plan", "", "original plan directory")
		flags.StringVar(&planManifest, "plan-manifest", "", "reviewed original plan manifest digest")
	} else if command != "snapshot" {
		flags.StringVar(&inputsDir, "inputs", "", "verified retained bundle")
		flags.StringVar(&manifest, "manifest", "", "reviewed input manifest digest")
	}
	if command == "snapshot" || command == "review" || command == "restore" {
		flags.StringVar(&journalDir, "journal", "", "original journal directory")
	}
	if command == "review" || command == "restore" {
		flags.StringVar(&journalSHA, "journal-sha256", "", "reviewed original journal snapshot digest")
		flags.StringVar(&purpose, "purpose", "", "interrupted or rollback")
	}
	hostOperation := command == "apply" || command == "review" || command == "restore"
	if hostOperation {
		flags.BoolVar(&lab, "lab", false, "acknowledge an experimental lab operation")
		flags.DurationVar(&timeout, "timeout", timeout, "operation deadline")
	}
	if command == "apply" || command == "restore" {
		flags.BoolVar(&maintenance, "maintenance", false, "authorize restarting both services")
		flags.StringVar(&approval, "approve", "", "exact intent or recovery review approval")
	}
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || output == "" {
		return errors.New("new --output and no positional arguments are required")
	}
	if err := validateTuningScope(scope); err != nil {
		return err
	}
	if hostOperation && (!lab || timeout <= 0 || timeout > 10*time.Minute) {
		return errors.New("--lab and a timeout within ten minutes are required")
	}
	if (command == "apply" || command == "restore") && (!maintenance || !validSHA256(approval)) {
		return errors.New("--maintenance and an exact --approve digest are required")
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	receipt := rehearsalReceipt{SchemaVersion: 1, Command: command, Purpose: purpose, EvidenceClass: deps.evidenceClass}
	if command == "stage" {
		if policyPath == "" || inventoryPath == "" || planDir == "" || !validSHA256(planManifest) {
			return errors.New("stage requires policy, inventory, plan and reviewed plan manifest")
		}
		files, err := readPrivateTuningDirectory(planDir, 7)
		if err != nil {
			return err
		}
		m := files["checksums.sha256"]
		delete(files, "checksums.sha256")
		if digest(m) != planManifest || string(m) != string(tuningFileManifest(files)) {
			return errors.New("original plan manifest mismatch")
		}
		var plan tuningPlan
		if err := decodeTuningJSON(files["tuning-plan.json"], &plan); err != nil {
			return err
		}
		if effectiveTuningScope(plan.Scope) != scope {
			return errors.New("selected scope differs from original plan")
		}
		expected, err := renderPlanArtifacts(plan)
		if err != nil {
			return err
		}
		if len(files) != len(expected) {
			return errors.New("original plan membership mismatch")
		}
		for name, data := range expected {
			if string(files[name]) != string(data) {
				return errors.New("original plan artifact mismatch: " + name)
			}
		}
		policy, err := readRehearsalInput(policyPath)
		if err != nil {
			return err
		}
		inventory, err := readRehearsalInput(inventoryPath)
		if err != nil {
			return err
		}
		anchor, err := stageRetainedTuningInputs(output, policy, inventory, plan)
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(struct {
			ManifestSHA256        string `json:"manifest_sha256"`
			Output                string `json:"output"`
			Scope                 string `json:"scope"`
			NICVerification       string `json:"nic_irq_verification"`
			MeasurementAuthorized bool   `json:"measurement_authorized"`
		}{anchor, output, scope, tuningNICVerification(plan.Scope), false})
	}
	if command == "snapshot" {
		if journalDir == "" {
			return errors.New("--journal is required")
		}
		files, err := readPrivateTuningDirectory(journalDir, 32)
		if err != nil {
			return err
		}
		receipt.Status = "diagnostic-snapshot"
		receipt.JournalSHA256 = digest(tuningFileManifest(files))
		receipt.JournalEntries = len(files)
		if err := beginRehearsalOutput(output); err != nil {
			return err
		}
		if err := finishRehearsalOutput(output, &receipt, ""); err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(receipt)
	}
	if inputsDir == "" || !validSHA256(manifest) {
		return errors.New("--inputs and reviewed --manifest are required")
	}
	inputs, err := loadRetainedTuningInputs(inputsDir, manifest)
	if err != nil {
		return err
	}
	if effectiveTuningScope(inputs.transaction.Plan.Scope) != scope {
		return errors.New("selected scope differs from retained plan")
	}
	receipt.Scope = scope
	receipt.NICVerification = tuningNICVerification(inputs.transaction.Plan.Scope)
	receipt.InputManifestSHA256 = manifest
	receipt.IntentSHA256 = inputs.transaction.IntentSHA256
	receipt.Execution = inputs.transaction.Execution
	receipt.Identity = &inputs.transaction.Identity
	if command == "check" {
		receipt.Status = "verified-inputs"
		if err := beginRehearsalOutput(output); err != nil {
			return err
		}
		if err := finishRehearsalOutput(output, &receipt, ""); err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(receipt)
	}
	var source tuningRecoverySource
	if command == "apply" {
		if approval != inputs.transaction.IntentSHA256 {
			return errors.New("apply approval differs from verified intent")
		}
	} else {
		if journalDir == "" || !validSHA256(journalSHA) {
			return errors.New("review/restore requires original journal and reviewed snapshot digest")
		}
		source, err = loadTuningRestorationSource(journalDir, journalSHA, inputs, purpose)
		if err != nil {
			return err
		}
	}
	// Reject duplicate attempts before opening the native backend or host lock.
	if _, err := os.Lstat(output); err == nil {
		return errors.New("rehearsal output already exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	if deps.host == nil {
		return errors.New("rehearsal host adapter is unavailable")
	}
	backend, closeHost, err := deps.host(inputs, output)
	if err != nil {
		return err
	}
	if backend == nil || closeHost == nil {
		return errors.New("rehearsal host adapter contract incomplete")
	}
	defer func() { resultErr = errors.Join(resultErr, closeHost()) }()
	if err := beginRehearsalOutput(output); err != nil {
		return err
	}
	if command == "review" {
		review, reviewErr := reviewTuningRecovery(ctx, inputs, source, backend)
		receipt.Status = "reviewed"
		if reviewErr != nil {
			receipt.Status = "rejected"
			receipt.Reason = reviewErr.Error()
		} else {
			receipt.Review = &review
		}
		if err := finishRehearsalOutput(output, &receipt, ""); err != nil {
			return errors.Join(reviewErr, err)
		}
		return errors.Join(reviewErr, json.NewEncoder(stdout).Encode(receipt))
	}
	journalPath := filepath.Join(output, "journal")
	journal, err := newTuningJournal(journalPath)
	if err != nil {
		return err
	}
	var outcome tuningOutcome
	if command == "apply" {
		outcome, err = applyTuningTransaction(ctx, inputs.transaction, approval, backend, journal)
	} else {
		outcome, err = recoverTuningTransaction(ctx, inputs, source, approval, backend, journal)
	}
	receipt.Status = outcome.Status
	if err != nil {
		receipt.Reason = err.Error()
	}
	evidenceErr := finishRehearsalOutput(output, &receipt, journalPath)
	if evidenceErr != nil {
		return errors.Join(err, evidenceErr)
	}
	return errors.Join(err, json.NewEncoder(stdout).Encode(receipt))
}

func beginRehearsalOutput(output string) error {
	if err := os.Mkdir(output, 0o700); err != nil {
		return err
	}
	return syncTuningDirectory(filepath.Dir(output))
}
func writeRehearsalFile(output, name string, data []byte) error {
	f, err := os.OpenFile(filepath.Join(output, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	return errors.Join(writeErr, f.Sync(), f.Close())
}
func finishRehearsalOutput(output string, receipt *rehearsalReceipt, journal string) error {
	files := map[string][]byte{}
	if journal != "" {
		entries, err := os.ReadDir(journal)
		if err != nil {
			return err
		}
		if len(entries) > 0 {
			journalFiles, err := readPrivateTuningDirectory(journal, 32)
			if err != nil {
				return err
			}
			receipt.JournalSHA256 = digest(tuningFileManifest(journalFiles))
			receipt.JournalEntries = len(journalFiles)
			for name, data := range journalFiles {
				files["journal/"+name] = data
			}
		}
	}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	files["receipt.json"] = append(data, '\n')
	if err = writeRehearsalFile(output, "receipt.json", files["receipt.json"]); err != nil {
		return err
	}
	if err = writeRehearsalFile(output, "checksums.sha256", tuningFileManifest(files)); err != nil {
		return err
	}
	return syncTuningDirectory(output)
}
