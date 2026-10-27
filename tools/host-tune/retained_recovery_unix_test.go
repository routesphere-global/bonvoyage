//go:build linux || darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func retainedFixture(t *testing.T) (string, string, map[string][]byte) {
	t.Helper()
	policyBytes, err := os.ReadFile("../../deploy/tuning/policies/throughput-balanced.yaml")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := decodeTuningPolicy(policyBytes)
	if err != nil {
		t.Fatal(err)
	}
	inventory := testInventory(16, 1)
	inventory.Host.BootID = "12345678-1234-1234-1234-123456789abc"
	inventoryBytes, _ := json.Marshal(inventory)
	plan, err := buildPlan(policy, digest(policyBytes), inventory, digest(inventoryBytes), "auto", 4, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	files, err := renderPlanArtifacts(plan)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := runningTuningExecution()
	if err != nil {
		t.Fatal(err)
	}
	files["execution.json"], _ = json.Marshal(execution)
	files["inventory.json"] = inventoryBytes
	files["policy.yaml"] = policyBytes
	dir := filepath.Join(t.TempDir(), "retained")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir, writeRetainedFixture(t, dir, files), files
}
func writeRetainedFixture(t *testing.T, dir string, files map[string][]byte) string {
	t.Helper()
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest := tuningFileManifest(files)
	if err := os.WriteFile(filepath.Join(dir, "checksums.sha256"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	return digest(manifest)
}

func TestRetainedStagingCreatesExclusiveVerifiedBundle(t *testing.T) {
	_, _, files := retainedFixture(t)
	var plan tuningPlan
	if err := decodeTuningJSON(files["tuning-plan.json"], &plan); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "review")
	anchor, err := stageRetainedTuningInputs(output, files["policy.yaml"], files["inventory.json"], plan)
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := loadRetainedTuningInputs(output, anchor)
	if err != nil || inputs.transaction.Execution == nil {
		t.Fatalf("%+v %v", inputs, err)
	}
	if _, err := stageRetainedTuningInputs(output, files["policy.yaml"], files["inventory.json"], plan); err == nil {
		t.Fatal("existing retained review overwritten")
	}
	plan.Memory.SystemdMemoryMaxMiB++
	rejected := filepath.Join(t.TempDir(), "invalid")
	if _, err := stageRetainedTuningInputs(rejected, files["policy.yaml"], files["inventory.json"], plan); err == nil {
		t.Fatal("non-regenerated plan staged")
	}
	if _, err := os.Stat(rejected); !os.IsNotExist(err) {
		t.Fatal("invalid staging created output")
	}
}

func TestRetainedInputRoundTripAndApply(t *testing.T) {
	dir, anchor, _ := retainedFixture(t)
	inputs, err := loadRetainedTuningInputs(dir, anchor)
	if err != nil {
		t.Fatal(err)
	}
	_, backend, journal := transactionFixture(t)
	backend.identity = inputs.transaction.Identity
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	outcome, err := applyTuningTransaction(ctx, inputs.transaction, inputs.transaction.IntentSHA256, backend, journal)
	if err != nil || outcome.Status != "applied" || outcome.MeasurementAuthorized {
		t.Fatalf("%+v %v", outcome, err)
	}
	if journal.prepared.Execution == nil {
		t.Fatal("execution binding not retained")
	}
}
func TestRetainedInputsRejectTamperingAndForeignArtifacts(t *testing.T) {
	for _, mode := range []string{"unanchored", "changed-bytes", "rehashed-render", "missing", "extra", "traversal",
		"execution", "contract", "unknown-json", "duplicate-json", "trailing-json", "trailing-yaml", "stale-inventory"} {
		t.Run(mode, func(t *testing.T) {
			dir, anchor, files := retainedFixture(t)
			switch mode {
			case "unanchored":
				anchor = ""
			case "changed-bytes":
				if err := os.WriteFile(filepath.Join(dir, "irqbalance.env"), []byte("tampered"), 0o600); err != nil {
					t.Fatal(err)
				}
			default:
				switch mode {
				case "rehashed-render":
					files["bonvoyage-runtime-arguments.txt"] = []byte("--smp 99 --cpuset 1 --memory 1M\n")
				case "missing":
					delete(files, "README.txt")
					if err := os.Remove(filepath.Join(dir, "README.txt")); err != nil {
						t.Fatal(err)
					}
				case "extra":
					files["unexpected.txt"] = []byte("extra")
				case "traversal":
					if err := os.WriteFile(filepath.Join(dir, "checksums.sha256"), []byte(strings.Repeat("a", 64)+"  ../outside\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					anchor = digest([]byte(strings.Repeat("a", 64) + "  ../outside\n"))
				case "execution", "contract":
					var binding tuningExecutionBinding
					if err := json.Unmarshal(files["execution.json"], &binding); err != nil {
						t.Fatal(err)
					}
					if mode == "execution" {
						binding.ExecutableSHA256 = strings.Repeat("a", 64)
					} else {
						binding.ServiceContractVersion++
					}
					files["execution.json"], _ = json.Marshal(binding)
				case "unknown-json":
					files["inventory.json"] = append([]byte("{\"unknown\":1,"), files["inventory.json"][1:]...)
				case "duplicate-json":
					files["inventory.json"] = append([]byte("{\"schema_version\":2,"), files["inventory.json"][1:]...)
				case "trailing-json":
					files["inventory.json"] = append(files["inventory.json"], []byte("{}")...)
				case "trailing-yaml":
					files["policy.yaml"] = append(files["policy.yaml"], []byte("\n---\nfoo: bar\n")...)
				case "stale-inventory":
					files["inventory.json"] = []byte(strings.Replace(string(files["inventory.json"]), "12345678-1234", "99999999-9999", 1))
				}
				if mode != "traversal" {
					anchor = writeRetainedFixture(t, dir, files)
				}
			}
			if _, err := loadRetainedTuningInputs(dir, anchor); err == nil {
				t.Fatal("unsafe retained package accepted")
			}
		})
	}
}
func TestRetainedInputsRejectUnsafeFilesystem(t *testing.T) {
	for _, mode := range []string{"public-directory", "public-file", "symlink-file", "symlink-directory", "hardlink", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			dir, anchor, _ := retainedFixture(t)
			target := filepath.Join(dir, "inventory.json")
			var err error
			switch mode {
			case "public-directory":
				err = os.Chmod(dir, 0o755)
			case "public-file":
				err = os.Chmod(target, 0o644)
			case "symlink-file":
				err = os.Remove(target)
				if err == nil {
					err = os.Symlink("/etc/passwd", target)
				}
			case "symlink-directory":
				link := dir + "-link"
				err = os.Symlink(dir, link)
				dir = link
			case "hardlink":
				err = os.Link(target, filepath.Join(t.TempDir(), "linked"))
			case "oversized":
				err = os.WriteFile(target, make([]byte, 1024*1024+1), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := loadRetainedTuningInputs(dir, anchor); err == nil {
				t.Fatal("unsafe filesystem accepted")
			}
		})
	}
}
func TestStrictTuningJSONRejectsAmbiguity(t *testing.T) {
	for _, data := range []string{`{"a":1,"a":2}`, `{"a":1,"A":2}`, `{"a":{"x":1,"x":2}}`, `{"a":1}{}`, strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66)} {
		var target any
		if err := decodeTuningJSON([]byte(data), &target); err == nil {
			t.Fatal("ambiguous JSON accepted")
		}
	}
}

func interruptedNativeFixture(t *testing.T, count int, lastWritten, activated bool) (*nativeFixture, verifiedTuningInputs, tuningRecoverySource) {
	t.Helper()
	f := newNativeFixture(t)
	execution, err := runningTuningExecution()
	if err != nil {
		t.Fatal(err)
	}
	f.tx.Execution = &execution
	f.tx.IntentSHA256 = tuningIntentDigest(f.tx)
	inputs := verifiedTuningInputs{transaction: f.tx, manifestSHA256: strings.Repeat("a", 64)}
	// The loader is tested independently above; this native fixture substitutes
	// the current test UID for root so real temporary writes need no privileges.
	inputs.transaction.Changes = append([]tuningChange(nil), f.tx.Changes...)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	unlock, err := f.backend.Lock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	for i := range f.tx.Changes {
		f.tx.Changes[i].Before, err = f.backend.Read(ctx, f.tx.Changes[i].Control)
		if err != nil {
			t.Fatal(err)
		}
	}
	f.tx.RuntimeBefore, err = captureTuningRuntime(ctx, f.backend)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "original")
	journal, err := newTuningJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err = journal.Record("prepared", f.tx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < count; i++ {
		if err = journal.Record("write-intent", i); err != nil {
			t.Fatal(err)
		}
		if i < count-1 || lastWritten {
			change := f.tx.Changes[i]
			if err = f.backend.Replace(ctx, change.Control, change.Before, change.After); err != nil {
				t.Fatal(err)
			}
		}
	}
	if activated {
		if err = f.backend.Verify(ctx, f.tx.Plan); err != nil {
			t.Fatal(err)
		}
	}
	files, err := readPrivateTuningDirectory(directory, 32)
	if err != nil {
		t.Fatal(err)
	}
	source, err := loadTuningRecovery(directory, digest(tuningFileManifest(files)), inputs)
	if err != nil {
		t.Fatal(err)
	}
	return f, inputs, source
}
func recoverNativeFixture(t *testing.T, f *nativeFixture, inputs verifiedTuningInputs, source tuningRecoverySource) (tuningOutcome, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	review, err := reviewTuningRecovery(ctx, inputs, source, f.backend)
	if err != nil {
		return tuningOutcome{Status: "rejected"}, err
	}
	directory := filepath.Join(t.TempDir(), "recovery")
	journal, err := newTuningJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := recoverTuningTransaction(ctx, inputs, source, review.ApprovalSHA256, f.backend, journal)
	if err == nil {
		if _, verifyErr := verifyTuningJournal(directory); verifyErr != nil {
			t.Fatal(verifyErr)
		}
	}
	return outcome, err
}
func TestRecoveryRestoresEveryWriteBoundary(t *testing.T) {
	for count := 0; count <= 3; count++ {
		for _, written := range []bool{false, true} {
			t.Run(fmt.Sprintf("intents-%d-written-%v", count, written), func(t *testing.T) {
				f, inputs, source := interruptedNativeFixture(t, count, written, false)
				original, err := os.ReadFile(filepath.Join(source.directory, "000001.json"))
				if err != nil {
					t.Fatal(err)
				}
				outcome, err := recoverNativeFixture(t, f, inputs, source)
				if err != nil || outcome.Status != "recovery-restored" || outcome.MeasurementAuthorized {
					t.Fatalf("%+v %v", outcome, err)
				}
				for _, p := range nativeControlPaths {
					if _, err := os.Stat(f.root + p); !os.IsNotExist(err) {
						t.Fatal("not restored")
					}
				}
				after, _ := os.ReadFile(filepath.Join(source.directory, "000001.json"))
				if string(after) != string(original) {
					t.Fatal("original journal edited")
				}
			})
		}
	}
}
func TestRecoveryRestoresActivatedOrPendingReload(t *testing.T) {
	for _, mode := range []string{"activated", "pending-reload"} {
		t.Run(mode, func(t *testing.T) {
			f, inputs, source := interruptedNativeFixture(t, 3, true, mode == "activated")
			if mode == "pending-reload" {
				pending := true
				f.backend.command = func(ctx context.Context, args ...string) (string, error) {
					if args[0] == "daemon-reload" {
						pending = false
					}
					value, err := f.command(ctx, args...)
					if pending {
						value = strings.ReplaceAll(value, "NeedDaemonReload=no", "NeedDaemonReload=yes")
					}
					return value, err
				}
			}
			outcome, err := recoverNativeFixture(t, f, inputs, source)
			if err != nil || outcome.Status != "recovery-restored" {
				t.Fatalf("%+v %v", outcome, err)
			}
			if f.state.CPUs != "0-15" || f.state.MemoryMax != "max" || f.state.IRQBan != "" ||
				!reflect.DeepEqual(f.state.Arguments, nativeArguments([]byte("--smp 1 --memory 512M"))) {
				t.Fatal("original live policy not restored")
			}
		})
	}
}
func TestRecoveryRejectsConflictsIdentityAndLiveUncertainty(t *testing.T) {
	for _, mode := range []string{"file-edit", "unattempted", "boot", "topology", "queued-job", "stopped", "foreign-policy", "before-image"} {
		t.Run(mode, func(t *testing.T) {
			count := 3
			if mode == "unattempted" {
				count = 1
			}
			f, inputs, source := interruptedNativeFixture(t, count, true, false)
			switch mode {
			case "file-edit":
				if err := os.WriteFile(f.root+nativeControlPaths["service-resources"], []byte("foreign"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "unattempted":
				value, _ := encodeNativeControl("irqbalance-exclusion", f.tx.Changes[2].After.Data)
				if err := os.WriteFile(f.root+nativeControlPaths["irqbalance-exclusion"], value, 0o644); err != nil {
					t.Fatal(err)
				}
			case "boot", "topology":
				f.backend.probe = func(context.Context) (tuningIdentity, error) {
					identity := f.tx.Identity
					if mode == "boot" {
						identity.BootID = "other"
					} else {
						identity.TopologySHA256 = strings.Repeat("f", 64)
					}
					return identity, nil
				}
			case "queued-job":
				f.backend.command = func(ctx context.Context, args ...string) (string, error) {
					value, err := f.command(ctx, args...)
					return strings.ReplaceAll(value, "Job=\n", "Job=123\n"), err
				}
			case "stopped":
				f.badPID = true
			case "foreign-policy":
				f.state.Arguments = append(f.state.Arguments, "--foreign")
			case "before-image":
				// Even a reviewed, rehashed journal must satisfy the runtime contract.
				rewriteRecoveryJournal(t, &source, inputs, func(entries []tuningJournalEntry) {
					var tx tuningTransaction
					if err := json.Unmarshal(entries[0].Data, &tx); err != nil {
						t.Fatal(err)
					}
					tx.RuntimeBefore = nil
					entries[0].Data, _ = json.Marshal(tx)
				})
			}
			before, _ := os.ReadFile(f.root + nativeControlPaths["service-resources"])
			outcome, err := recoverNativeFixture(t, f, inputs, source)
			if err == nil || outcome.Status != "rejected" {
				t.Fatalf("%+v %v", outcome, err)
			}
			after, _ := os.ReadFile(f.root + nativeControlPaths["service-resources"])
			if string(before) != string(after) {
				t.Fatal("rejection mutated current controls")
			}
		})
	}
}
func rewriteRecoveryJournal(t *testing.T, source *tuningRecoverySource, inputs verifiedTuningInputs, edit func([]tuningJournalEntry)) {
	t.Helper()
	files, err := readPrivateTuningDirectory(source.directory, 32)
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]tuningJournalEntry, len(files))
	for i := range entries {
		var envelope tuningJournalEnvelope
		if err := json.Unmarshal(files[fmt.Sprintf("%06d.json", i+1)], &envelope); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(envelope.Entry, &entries[i]); err != nil {
			t.Fatal(err)
		}
	}
	edit(entries)
	previous := ""
	for i := range entries {
		entries[i].PreviousSHA256 = previous
		data, _ := json.Marshal(entries[i])
		previous = digest(data)
		envelope, _ := json.Marshal(tuningJournalEnvelope{previous, data})
		name := fmt.Sprintf("%06d.json", i+1)
		files[name] = envelope
		if err := os.WriteFile(filepath.Join(source.directory, name), envelope, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	source.sha256 = digest(tuningFileManifest(files))
}
func TestRecoveryRejectsJournalSemanticForgery(t *testing.T) {
	for _, mode := range []string{"duplicate-intent", "skipped-intent", "terminal-middle", "plan", "utility", "invalid-before", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			_, inputs, source := interruptedNativeFixture(t, 3, true, false)
			rewriteRecoveryJournal(t, &source, inputs, func(entries []tuningJournalEntry) {
				switch mode {
				case "duplicate-intent":
					entries[2].Data = json.RawMessage("0")
				case "skipped-intent":
					entries[1].Data = json.RawMessage("2")
				case "terminal-middle":
					entries[1].Kind = "rolled-back"
				default:
					var tx tuningTransaction
					if err := json.Unmarshal(entries[0].Data, &tx); err != nil {
						t.Fatal(err)
					}
					switch mode {
					case "plan":
						tx.Plan.Memory.SystemdMemoryMaxMiB++
					case "utility":
						tx.Execution.ExecutableSHA256 = strings.Repeat("a", 64)
					case "invalid-before":
						tx.Changes[0].Before = tuningValue{Mode: 0o7777}
					}
					entries[0].Data, _ = json.Marshal(tx)
				}
			})
			if mode == "truncated" {
				if err := os.WriteFile(filepath.Join(source.directory, "000004.json"), []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
				files, _ := readPrivateTuningDirectory(source.directory, 32)
				source.sha256 = digest(tuningFileManifest(files))
			}
			if _, err := loadTuningRecovery(source.directory, source.sha256, inputs); err == nil {
				t.Fatal("invalid semantics accepted")
			}
		})
	}
}
func TestRecoveryRequiresFreshApprovalAndOriginalJournal(t *testing.T) {
	for _, mode := range []string{"approval", "process", "journal"} {
		t.Run(mode, func(t *testing.T) {
			f, inputs, source := interruptedNativeFixture(t, 3, true, false)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			review, err := reviewTuningRecovery(ctx, inputs, source, f.backend)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "approval":
				review.ApprovalSHA256 = strings.Repeat("a", 64)
			case "process":
				f.state.GatewayPID++
			case "journal":
				if err := os.WriteFile(filepath.Join(source.directory, "000004.json"), []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			journal := &memoryTuningJournal{}
			outcome, err := recoverTuningTransaction(ctx, inputs, source, review.ApprovalSHA256, f.backend, journal)
			if err == nil || outcome.Status != "rejected" || len(journal.events) != 0 {
				t.Fatalf("%+v %v", outcome, err)
			}
		})
	}
}
func TestRecoveryPartialFailureCanBeReviewedAgain(t *testing.T) {
	f, inputs, source := interruptedNativeFixture(t, 3, true, true)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	review, err := reviewTuningRecovery(ctx, inputs, source, f.backend)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := recoverTuningTransaction(ctx, inputs, source, review.ApprovalSHA256, f.backend, &memoryTuningJournal{failKind: "recovery-write-intent"})
	if err == nil || outcome.Status != "recovery-required" {
		t.Fatalf("%+v %v", outcome, err)
	}
	outcome, err = recoverNativeFixture(t, f, inputs, source)
	if err != nil || outcome.Status != "recovery-restored" {
		t.Fatalf("%+v %v", outcome, err)
	}
}
func TestRecoveryRestoreFailureRemainsUnqualified(t *testing.T) {
	f, inputs, source := interruptedNativeFixture(t, 3, true, true)
	f.failRestart = true
	outcome, err := recoverNativeFixture(t, f, inputs, source)
	if err == nil || outcome.Status != "recovery-required" || outcome.MeasurementAuthorized {
		t.Fatalf("%+v %v", outcome, err)
	}
	outcome, err = recoverNativeFixture(t, f, inputs, source)
	if err != nil || outcome.Status != "recovery-restored" {
		t.Fatalf("%+v %v", outcome, err)
	}
}

type mutatingRecoveryLock struct {
	*nativeServiceBackend
	mutate func()
}

func (b *mutatingRecoveryLock) LockRecovery(ctx context.Context, tx tuningTransaction) (func(), error) {
	unlock, err := b.nativeServiceBackend.LockRecovery(ctx, tx)
	if err == nil {
		b.mutate()
	}
	return unlock, err
}
func TestRecoveryRechecksJournalAfterHostLock(t *testing.T) {
	for _, mode := range []string{"review", "execute"} {
		t.Run(mode, func(t *testing.T) {
			f, inputs, source := interruptedNativeFixture(t, 3, true, false)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			review, err := reviewTuningRecovery(ctx, inputs, source, f.backend)
			if err != nil {
				t.Fatal(err)
			}
			backend := &mutatingRecoveryLock{f.backend, func() {
				if err := os.WriteFile(filepath.Join(source.directory, "000004.json"), []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			}}
			if mode == "review" {
				if _, err := reviewTuningRecovery(ctx, inputs, source, backend); err == nil {
					t.Fatal("stale pre-lock journal accepted")
				}
			} else {
				journal := &memoryTuningJournal{}
				outcome, err := recoverTuningTransaction(ctx, inputs, source, review.ApprovalSHA256, backend, journal)
				if err == nil || outcome.Status != "rejected" || len(journal.events) != 0 {
					t.Fatalf("%+v %v", outcome, err)
				}
			}
		})
	}
}

type faultRecoveryJournal struct {
	memoryTuningJournal
	writes int
	failAt int
	mutate func()
}

func (j *faultRecoveryJournal) Record(kind string, data any) error {
	if kind == "recovery-write-intent" {
		j.writes++
		if j.mutate != nil {
			j.mutate()
			j.mutate = nil
		}
		if j.writes == j.failAt {
			return errors.New("interruption before next restoration")
		}
	}
	return j.memoryTuningJournal.Record(kind, data)
}
func TestRecoveryResumesPartiallyRestoredFiles(t *testing.T) {
	f, inputs, source := interruptedNativeFixture(t, 3, true, true)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	review, err := reviewTuningRecovery(ctx, inputs, source, f.backend)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := recoverTuningTransaction(ctx, inputs, source, review.ApprovalSHA256, f.backend, &faultRecoveryJournal{failAt: 2})
	if err == nil || outcome.Status != "recovery-required" {
		t.Fatalf("%+v %v", outcome, err)
	}
	if _, err := os.Stat(f.root + nativeControlPaths["irqbalance-exclusion"]); !os.IsNotExist(err) {
		t.Fatal("first restoration did not happen")
	}
	if _, err := os.Stat(f.root + nativeControlPaths["runtime-arguments"]); err != nil {
		t.Fatal("unexpected second restoration")
	}
	outcome, err = recoverNativeFixture(t, f, inputs, source)
	if err != nil || outcome.Status != "recovery-restored" {
		t.Fatalf("%+v %v", outcome, err)
	}
}
func TestRecoveryPreservesEditDuringRestoration(t *testing.T) {
	f, inputs, source := interruptedNativeFixture(t, 3, true, false)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	review, err := reviewTuningRecovery(ctx, inputs, source, f.backend)
	if err != nil {
		t.Fatal(err)
	}
	p := f.root + nativeControlPaths["irqbalance-exclusion"]
	journal := &faultRecoveryJournal{mutate: func() {
		if err := os.WriteFile(p, []byte("operator edit"), 0o644); err != nil {
			t.Fatal(err)
		}
	}}
	outcome, err := recoverTuningTransaction(ctx, inputs, source, review.ApprovalSHA256, f.backend, journal)
	if err == nil || outcome.Status != "recovery-required" {
		t.Fatalf("%+v %v", outcome, err)
	}
	data, _ := os.ReadFile(p)
	if string(data) != "operator edit" {
		t.Fatal("operator edit overwritten")
	}
}
func TestRecoveryRefusesCompletedOriginalJournals(t *testing.T) {
	for _, mode := range []string{"applied", "rolled-back"} {
		t.Run(mode, func(t *testing.T) {
			_, inputs, source := interruptedNativeFixture(t, 3, true, false)
			files, err := readPrivateTuningDirectory(source.directory, 32)
			if err != nil {
				t.Fatal(err)
			}
			var last tuningJournalEnvelope
			if err := json.Unmarshal(files["000004.json"], &last); err != nil {
				t.Fatal(err)
			}
			journal := &fileTuningJournal{directory: source.directory, sequence: 4, previous: last.SHA256}
			if mode == "applied" {
				if err := journal.Record("runtime-verified", struct{}{}); err != nil {
					t.Fatal(err)
				}
			}
			if err := journal.Record(mode, struct{}{}); err != nil {
				t.Fatal(err)
			}
			files, err = readPrivateTuningDirectory(source.directory, 32)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := loadTuningRecovery(source.directory, digest(tuningFileManifest(files)), inputs); err == nil {
				t.Fatal("completed run accepted for interruption recovery")
			}
		})
	}
}

func TestRecoveryHonorsDeadlinesAndPreMutationJournalFailure(t *testing.T) {
	f, inputs, source := interruptedNativeFixture(t, 3, true, false)
	if _, err := reviewTuningRecovery(context.Background(), inputs, source, f.backend); err == nil {
		t.Fatal("unbounded recovery accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	review, err := reviewTuningRecovery(ctx, inputs, source, f.backend)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := recoverTuningTransaction(ctx, inputs, source, review.ApprovalSHA256, f.backend, &memoryTuningJournal{failKind: "recovery-prepared"})
	if err == nil || outcome.Status != "rejected" {
		t.Fatalf("%+v %v", outcome, err)
	}
	cancel()
	if _, err := reviewTuningRecovery(ctx, inputs, source, f.backend); !errors.Is(err, context.Canceled) && err == nil {
		t.Fatal("cancelled recovery accepted")
	}
}
