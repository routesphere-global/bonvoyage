//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Translate semantic root metadata only inside the private test fixture. The
// installed CLI has no fixture switch and always constructs the root backend.
type rehearsalFixtureBackend struct{ *nativeServiceBackend }

func (b rehearsalFixtureBackend) Read(ctx context.Context, key string) (tuningValue, error) {
	v, err := b.nativeServiceBackend.Read(ctx, key)
	if v.Exists {
		v.UID = 0
		v.GID = 0
	}
	return v, err
}
func (b rehearsalFixtureBackend) Replace(ctx context.Context, key string, before, after tuningValue) error {
	for _, v := range []*tuningValue{&before, &after} {
		if v.Exists {
			v.UID = os.Getuid()
			v.GID = os.Getgid()
		}
	}
	return b.nativeServiceBackend.Replace(ctx, key, before, after)
}
func rehearsalFixture(t *testing.T) (string, string, *nativeFixture, rehearsalDependencies) {
	t.Helper()
	dir, anchor, _ := retainedFixture(t)
	f := newNativeFixture(t)
	deps := rehearsalDependencies{evidenceClass: "local-command-fixture",
		host: func(inputs verifiedTuningInputs, _ string) (tuningRecoveryBackend, func() error, error) {
			f.backend.scope = inputs.transaction.Plan.Scope
			f.backend.probe = func(ctx context.Context) (tuningIdentity, error) { return inputs.transaction.Identity, ctx.Err() }
			return rehearsalFixtureBackend{f.backend}, func() error { return nil }, nil
		},
	}
	return dir, anchor, f, deps
}
func rehearsalCommand(t *testing.T, deps rehearsalDependencies, args ...string) (rehearsalReceipt, error) {
	t.Helper()
	var stdout bytes.Buffer
	err := runRehearsalWith(context.Background(), args, deps, &stdout)
	var receipt rehearsalReceipt
	if stdout.Len() > 0 {
		if decodeErr := decodeTuningJSON(stdout.Bytes(), &receipt); decodeErr != nil {
			t.Fatalf("decode receipt: %v %s", decodeErr, stdout.Bytes())
		}
	}
	return receipt, err
}
func checkRehearsalEvidence(t *testing.T, output string) rehearsalReceipt {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(output, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	var receipt rehearsalReceipt
	if err = decodeTuningJSON(data, &receipt); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"receipt.json": data}
	if receipt.JournalEntries > 0 {
		journal, err := readPrivateTuningDirectory(filepath.Join(output, "journal"), 32)
		if err != nil {
			t.Fatal(err)
		}
		if digest(tuningFileManifest(journal)) != receipt.JournalSHA256 {
			t.Fatal("journal digest mismatch")
		}
		for name, data := range journal {
			files["journal/"+name] = data
		}
	}
	checksums, err := os.ReadFile(filepath.Join(output, "checksums.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	if string(checksums) != string(tuningFileManifest(files)) {
		t.Fatal("receipt manifest mismatch")
	}
	if receipt.MeasurementAuthorized || receipt.NativeReadinessQualified {
		t.Fatal("local evidence qualified")
	}
	st, err := os.Stat(output)
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Fatal("evidence not private")
	}
	return receipt
}
func TestRehearsalCommandApplyReviewOrderlyRollback(t *testing.T) {
	testRehearsalOrderlyRollback(t, tuningScopeFullHost)
}
func testRehearsalOrderlyRollback(t *testing.T, scope string) {
	inputs, manifest, f, deps := rehearsalFixture(t)
	if scope == tuningScopeVMCPU {
		manifest = convertRetainedFixtureScope(t, inputs, scope)
		rejectFixtureIRQReads(f)
	}
	output := t.TempDir()
	common := []string{"--inputs", inputs, "--manifest", manifest, "--scope", scope}
	check := filepath.Join(output, "check")
	receipt, err := rehearsalCommand(t, deps, append([]string{"check"}, append(common, "--output", check)...)...)
	if err != nil || receipt.Status != "verified-inputs" {
		t.Fatalf("%+v %v", receipt, err)
	}
	checkRehearsalEvidence(t, check)
	applied := filepath.Join(output, "apply")
	receipt, err = rehearsalCommand(t, deps, append([]string{"apply"}, append(common, "--lab", "--maintenance", "--approve", receipt.IntentSHA256, "--output", applied)...)...)
	if err != nil || receipt.Status != "applied" {
		t.Fatalf("%+v %v", receipt, err)
	}
	applyReceipt := checkRehearsalEvidence(t, applied)
	if applyReceipt.Scope != scope || applyReceipt.NICVerification != tuningNICVerification(scope) {
		t.Fatal("apply scope missing from checksum-bound receipt")
	}
	bundle, err := loadRetainedTuningInputs(inputs, manifest)
	if err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(applied, "journal")
	if _, err := loadTuningRecovery(journal, receipt.JournalSHA256, bundle); err == nil {
		t.Fatal("completed apply admitted as interruption")
	}
	if f.state.CPUs != bundle.transaction.Plan.CPU.GatewayCPUSet {
		t.Fatal("planned live policy not active")
	}
	restoreCommon := append(append([]string{}, common...), "--journal", journal, "--journal-sha256", receipt.JournalSHA256, "--purpose", "rollback", "--lab")
	reviewOutput := filepath.Join(output, "review")
	receipt, err = rehearsalCommand(t, deps, append([]string{"review"}, append(restoreCommon, "--output", reviewOutput)...)...)
	if err != nil || receipt.Status != "reviewed" || receipt.Review == nil || receipt.Review.Purpose != "rollback" {
		t.Fatalf("%+v %v", receipt, err)
	}
	checkRehearsalEvidence(t, reviewOutput)
	if receipt.Review.Scope != scope || receipt.Review.NICVerification != tuningNICVerification(scope) {
		t.Fatal("recovery review lost scope")
	}
	restored := filepath.Join(output, "rollback")
	receipt, err = rehearsalCommand(t, deps, append([]string{"restore"}, append(restoreCommon, "--maintenance", "--approve", receipt.Review.ApprovalSHA256, "--output", restored)...)...)
	if err != nil || receipt.Status != "recovery-restored" {
		t.Fatalf("%+v %v", receipt, err)
	}
	checkRehearsalEvidence(t, restored)
	if _, err := verifyTuningJournal(filepath.Join(restored, "journal")); err != nil {
		t.Fatal(err)
	}
	for _, p := range nativeControlPaths {
		if _, err := os.Stat(f.root + p); !os.IsNotExist(err) {
			t.Fatal("owned control remains after rollback")
		}
	}
	if f.state.CPUs != "0-15" || f.state.MemoryMax != "max" || !reflect.DeepEqual(f.state.Arguments, nativeArguments([]byte("--smp 1 --memory 512M"))) {
		t.Fatal("prior effective policy not restored")
	}
	if checkRehearsalEvidence(t, applied).JournalSHA256 != applyReceipt.JournalSHA256 {
		t.Fatal("original receipt changed")
	}
}
func TestRehearsalCommandSnapshotsAndRecoversInterruptedApply(t *testing.T) {
	testRehearsalInterruptedRecovery(t, tuningScopeFullHost)
}
func testRehearsalInterruptedRecovery(t *testing.T, scope string) {
	inputDir, manifest, f, deps := rehearsalFixture(t)
	if scope == tuningScopeVMCPU {
		manifest = convertRetainedFixtureScope(t, inputDir, scope)
		rejectFixtureIRQReads(f)
	}
	inputs, err := loadRetainedTuningInputs(inputDir, manifest)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	backend, closeHost, err := deps.host(inputs, "")
	if err != nil {
		t.Fatal(err)
	}
	defer closeHost()
	unlock, err := backend.Lock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tx := inputs.transaction
	tx.Changes = append([]tuningChange(nil), tx.Changes...)
	for i := range tx.Changes {
		tx.Changes[i].Before, err = backend.Read(ctx, tx.Changes[i].Control)
		if err != nil {
			t.Fatal(err)
		}
	}
	tx.RuntimeBefore, err = captureTuningRuntime(ctx, backend)
	if err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(t.TempDir(), "original")
	j, err := newTuningJournal(original)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.Record("prepared", tx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err = j.Record("write-intent", i); err != nil {
			t.Fatal(err)
		}
		if i < 2 {
			c := tx.Changes[i]
			if err = backend.Replace(ctx, c.Control, c.Before, c.After); err != nil {
				t.Fatal(err)
			}
		}
	}
	unlock()
	output := t.TempDir()
	snapshot, err := rehearsalCommand(t, deps, "snapshot", "--journal", original, "--output", filepath.Join(output, "snapshot"))
	if err != nil || snapshot.Status != "diagnostic-snapshot" {
		t.Fatalf("%+v %v", snapshot, err)
	}
	if snapshot.Scope != "" || snapshot.NICVerification != "" {
		t.Fatal("diagnostic snapshot claimed a verified scope")
	}
	if _, err := loadTuningRollback(original, snapshot.JournalSHA256, inputs); err == nil {
		t.Fatal("interruption admitted to orderly rollback")
	}
	common := []string{"--inputs", inputDir, "--manifest", manifest, "--scope", scope, "--journal", original, "--journal-sha256", snapshot.JournalSHA256, "--purpose", "interrupted", "--lab"}
	review, err := rehearsalCommand(t, deps, append([]string{"review"}, append(common, "--output", filepath.Join(output, "review"))...)...)
	if err != nil || review.Review == nil {
		t.Fatalf("%+v %v", review, err)
	}
	receipt, err := rehearsalCommand(t, deps, append([]string{"restore"}, append(common, "--maintenance", "--approve", review.Review.ApprovalSHA256, "--output", filepath.Join(output, "restore"))...)...)
	if err != nil || receipt.Status != "recovery-restored" {
		t.Fatalf("%+v %v", receipt, err)
	}
	if receipt.Scope != scope || receipt.NICVerification != tuningNICVerification(scope) {
		t.Fatal("restore receipt lost scope")
	}
	for _, p := range nativeControlPaths {
		if _, err := os.Stat(f.root + p); !os.IsNotExist(err) {
			t.Fatal("interrupted state not restored")
		}
	}
	files, err := readPrivateTuningDirectory(original, 32)
	if err != nil || digest(tuningFileManifest(files)) != snapshot.JournalSHA256 {
		t.Fatal("original interruption evidence changed")
	}
}
func TestRehearsalRejectsInvalidRequestsBeforeHostFactory(t *testing.T) {
	inputs, manifest, _, deps := rehearsalFixture(t)
	bundle, err := loadRetainedTuningInputs(inputs, manifest)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	deps.host = func(verifiedTuningInputs, string) (tuningRecoveryBackend, func() error, error) {
		calls++
		return nil, nil, errors.New("unexpected host factory")
	}
	for _, mode := range []string{"lab", "maintenance", "approve", "timeout", "manifest", "duplicate", "extra", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			args := []string{"apply", "--inputs", inputs, "--manifest", manifest, "--approve", bundle.transaction.IntentSHA256, "--output", filepath.Join(t.TempDir(), "attempt")}
			if mode != "lab" {
				args = append(args, "--lab")
			}
			if mode != "maintenance" {
				args = append(args, "--maintenance")
			}
			switch mode {
			case "approve":
				args = append(args, "--approve", strings.Repeat("a", 64))
			case "timeout":
				args = append(args, "--timeout", "11m")
			case "manifest":
				args = append(args, "--manifest", strings.Repeat("a", 64))
			case "duplicate":
				if err := os.Mkdir(args[8], 0o700); err != nil {
					t.Fatal(err)
				}
			case "extra":
				args = append(args, "unexpected")
			case "unknown":
				args[0] = "install"
			}
			if _, err := rehearsalCommand(t, deps, args...); err == nil {
				t.Fatal("invalid request admitted")
			}
			if calls != 0 {
				t.Fatal("invalid request opened native backend")
			}
		})
	}
}
func TestRehearsalRejectionAndEvidenceWriteFailureAreRetained(t *testing.T) {
	for _, mode := range []string{"service", "receipt-conflict"} {
		t.Run(mode, func(t *testing.T) {
			inputs, manifest, f, deps := rehearsalFixture(t)
			bundle, err := loadRetainedTuningInputs(inputs, manifest)
			if err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(t.TempDir(), "attempt")
			if mode == "service" {
				f.badPID = true
			} else {
				f.backend.command = func(ctx context.Context, args ...string) (string, error) {
					value, err := f.command(ctx, args...)
					if args[0] == "restart" && args[1] == "bonvoyage.service" {
						if writeErr := os.WriteFile(filepath.Join(output, "receipt.json"), []byte("preserve existing receipt"), 0o600); writeErr != nil {
							t.Fatal(writeErr)
						}
					}
					return value, err
				}
			}
			_, err = rehearsalCommand(t, deps, "apply", "--inputs", inputs, "--manifest", manifest, "--approve", bundle.transaction.IntentSHA256, "--lab", "--maintenance", "--output", output)
			if err == nil {
				t.Fatal("failure was reported as success")
			}
			if mode == "service" {
				receipt := checkRehearsalEvidence(t, output)
				if receipt.Status != "rejected" || receipt.JournalEntries != 0 {
					t.Fatal(receipt)
				}
			} else {
				data, _ := os.ReadFile(filepath.Join(output, "receipt.json"))
				if string(data) != "preserve existing receipt" {
					t.Fatal("receipt conflict overwritten")
				}
				if _, err := verifyTuningJournal(filepath.Join(output, "journal")); err != nil {
					t.Fatal("valid activation journal lost")
				}
				if _, err := os.Stat(filepath.Join(output, "checksums.sha256")); !os.IsNotExist(err) {
					t.Fatal("failed evidence sealed")
				}
			}
		})
	}
}
func TestRehearsalStageAndCheckThroughCompiledCLI(t *testing.T) {
	_, _, files := retainedFixture(t)
	root := t.TempDir()
	var plan tuningPlan
	if err := decodeTuningJSON(files["tuning-plan.json"], &plan); err != nil {
		t.Fatal(err)
	}
	planDir := filepath.Join(root, "plan")
	if err := writePlanArtifacts(planDir, plan); err != nil {
		t.Fatal(err)
	}
	planManifest, err := os.ReadFile(filepath.Join(planDir, "checksums.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(root, "policy.yaml")
	inventory := filepath.Join(root, "inventory.json")
	for name, data := range map[string][]byte{policy: files["policy.yaml"], inventory: files["inventory.json"]} {
		if err := os.WriteFile(name, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(root, "bonvoyage-host-tune")
	build := exec.Command("go", "build", "-o", binary, ".")
	if data, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, data)
	}
	run := func(args ...string) ([]byte, error) { return exec.Command(binary, args...).CombinedOutput() }
	bundleDir := filepath.Join(root, "bundle")
	data, err := run("rehearsal", "stage", "--policy", policy, "--inventory", inventory, "--plan", planDir, "--plan-manifest", digest(planManifest), "--output", bundleDir)
	if err != nil {
		t.Fatalf("stage: %v %s", err, data)
	}
	var stage struct {
		ManifestSHA256        string `json:"manifest_sha256"`
		Output                string `json:"output"`
		Scope                 string `json:"scope"`
		NICVerification       string `json:"nic_irq_verification"`
		MeasurementAuthorized bool   `json:"measurement_authorized"`
	}
	if err := decodeTuningJSON(data, &stage); err != nil || stage.MeasurementAuthorized {
		t.Fatalf("%+v %v", stage, err)
	}
	checkOutput := filepath.Join(root, "check")
	data, err = run("rehearsal", "check", "--inputs", bundleDir, "--manifest", stage.ManifestSHA256, "--output", checkOutput)
	if err != nil {
		t.Fatalf("check: %v %s", err, data)
	}
	receipt := checkRehearsalEvidence(t, checkOutput)
	if receipt.Execution == nil || receipt.IntentSHA256 == "" {
		t.Fatal("compiled command lost binding")
	}
	for _, args := range [][]string{{"apply"}, {"rollback"}, {"rehearsal", "apply", "--inputs", bundleDir, "--manifest", stage.ManifestSHA256, "--approve", receipt.IntentSHA256, "--maintenance", "--output", filepath.Join(root, "denied")}} {
		if data, err := run(args...); err == nil {
			t.Fatalf("unguarded command accepted: %s", data)
		}
	}
	if data, err := run("rehearsal", "--help"); err != nil || !bytes.Contains(data, []byte("Experimental lab")) {
		t.Fatalf("%v %s", err, data)
	}
	if data, err := run("version"); err != nil || !bytes.Contains(data, []byte(toolVersion)) {
		t.Fatalf("%v %s", err, data)
	}
}
func TestRehearsalStageRejectsModifiedOriginalPlan(t *testing.T) {
	_, _, files := retainedFixture(t)
	root := t.TempDir()
	var plan tuningPlan
	if err := decodeTuningJSON(files["tuning-plan.json"], &plan); err != nil {
		t.Fatal(err)
	}
	planDir := filepath.Join(root, "plan")
	if err := writePlanArtifacts(planDir, plan); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(planDir, "checksums.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(planDir, "irqbalance.env"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "bundle")
	var stdout bytes.Buffer
	err = runRehearsalWith(context.Background(), []string{"stage", "--policy", "unused", "--inventory", "unused", "--plan", planDir, "--plan-manifest", digest(manifest), "--output", output}, rehearsalDependencies{}, &stdout)
	if err == nil {
		t.Fatal("changed original plan accepted")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("invalid bundle created")
	}
}
func TestRehearsalInputRejectsNonRegularAndSymlinkFiles(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "file")
	if err := os.WriteFile(p, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRehearsalInput(p); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{link, root} {
		if _, err := readRehearsalInput(name); err == nil {
			t.Fatalf("unsafe input accepted: %s", name)
		}
	}
}
func TestRehearsalRollbackPurposeRequiresSeparateReview(t *testing.T) {
	f, inputs, source := interruptedNativeFixture(t, 3, true, true)
	files, err := readPrivateTuningDirectory(source.directory, 32)
	if err != nil {
		t.Fatal(err)
	}
	var last tuningJournalEnvelope
	if err := decodeTuningJSON(files["000004.json"], &last); err != nil {
		t.Fatal(err)
	}
	journal := &fileTuningJournal{directory: source.directory, sequence: 4, previous: last.SHA256}
	if err := journal.Record("runtime-verified", struct{}{}); err != nil {
		t.Fatal(err)
	}
	if err := journal.Record("applied", struct{}{}); err != nil {
		t.Fatal(err)
	}
	files, err = readPrivateTuningDirectory(source.directory, 32)
	if err != nil {
		t.Fatal(err)
	}
	source, err = loadTuningRollback(source.directory, digest(tuningFileManifest(files)), inputs)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	review, err := reviewTuningRecovery(ctx, inputs, source, f.backend)
	if err != nil {
		t.Fatal(err)
	}
	if review.Purpose != "rollback" {
		t.Fatal(review)
	}
	review.Purpose = "interrupted"
	review.ApprovalSHA256 = ""
	data, _ := json.Marshal(review)
	outcome, err := recoverTuningTransaction(ctx, inputs, source, digest(data), f.backend, &memoryTuningJournal{})
	if err == nil || outcome.Status != "rejected" {
		t.Fatalf("purpose-swapped approval accepted: %+v %v", outcome, err)
	}
	if _, err := loadTuningRestorationSource(source.directory, source.sha256, inputs, "unknown"); err == nil {
		t.Fatal("unknown purpose accepted")
	}
}
func TestRehearsalNativeEvidencePathContract(t *testing.T) {
	for _, name := range []string{"apply-001", "rollback.2", "Bundle_A"} {
		if err := validateNativeRehearsalPath(nativeRehearsalBase + "/" + name); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"/tmp/attempt", nativeRehearsalBase + "/../attempt",
		nativeRehearsalBase + "/nested/attempt", nativeRehearsalBase + "/..",
		nativeRehearsalBase + "//attempt", nativeRehearsalBase + "/attempt/",
		nativeRehearsalBase + "/" + strings.Repeat("a", 65), nativeRehearsalBase + "/bad name"} {
		if err := validateNativeRehearsalPath(name); err == nil {
			t.Fatalf("unsafe evidence path admitted: %s", name)
		}
	}
}

func TestRehearsalCanceledContextDoesNotApply(t *testing.T) {
	inputs, manifest, f, deps := rehearsalFixture(t)
	bundle, err := loadRetainedTuningInputs(inputs, manifest)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout bytes.Buffer
	err = runRehearsalWith(ctx, []string{"apply", "--inputs", inputs, "--manifest", manifest, "--approve", bundle.transaction.IntentSHA256, "--lab", "--maintenance", "--output", filepath.Join(t.TempDir(), "canceled")}, deps, &stdout)
	if err == nil {
		t.Fatal("canceled request admitted")
	}
	for _, p := range nativeControlPaths {
		if _, err := os.Stat(f.root + p); !os.IsNotExist(err) {
			t.Fatal("canceled operation changed controls")
		}
	}
}
