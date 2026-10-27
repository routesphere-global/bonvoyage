package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeTuningBackend struct {
	identity    tuningIdentity
	values      map[string]tuningValue
	writes      []string
	trace       *[]string
	locked      bool
	replaceHook func(string, tuningValue) error
	verifyHook  func() error
	restoreHook func() error
	lockError   error
	readError   bool
}

func (f *fakeTuningBackend) Lock(ctx context.Context) (func(), error) {
	if f.lockError != nil {
		return nil, f.lockError
	}
	if f.locked {
		return nil, errors.New("already locked")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.locked = true
	return func() { f.locked = false }, nil
}
func (f *fakeTuningBackend) Identity(ctx context.Context) (tuningIdentity, error) {
	return f.identity, ctx.Err()
}
func (f *fakeTuningBackend) Read(ctx context.Context, key string) (tuningValue, error) {
	if f.readError {
		return tuningValue{}, errors.New("read failure")
	}
	return f.values[key], ctx.Err()
}
func (f *fakeTuningBackend) Replace(ctx context.Context, key string, before, after tuningValue) error {
	if !f.locked {
		return errors.New("mutation without lock")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !equalTuningValue(f.values[key], before) {
		return errors.New("external state conflict")
	}
	f.values[key] = after
	f.writes = append(f.writes, key)
	if f.trace != nil {
		*f.trace = append(*f.trace, "write:"+key)
	}
	if f.replaceHook != nil {
		return f.replaceHook(key, after)
	}
	return nil
}
func (f *fakeTuningBackend) Verify(ctx context.Context, _ tuningPlan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.verifyHook != nil {
		return f.verifyHook()
	}
	return nil
}
func (f *fakeTuningBackend) VerifyRestored(ctx context.Context, _ []tuningChange) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.restoreHook != nil {
		return f.restoreHook()
	}
	return nil
}

type memoryTuningJournal struct {
	events   []string
	prepared tuningTransaction
	trace    *[]string
	failKind string
}

func (j *memoryTuningJournal) Record(kind string, data any) error {
	if kind == j.failKind {
		return errors.New("journal failure")
	}
	j.events = append(j.events, kind)
	if j.trace != nil {
		*j.trace = append(*j.trace, "record:"+kind)
	}
	if kind == "prepared" {
		encoded, _ := json.Marshal(data)
		return json.Unmarshal(encoded, &j.prepared)
	}
	return nil
}
func transactionFixture(t *testing.T) (tuningTransaction, *fakeTuningBackend, *memoryTuningJournal) {
	t.Helper()
	policy, pd, err := loadPolicy(filepath.Join("..", "..", "deploy", "tuning", "policies", "throughput-balanced.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	inventory := testInventory(16, 1)
	inventory.Host.BootID = "12345678-1234-1234-1234-123456789abc"
	plan, err := buildPlan(policy, pd, inventory, strings.Repeat("b", 64), "auto", 4, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := prepareTuningTransaction(policy, pd, inventory, strings.Repeat("b", 64), plan)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]tuningValue{
		"service-resources":    {Exists: true, Data: []byte("prior resources\n"), Mode: 0o640, UID: 23, GID: 24},
		"runtime-arguments":    {},
		"irqbalance-exclusion": {Exists: true, Data: []byte("prior exclusion\n"), Mode: 0o600},
	}
	return tx, &fakeTuningBackend{identity: tx.Identity, values: values}, &memoryTuningJournal{}
}
func applyFixture(t *testing.T, tx tuningTransaction, f *fakeTuningBackend, j tuningJournal) (tuningOutcome, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return applyTuningTransaction(ctx, tx, tx.IntentSHA256, f, j)
}
func beforeValues(f *fakeTuningBackend) map[string]tuningValue {
	copy := make(map[string]tuningValue)
	for k, v := range f.values {
		copy[k] = v
	}
	return copy
}
func TestTuningTransactionSuccessRecordsBeforeMutation(t *testing.T) {
	tx, f, j := transactionFixture(t)
	trace := []string{}
	f.trace = &trace
	j.trace = &trace
	before := beforeValues(f)
	outcome, err := applyFixture(t, tx, f, j)
	if err != nil || outcome.Status != "applied" {
		t.Fatalf("%+v %v", outcome, err)
	}
	if trace[0] != "record:prepared" {
		t.Fatal(trace)
	}
	for i, change := range j.prepared.Changes {
		if !equalTuningValue(change.Before, before[change.Control]) {
			t.Fatal("lost before-image")
		}
		if !equalTuningValue(f.values[change.Control], tx.Changes[i].After) {
			t.Fatal("wrong target")
		}
	}
	if f.locked {
		t.Fatal("host lock leaked")
	}
}
func TestTuningTransactionRejectsUnapprovedOrStaleIntent(t *testing.T) {
	for _, mode := range []string{"approval", "plan", "control", "payload", "identity", "warning", "lock", "read", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			tx, f, j := transactionFixture(t)
			approval := tx.IntentSHA256
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			switch mode {
			case "approval":
				approval = "wrong"
			case "plan":
				tx.Plan.Memory.SeastarMiB++
			case "control":
				tx.Changes[0].Control = "/etc/passwd"
			case "payload":
				tx.Changes[0].After.Data = []byte("unreviewed payload")
			case "identity":
				f.identity.BootID = "rebooted"
			case "warning":
				tx.Plan.Warnings = []string{"unresolved"}
			case "lock":
				f.lockError = errors.New("busy")
			case "read":
				f.readError = true
			case "deadline":
				cancel()
			}
			outcome, err := applyTuningTransaction(ctx, tx, approval, f, j)
			if err == nil || outcome.Status != "rejected" || len(f.writes) != 0 || len(j.events) != 0 {
				t.Fatalf("%+v %v writes=%v journal=%v", outcome, err, f.writes, j.events)
			}
		})
	}
}
func TestTuningTransactionRollsBackPartialWritesInReverse(t *testing.T) {
	for failAt := 1; failAt <= 3; failAt++ {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			tx, f, j := transactionFixture(t)
			before := beforeValues(f)
			f.replaceHook = func(_ string, _ tuningValue) error {
				if len(f.writes) == failAt {
					return errors.New("partial write failed")
				}
				return nil
			}
			outcome, err := applyFixture(t, tx, f, j)
			if err == nil || outcome.Status != "rolled-back" {
				t.Fatalf("%+v %v", outcome, err)
			}
			if !reflect.DeepEqual(before, f.values) {
				t.Fatal("before-images not restored")
			}
			for i := 0; i < failAt; i++ {
				if f.writes[failAt+i] != tx.Changes[failAt-1-i].Control {
					t.Fatal(f.writes)
				}
			}
		})
	}
}
func TestTuningTransactionEffectiveVerificationFailureRollsBack(t *testing.T) {
	tx, f, j := transactionFixture(t)
	before := beforeValues(f)
	f.verifyHook = func() error { return errors.New("effective IRQ affinity overlaps reactors") }
	outcome, err := applyFixture(t, tx, f, j)
	if err == nil || outcome.Status != "rolled-back" || !reflect.DeepEqual(before, f.values) {
		t.Fatalf("%+v %v", outcome, err)
	}
}
func TestTuningTransactionRollbackConflictPreservesExternalEdit(t *testing.T) {
	tx, f, j := transactionFixture(t)
	foreign := tuningValue{Exists: true, Data: []byte("operator edit"), Mode: 0o600}
	f.replaceHook = func(_ string, _ tuningValue) error {
		if len(f.writes) == 2 {
			f.values["service-resources"] = foreign
			return errors.New("failed")
		}
		return nil
	}
	outcome, err := applyFixture(t, tx, f, j)
	if err == nil || outcome.Status != "recovery-required" || !equalTuningValue(f.values["service-resources"], foreign) {
		t.Fatalf("%+v %v", outcome, err)
	}
	if f.values["runtime-arguments"].Exists {
		t.Fatal("independent owned change not restored")
	}
}
func TestTuningTransactionRebootBlocksFurtherWritesAndRollback(t *testing.T) {
	tx, f, j := transactionFixture(t)
	f.replaceHook = func(_ string, _ tuningValue) error { f.identity.BootID = "new-boot"; return nil }
	outcome, err := applyFixture(t, tx, f, j)
	if err == nil || outcome.Status != "recovery-required" || len(f.writes) != 1 {
		t.Fatalf("%+v %v", outcome, err)
	}
}
func TestTuningTransactionCancellationStillRestores(t *testing.T) {
	tx, f, j := transactionFixture(t)
	before := beforeValues(f)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f.replaceHook = func(_ string, _ tuningValue) error { cancel(); return nil }
	outcome, err := applyTuningTransaction(ctx, tx, tx.IntentSHA256, f, j)
	if err == nil || outcome.Status != "rolled-back" || !reflect.DeepEqual(before, f.values) {
		t.Fatalf("%+v %v", outcome, err)
	}
}
func TestTuningTransactionJournalFailureNeverBecomesApplied(t *testing.T) {
	for _, kind := range []string{"prepared", "write-intent", "applied", "rollback-intent", "rolled-back"} {
		t.Run(kind, func(t *testing.T) {
			tx, f, j := transactionFixture(t)
			j.failKind = kind
			before := beforeValues(f)
			if kind == "rollback-intent" || kind == "rolled-back" {
				f.verifyHook = func() error { return errors.New("bad effective state") }
			}
			outcome, err := applyFixture(t, tx, f, j)
			if err == nil || outcome.Status == "applied" {
				t.Fatalf("%+v %v", outcome, err)
			}
			if !reflect.DeepEqual(before, f.values) {
				t.Fatal("owned state not restored after journal failure")
			}
			if kind == "prepared" && len(f.writes) != 0 {
				t.Fatal("write without durable before-image")
			}
		})
	}
}
func TestTuningTransactionRollbackEffectiveFailureRequiresRecovery(t *testing.T) {
	tx, f, j := transactionFixture(t)
	f.verifyHook = func() error { return errors.New("apply verification failed") }
	f.restoreHook = func() error { return errors.New("restored file but effective state still wrong") }
	outcome, err := applyFixture(t, tx, f, j)
	if err == nil || outcome.Status != "recovery-required" {
		t.Fatalf("%+v %v", outcome, err)
	}
}
func TestTuningIdentityDetectsIRQAndSiblingChanges(t *testing.T) {
	inventory := testInventory(16, 1)
	before := transactionIdentity(inventory)
	inventory.Interfaces[0].IRQs[0].IRQ++
	if before == transactionIdentity(inventory) {
		t.Fatal("IRQ renumbering missed")
	}
	inventory = testInventory(16, 1)
	inventory.CPUs[0].Siblings = []int{0, 1}
	if before == transactionIdentity(inventory) {
		t.Fatal("SMT ownership change missed")
	}
	inventory = testInventory(16, 1)
	inventory.Interfaces[0].IRQs[0].EffectiveAffinityList = "2"
	if before != transactionIdentity(inventory) {
		t.Fatal("expected affinity change invalidates identity")
	}
}
func TestTuningJournalDurableRoundTripAndTamperRejection(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "journal")
	j, err := newTuningJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	tx, f, _ := transactionFixture(t)
	if outcome, err := applyFixture(t, tx, f, j); err != nil || outcome.Status != "applied" {
		t.Fatalf("%+v %v", outcome, err)
	}
	entries, err := verifyTuningJournal(directory)
	if err != nil || len(entries) != 5 {
		t.Fatalf("%v %v", entries, err)
	}
	if _, err := newTuningJournal(directory); err == nil {
		t.Fatal("reused journal")
	}
	target := filepath.Join(directory, "000002.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyTuningJournal(directory); err == nil {
		t.Fatal("tamper accepted")
	}
}
func TestTuningJournalRejectsIncompleteGapSymlinkAndPublicEvidence(t *testing.T) {
	for _, mode := range []string{"incomplete", "gap", "symlink", "public", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "journal")
			j, err := newTuningJournal(directory)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "oversized" {
				if err := j.Record("prepared", strings.Repeat("x", 1024*1024)); err == nil {
					t.Fatal("oversized evidence accepted")
				}
				return
			}
			if err := j.Record("prepared", struct{}{}); err != nil {
				t.Fatal(err)
			}
			if mode != "incomplete" {
				if err := j.Record("applied", struct{}{}); err != nil {
					t.Fatal(err)
				}
			}
			target := filepath.Join(directory, "000001.json")
			switch mode {
			case "gap":
				err = os.Rename(target, filepath.Join(directory, "000003.json"))
			case "symlink":
				err = os.Remove(target)
				if err == nil {
					err = os.Symlink("000002.json", target)
				}
			case "public":
				err = os.Chmod(target, 0o644)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := verifyTuningJournal(directory); err == nil {
				t.Fatal("unsafe journal accepted")
			}
		})
	}
}
func TestTuningTransactionIdentityChangeDuringVerification(t *testing.T) {
	for _, stage := range []string{"apply", "restore"} {
		t.Run(stage, func(t *testing.T) {
			tx, f, j := transactionFixture(t)
			if stage == "apply" {
				f.verifyHook = func() error { f.identity.TopologySHA256 = "changed"; return nil }
			} else {
				f.verifyHook = func() error { return errors.New("force rollback") }
				f.restoreHook = func() error { f.identity.TopologySHA256 = "changed"; return nil }
			}
			outcome, err := applyFixture(t, tx, f, j)
			if err == nil || outcome.Status != "recovery-required" {
				t.Fatalf("%+v %v", outcome, err)
			}
		})
	}
}
func TestTuningTransactionRejectsUnboundedDeadlineAndBeforeImages(t *testing.T) {
	for _, mode := range []string{"no-deadline", "long-deadline", "oversized", "special-mode", "negative-owner", "absent-with-data"} {
		t.Run(mode, func(t *testing.T) {
			tx, f, j := transactionFixture(t)
			ctx := context.Background()
			timeout := time.Second
			if mode == "long-deadline" {
				timeout = 11 * time.Minute
			}
			if mode != "no-deadline" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, timeout)
				defer cancel()
			}
			value := f.values["service-resources"]
			switch mode {
			case "oversized":
				value.Data = make([]byte, 65537)
			case "special-mode":
				value.Mode = 0o4755
			case "negative-owner":
				value.UID = -1
			case "absent-with-data":
				value.Exists = false
			}
			f.values["service-resources"] = value
			outcome, err := applyTuningTransaction(ctx, tx, tx.IntentSHA256, f, j)
			if err == nil || outcome.Status != "rejected" || len(f.writes) != 0 || len(j.events) != 0 {
				t.Fatalf("%+v %v", outcome, err)
			}
		})
	}
}
func TestTuningTransactionPreparationRegeneratesAndMatchesPlanArtifacts(t *testing.T) {
	policy, pd, err := loadPolicy(filepath.Join("..", "..", "deploy", "tuning", "policies", "throughput-balanced.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	inventory := testInventory(16, 1)
	inventory.Host.BootID = "12345678-1234-1234-1234-123456789abc"
	id := strings.Repeat("b", 64)
	plan, err := buildPlan(policy, pd, inventory, id, "auto", 4, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := prepareTuningTransaction(policy, pd, inventory, id, plan)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "plan")
	if err := writePlanArtifacts(directory, plan); err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"bonvoyage-resources.conf", "bonvoyage-runtime-arguments.txt", "irqbalance.env"} {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || string(data) != string(tx.Changes[i].After.Data) {
			t.Fatalf("artifact divergence: %s %v", name, err)
		}
	}
	for _, mode := range []string{"policy-hash", "inventory-hash", "cpuset", "warning", "boot", "schema"} {
		t.Run(mode, func(t *testing.T) {
			changed := plan
			inv := inventory
			policyHash, inventoryHash := pd, id
			switch mode {
			case "policy-hash":
				policyHash = strings.Repeat("e", 64)
			case "inventory-hash":
				inventoryHash = strings.Repeat("e", 64)
			case "cpuset":
				changed.CPU.GatewayCPUSet = "0"
			case "warning":
				changed.Warnings = []string{"unresolved"}
			case "boot":
				inv.Host.BootID = ""
			case "schema":
				inv.SchemaVersion = 0
			}
			if _, err := prepareTuningTransaction(policy, policyHash, inv, inventoryHash, changed); err == nil {
				t.Fatal("unverified input accepted")
			}
		})
	}
}

func TestTuningPrivilegedCommandsRemainUnavailable(t *testing.T) {
	// CLI dispatch intentionally has no apply/verify/rollback branch. Inspection
	// and planning keep their existing read-only contract.
	data, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"apply", "verify", "rollback"} {
		if strings.Contains(string(data), `case "`+command+`":`) {
			t.Fatal("live mutation command enabled")
		}
	}
}
