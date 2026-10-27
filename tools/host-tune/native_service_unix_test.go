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
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type nativeFixture struct {
	backend     *nativeServiceBackend
	tx          tuningTransaction
	root        string
	state       nativeRuntimeState
	badOverride bool
	badPID      bool
	failRestart bool
	wrongMemory bool
}

func newNativeFixture(t *testing.T) *nativeFixture {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"etc/systemd/system/bonvoyage.service.d",
		"etc/systemd/system/irqbalance.service.d", "run/bonvoyage-host-tune"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	unit, err := os.ReadFile("../../packaging/systemd/bonvoyage.service")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(root+nativeServiceUnit, unit, 0o644); err != nil {
		t.Fatal(err)
	}
	files, err := openNativeTuningFiles(root, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { files.root.Close() })
	tx, _, _ := transactionFixture(t)
	for i := range tx.Changes {
		tx.Changes[i].After.UID = os.Getuid()
		tx.Changes[i].After.GID = os.Getgid()
	}
	tx.IntentSHA256 = tuningIntentDigest(tx)
	inventory := testInventory(16, 1)
	fixture := &nativeFixture{root: root, tx: tx, state: nativeRuntimeState{
		GatewayPID: 1000, IRQBalancePID: 2000, Arguments: nativeArguments([]byte("--smp 1 --memory 512M")),
		CPUs: "0-15", MemoryHigh: "max", MemoryMax: "max", IRQs: map[int]string{},
	}}
	for _, irq := range inventory.Interfaces[0].IRQs {
		fixture.state.IRQs[irq.IRQ] = "0-15"
	}
	fixture.backend = &nativeServiceBackend{files: files, inventory: inventory,
		probe:   func(ctx context.Context) (tuningIdentity, error) { return tx.Identity, ctx.Err() },
		command: fixture.command, readFile: fixture.read}
	return fixture
}
func (f *nativeFixture) command(ctx context.Context, args ...string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	switch args[0] {
	case "show":
		name := args[1]
		pid := f.state.GatewayPID
		fragment := nativeServiceUnit
		keys := []string{"service-resources", "runtime-arguments"}
		if name == "irqbalance.service" {
			pid = f.state.IRQBalancePID
			fragment = "/usr/lib/systemd/system/irqbalance.service"
			keys = []string{"irqbalance-exclusion"}
		}
		paths := []string{}
		for _, key := range keys {
			if _, err := os.Stat(f.root + nativeControlPaths[key]); err == nil {
				paths = append(paths, nativeControlPaths[key])
			}
		}
		if f.badOverride {
			paths = append(paths, "/etc/systemd/system/bonvoyage.service.d/99-foreign.conf")
		}
		if f.badPID {
			pid = 0
		}
		return fmt.Sprintf("ActiveState=active\nSubState=running\nMainPID=%d\nControlGroup=/system.slice/%s\nFragmentPath=%s\nDropInPaths=%s\nNeedDaemonReload=no\nJob=\n",
			pid, name, fragment, strings.Join(paths, " ")), nil
	case "daemon-reload":
		return "", nil
	case "restart":
		if err := f.reload(ctx, args[1]); err != nil {
			return "", err
		}
		if args[1] == "bonvoyage.service" && f.failRestart {
			f.failRestart = false
			return "", errors.New("restart transport failed after mutation")
		}
		return "", nil
	}
	return "", errors.New("unexpected systemctl command")
}
func (f *nativeFixture) reload(ctx context.Context, name string) error {
	if name == "irqbalance.service" {
		f.state.IRQBalancePID++
		value, err := f.backend.files.Read(ctx, "irqbalance-exclusion")
		if err != nil {
			return err
		}
		f.state.IRQBan = ""
		if value.Exists {
			f.state.IRQBan = strings.TrimSpace(strings.TrimPrefix(string(value.Data), "IRQBALANCE_BANNED_CPULIST="))
		}
		for irq := range f.state.IRQs {
			f.state.IRQs[irq] = "0-15"
			if value.Exists {
				f.state.IRQs[irq] = "0"
			}
		}
		return nil
	}
	f.state.GatewayPID++
	f.state.Arguments = nativeArguments([]byte("--smp 1 --memory 512M"))
	value, err := f.backend.files.Read(ctx, "runtime-arguments")
	if err != nil {
		return err
	}
	if value.Exists {
		f.state.Arguments = nativeArguments(value.Data)
	}
	f.state.CPUs = "0-15"
	f.state.MemoryHigh = "max"
	f.state.MemoryMax = "max"
	value, err = f.backend.files.Read(ctx, "service-resources")
	if err != nil {
		return err
	}
	if value.Exists {
		props, err := nativeProperties(strings.TrimPrefix(string(value.Data), "[Service]\n"))
		if err != nil {
			return err
		}
		f.state.CPUs = props["AllowedCPUs"]
		high, _ := strconv.ParseInt(strings.TrimSuffix(props["MemoryHigh"], "M"), 10, 64)
		max, _ := strconv.ParseInt(strings.TrimSuffix(props["MemoryMax"], "M"), 10, 64)
		f.state.MemoryHigh = strconv.FormatInt(high*1024*1024, 10)
		f.state.MemoryMax = strconv.FormatInt(max*1024*1024, 10)
		if f.wrongMemory {
			f.state.MemoryMax = "1"
			f.wrongMemory = false
		}
	}
	return nil
}
func (f *nativeFixture) read(name string) ([]byte, error) {
	switch name {
	case fmt.Sprintf("/proc/%d/cmdline", f.state.GatewayPID):
		return []byte(strings.Join(f.state.Arguments, "\x00") + "\x00"), nil
	case fmt.Sprintf("/proc/%d/environ", f.state.IRQBalancePID):
		if f.state.IRQBan == "" {
			return []byte("LANG=C\x00"), nil
		}
		return []byte("IRQBALANCE_BANNED_CPULIST=" + f.state.IRQBan + "\x00"), nil
	case "/sys/fs/cgroup/system.slice/bonvoyage.service/cpuset.cpus.effective":
		return []byte(f.state.CPUs), nil
	case "/sys/fs/cgroup/system.slice/bonvoyage.service/memory.high":
		return []byte(f.state.MemoryHigh), nil
	case "/sys/fs/cgroup/system.slice/bonvoyage.service/memory.max":
		return []byte(f.state.MemoryMax), nil
	}
	for irq, value := range f.state.IRQs {
		if name == fmt.Sprintf("/proc/irq/%d/effective_affinity_list", irq) {
			return []byte(value), nil
		}
	}
	return nil, fmt.Errorf("unexpected observation %s", name)
}
func runNativeFixture(t *testing.T, f *nativeFixture) (tuningOutcome, error, *memoryTuningJournal) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	journal := &memoryTuningJournal{}
	outcome, err := applyTuningTransaction(ctx, f.tx, f.tx.IntentSHA256, f.backend, journal)
	return outcome, err, journal
}
func TestNativeServiceContractMatchesInstalledUnit(t *testing.T) {
	data, err := os.ReadFile("../../packaging/systemd/bonvoyage.service")
	if err != nil {
		t.Fatal(err)
	}
	if digest(data) != nativeServiceUnitSHA256 {
		t.Fatal("native service contract drift")
	}
	tx, _, _ := transactionFixture(t)
	for _, change := range tx.Changes {
		encoded, err := encodeNativeControl(change.Control, change.After.Data)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeNativeControl(change.Control, encoded)
		if err != nil || string(decoded) != string(change.After.Data) {
			t.Fatalf("%s %v", change.Control, err)
		}
		if _, err := decodeNativeControl(change.Control, append(encoded, []byte("ExecStart=/bin/sh\n")...)); err == nil {
			t.Fatal("foreign override accepted")
		}
	}
}
func TestNativeAdapterAppliesFilesAndVerifiesRuntime(t *testing.T) {
	f := newNativeFixture(t)
	outcome, err, journal := runNativeFixture(t, f)
	if err != nil || outcome.Status != "applied" || outcome.MeasurementAuthorized {
		t.Fatalf("%+v %v", outcome, err)
	}
	if len(journal.prepared.RuntimeBefore) == 0 || !json.Valid(journal.prepared.RuntimeBefore) {
		t.Fatal("runtime before-image missing")
	}
	if !reflect.DeepEqual(journal.events, []string{"prepared", "write-intent", "write-intent", "write-intent", "runtime-verified", "applied"}) {
		t.Fatal(journal.events)
	}
	for _, change := range f.tx.Changes {
		data, err := os.ReadFile(f.root + nativeControlPaths[change.Control])
		if err != nil {
			t.Fatal(err)
		}
		want, _ := encodeNativeControl(change.Control, change.After.Data)
		if string(data) != string(want) {
			t.Fatal("installed bytes differ")
		}
	}
}

func TestNativeLoggingSurvivesTuningAndRollback(t *testing.T) {
	for _, fail := range []bool{false, true} {
		f := newNativeFixture(t)
		f.failRestart = fail
		before, err := os.ReadFile(f.root + nativeServiceUnit)
		if err != nil {
			t.Fatal(err)
		}
		outcome, err, _ := runNativeFixture(t, f)
		if (!fail && (err != nil || outcome.Status != "applied")) ||
			(fail && (err == nil || outcome.Status != "rolled-back")) {
			t.Fatalf("%+v %v", outcome, err)
		}
		for flag, value := range map[string]string{"--log-to-syslog": "1", "--log-to-stdout": "0", "--log-with-color": "0"} {
			count := 0
			for i, arg := range f.state.Arguments {
				if arg == flag && i+1 < len(f.state.Arguments) && f.state.Arguments[i+1] == value {
					count++
				}
			}
			if count != 1 {
				t.Fatalf("logging flag lost/duplicated: %s in %v", flag, f.state.Arguments)
			}
		}
		after, err := os.ReadFile(f.root + nativeServiceUnit)
		if err != nil || string(before) != string(after) {
			t.Fatal("tuning changed base logging unit")
		}
	}
}

func TestNativeLoggingRejectsLegacyAndInjectedOverrides(t *testing.T) {
	value := []byte("--smp 2 --cpuset 2-3 --memory 512M\n")
	encoded, err := encodeNativeControl("runtime-arguments", value)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{
		strings.Replace(string(encoded), " --log-to-syslog 1 --log-to-stdout 0 --log-with-color 0", "", 1),
		strings.Replace(string(encoded), "--log-to-syslog 1", "--log-to-syslog 0", 1),
		string(encoded) + "SyslogLevelPrefix=yes\n",
	} {
		if _, err := decodeNativeControl("runtime-arguments", []byte(text)); err == nil {
			t.Fatal("legacy or weakened logging override accepted")
		}
	}
	if _, err := encodeNativeControl("runtime-arguments", []byte("--smp 2 --cpuset 2-3 --memory 512M --log-to-syslog 0\n")); err == nil {
		t.Fatal("extra logging option accepted")
	}
}
func TestNativeAdapterRestoresAfterRestartOrEffectiveFailure(t *testing.T) {
	for _, mode := range []string{"restart", "memory", "irq-locality"} {
		t.Run(mode, func(t *testing.T) {
			f := newNativeFixture(t)
			f.failRestart = mode == "restart"
			f.wrongMemory = mode == "memory"
			if mode == "irq-locality" {
				f.backend.readFile = func(name string) ([]byte, error) {
					if strings.HasPrefix(name, "/proc/irq/") && f.state.IRQBan != "" {
						// CPU 15 is host-reserved, but outside the plan's NIC-local IRQ set.
						return []byte("15"), nil
					}
					return f.read(name)
				}
			}
			outcome, err, _ := runNativeFixture(t, f)
			if err == nil || outcome.Status != "rolled-back" {
				t.Fatalf("%+v %v", outcome, err)
			}
			for _, p := range nativeControlPaths {
				if _, err := os.Stat(f.root + p); !os.IsNotExist(err) {
					t.Fatal("rollback did not restore absence")
				}
			}
			if f.state.CPUs != "0-15" || f.state.MemoryMax != "max" || f.state.IRQBan != "" {
				t.Fatal(f.state)
			}
		})
	}
}
func TestNativeAdapterRejectsForeignServiceBeforeWrites(t *testing.T) {
	for _, mode := range []string{"unit", "override", "pid", "arguments"} {
		t.Run(mode, func(t *testing.T) {
			f := newNativeFixture(t)
			switch mode {
			case "unit":
				if err := os.WriteFile(f.root+nativeServiceUnit, []byte("foreign"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "override":
				f.badOverride = true
			case "pid":
				f.badPID = true
			case "arguments":
				f.state.Arguments = append(f.state.Arguments, "--foreign-option")
			}
			outcome, err, journal := runNativeFixture(t, f)
			if err == nil || outcome.Status != "rejected" || len(journal.events) != 0 {
				t.Fatalf("%+v %v", outcome, err)
			}
			for _, cmd := range f.backend.commands {
				if strings.HasPrefix(cmd, "restart") {
					t.Fatal("service restarted before approval checks")
				}
			}
		})
	}
}
func TestNativeFilesRejectUnsafeExistingTargets(t *testing.T) {
	for _, mode := range []string{"symlink", "hardlink", "writable", "special-mode", "special-file", "oversized", "foreign"} {
		t.Run(mode, func(t *testing.T) {
			f := newNativeFixture(t)
			target := f.root + nativeControlPaths["service-resources"]
			value, _ := encodeNativeControl("service-resources", f.tx.Changes[0].After.Data)
			outside := filepath.Join(t.TempDir(), "untouched")
			if err := os.WriteFile(outside, []byte("sentinel"), 0o600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch mode {
			case "symlink":
				err = os.Symlink(outside, target)
			case "hardlink":
				err = os.Link(outside, target)
			case "writable":
				err = os.WriteFile(target, value, 0o666)
				if err == nil {
					err = os.Chmod(target, 0o666)
				}
			case "special-mode":
				err = os.WriteFile(target, value, 0o644)
				if err == nil {
					err = os.Chmod(target, os.ModeSetuid|0o644)
				}
				if err == nil {
					info, statErr := os.Lstat(target)
					if statErr != nil {
						err = statErr
					} else if info.Mode()&os.ModeSetuid == 0 {
						t.Skip("filesystem does not retain the set-user-ID bit")
					}
				}
			case "special-file":
				err = unix.Mkfifo(target, 0o600)
			case "oversized":
				err = os.WriteFile(target, make([]byte, 65537), 0o600)
			case "foreign":
				err = os.WriteFile(target, []byte("[Service]\nUser=root\n"), 0o644)
			}
			if err != nil {
				t.Fatal(err)
			}
			outcome, err, _ := runNativeFixture(t, f)
			if err == nil || outcome.Status != "rejected" {
				t.Fatalf("%+v %v", outcome, err)
			}
			data, _ := os.ReadFile(outside)
			if string(data) != "sentinel" {
				t.Fatal("outside file modified")
			}
		})
	}
}
func TestNativeFilesRejectSymlinkedOrWritableParents(t *testing.T) {
	for _, mode := range []string{"symlink", "writable"} {
		t.Run(mode, func(t *testing.T) {
			f := newNativeFixture(t)
			parent := filepath.Dir(f.root + nativeControlPaths["service-resources"])
			if mode == "writable" {
				if err := os.Chmod(parent, 0o777); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Remove(parent); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), parent); err != nil {
					t.Fatal(err)
				}
			}
			outcome, err, _ := runNativeFixture(t, f)
			if err == nil || outcome.Status != "rejected" {
				t.Fatalf("%+v %v", outcome, err)
			}
		})
	}
}
func TestNativeFilesConflictAndHostLock(t *testing.T) {
	f := newNativeFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	unlock, err := f.backend.files.Lock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	other, err := openNativeTuningFiles(f.root, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer other.root.Close()
	short, stop := context.WithTimeout(ctx, 30*time.Millisecond)
	defer stop()
	if release, err := other.Lock(short); err == nil {
		release()
		t.Fatal("concurrent host lock acquired")
	}
	before := tuningValue{}
	target := f.root + nativeControlPaths["service-resources"]
	value, _ := encodeNativeControl("service-resources", f.tx.Changes[0].After.Data)
	if err := os.WriteFile(target, value, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.backend.files.Replace(ctx, "service-resources", before, f.tx.Changes[0].After); err == nil {
		t.Fatal("external edit overwritten")
	}
	if err := f.backend.files.Replace(ctx, "/etc/passwd", before, f.tx.Changes[0].After); err == nil {
		t.Fatal("unlisted target accepted")
	}
}

func TestNativeAdapterRejectsUnloadedOverridesAndIncompleteObservations(t *testing.T) {
	for _, mode := range []string{"unloaded-gateway", "unloaded-irqbalance", "missing-property", "pending-reload"} {
		t.Run(mode, func(t *testing.T) {
			f := newNativeFixture(t)
			if strings.HasPrefix(mode, "unloaded-") {
				key := "service-resources"
				if mode == "unloaded-irqbalance" {
					key = "irqbalance-exclusion"
				}
				p := filepath.Dir(f.root+nativeControlPaths[key]) + "/99-foreign.conf"
				if err := os.WriteFile(p, []byte("[Service]\nUser=root\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			} else {
				f.backend.command = func(ctx context.Context, args ...string) (string, error) {
					value, err := f.command(ctx, args...)
					if mode == "missing-property" {
						value = strings.ReplaceAll(value, "DropInPaths=\n", "")
					}
					if mode == "pending-reload" {
						value = strings.ReplaceAll(value, "NeedDaemonReload=no", "NeedDaemonReload=yes")
					}
					return value, err
				}
			}
			outcome, err, journal := runNativeFixture(t, f)
			if err == nil || outcome.Status != "rejected" || len(journal.events) != 0 {
				t.Fatalf("%+v %v", outcome, err)
			}
			for _, cmd := range f.backend.commands {
				if strings.HasPrefix(cmd, "restart") || cmd == "daemon-reload" {
					t.Fatal("mutated unsupported service")
				}
			}
		})
	}
}

func TestNativeExecutableContract(t *testing.T) {
	for _, mode := range []string{"valid", "not-executable", "writable", "symlink", "hardlink"} {
		t.Run(mode, func(t *testing.T) {
			f := newNativeFixture(t)
			p := f.root + "/run/bonvoyage-host-tune/binary"
			if err := os.WriteFile(p, []byte("fixture, never executed"), 0o755); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "not-executable":
				if err := os.Chmod(p, 0o644); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := os.Chmod(p, 0o777); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("other", p); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(p, p+"-link"); err != nil {
					t.Fatal(err)
				}
			}
			err := f.backend.files.validateExecutable("/run/bonvoyage-host-tune/binary")
			if (err == nil) != (mode == "valid") {
				t.Fatalf("%s: %v", mode, err)
			}
		})
	}
}

type nativeEvidenceFailure struct {
	*nativeServiceBackend
	calls  int
	failAt int
}

func (b *nativeEvidenceFailure) RuntimeEvidence(ctx context.Context) (json.RawMessage, error) {
	b.calls++
	if b.calls == b.failAt {
		return json.RawMessage("{invalid"), nil
	}
	return b.nativeServiceBackend.RuntimeEvidence(ctx)
}
func TestNativeRuntimeEvidenceFailureIsNotAccepted(t *testing.T) {
	for _, mode := range []string{"before", "after", "journal"} {
		t.Run(mode, func(t *testing.T) {
			f := newNativeFixture(t)
			b := &nativeEvidenceFailure{nativeServiceBackend: f.backend}
			journal := &memoryTuningJournal{}
			expected := "rolled-back"
			switch mode {
			case "before":
				b.failAt = 1
				expected = "rejected"
			case "after":
				b.failAt = 2
			case "journal":
				journal.failKind = "runtime-verified"
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			outcome, err := applyTuningTransaction(ctx, f.tx, f.tx.IntentSHA256, b, journal)
			if err == nil || outcome.Status != expected || outcome.MeasurementAuthorized {
				t.Fatalf("%+v %v", outcome, err)
			}
			for _, name := range nativeControlPaths {
				if _, err := os.Stat(f.root + name); !os.IsNotExist(err) {
					t.Fatal("unexpected retained mutation")
				}
			}
		})
	}
}
func TestNativeRuntimeEvidenceDurableRoundTrip(t *testing.T) {
	f := newNativeFixture(t)
	directory := filepath.Join(t.TempDir(), "journal")
	journal, err := newTuningJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	outcome, err := applyTuningTransaction(ctx, f.tx, f.tx.IntentSHA256, f.backend, journal)
	if err != nil || outcome.Status != "applied" {
		t.Fatalf("%+v %v", outcome, err)
	}
	entries, err := verifyTuningJournal(directory)
	if err != nil || len(entries) != 6 {
		t.Fatalf("%d %v", len(entries), err)
	}
}

func TestNativeFactoryDoesNotEnableOtherPlatformsOrNonRoot(t *testing.T) {
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		t.Skip("do not open actual host backend in tests")
	}
	if backend, err := newNativeServiceBackend(testInventory(16, 1)); err == nil {
		backend.files.root.Close()
		t.Fatal("unsupported privileged backend enabled")
	}
}

func TestNativeAdapterWaitsForExecAfterRestart(t *testing.T) {
	for _, mode := range []string{"apply", "restoration"} {
		t.Run(mode, func(t *testing.T) {
			f := newNativeFixture(t)
			f.wrongMemory = mode == "restoration"
			remaining, observations := 0, 0
			f.backend.command = func(ctx context.Context, args ...string) (string, error) {
				value, err := f.command(ctx, args...)
				if err == nil && args[0] == "restart" && args[1] == "bonvoyage.service" {
					remaining = 2
				}
				return value, err
			}
			f.backend.readFile = func(name string) ([]byte, error) {
				if strings.HasSuffix(name, "/cmdline") && remaining > 0 {
					remaining--
					observations++
					return []byte("(ataplane)\x00"), nil
				}
				return f.read(name)
			}
			outcome, err, _ := runNativeFixture(t, f)
			expected := "applied"
			if mode == "restoration" {
				expected = "rolled-back"
				if err == nil {
					t.Fatal("wrong memory was not rejected")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if outcome.Status != expected || observations < 2 {
				t.Fatalf("%+v observations=%d error=%v", outcome, observations, err)
			}
		})
	}
}

func TestNativeExecWaitRejectsForeignArgumentsAndHonorsDeadline(t *testing.T) {
	for _, mode := range []string{"foreign", "deadline", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			f := newNativeFixture(t)
			f.state.Arguments = []string{"(ataplane)"}
			if mode == "foreign" {
				f.state.Arguments = []string{"/usr/bin/foreign-gateway"}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			_, err := f.backend.captureStarted(ctx)
			if err == nil {
				t.Fatal("incomplete or foreign startup accepted")
			}
			if mode == "foreign" && !strings.Contains(err.Error(), "unexpected gateway executable") {
				t.Fatal(err)
			}
			if mode == "deadline" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal(err)
			}
			if mode == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			for _, command := range f.backend.commands {
				if strings.HasPrefix(command, "restart") {
					t.Fatal("observation restarted a service")
				}
			}
		})
	}
}

func TestNativeCapturePreservesFinalObservationErrors(t *testing.T) {
	for _, service := range []string{"bonvoyage.service", "irqbalance.service"} {
		for _, expected := range []error{context.DeadlineExceeded, context.Canceled, errors.New("systemctl observation failed")} {
			t.Run(service+"/"+expected.Error(), func(t *testing.T) {
				f := newNativeFixture(t)
				observations := 0
				f.backend.command = func(ctx context.Context, args ...string) (string, error) {
					if len(args) >= 2 && args[0] == "show" && args[1] == service {
						observations++
						if observations == 2 {
							return "", expected
						}
					}
					return f.command(ctx, args...)
				}
				_, err := f.backend.capture(context.Background())
				if observations != 2 || !errors.Is(err, expected) {
					t.Fatalf("observations=%d error=%v; want wrapped %v", observations, err, expected)
				}
				for _, command := range f.backend.commands {
					if strings.HasPrefix(command, "restart") {
						t.Fatal("failed observation restarted a service")
					}
				}
			})
		}
	}
}
