//go:build linux || darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type nativeRuntimeState struct {
	GatewayPID    int            `json:"gateway_pid"`
	IRQBalancePID int            `json:"irqbalance_pid"`
	Arguments     []string       `json:"arguments"`
	CPUs          string         `json:"effective_cpuset"`
	MemoryHigh    string         `json:"memory_high"`
	MemoryMax     string         `json:"memory_max"`
	IRQBan        string         `json:"irqbalance_banned_cpulist"`
	IRQs          map[int]string `json:"effective_irq_affinity"`
}
type nativeRuntimeRecord struct {
	ContractVersion int                `json:"contract_version"`
	Scope           string             `json:"scope,omitempty"`
	NICVerification string             `json:"nic_irq_verification,omitempty"`
	Before          nativeRuntimeState `json:"before"`
	Latest          nativeRuntimeState `json:"latest"`
	Commands        []string           `json:"commands"`
}
type nativeServiceBackend struct {
	scope     string
	files     *nativeTuningFiles
	inventory hostInventory
	probe     func(context.Context) (tuningIdentity, error)
	command   func(context.Context, ...string) (string, error)
	readFile  func(string) ([]byte, error)
	baseline  nativeRuntimeState
	latest    nativeRuntimeState
	commands  []string
}

func newNativeServiceBackend(inventory hostInventory) (*nativeServiceBackend, error) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return nil, errors.New("native tuning requires Linux and root")
	}
	release, err := readNativeSmall("/etc/os-release")
	if err != nil || !strings.Contains("\n"+string(release), "\nID=ubuntu\n") ||
		!strings.Contains(string(release), "VERSION_ID=\"24.04\"") {
		return nil, errors.New("native contract currently supports Ubuntu 24.04 only")
	}
	files, err := openNativeTuningFiles("/", 0)
	if err != nil {
		return nil, err
	}
	for _, binary := range []string{"/usr/bin/systemctl", nativeDataplane} {
		if err = files.validateExecutable(binary); err != nil {
			files.root.Close()
			return nil, err
		}
	}
	b := &nativeServiceBackend{files: files, inventory: inventory,
		command: runNativeSystemctl, readFile: readNativeSmall}
	b.probe = func(ctx context.Context) (tuningIdentity, error) { return freshNativeIdentity(ctx, inventory) }
	return b, nil
}

func newNativeServiceBackendForScope(inventory hostInventory, scope string) (*nativeServiceBackend, error) {
	if err := validateTuningScope(scope); err != nil {
		return nil, err
	}
	b, err := newNativeServiceBackend(inventory)
	if err != nil {
		return nil, err
	}
	if effectiveTuningScope(scope) == tuningScopeVMCPU {
		b.scope = tuningScopeVMCPU
	}
	return b, nil
}

func (b *nativeServiceBackend) Close() error {
	if b.files.locked {
		return errors.New("release native tuning lock before closing backend")
	}
	return b.files.root.Close()
}
func readNativeSmall(name string) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil {
		return nil, err
	}
	if len(data) > 65536 {
		return nil, errors.New("native observation exceeds 64 KiB")
	}
	return data, nil
}
func runNativeSystemctl(ctx context.Context, args ...string) (string, error) {
	childCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	command := exec.CommandContext(childCtx, "/usr/bin/systemctl",
		append([]string{"--no-pager", "--no-ask-password"}, args...)...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin", "LANG=C", "SYSTEMD_COLORS=0"}
	command.WaitDelay = time.Second
	stdout, stderr := boundedBuffer{limit: 65536}, boundedBuffer{limit: 65536}
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if stdout.truncated || stderr.truncated {
		return "", errors.New("systemctl output truncated")
	}
	if err != nil {
		return "", fmt.Errorf("systemctl %v: %w: %s", args, err, stderr.Bytes())
	}
	return string(stdout.Bytes()), nil
}
func (b *nativeServiceBackend) control(ctx context.Context, args ...string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	b.commands = append(b.commands, strings.Join(args, " "))
	return b.command(ctx, args...)
}
func nativeProperties(text string) (map[string]string, error) {
	result := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return nil, errors.New("invalid systemd property output")
		}
		if _, exists := result[key]; exists {
			return nil, errors.New("duplicate systemd property")
		}
		result[key] = value
	}
	return result, nil
}
func (b *nativeServiceBackend) service(ctx context.Context, name string) (map[string]string, error) {
	return b.serviceState(ctx, name, false)
}
func (b *nativeServiceBackend) serviceState(ctx context.Context, name string, allowPending bool) (map[string]string, error) {
	text, err := b.control(ctx, "show", name, "--all", "--property=ActiveState,SubState,MainPID,ControlGroup,FragmentPath,DropInPaths,NeedDaemonReload,Job")
	if err != nil {
		return nil, err
	}
	props, err := nativeProperties(text)
	if err != nil {
		return nil, err
	}
	for _, key := range []string{"ActiveState", "SubState", "MainPID", "ControlGroup", "FragmentPath", "DropInPaths", "NeedDaemonReload", "Job"} {
		if _, ok := props[key]; !ok {
			return nil, fmt.Errorf("missing systemd property: %s", key)
		}
	}
	// systemd v255 prints an empty Job value for no queued job. --all keeps
	// that property present so absence cannot be mistaken for an idle unit.
	if props["Job"] != "" {
		return nil, errors.New("service job is pending or unknown; reconcile before recovery")
	}
	if props["NeedDaemonReload"] != "no" && !(allowPending && props["NeedDaemonReload"] == "yes") {
		return nil, errors.New("service has pending configuration changes")
	}
	if props["ActiveState"] != "active" || props["SubState"] != "running" {
		return nil, fmt.Errorf("%s must be active and running", name)
	}
	pid, err := strconv.Atoi(props["MainPID"])
	if err != nil || pid < 1 {
		return nil, errors.New("invalid service process identity")
	}
	if name == "bonvoyage.service" && props["FragmentPath"] != nativeServiceUnit {
		return nil, errors.New("unsupported gateway service fragment")
	}
	allowed := map[string]bool{}
	if name == "bonvoyage.service" {
		allowed[nativeControlPaths["service-resources"]] = true
		allowed[nativeControlPaths["runtime-arguments"]] = true
	} else {
		allowed[nativeControlPaths["irqbalance-exclusion"]] = true
	}
	for _, p := range strings.Fields(props["DropInPaths"]) {
		if !allowed[p] {
			return nil, fmt.Errorf("unsupported service override: %s", p)
		}
	}
	if props["ControlGroup"] != "/system.slice/"+name {
		return nil, errors.New("unsupported service cgroup")
	}
	return props, nil
}
func (b *nativeServiceBackend) capture(ctx context.Context) (nativeRuntimeState, error) {
	return b.captureState(ctx, false)
}
func (b *nativeServiceBackend) captureState(ctx context.Context, allowPending bool) (nativeRuntimeState, error) {
	state := nativeRuntimeState{IRQs: make(map[int]string)}
	if err := validateTuningScope(b.scope); err != nil {
		return state, err
	}
	gateway, err := b.serviceState(ctx, "bonvoyage.service", allowPending)
	if err != nil {
		return state, err
	}
	irqbalance, err := b.serviceState(ctx, "irqbalance.service", allowPending)
	if err != nil {
		return state, err
	}
	state.GatewayPID, _ = strconv.Atoi(gateway["MainPID"])
	state.IRQBalancePID, _ = strconv.Atoi(irqbalance["MainPID"])
	args, err := b.readFile(fmt.Sprintf("/proc/%d/cmdline", state.GatewayPID))
	if err != nil {
		return state, err
	}
	state.Arguments = strings.Split(strings.TrimSuffix(string(args), "\x00"), "\x00")
	for _, item := range []struct {
		name   string
		target *string
	}{
		{"cpuset.cpus.effective", &state.CPUs}, {"memory.high", &state.MemoryHigh}, {"memory.max", &state.MemoryMax},
	} {
		data, err := b.readFile("/sys/fs/cgroup" + gateway["ControlGroup"] + "/" + item.name)
		if err != nil {
			return state, err
		}
		*item.target = strings.TrimSpace(string(data))
	}
	cpus, err := parseCPUList(state.CPUs)
	if err != nil || len(cpus) == 0 {
		return state, errors.New("empty or invalid effective service cpuset")
	}
	state.CPUs = formatCPUList(cpus)
	environment, err := b.readFile(fmt.Sprintf("/proc/%d/environ", state.IRQBalancePID))
	if err != nil {
		return state, err
	}
	seen := false
	for _, entry := range strings.Split(string(environment), "\x00") {
		if strings.HasPrefix(entry, "IRQBALANCE_BANNED_CPUS=") && strings.TrimPrefix(entry, "IRQBALANCE_BANNED_CPUS=") != "" {
			return state, errors.New("legacy irqbalance mask requires explicit migration")
		}
		if value, ok := strings.CutPrefix(entry, "IRQBALANCE_BANNED_CPULIST="); ok {
			if seen {
				return state, errors.New("duplicate irqbalance exclusion")
			}
			state.IRQBan = value
			seen = true
		}
	}
	// VM scope keeps NIC topology identity checks, but does not require guest
	// access to effective per-NIC affinity or attest that affinity is valid.
	if effectiveTuningScope(b.scope) == tuningScopeFullHost {
		for _, nic := range b.inventory.Interfaces {
			for _, irq := range nic.IRQs {
				data, err := b.readFile(fmt.Sprintf("/proc/irq/%d/effective_affinity_list", irq.IRQ))
				if err != nil {
					return state, err
				}
				cpus, err := parseCPUList(strings.TrimSpace(string(data)))
				if err != nil || len(cpus) == 0 {
					return state, errors.New("invalid effective IRQ affinity")
				}
				state.IRQs[irq.IRQ] = formatCPUList(cpus)
			}
		}
	}
	// Reject a process replacement during the observation, rather than combine
	// cgroup and argv observations from different service generations.
	again, err := b.serviceState(ctx, "bonvoyage.service", allowPending)
	if err != nil {
		return state, fmt.Errorf("gateway final observation: %w", err)
	}
	if again["MainPID"] != gateway["MainPID"] {
		return state, errors.New("gateway changed during observation")
	}
	again, err = b.serviceState(ctx, "irqbalance.service", allowPending)
	if err != nil {
		return state, fmt.Errorf("irqbalance final observation: %w", err)
	}
	if again["MainPID"] != irqbalance["MainPID"] {
		return state, errors.New("irqbalance changed during observation")
	}
	return state, nil
}
func (b *nativeServiceBackend) Lock(ctx context.Context) (func(), error) {
	unlock, err := b.lockContract(ctx)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (func(), error) { unlock(); return nil, err }
	baseline, err := b.capture(ctx)
	if err != nil {
		return fail(err)
	}
	runtimeValue, err := b.files.Read(ctx, "runtime-arguments")
	if err != nil {
		return fail(err)
	}
	expectedArguments := nativeArguments([]byte("--smp 1 --memory 512M"))
	if runtimeValue.Exists {
		expectedArguments = nativeArguments(runtimeValue.Data)
	}
	if !reflect.DeepEqual(baseline.Arguments, expectedArguments) {
		return fail(errors.New("running arguments differ from the managed unit"))
	}
	b.baseline = baseline
	b.latest = baseline
	return unlock, nil
}
func (b *nativeServiceBackend) lockContract(ctx context.Context) (func(), error) {
	unlock, err := b.files.Lock(ctx)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (func(), error) { unlock(); return nil, err }
	b.commands = nil
	if err = b.files.validateManagedDirectories(); err != nil {
		return fail(err)
	}
	unit, err := b.files.readPath(nativeServiceUnit)
	if err != nil || !unit.Exists || digest(unit.Data) != nativeServiceUnitSHA256 {
		return fail(errors.New("installed unit does not match native service contract"))
	}
	return unlock, nil
}

func (b *nativeServiceBackend) LockRecovery(ctx context.Context, tx tuningTransaction) (func(), error) {
	if err := validateTuningPlanScope(tx.Plan); err != nil {
		return nil, err
	}
	if effectiveTuningScope(tx.Plan.Scope) != effectiveTuningScope(b.scope) {
		return nil, errors.New("recovery plan differs from native verification scope")
	}
	var retained nativeRuntimeRecord
	if len(tx.RuntimeBefore) > 65536 || decodeTuningJSON(tx.RuntimeBefore, &retained) != nil ||
		retained.ContractVersion != nativeServiceContractVersion || len(tx.Changes) != 3 ||
		!reflect.DeepEqual(retained.Before, retained.Latest) {
		return nil, errors.New("supported runtime before-image required for native recovery")
	}
	before := retained.Before
	if effectiveTuningScope(retained.Scope) != effectiveTuningScope(b.scope) ||
		(retained.Scope == tuningScopeVMCPU && retained.NICVerification != "deferred") ||
		(effectiveTuningScope(retained.Scope) == tuningScopeFullHost && (retained.Scope != "" || retained.NICVerification != "")) {
		return nil, errors.New("runtime before-image differs from recovery scope")
	}
	args := nativeArguments([]byte("--smp 1 --memory 512M"))
	if tx.Changes[1].Before.Exists {
		args = nativeArguments(tx.Changes[1].Before.Data)
	}
	if !reflect.DeepEqual(args, before.Arguments) || before.GatewayPID < 1 || before.IRQBalancePID < 1 {
		return nil, errors.New("runtime before-image conflicts with prior managed arguments")
	}
	unlock, err := b.lockContract(ctx)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (func(), error) { unlock(); return nil, err }
	for _, change := range tx.Changes {
		if _, err := b.files.Read(ctx, change.Control); err != nil {
			return fail(err)
		}
		if change.Before.Exists {
			if _, err := encodeNativeControl(change.Control, change.Before.Data); err != nil {
				return fail(err)
			}
		}
	}
	current, err := b.captureState(ctx, true)
	if err != nil {
		return fail(err)
	}
	beforeLimits := current.CPUs == before.CPUs && current.MemoryHigh == before.MemoryHigh && current.MemoryMax == before.MemoryMax
	afterLimits := current.CPUs == tx.Plan.CPU.GatewayCPUSet &&
		current.MemoryHigh == strconv.FormatInt(tx.Plan.Memory.SystemdMemoryHighMiB*1024*1024, 10) &&
		current.MemoryMax == strconv.FormatInt(tx.Plan.Memory.SystemdMemoryMaxMiB*1024*1024, 10)
	if (!reflect.DeepEqual(current.Arguments, before.Arguments) &&
		!reflect.DeepEqual(current.Arguments, nativeArguments(tx.Changes[1].After.Data))) ||
		(!beforeLimits && !afterLimits) ||
		(current.IRQBan != before.IRQBan && current.IRQBan != tx.Plan.IRQ.IRQBalanceBannedCPUList) {
		return fail(errors.New("live service policy is neither the recorded before nor proposed state"))
	}
	b.baseline = before
	b.latest = current
	return unlock, nil
}
func (b *nativeServiceBackend) Identity(ctx context.Context) (tuningIdentity, error) {
	return b.probe(ctx)
}
func (b *nativeServiceBackend) Read(ctx context.Context, key string) (tuningValue, error) {
	return b.files.Read(ctx, key)
}
func (b *nativeServiceBackend) Replace(ctx context.Context, key string, before, after tuningValue) error {
	return b.files.Replace(ctx, key, before, after)
}
func (b *nativeServiceBackend) RuntimeEvidence(context.Context) (json.RawMessage, error) {
	record := nativeRuntimeRecord{ContractVersion: nativeServiceContractVersion,
		Before: b.baseline, Latest: b.latest, Commands: b.commands}
	if b.scope == tuningScopeVMCPU {
		record.Scope, record.NICVerification = tuningScopeVMCPU, "deferred"
	}
	return json.Marshal(record)
}
func (b *nativeServiceBackend) restart(ctx context.Context) error {
	for _, args := range [][]string{{"daemon-reload"}, {"restart", "irqbalance.service"}, {"restart", "bonvoyage.service"}} {
		if _, err := b.control(ctx, args...); err != nil {
			return err
		}
	}
	return nil
}

// Type=simple can report running before its child execs the gateway. Only that
// pre-exec placeholder is retryable; other observation or identity errors fail.
func (b *nativeServiceBackend) captureStarted(ctx context.Context) (nativeRuntimeState, error) {
	startup, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		state, err := b.capture(startup)
		if err != nil {
			return state, err
		}
		b.latest = state
		if len(state.Arguments) > 0 && state.Arguments[0] == nativeDataplane {
			return state, nil
		}
		if len(state.Arguments) != 1 || !strings.HasPrefix(state.Arguments[0], "(") ||
			!strings.HasSuffix(state.Arguments[0], ")") {
			return state, errors.New("unexpected gateway executable during startup")
		}
		select {
		case <-startup.Done():
			return state, fmt.Errorf("gateway did not finish exec within startup deadline: %w", startup.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func nativeArguments(runtimeData []byte) []string {
	prefix := append([]string{nativeDataplane}, strings.Fields(nativeFixedArguments)...)
	return append(prefix, strings.Fields(string(runtimeData))...)
}
func (b *nativeServiceBackend) Verify(ctx context.Context, plan tuningPlan) error {
	if err := validateTuningPlanScope(plan); err != nil {
		return err
	}
	if effectiveTuningScope(plan.Scope) != effectiveTuningScope(b.scope) {
		return errors.New("plan differs from native verification scope")
	}
	if err := b.restart(ctx); err != nil {
		return err
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		state, err := b.captureStarted(ctx)
		if err != nil {
			return err
		}
		b.latest = state
		expectedArgs := nativeArguments([]byte(fmt.Sprintf("--smp %d --cpuset %s --memory %s",
			len(plan.CPU.GatewayLogicalCPUs), plan.CPU.GatewayCPUSet, plan.Memory.SeastarArgument)))
		if !reflect.DeepEqual(state.Arguments, expectedArgs) || state.CPUs != plan.CPU.GatewayCPUSet ||
			state.MemoryHigh != strconv.FormatInt(plan.Memory.SystemdMemoryHighMiB*1024*1024, 10) ||
			state.MemoryMax != strconv.FormatInt(plan.Memory.SystemdMemoryMaxMiB*1024*1024, 10) ||
			state.IRQBan != plan.IRQ.IRQBalanceBannedCPUList {
			return errors.New("native process, cgroup or irqbalance settings did not match plan")
		}
		// The explicit VM contract retains CPU/memory/exclusion verification but
		// cannot claim the full-host per-NIC affinity gate.
		if b.scope == tuningScopeVMCPU {
			return nil
		}
		valid := true
		for _, assignment := range plan.IRQ.Assignments {
			affinity, ok := state.IRQs[assignment.IRQ]
			cpus, err := parseCPUList(affinity)
			if !ok || err != nil || len(cpus) == 0 {
				valid = false
				break
			}
			allowed := make(map[int]bool)
			for _, cpu := range plan.IRQ.ReservedLogicalCPUs {
				allowed[cpu] = true
			}
			for _, cpu := range cpus {
				if !allowed[cpu] {
					valid = false
				}
			}
		}
		if valid {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("NIC IRQs did not converge within NIC-local reserved CPUs")
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func (b *nativeServiceBackend) VerifyRestored(ctx context.Context, changes []tuningChange) error {
	for _, change := range changes {
		actual, err := b.Read(ctx, change.Control)
		if err != nil {
			return err
		}
		if !equalTuningValue(actual, change.Before) {
			return errors.New("rollback control drift")
		}
	}
	if err := b.restart(ctx); err != nil {
		return err
	}
	state, err := b.captureStarted(ctx)
	if err != nil {
		return err
	}
	b.latest = state
	if !reflect.DeepEqual(state.Arguments, b.baseline.Arguments) || state.CPUs != b.baseline.CPUs ||
		state.MemoryHigh != b.baseline.MemoryHigh || state.MemoryMax != b.baseline.MemoryMax ||
		state.IRQBan != b.baseline.IRQBan {
		return errors.New("prior effective service policy was not restored")
	}
	// irqbalance remains dynamic: restore its policy, not stale IRQ numbers/masks.
	return nil
}
func freshNativeIdentity(ctx context.Context, expected hostInventory) (tuningIdentity, error) {
	if err := ctx.Err(); err != nil {
		return tuningIdentity{}, err
	}
	current := expected
	host, err := inspectHost()
	if err != nil {
		return tuningIdentity{}, err
	}
	if host.MachineIDHash != expected.Host.MachineIDHash || host.BootID != expected.Host.BootID ||
		host.KernelRelease != expected.Host.KernelRelease || host.Architecture != expected.Host.Architecture {
		return tuningIdentity{}, errors.New("native host identity changed")
	}
	host.Fingerprint = expected.Host.Fingerprint
	current.Host = host
	current.CPULists = inspectKernelCPULists()
	current.CPUs, err = inspectCPUs()
	if err != nil {
		return tuningIdentity{}, err
	}
	current.NUMANodes, err = inspectNUMANodes()
	if err != nil {
		return tuningIdentity{}, err
	}
	current.Interfaces = append([]networkInterface(nil), expected.Interfaces...)
	for i := range current.Interfaces {
		nic := &current.Interfaces[i]
		if nic.Name == "" || safeName(nic.Name) != nic.Name {
			return tuningIdentity{}, errors.New("invalid NIC name")
		}
		base := "/sys/class/net/" + nic.Name
		device, err := os.Readlink(base + "/device")
		if err != nil {
			return tuningIdentity{}, err
		}
		driver, err := os.Readlink(base + "/device/driver")
		if err != nil {
			return tuningIdentity{}, err
		}
		nic.PCIBusAddress = filepath.Base(device)
		nic.Driver = filepath.Base(driver)
		nic.NUMANode, err = readIntFile(base + "/device/numa_node")
		if err != nil {
			return tuningIdentity{}, err
		}
		nic.RXQueues = globBaseNames(base + "/queues/rx-*")
		nic.TXQueues = globBaseNames(base + "/queues/tx-*")
		nic.IRQs = inspectIRQs(base + "/device/msi_irqs")
	}
	if err := ctx.Err(); err != nil {
		return tuningIdentity{}, err
	}
	return transactionIdentity(current), nil
}
