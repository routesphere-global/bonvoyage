package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"
)

// Backends must hold a host-wide lock, honor deadlines, compare full before-images
// and verify effective state. The native adapter remains behind qualification.
type tuningBackend interface {
	Lock(context.Context) (func(), error)
	Identity(context.Context) (tuningIdentity, error)
	Read(context.Context, string) (tuningValue, error)
	Replace(context.Context, string, tuningValue, tuningValue) error
	Verify(context.Context, tuningPlan) error
	VerifyRestored(context.Context, []tuningChange) error
}

type tuningJournal interface {
	Record(string, any) error
}

type tuningIdentity struct {
	HostFingerprint string `json:"host_fingerprint"`
	BootID          string `json:"boot_id"`
	TopologySHA256  string `json:"topology_sha256"`
}

type tuningValue struct {
	Exists bool   `json:"exists"`
	Data   []byte `json:"data"`
	Mode   uint32 `json:"mode"`
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
}

type tuningChange struct {
	Control string      `json:"control"`
	Before  tuningValue `json:"before"`
	After   tuningValue `json:"after"`
}

type tuningTransaction struct {
	Plan          tuningPlan              `json:"plan"`
	PlanSHA256    string                  `json:"plan_sha256"`
	IntentSHA256  string                  `json:"intent_sha256"`
	Identity      tuningIdentity          `json:"identity"`
	Changes       []tuningChange          `json:"changes"`
	RuntimeBefore json.RawMessage         `json:"runtime_before,omitempty"`
	Execution     *tuningExecutionBinding `json:"execution,omitempty"`
}

type tuningRuntimeEvidence interface {
	RuntimeEvidence(context.Context) (json.RawMessage, error)
}

func captureTuningRuntime(ctx context.Context, backend tuningBackend) (json.RawMessage, error) {
	source, ok := backend.(tuningRuntimeEvidence)
	if !ok {
		return nil, nil
	}
	data, err := source.RuntimeEvidence(ctx)
	if err != nil {
		return nil, err
	}
	if len(data) > 65536 || !json.Valid(data) {
		return nil, errors.New("invalid or oversized runtime evidence")
	}
	return data, nil
}

type tuningOutcome struct {
	Status                string
	MeasurementAuthorized bool
}

func tuningIntentDigest(tx tuningTransaction) string {
	type change struct {
		Control string
		After   tuningValue
	}
	changes := make([]change, 0, len(tx.Changes))
	for _, item := range tx.Changes {
		changes = append(changes, change{item.Control, item.After})
	}
	encoded, _ := json.Marshal(struct {
		PlanSHA256 string
		Identity   tuningIdentity
		Changes    []change
		Execution  *tuningExecutionBinding
	}{tx.PlanSHA256, tx.Identity, changes, tx.Execution})
	return digest(encoded)
}

// Affinities and available memory change during tuning; CPU/NUMA ownership,
// queue identity and IRQ numbers must not. Recompute this from fresh discovery.
func transactionIdentity(inventory hostInventory) tuningIdentity {
	type device struct {
		Name, PCI, Driver string
		NUMA              int
		RX, TX            []string
		IRQs              []int
	}
	devices := make([]device, 0, len(inventory.Interfaces))
	for _, nic := range inventory.Interfaces {
		d := device{Name: nic.Name, PCI: nic.PCIBusAddress, Driver: nic.Driver,
			NUMA: nic.NUMANode, RX: nic.RXQueues, TX: nic.TXQueues}
		for _, irq := range nic.IRQs {
			d.IRQs = append(d.IRQs, irq.IRQ)
		}
		devices = append(devices, d)
	}
	material := struct {
		Lists   kernelCPULists
		CPUs    []logicalCPU
		Nodes   []numaNode
		Devices []device
		Memory  int64
		Cgroup  int
	}{inventory.CPULists, inventory.CPUs, inventory.NUMANodes, devices,
		inventory.Host.MemoryTotalBytes, inventory.Host.CgroupVersion}
	encoded, _ := json.Marshal(material)
	return tuningIdentity{inventory.Host.Fingerprint, inventory.Host.BootID, digest(encoded)}
}

// Regenerate the plan rather than accepting caller-authored control strings.
// The retained-input loader additionally verifies the complete artifact bundle.
func prepareTuningTransaction(policy tuningPolicy, policyDigest string,
	inventory hostInventory, inventoryDigest string, plan tuningPlan) (tuningTransaction, error) {
	if err := validateTuningPlanScope(plan); err != nil {
		return tuningTransaction{}, err
	}
	if err := validatePolicy(policy); err != nil {
		return tuningTransaction{}, err
	}
	if inventory.SchemaVersion != inventorySchemaVersion || inventory.Host.BootID == "" ||
		len(inventory.Host.Fingerprint) != 64 {
		return tuningTransaction{}, errors.New("transaction requires boot-bound inventory v2")
	}
	cores := 0
	if plan.Mode == "benchmark-fixed" {
		cores = plan.CPU.GatewayPhysicalCoreCount
	} else if plan.Mode != "production-auto" {
		return tuningTransaction{}, errors.New("unsupported plan mode")
	}
	expected, err := buildPlanForScope(policy, policyDigest, inventory, inventoryDigest,
		plan.Interface.Name, cores, plan.GeneratedAt, plan.Scope)
	if err != nil {
		return tuningTransaction{}, err
	}
	if !reflect.DeepEqual(expected, plan) || len(plan.Warnings) != 0 {
		return tuningTransaction{}, errors.New("plan differs from its inputs or has unresolved warnings")
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		return tuningTransaction{}, err
	}
	values := []struct{ control, data string }{
		{"service-resources", fmt.Sprintf("[Service]\nCPUAffinity=%s\nAllowedCPUs=%s\nMemoryHigh=%dM\nMemoryMax=%dM\n",
			joinInts(plan.CPU.GatewayLogicalCPUs, " "), plan.CPU.GatewayCPUSet,
			plan.Memory.SystemdMemoryHighMiB, plan.Memory.SystemdMemoryMaxMiB)},
		{"runtime-arguments", fmt.Sprintf("--smp %d --cpuset %s --memory %s\n",
			len(plan.CPU.GatewayLogicalCPUs), plan.CPU.GatewayCPUSet, plan.Memory.SeastarArgument)},
		{"irqbalance-exclusion", fmt.Sprintf("IRQBALANCE_BANNED_CPULIST=%s\n", plan.IRQ.IRQBalanceBannedCPUList)},
	}
	tx := tuningTransaction{Plan: plan, PlanSHA256: digest(encoded), Identity: transactionIdentity(inventory)}
	for _, value := range values {
		tx.Changes = append(tx.Changes, tuningChange{Control: value.control,
			After: tuningValue{Exists: true, Data: []byte(value.data), Mode: 0o644}})
	}
	tx.IntentSHA256 = tuningIntentDigest(tx)
	return tx, nil
}

func checkTuningIdentity(ctx context.Context, backend tuningBackend, expected tuningIdentity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	actual, err := backend.Identity(ctx)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("host, boot or CPU/NIC/IRQ topology changed")
	}
	return nil
}

func validTuningValue(value tuningValue) bool {
	return len(value.Data) <= 65536 && value.Mode & ^uint32(0o777) == 0 &&
		value.UID >= 0 && value.GID >= 0 &&
		(value.Exists || (len(value.Data) == 0 && value.Mode == 0 && value.UID == 0 && value.GID == 0))
}

func equalTuningValue(a, b tuningValue) bool {
	return a.Exists == b.Exists && string(a.Data) == string(b.Data) &&
		a.Mode == b.Mode && a.UID == b.UID && a.GID == b.GID
}

// The caller retains the host lock throughout rollback. A separate bounded
// context allows restoration even after the apply deadline was cancelled.
func rollbackTuningChanges(ctx context.Context, tx tuningTransaction, attempted int,
	backend tuningBackend, journal tuningJournal) error {
	var failures []error
	for i := attempted - 1; i >= 0; i-- {
		change := tx.Changes[i]
		if err := checkTuningIdentity(ctx, backend, tx.Identity); err != nil {
			failures = append(failures, err)
			break
		}
		current, err := backend.Read(ctx, change.Control)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if equalTuningValue(current, change.Before) {
			continue
		}
		if !equalTuningValue(current, change.After) {
			failures = append(failures, fmt.Errorf("rollback conflict: %s", change.Control))
			continue
		}
		// Journal failure cannot excuse leaving a known owned change in place.
		if err := journal.Record("rollback-intent", i); err != nil {
			failures = append(failures, err)
		}
		if err := backend.Replace(ctx, change.Control, change.After, change.Before); err != nil {
			failures = append(failures, err)
			continue
		}
		restored, err := backend.Read(ctx, change.Control)
		if err != nil {
			failures = append(failures, err)
		} else if !equalTuningValue(restored, change.Before) {
			failures = append(failures, fmt.Errorf("rollback verification failed: %s", change.Control))
		}
	}
	// Restored bytes alone cannot prove restored effective systemd/IRQ behavior.
	if len(failures) == 0 && attempted > 0 {
		if err := checkTuningIdentity(ctx, backend, tx.Identity); err != nil {
			failures = append(failures, err)
		} else if err := backend.VerifyRestored(ctx, tx.Changes[:attempted]); err != nil {
			failures = append(failures, err)
		} else if err := checkTuningIdentity(ctx, backend, tx.Identity); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func applyTuningTransaction(ctx context.Context, tx tuningTransaction, approval string,
	backend tuningBackend, journal tuningJournal) (tuningOutcome, error) {
	rejected := tuningOutcome{Status: "rejected"}
	if err := validateTuningPlanScope(tx.Plan); err != nil {
		return rejected, err
	}
	if tx.Execution != nil {
		current, err := runningTuningExecution()
		if err != nil || *tx.Execution != current {
			return rejected, errors.New("execution binding differs from running utility")
		}
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 10*time.Minute {
		return rejected, errors.New("apply requires a deadline within ten minutes")
	}
	if approval != tx.IntentSHA256 || approval == "" || approval != tuningIntentDigest(tx) || len(tx.Changes) != 3 {
		return rejected, errors.New("explicit exact-plan approval is required")
	}
	// Transactions are internal prepared values, but reject tampered copies before
	// passing even a semantic control name to a future privileged adapter.
	encoded, _ := json.Marshal(tx.Plan)
	if digest(encoded) != tx.PlanSHA256 {
		return rejected, errors.New("plan binding changed")
	}
	controls := []string{"service-resources", "runtime-arguments", "irqbalance-exclusion"}
	for i, change := range tx.Changes {
		if change.Control != controls[i] || !validTuningValue(change.After) {
			return rejected, errors.New("invalid tuning controls")
		}
	}
	unlock, err := backend.Lock(ctx)
	if err != nil {
		return rejected, err
	}
	if unlock == nil {
		return rejected, errors.New("backend did not provide an exclusive lock")
	}
	defer unlock()
	if err = checkTuningIdentity(ctx, backend, tx.Identity); err != nil {
		return rejected, err
	}
	// Capture all before-images, including absence and ownership, before mutation.
	tx.Changes = append([]tuningChange(nil), tx.Changes...)
	for i := range tx.Changes {
		before, readErr := backend.Read(ctx, tx.Changes[i].Control)
		if readErr != nil {
			return rejected, readErr
		}
		if !validTuningValue(before) {
			return rejected, errors.New("unsupported before-image")
		}
		before.Data = append([]byte(nil), before.Data...)
		tx.Changes[i].Before = before
	}
	tx.RuntimeBefore, err = captureTuningRuntime(ctx, backend)
	if err != nil {
		return rejected, err
	}
	if err = journal.Record("prepared", tx); err != nil {
		return rejected, err
	}
	attempted := 0
	applyErr := func() error {
		for i, change := range tx.Changes {
			if err := checkTuningIdentity(ctx, backend, tx.Identity); err != nil {
				return err
			}
			if err := journal.Record("write-intent", i); err != nil {
				return err
			}
			attempted = i + 1 // A failed write can still have changed the destination.
			if err := backend.Replace(ctx, change.Control, change.Before, change.After); err != nil {
				return err
			}
			actual, err := backend.Read(ctx, change.Control)
			if err != nil {
				return err
			}
			if !equalTuningValue(actual, change.After) {
				return errors.New("written control did not verify")
			}
		}
		if err := checkTuningIdentity(ctx, backend, tx.Identity); err != nil {
			return err
		}
		if err := backend.Verify(ctx, tx.Plan); err != nil {
			return err
		}
		if err := checkTuningIdentity(ctx, backend, tx.Identity); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		evidence, err := captureTuningRuntime(ctx, backend)
		if err != nil {
			return err
		}
		if evidence != nil {
			if err := journal.Record("runtime-verified", evidence); err != nil {
				return err
			}
		}
		return journal.Record("applied", struct{}{})
	}()
	if applyErr == nil {
		return tuningOutcome{Status: "applied"}, nil
	}
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rollbackErr := rollbackTuningChanges(rollbackCtx, tx, attempted, backend, journal)
	status := "rolled-back"
	if rollbackErr != nil {
		status = "recovery-required"
	}
	evidence, evidenceErr := captureTuningRuntime(rollbackCtx, backend)
	if evidenceErr != nil {
		rollbackErr = errors.Join(rollbackErr, evidenceErr)
		status = "recovery-required"
	}
	if err := journal.Record(status, struct {
		Reason  string          `json:"reason"`
		Runtime json.RawMessage `json:"runtime,omitempty"`
	}{applyErr.Error(), evidence}); err != nil {
		rollbackErr = errors.Join(rollbackErr, err)
		status = "recovery-required"
	}
	return tuningOutcome{Status: status}, errors.Join(applyErr, rollbackErr)
}
