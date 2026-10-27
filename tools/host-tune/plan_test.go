package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestVersionedPolicyLoads(t *testing.T) {
	policyPath := filepath.Join(
		"..", "..", "deploy", "tuning", "policies", "throughput-balanced.yaml",
	)
	policy, policyDigest, err := loadPolicy(policyPath)
	if err != nil {
		t.Fatalf("loadPolicy returned an error: %v", err)
	}
	if policy.ID != "throughput-balanced-v1" ||
		policy.GatewayCPUTargetPercent != 80 ||
		len(policyDigest) != 64 {
		t.Fatalf("unexpected versioned policy identity: %+v %q", policy, policyDigest)
	}
}

func TestBuildPlanNoSMTUsesEightyPercentAndKeepsIRQsLocal(t *testing.T) {
	policy := testPolicy()
	inventory := testInventory(16, 1)

	plan, err := buildPlan(
		policy,
		strings.Repeat("a", 64),
		inventory,
		strings.Repeat("b", 64),
		"auto",
		0,
		time.Unix(0, 0),
	)
	if err != nil {
		t.Fatalf("buildPlan returned an error: %v", err)
	}

	if plan.Mode != "production-auto" || plan.CPU.GatewayPhysicalCoreCount != 12 {
		t.Fatalf("unexpected automatic CPU plan: %+v", plan.CPU)
	}
	if got, want := plan.IRQ.ReservedLogicalCPUs, []int{0, 1}; !reflect.DeepEqual(got, want) {
		t.Fatalf("IRQ CPUs = %v, want %v", got, want)
	}
	if containsAny(plan.CPU.GatewayLogicalCPUs, plan.IRQ.ReservedLogicalCPUs) {
		t.Fatalf("gateway and IRQ CPU sets overlap: %+v", plan.CPU)
	}
	if got, want := plan.Memory.SeastarMiB, int64(6144); got != want {
		t.Fatalf("Seastar memory = %d MiB, want %d MiB", got, want)
	}
	for _, assignment := range plan.IRQ.Assignments {
		if assignment.LogicalCPU != 0 && assignment.LogicalCPU != 1 {
			t.Fatalf("IRQ %d was assigned outside the NIC-local reserve", assignment.IRQ)
		}
	}
}

func TestBuildPlanKeepsSMTSiblingsTogether(t *testing.T) {
	policy := testPolicy()
	inventory := testInventory(8, 2)

	plan, err := buildPlan(
		policy,
		strings.Repeat("a", 64),
		inventory,
		strings.Repeat("b", 64),
		"eth0",
		4,
		time.Unix(0, 0),
	)
	if err != nil {
		t.Fatalf("buildPlan returned an error: %v", err)
	}
	if plan.Mode != "benchmark-fixed" || plan.CPU.GatewayPhysicalCoreCount != 4 {
		t.Fatalf("unexpected fixed CPU plan: %+v", plan.CPU)
	}
	if len(plan.CPU.GatewayLogicalCPUs) != 8 {
		t.Fatalf("logical CPUs = %v, want four complete SMT pairs", plan.CPU.GatewayLogicalCPUs)
	}
	selected := make(map[int]bool)
	for _, cpu := range plan.CPU.GatewayLogicalCPUs {
		selected[cpu] = true
	}
	for _, cpu := range inventory.CPUs {
		if !selected[cpu.ID] {
			continue
		}
		for _, sibling := range cpu.Siblings {
			if !selected[sibling] {
				t.Fatalf("CPU %d selected without sibling %d", cpu.ID, sibling)
			}
		}
	}
}

func TestBuildPlanReducesAutomaticAllocationToPreserveSmallHost(t *testing.T) {
	policy := testPolicy()
	plan, err := buildPlan(
		policy,
		strings.Repeat("a", 64),
		testInventory(4, 1),
		strings.Repeat("b", 64),
		"auto",
		0,
		time.Unix(0, 0),
	)
	if err != nil {
		t.Fatalf("buildPlan returned an error: %v", err)
	}
	if plan.CPU.GatewayPhysicalCoreCount != 2 ||
		plan.CPU.HostReservedPhysicalCores != 2 {
		t.Fatalf("small-host reserve was not preserved: %+v", plan.CPU)
	}
	foundWarning := false
	for _, warning := range plan.Warnings {
		if strings.Contains(warning, "reduced automatic gateway allocation") {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Fatalf("small-host reduction warning is missing: %v", plan.Warnings)
	}
}

func TestBuildPlanRejectsMissingNICIRQInventory(t *testing.T) {
	policy := testPolicy()
	inventory := testInventory(16, 1)
	inventory.Interfaces[0].IRQs = nil

	_, err := buildPlan(
		policy,
		strings.Repeat("a", 64),
		inventory,
		strings.Repeat("b", 64),
		"auto",
		0,
		time.Unix(0, 0),
	)
	if err == nil || !strings.Contains(err.Error(), "IRQ inventory") {
		t.Fatalf("expected missing IRQ inventory error, got %v", err)
	}
}

func TestWritePlanArtifactsIsPlanOnlyAndChecksumBound(t *testing.T) {
	policy := testPolicy()
	plan, err := buildPlan(
		policy,
		strings.Repeat("a", 64),
		testInventory(16, 1),
		strings.Repeat("b", 64),
		"auto",
		0,
		time.Unix(0, 0),
	)
	if err != nil {
		t.Fatalf("buildPlan returned an error: %v", err)
	}
	output := filepath.Join(t.TempDir(), "plan")
	if err := writePlanArtifacts(output, plan); err != nil {
		t.Fatalf("writePlanArtifacts returned an error: %v", err)
	}
	for _, name := range []string{
		"tuning-plan.json",
		"bonvoyage-resources.conf",
		"bonvoyage-runtime-arguments.txt",
		"irqbalance.env",
		"irq-affinity.plan.tsv",
		"README.txt",
		"checksums.sha256",
	} {
		if _, err := os.Stat(filepath.Join(output, name)); err != nil {
			t.Errorf("expected artifact %s: %v", name, err)
		}
	}
	readme, err := os.ReadFile(filepath.Join(output, "README.txt"))
	if err != nil || !strings.Contains(string(readme), "PLAN ONLY") {
		t.Fatalf("plan-only boundary missing from README: %v", err)
	}
	if err := writePlanArtifacts(output, plan); err == nil {
		t.Fatal("expected an existing output directory to be rejected")
	}
}

func TestRunPlanUsesVersionedPolicyEndToEnd(t *testing.T) {
	temporaryDirectory := t.TempDir()
	inventoryPath := filepath.Join(temporaryDirectory, "inventory.json")
	encoded, err := json.Marshal(testInventory(16, 1))
	if err != nil {
		t.Fatalf("encode inventory: %v", err)
	}
	if err := os.WriteFile(inventoryPath, encoded, 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	outputPath := filepath.Join(temporaryDirectory, "plan")
	policyPath := filepath.Join(
		"..", "..", "deploy", "tuning", "policies", "throughput-balanced.yaml",
	)
	if err := runPlan([]string{
		"--inventory", inventoryPath,
		"--policy", policyPath,
		"--gateway-physical-cores", "8",
		"--output", outputPath,
	}); err != nil {
		t.Fatalf("runPlan returned an error: %v", err)
	}
	planData, err := os.ReadFile(filepath.Join(outputPath, "tuning-plan.json"))
	if err != nil {
		t.Fatalf("read generated plan: %v", err)
	}
	var plan tuningPlan
	if err := json.Unmarshal(planData, &plan); err != nil {
		t.Fatalf("decode generated plan: %v", err)
	}
	if plan.PolicyID != "throughput-balanced-v1" ||
		plan.CPU.GatewayPhysicalCoreCount != 8 {
		t.Fatalf("unexpected generated plan: %+v", plan)
	}
}

func TestCPUListRoundTrip(t *testing.T) {
	parsed, err := parseCPUList("0-3,8,10-11")
	if err != nil {
		t.Fatalf("parseCPUList returned an error: %v", err)
	}
	if got, want := formatCPUList(parsed), "0-3,8,10-11"; got != want {
		t.Fatalf("formatCPUList = %q, want %q", got, want)
	}
}

func testPolicy() tuningPolicy {
	return tuningPolicy{
		SchemaVersion:           1,
		ID:                      "throughput-balanced-v1",
		GatewayCPUTargetPercent: 80,
		CPU: cpuPolicy{
			MinimumReservedPhysicalCores: 2,
			MinimumReservedPercent:       20,
			KeepSMTSiblingsTogether:      true,
			RequireOnlineCPUVerification: true,
		},
		Memory: memoryPolicy{
			AllocationMode:              "bounded-per-shard",
			SeastarMiBPerShard:          512,
			SeastarMinimumMiB:           1024,
			SeastarMaximumHostPercent:   70,
			MinimumHostReserveMiB:       4096,
			SystemdMemoryHighPercent:    80,
			SystemdMemoryMaxPercent:     85,
			BenchmarkMode:               "fixed-explicit",
			RequireCgroupV2Verification: true,
			RequireSwapStateRecording:   true,
		},
		IRQ: irqPolicy{
			KeepIRQBalanceEnabled:        true,
			ExcludeGatewayCPUs:           true,
			MinimumReservedPhysicalCores: 2,
			MaximumReservedPhysicalCores: 8,
			QueuesPerReservedCore:        4,
			RequireQueueIRQInventory:     true,
		},
		Safety: safetyPolicy{
			DefaultMode:             "plan-only",
			RequireExplicitApply:    true,
			RequireRollbackPlan:     true,
			RejectUnverifiedChanges: true,
			AllowKernelBootChanges:  false,
		},
	}
}

func testInventory(physicalCores, threadsPerCore int) hostInventory {
	logicalCount := physicalCores * threadsPerCore
	logicalCPUs := make([]logicalCPU, 0, logicalCount)
	for core := 0; core < physicalCores; core++ {
		siblings := make([]int, 0, threadsPerCore)
		for thread := 0; thread < threadsPerCore; thread++ {
			siblings = append(siblings, core+thread*physicalCores)
		}
		node := 0
		if core >= physicalCores/2 {
			node = 1
		}
		for _, id := range siblings {
			logicalCPUs = append(logicalCPUs, logicalCPU{
				ID: id, CoreID: core, SocketID: 0, NUMANode: node,
				Online: true, Siblings: append([]int(nil), siblings...),
			})
		}
	}
	sortLogicalCPUs(logicalCPUs)
	online := make([]int, logicalCount)
	for index := range online {
		online[index] = index
	}
	irqs := make([]irqInventory, 8)
	for index := range irqs {
		irqs[index] = irqInventory{
			IRQ:                    100 + index,
			ConfiguredAffinityList: "0-15",
			EffectiveAffinityList:  "0-15",
		}
	}
	queues := []string{"rx-0", "rx-1", "rx-2", "rx-3", "rx-4", "rx-5", "rx-6", "rx-7"}
	return hostInventory{
		SchemaVersion: inventorySchemaVersion,
		Host: hostIdentity{
			OperatingSystem:  "linux",
			Architecture:     "amd64",
			Fingerprint:      strings.Repeat("c", 64),
			MemoryTotalBytes: 128 * 1024 * 1024 * 1024,
			CgroupVersion:    2,
		},
		CPULists: kernelCPULists{Online: online, Isolated: []int{}, NoHZFull: []int{}},
		CPUs:     logicalCPUs,
		NUMANodes: []numaNode{
			{ID: 0, Distance: []int{10, 20}},
			{ID: 1, Distance: []int{20, 10}},
		},
		Interfaces: []networkInterface{{
			Name: "eth0", DefaultRoute: true, OperationalState: "up", Driver: "ena",
			PCIBusAddress: "0000:00:05.0", NUMANode: 0,
			RXQueues: queues, TXQueues: queues, IRQs: irqs,
			HardwareRSSInventoryPassed: true,
		}},
	}
}

func sortLogicalCPUs(cpus []logicalCPU) {
	sort.Slice(cpus, func(i, j int) bool { return cpus[i].ID < cpus[j].ID })
}

func containsAny(left, right []int) bool {
	seen := make(map[int]bool)
	for _, value := range left {
		seen[value] = true
	}
	for _, value := range right {
		if seen[value] {
			return true
		}
	}
	return false
}
