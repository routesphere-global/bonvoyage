package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type physicalCore struct {
	key        string
	socketID   int
	coreID     int
	numaNode   int
	logicalIDs []int
}

func loadPolicy(path string) (tuningPolicy, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tuningPolicy{}, "", fmt.Errorf("read policy: %w", err)
	}

	policy, err := decodeTuningPolicy(data)
	return policy, digest(data), err
}

func decodeTuningPolicy(data []byte) (tuningPolicy, error) {
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	var policy tuningPolicy
	if err := decoder.Decode(&policy); err != nil {
		return tuningPolicy{}, fmt.Errorf("decode policy: %w", err)
	}
	if err := validatePolicy(policy); err != nil {
		return tuningPolicy{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return tuningPolicy{}, errors.New("trailing policy YAML")
	}
	return policy, nil
}

func loadInventory(path string) (hostInventory, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return hostInventory{}, "", fmt.Errorf("read inventory: %w", err)
	}
	var inventory hostInventory
	if err := decodeTuningJSON(data, &inventory); err != nil {
		return hostInventory{}, "", fmt.Errorf("decode inventory: %w", err)
	}
	if inventory.SchemaVersion != inventorySchemaVersion {
		return hostInventory{}, "", fmt.Errorf(
			"unsupported inventory schema version %d", inventory.SchemaVersion,
		)
	}
	return inventory, digest(data), nil
}

func validatePolicy(policy tuningPolicy) error {
	if policy.SchemaVersion != 1 || policy.ID == "" {
		return errors.New("policy identity is incomplete")
	}
	if policy.GatewayCPUTargetPercent < 50 || policy.GatewayCPUTargetPercent > 90 {
		return errors.New("gateway CPU target must be between 50 and 90 percent")
	}
	if !policy.Discovery.RequireLinux || !policy.Discovery.RequireSysfs ||
		!policy.Discovery.CollectLSCPU || !policy.Discovery.CollectLSPCI ||
		!policy.Discovery.CollectKernelMessages ||
		policy.Discovery.KernelMessageAccess != "record-evidence-gap-when-restricted" ||
		!policy.Discovery.CollectNetworkDriverState ||
		!policy.Discovery.CollectSystemdAndCgroup {
		return errors.New("host discovery invariants are incomplete")
	}
	if policy.CPU.MinimumReservedPhysicalCores < 1 ||
		policy.CPU.MinimumReservedPercent < 10 ||
		policy.GatewayCPUTargetPercent+policy.CPU.MinimumReservedPercent > 100 ||
		!policy.CPU.KeepSMTSiblingsTogether ||
		!policy.CPU.RequireOnlineCPUVerification {
		return errors.New("CPU reservation and topology invariants are incomplete")
	}
	if policy.IRQ.Strategy != "reserved-same-numa" ||
		policy.IRQ.MinimumReservedPhysicalCores < 1 ||
		policy.IRQ.MaximumReservedPhysicalCores < policy.IRQ.MinimumReservedPhysicalCores ||
		policy.IRQ.QueuesPerReservedCore < 1 ||
		!policy.IRQ.KeepIRQBalanceEnabled ||
		!policy.IRQ.ExcludeGatewayCPUs ||
		!policy.IRQ.RequireQueueIRQInventory ||
		!policy.IRQ.RequireEffectiveAffinityVerification {
		return errors.New("IRQ reservation policy is invalid")
	}
	if policy.Memory.AllocationMode != "bounded-per-shard" ||
		policy.Memory.SeastarMiBPerShard < 128 ||
		policy.Memory.SeastarMinimumMiB < 256 ||
		policy.Memory.MinimumHostReserveMiB < 1024 ||
		policy.Memory.SeastarMaximumHostPercent > 75 ||
		policy.Memory.SystemdMemoryHighPercent >= policy.Memory.SystemdMemoryMaxPercent ||
		policy.Memory.SystemdMemoryMaxPercent > 95 ||
		!policy.Memory.RequireCgroupV2Verification ||
		!policy.Memory.RequireSwapStateRecording {
		return errors.New("memory bounds are invalid")
	}
	if !policy.NUMA.PreferSingleNode || !policy.NUMA.PreferNICLocality ||
		!policy.NUMA.RejectAsymmetricPartialCoreSets ||
		!policy.NUMA.RecordDistanceMatrix {
		return errors.New("NUMA topology invariants are incomplete")
	}
	if !policy.Network.DiscoverPCINUMALocality ||
		!policy.Network.DiscoverRXTXQueues ||
		policy.Network.RPSPolicy != "only-when-hardware-rss-is-insufficient" ||
		policy.Network.XPSPolicy != "topology-aware-when-measured" ||
		policy.Network.OffloadPolicy != "preserve-unless-ab-qualified" ||
		policy.Network.CoalescingPolicy != "preserve-unless-ab-qualified" ||
		!policy.Network.RequireBeforeAfterCounters {
		return errors.New("network tuning invariants are incomplete")
	}
	if policy.Memory.BenchmarkMode != "fixed-explicit" ||
		policy.Safety.DefaultMode != "plan-only" ||
		!policy.Safety.RequireExplicitApply ||
		!policy.Safety.RequireRollbackPlan ||
		!policy.Safety.RejectUnverifiedChanges ||
		policy.Safety.AllowKernelBootChanges {
		return errors.New("safety invariants are incomplete")
	}
	return nil
}

func buildPlan(
	policy tuningPolicy,
	policyDigest string,
	inventory hostInventory,
	inventoryDigest string,
	interfaceName string,
	requestedPhysicalCores int,
	now time.Time,
) (tuningPlan, error) {
	return buildResourcePlan(policy, policyDigest, inventory, inventoryDigest,
		interfaceName, requestedPhysicalCores, now, false)
}

// Keep the legacy planner strict. Only the explicit scoped entry point may
// defer guest affinity evidence; all topology and resource guards are shared.
func buildResourcePlan(policy tuningPolicy, policyDigest string, inventory hostInventory,
	inventoryDigest, interfaceName string, requestedPhysicalCores int, now time.Time,
	deferNICAffinity bool) (tuningPlan, error) {
	if inventory.Host.OperatingSystem != "linux" {
		return tuningPlan{}, fmt.Errorf(
			"inventory operating system %q is not Linux", inventory.Host.OperatingSystem,
		)
	}
	if inventory.Host.CgroupVersion != 2 && policy.Memory.RequireCgroupV2Verification {
		return tuningPlan{}, errors.New("cgroup v2 is required for the systemd memory plan")
	}
	if inventory.Host.MemoryTotalBytes <= 0 {
		return tuningPlan{}, errors.New("inventory has no physical memory total")
	}
	if err := validateOnlineCPUSet(inventory.CPULists.Online, inventory.CPUs); err != nil {
		return tuningPlan{}, err
	}

	nic, err := selectInterface(inventory.Interfaces, interfaceName)
	if err != nil {
		return tuningPlan{}, err
	}
	if nic.PCIBusAddress == "" || nic.Driver == "" || nic.NUMANode < 0 {
		return tuningPlan{}, fmt.Errorf(
			"interface %s lacks a usable driver/PCI/NUMA identity", nic.Name,
		)
	}
	if policy.IRQ.RequireQueueIRQInventory &&
		(len(nic.RXQueues) == 0 || len(nic.IRQs) == 0) {
		return tuningPlan{}, fmt.Errorf(
			"interface %s lacks RX queue or IRQ inventory", nic.Name,
		)
	}
	if policy.IRQ.RequireEffectiveAffinityVerification && !deferNICAffinity {
		for _, irq := range nic.IRQs {
			if irq.ConfiguredAffinityList == "" || irq.EffectiveAffinityList == "" {
				return tuningPlan{}, fmt.Errorf(
					"IRQ %d lacks configured or effective affinity evidence", irq.IRQ,
				)
			}
		}
	}

	cores, warnings, err := groupPhysicalCores(inventory.CPUs)
	if err != nil {
		return tuningPlan{}, err
	}
	warnings = append(warnings, inventory.Warnings...)
	if nic.OperationalState != "up" {
		warnings = append(warnings, fmt.Sprintf(
			"interface %s operational state is %q", nic.Name, nic.OperationalState,
		))
	}
	local := filterCoresByNode(cores, nic.NUMANode)
	distances, err := numaDistanceMap(inventory.NUMANodes, nic.NUMANode)
	if err != nil {
		return tuningPlan{}, err
	}
	if len(local) < policy.IRQ.MinimumReservedPhysicalCores {
		return tuningPlan{}, fmt.Errorf(
			"NIC-local NUMA node %d has only %d complete physical cores; need %d for IRQ reservation",
			nic.NUMANode,
			len(local),
			policy.IRQ.MinimumReservedPhysicalCores,
		)
	}

	minimumReserve := maxInt(
		policy.CPU.MinimumReservedPhysicalCores,
		ceilPercent(len(cores), policy.CPU.MinimumReservedPercent),
	)
	if minimumReserve >= len(cores) {
		return tuningPlan{}, fmt.Errorf(
			"host reservation of %d physical cores leaves no gateway capacity", minimumReserve,
		)
	}

	gatewayCoreCount := len(cores) * policy.GatewayCPUTargetPercent / 100
	mode := "production-auto"
	if requestedPhysicalCores > 0 {
		gatewayCoreCount = requestedPhysicalCores
		mode = "benchmark-fixed"
	}
	maximumGatewayCores := len(cores) - minimumReserve
	if gatewayCoreCount > maximumGatewayCores {
		if requestedPhysicalCores > 0 {
			return tuningPlan{}, fmt.Errorf(
				"requested %d gateway physical cores exceeds the safe maximum %d",
				gatewayCoreCount,
				maximumGatewayCores,
			)
		}
		warnings = append(warnings, fmt.Sprintf(
			"reduced automatic gateway allocation from %d to %d physical cores to preserve the host reserve",
			gatewayCoreCount,
			maximumGatewayCores,
		))
		gatewayCoreCount = maximumGatewayCores
	}
	if gatewayCoreCount < 1 {
		return tuningPlan{}, errors.New("gateway allocation contains no physical cores")
	}

	queueDemand := maxInt(len(nic.RXQueues), len(nic.IRQs))
	irqCoreCount := (queueDemand + policy.IRQ.QueuesPerReservedCore - 1) /
		policy.IRQ.QueuesPerReservedCore
	irqCoreCount = maxInt(irqCoreCount, policy.IRQ.MinimumReservedPhysicalCores)
	irqCoreCount = minInt(irqCoreCount, policy.IRQ.MaximumReservedPhysicalCores)
	irqCoreCount = minInt(irqCoreCount, minimumReserve)
	if irqCoreCount > len(local) {
		return tuningPlan{}, fmt.Errorf(
			"NIC-local NUMA node %d cannot supply %d IRQ cores", nic.NUMANode, irqCoreCount,
		)
	}

	irqCores := append([]physicalCore(nil), local[:irqCoreCount]...)
	irqKeys := make(map[string]bool, len(irqCores))
	for _, core := range irqCores {
		irqKeys[core.key] = true
	}

	candidates := make([]physicalCore, 0, len(cores)-irqCoreCount)
	for _, core := range cores {
		if !irqKeys[core.key] {
			candidates = append(candidates, core)
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		iLocal := candidates[i].numaNode == nic.NUMANode
		jLocal := candidates[j].numaNode == nic.NUMANode
		if iLocal != jLocal {
			return iLocal
		}
		if candidates[i].numaNode != candidates[j].numaNode {
			iDistance := distances[candidates[i].numaNode]
			jDistance := distances[candidates[j].numaNode]
			if iDistance != jDistance {
				return iDistance < jDistance
			}
			return candidates[i].numaNode < candidates[j].numaNode
		}
		if candidates[i].socketID != candidates[j].socketID {
			return candidates[i].socketID < candidates[j].socketID
		}
		return candidates[i].coreID < candidates[j].coreID
	})
	gatewayCores := append([]physicalCore(nil), candidates[:gatewayCoreCount]...)
	gatewayKeys := make(map[string]bool, len(gatewayCores))
	for _, core := range gatewayCores {
		gatewayKeys[core.key] = true
	}
	hostCores := make([]physicalCore, 0, len(cores)-len(gatewayCores))
	for _, core := range cores {
		if !gatewayKeys[core.key] {
			hostCores = append(hostCores, core)
		}
	}

	gatewayCPUs := logicalIDs(gatewayCores)
	hostCPUs := logicalIDs(hostCores)
	irqCPUs := logicalIDs(irqCores)
	gatewayNodes := uniqueNodes(gatewayCores)
	if len(gatewayNodes) > 1 {
		warnings = append(warnings, fmt.Sprintf(
			"gateway allocation spans NUMA nodes %s because %d complete NIC-local cores were available",
			joinInts(gatewayNodes, ","),
			len(local)-irqCoreCount,
		))
	}
	if len(inventory.CPULists.Isolated) > 0 {
		warnings = append(warnings,
			"kernel-isolated CPUs exist; verify their ownership before applying this plan")
	}
	if inventory.Host.SwapTotalBytes > 0 {
		warnings = append(warnings,
			"swap is enabled; disable it before dedicated qualification")
	}

	memory, err := planMemory(policy.Memory, inventory.Host.MemoryTotalBytes, len(gatewayCPUs))
	if err != nil {
		return tuningPlan{}, err
	}
	assignments := assignIRQs(nic.IRQs, irqCores)
	recommendations := networkRecommendations(nic, len(gatewayCores))

	return tuningPlan{
		SchemaVersion:   planSchemaVersion,
		GeneratedAt:     now.UTC(),
		PolicyID:        policy.ID,
		PolicySHA256:    policyDigest,
		InventorySHA256: inventoryDigest,
		HostFingerprint: inventory.Host.Fingerprint,
		Mode:            mode,
		Interface: plannedInterface{
			Name:          nic.Name,
			Driver:        nic.Driver,
			PCIBusAddress: nic.PCIBusAddress,
			NUMANode:      nic.NUMANode,
			RXQueueCount:  len(nic.RXQueues),
			TXQueueCount:  len(nic.TXQueues),
		},
		CPU: plannedCPU{
			PhysicalCoreCount:         len(cores),
			LogicalCPUCount:           countLogical(cores),
			GatewayPhysicalCoreCount:  len(gatewayCores),
			GatewayLogicalCPUs:        gatewayCPUs,
			GatewayCPUSet:             formatCPUList(gatewayCPUs),
			HostReservedPhysicalCores: len(hostCores),
			HostReservedLogicalCPUs:   hostCPUs,
			HostReservedCPUSet:        formatCPUList(hostCPUs),
			NUMANodes:                 gatewayNodes,
		},
		Memory: memory,
		IRQ: plannedIRQ{
			ReservedPhysicalCoreCount: len(irqCores),
			ReservedLogicalCPUs:       irqCPUs,
			ReservedCPUSet:            formatCPUList(irqCPUs),
			Assignments:               assignments,
			IRQBalanceBannedCPUList:   formatCPUList(gatewayCPUs),
		},
		Recommendations: recommendations,
		Warnings:        warnings,
	}, nil
}

func selectInterface(interfaces []networkInterface, requested string) (networkInterface, error) {
	if requested != "" && requested != "auto" {
		for _, nic := range interfaces {
			if nic.Name == requested {
				return nic, nil
			}
		}
		return networkInterface{}, fmt.Errorf("interface %q is not in the inventory", requested)
	}
	var selected []networkInterface
	for _, nic := range interfaces {
		if nic.DefaultRoute {
			selected = append(selected, nic)
		}
	}
	if len(selected) != 1 {
		return networkInterface{}, fmt.Errorf(
			"automatic interface selection requires exactly one default-route interface; found %d",
			len(selected),
		)
	}
	return selected[0], nil
}

func groupPhysicalCores(cpus []logicalCPU) ([]physicalCore, []string, error) {
	online := make(map[int]logicalCPU)
	groups := make(map[string]*physicalCore)
	for _, cpu := range cpus {
		if !cpu.Online {
			continue
		}
		if cpu.ID < 0 || cpu.CoreID < 0 || cpu.SocketID < 0 || cpu.NUMANode < 0 {
			return nil, nil, fmt.Errorf("logical CPU %d has incomplete topology", cpu.ID)
		}
		if _, exists := online[cpu.ID]; exists {
			return nil, nil, fmt.Errorf("logical CPU %d is duplicated", cpu.ID)
		}
		online[cpu.ID] = cpu
		key := fmt.Sprintf("%d:%d", cpu.SocketID, cpu.CoreID)
		group := groups[key]
		if group == nil {
			group = &physicalCore{
				key: key, socketID: cpu.SocketID, coreID: cpu.CoreID, numaNode: cpu.NUMANode,
			}
			groups[key] = group
		}
		if group.numaNode != cpu.NUMANode {
			return nil, nil, fmt.Errorf("physical core %s spans NUMA nodes", key)
		}
		group.logicalIDs = append(group.logicalIDs, cpu.ID)
	}

	warnings := []string{}
	complete := make([]physicalCore, 0, len(groups))
	for _, group := range groups {
		sort.Ints(group.logicalIDs)
		valid := true
		for _, cpuID := range group.logicalIDs {
			siblings := append([]int(nil), online[cpuID].Siblings...)
			sort.Ints(siblings)
			if len(siblings) > 0 && !equalInts(siblings, group.logicalIDs) {
				valid = false
				break
			}
		}
		if !valid {
			warnings = append(warnings,
				fmt.Sprintf("excluded physical core %s because not all SMT siblings are online", group.key))
			continue
		}
		complete = append(complete, *group)
	}
	if len(complete) == 0 {
		return nil, nil, errors.New("inventory contains no complete online physical cores")
	}
	sort.Slice(complete, func(i, j int) bool {
		if complete[i].numaNode != complete[j].numaNode {
			return complete[i].numaNode < complete[j].numaNode
		}
		if complete[i].socketID != complete[j].socketID {
			return complete[i].socketID < complete[j].socketID
		}
		return complete[i].coreID < complete[j].coreID
	})
	return complete, warnings, nil
}

func validateOnlineCPUSet(declared []int, cpus []logicalCPU) error {
	actual := make([]int, 0)
	for _, cpu := range cpus {
		if cpu.Online {
			actual = append(actual, cpu.ID)
		}
	}
	sort.Ints(actual)
	orderedDeclared := append([]int(nil), declared...)
	sort.Ints(orderedDeclared)
	if !equalInts(orderedDeclared, actual) {
		return fmt.Errorf(
			"declared online CPU set %q differs from normalized topology %q",
			formatCPUList(orderedDeclared),
			formatCPUList(actual),
		)
	}
	return nil
}

func planMemory(policy memoryPolicy, totalBytes int64, shards int) (plannedMemory, error) {
	totalMiB := totalBytes / (1024 * 1024)
	seastarMiB := maxInt64(policy.SeastarMinimumMiB, int64(shards)*policy.SeastarMiBPerShard)
	percentCap := totalMiB * policy.SeastarMaximumHostPercent / 100
	reserveCap := totalMiB - policy.MinimumHostReserveMiB
	capMiB := minInt64(percentCap, reserveCap)
	if capMiB < policy.SeastarMinimumMiB {
		return plannedMemory{}, errors.New("host memory cannot satisfy the minimum allocator and host reserve")
	}
	if seastarMiB > capMiB {
		seastarMiB = capMiB
	}
	highMiB := totalMiB * policy.SystemdMemoryHighPercent / 100
	maxMiB := totalMiB * policy.SystemdMemoryMaxPercent / 100
	if seastarMiB+256 > highMiB {
		return plannedMemory{}, errors.New("Seastar allocation leaves insufficient process overhead below MemoryHigh")
	}
	return plannedMemory{
		HostTotalMiB:         totalMiB,
		SeastarMiB:           seastarMiB,
		SeastarArgument:      fmt.Sprintf("%dM", seastarMiB),
		SystemdMemoryHighMiB: highMiB,
		SystemdMemoryMaxMiB:  maxMiB,
		HostReserveMiB:       totalMiB - seastarMiB,
	}, nil
}

func assignIRQs(irqs []irqInventory, cores []physicalCore) []irqAssignment {
	orderedIRQs := append([]irqInventory(nil), irqs...)
	sort.Slice(orderedIRQs, func(i, j int) bool { return orderedIRQs[i].IRQ < orderedIRQs[j].IRQ })
	assignments := make([]irqAssignment, 0, len(orderedIRQs))
	for index, irq := range orderedIRQs {
		core := cores[index%len(cores)]
		logicalCPU := core.logicalIDs[(index/len(cores))%len(core.logicalIDs)]
		assignments = append(assignments, irqAssignment{IRQ: irq.IRQ, LogicalCPU: logicalCPU})
	}
	return assignments
}

func networkRecommendations(nic networkInterface, gatewayCores int) []recommendation {
	rpsDecision := "review-required"
	rpsReason := "hardware RSS inventory is incomplete or has fewer RX queues than gateway physical cores"
	if nic.HardwareRSSInventoryPassed && len(nic.RXQueues) >= gatewayCores {
		rpsDecision = "keep-disabled"
		rpsReason = "hardware RSS exposes at least one RX queue per selected gateway physical core"
	}
	return []recommendation{
		{ID: "software-rps", Decision: rpsDecision, Reason: rpsReason},
		{ID: "xps", Decision: "measure-before-change", Reason: "XPS requires a topology-specific A/B result"},
		{ID: "offloads", Decision: "preserve", Reason: "offload changes are outside the automatic baseline"},
		{ID: "coalescing", Decision: "preserve", Reason: "coalescing changes require latency and CPU A/B evidence"},
		{ID: "kernel-boot", Decision: "preserve", Reason: "automatic kernel boot changes are prohibited"},
	}
}

func renderPlanArtifacts(plan tuningPlan) (map[string][]byte, error) {
	if err := validateTuningPlanScope(plan); err != nil {
		return nil, err
	}
	planJSON, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode plan: %w", err)
	}
	planJSON = append(planJSON, '\n')

	files := map[string][]byte{
		"tuning-plan.json": planJSON,
		"bonvoyage-resources.conf": []byte(fmt.Sprintf(
			"[Service]\nCPUAffinity=%s\nAllowedCPUs=%s\nMemoryHigh=%dM\nMemoryMax=%dM\n",
			joinInts(plan.CPU.GatewayLogicalCPUs, " "),
			plan.CPU.GatewayCPUSet,
			plan.Memory.SystemdMemoryHighMiB,
			plan.Memory.SystemdMemoryMaxMiB,
		)),
		"bonvoyage-runtime-arguments.txt": []byte(fmt.Sprintf(
			"--smp %d --cpuset %s --memory %s\n",
			len(plan.CPU.GatewayLogicalCPUs),
			plan.CPU.GatewayCPUSet,
			plan.Memory.SeastarArgument,
		)),
		"irqbalance.env": []byte(fmt.Sprintf(
			"IRQBALANCE_BANNED_CPULIST=%s\n", plan.IRQ.IRQBalanceBannedCPUList,
		)),
		"irq-affinity.plan.tsv": []byte(formatIRQPlan(plan.IRQ.Assignments)),
		"README.txt": []byte(
			"PLAN ONLY: these files do not change the host.\n" +
				"Review the JSON identity, topology warnings, service limits, and IRQ assignments.\n" +
				"Do not apply this bundle with ad hoc shell commands; the verified apply/rollback stage is required.\n",
		),
	}

	if plan.Scope == tuningScopeVMCPU {
		files["README.txt"] = append(files["README.txt"], []byte("Scope: vm-cpu-memory. Explicit lab/maintenance approval is required.\nNIC-local affinity qualification is deferred; proposed IRQ assignments are not qualification evidence.\nMeasurements and production tuning remain unauthorized.\n")...)
	}
	return files, nil
}

func writePlanArtifacts(outputDirectory string, plan tuningPlan) error {
	if err := os.Mkdir(outputDirectory, 0o700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	files, err := renderPlanArtifacts(plan)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	checksums := make([]string, 0, len(names))
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(outputDirectory, name), files[name], 0o600); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
		checksums = append(checksums, fmt.Sprintf("%s  %s", digest(files[name]), name))
	}
	return os.WriteFile(
		filepath.Join(outputDirectory, "checksums.sha256"),
		[]byte(strings.Join(checksums, "\n")+"\n"),
		0o600,
	)
}

func formatIRQPlan(assignments []irqAssignment) string {
	var builder strings.Builder
	builder.WriteString("irq\tlogical_cpu\taffinity_list_path\teffective_affinity_list_path\n")
	for _, assignment := range assignments {
		fmt.Fprintf(
			&builder,
			"%d\t%d\t/proc/irq/%d/smp_affinity_list\t/proc/irq/%d/effective_affinity_list\n",
			assignment.IRQ,
			assignment.LogicalCPU,
			assignment.IRQ,
			assignment.IRQ,
		)
	}
	return builder.String()
}

func filterCoresByNode(cores []physicalCore, node int) []physicalCore {
	filtered := make([]physicalCore, 0)
	for _, core := range cores {
		if core.numaNode == node {
			filtered = append(filtered, core)
		}
	}
	return filtered
}

func numaDistanceMap(nodes []numaNode, source int) (map[int]int, error) {
	var sourceNode *numaNode
	knownNodes := make(map[int]bool, len(nodes))
	for index := range nodes {
		knownNodes[nodes[index].ID] = true
		if nodes[index].ID == source {
			sourceNode = &nodes[index]
		}
	}
	if sourceNode == nil {
		return nil, fmt.Errorf("NIC-local NUMA node %d is absent from the inventory", source)
	}
	if len(sourceNode.Distance) != len(nodes) {
		return nil, fmt.Errorf(
			"NUMA node %d has %d distance values for %d nodes",
			source,
			len(sourceNode.Distance),
			len(nodes),
		)
	}
	distances := make(map[int]int, len(nodes))
	for index, node := range nodes {
		if node.ID != index {
			return nil, fmt.Errorf(
				"NUMA node IDs must be contiguous from zero; found node %d at position %d",
				node.ID,
				index,
			)
		}
		if !knownNodes[node.ID] || sourceNode.Distance[node.ID] <= 0 {
			return nil, fmt.Errorf("NUMA distance matrix is invalid at node %d", node.ID)
		}
		distances[node.ID] = sourceNode.Distance[node.ID]
	}
	return distances, nil
}

func logicalIDs(cores []physicalCore) []int {
	ids := make([]int, 0)
	for _, core := range cores {
		ids = append(ids, core.logicalIDs...)
	}
	sort.Ints(ids)
	return ids
}

func uniqueNodes(cores []physicalCore) []int {
	seen := make(map[int]bool)
	for _, core := range cores {
		seen[core.numaNode] = true
	}
	nodes := make([]int, 0, len(seen))
	for node := range seen {
		nodes = append(nodes, node)
	}
	sort.Ints(nodes)
	return nodes
}

func countLogical(cores []physicalCore) int {
	total := 0
	for _, core := range cores {
		total += len(core.logicalIDs)
	}
	return total
}

func formatCPUList(ids []int) string {
	if len(ids) == 0 {
		return ""
	}
	ordered := append([]int(nil), ids...)
	sort.Ints(ordered)
	parts := make([]string, 0)
	start := ordered[0]
	previous := ordered[0]
	for _, current := range ordered[1:] {
		if current == previous+1 {
			previous = current
			continue
		}
		parts = append(parts, formatRange(start, previous))
		start = current
		previous = current
	}
	parts = append(parts, formatRange(start, previous))
	return strings.Join(parts, ",")
}

func formatRange(start, end int) string {
	if start == end {
		return strconv.Itoa(start)
	}
	return fmt.Sprintf("%d-%d", start, end)
}

func joinInts(values []int, separator string) string {
	parts := make([]string, len(values))
	for index, value := range values {
		parts[index] = strconv.Itoa(value)
	}
	return strings.Join(parts, separator)
}

func equalInts(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func ceilPercent(value, percent int) int {
	return (value*percent + 99) / 100
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func minInt64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}
