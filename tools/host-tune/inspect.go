package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const commandOutputLimit = 16 * 1024 * 1024

type boundedBuffer struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (buffer *boundedBuffer) Write(data []byte) (int, error) {
	originalLength := len(data)
	remaining := buffer.limit - buffer.buffer.Len()
	if remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
			buffer.truncated = true
		}
		_, _ = buffer.buffer.Write(data)
	} else if len(data) > 0 {
		buffer.truncated = true
	}
	return originalLength, nil
}

func (buffer *boundedBuffer) Bytes() []byte {
	if !buffer.truncated {
		return buffer.buffer.Bytes()
	}
	return append(buffer.buffer.Bytes(), []byte("\n[output truncated by bonvoyage-host-tune]\n")...)
}

func collectInventory(
	outputDirectory string,
	requestedInterface string,
	requireAWSIdentity bool,
	now time.Time,
) (hostInventory, error) {
	if runtime.GOOS != "linux" {
		return hostInventory{}, fmt.Errorf("inspect requires Linux; current platform is %s", runtime.GOOS)
	}
	if err := os.Mkdir(outputDirectory, 0o700); err != nil {
		return hostInventory{}, fmt.Errorf("create output directory: %w", err)
	}
	rawDirectory := filepath.Join(outputDirectory, "raw")
	if err := os.Mkdir(rawDirectory, 0o700); err != nil {
		return hostInventory{}, fmt.Errorf("create raw evidence directory: %w", err)
	}

	inventory := hostInventory{
		SchemaVersion: inventorySchemaVersion,
		CapturedAt:    now.UTC(),
		Warnings:      []string{},
	}
	host, err := inspectHost()
	if err != nil {
		return hostInventory{}, err
	}
	inventory.Host = host
	if requireAWSIdentity {
		cloud, err := collectAWSIdentity(awsMetadataEndpoint)
		if err != nil {
			return hostInventory{}, fmt.Errorf("collect AWS instance identity: %w", err)
		}
		inventory.Cloud = &cloud
	}
	inventory.CPULists = inspectKernelCPULists()
	if len(inventory.CPULists.Online) == 0 {
		return hostInventory{}, errors.New("sysfs contains no authoritative online CPU list")
	}
	inventory.CPUs, err = inspectCPUs()
	if err != nil {
		return hostInventory{}, err
	}
	inventory.NUMANodes, err = inspectNUMANodes()
	if err != nil {
		return hostInventory{}, err
	}

	runner := evidenceRunner{rawDirectory: rawDirectory}
	defaultRoutes := inspectDefaultRoutes(&runner)
	inventory.Interfaces, err = inspectInterfaces(&runner, defaultRoutes, requestedInterface)
	if err != nil {
		return hostInventory{}, err
	}

	runner.capture("lscpu", "lscpu", "-J", "-e=CPU,NODE,SOCKET,CORE,ONLINE,MAXMHZ,MINMHZ")
	runner.capture("numactl-hardware", "numactl", "--hardware")
	runner.capture("lspci", "lspci", "-Dnnk")
	runner.capture("lspci-tree", "lspci", "-Dtv")
	runner.capture("cpupower-frequency", "cpupower", "frequency-info")
	runner.capture("uname", "uname", "-a")
	runner.capture("os-release", "cat", "/etc/os-release")
	runner.capture("kernel-command-line", "cat", "/proc/cmdline")
	runner.capture("interrupts", "cat", "/proc/interrupts")
	runner.capture("memory", "cat", "/proc/meminfo")
	runner.capture("scheduler-stat", "cat", "/proc/stat")
	runner.capture("network-device-stat", "cat", "/proc/net/dev")
	runner.capture("ip-addresses-json", "ip", "-j", "address", "show")
	runner.capture("ip-routes-all-json", "ip", "-j", "route", "show", "table", "all")
	runner.capture(
		"clock-state",
		"timedatectl",
		"show",
		"--property=NTPSynchronized",
		"--property=Timezone",
		"--property=LocalRTC",
		"--property=TimeUSec",
	)
	runner.capture("systemd-version", "systemctl", "--version")
	runner.capture(
		"systemd-timers",
		"systemctl", "list-timers", "--all", "--no-pager", "--no-legend",
	)
	runner.capture(
		"systemd-running-services",
		"systemctl", "list-units", "--type=service", "--state=running",
		"--no-pager", "--no-legend",
	)
	runner.capture(
		"bonvoyage-systemd-state",
		"systemctl",
		"show",
		"bonvoyage.service",
		"--property=AllowedCPUs,CPUAffinity,MemoryCurrent,MemoryHigh,MemoryMax,LimitNOFILE",
	)
	runner.capture("process-snapshot", "ps", "-eo", "pid=,ppid=,psr=,stat=,comm=")
	runner.capture("uptime", "uptime")
	runner.capture(
		"clocksource",
		"cat", "/sys/devices/system/clocksource/clocksource0/current_clocksource",
	)
	runner.capture("kernel-warnings", "dmesg", "--color=never", "--level=err,warn")
	inventory.Commands = runner.evidence
	inventory.Warnings = append(inventory.Warnings, runner.warnings...)

	cloudFingerprint := ""
	if inventory.Cloud != nil {
		cloudFingerprint = fmt.Sprintf(
			"%s:%s:%s:%s:%s:%s:%s:%s:%s",
			inventory.Cloud.Provider,
			inventory.Cloud.InstanceID,
			inventory.Cloud.InstanceType,
			inventory.Cloud.ImageID,
			inventory.Cloud.PrivateIPv4,
			inventory.Cloud.AvailabilityZone,
			inventory.Cloud.Region,
			inventory.Cloud.Architecture,
			inventory.Cloud.HostID,
		)
	}
	fingerprintMaterial := fmt.Sprintf(
		"%s\n%s\n%s\n%s\n%s\n%s\n",
		inventory.Host.MachineIDHash,
		inventory.Host.BootID,
		formatCPUList(inventory.CPULists.Online),
		interfaceFingerprint(inventory.Interfaces),
		inventory.Host.KernelRelease,
		cloudFingerprint,
	)
	inventory.Host.Fingerprint = digest([]byte(fingerprintMaterial))

	encoded, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		return hostInventory{}, fmt.Errorf("encode inventory: %w", err)
	}
	if err := os.WriteFile(
		filepath.Join(outputDirectory, "inventory.json"),
		append(encoded, '\n'),
		0o600,
	); err != nil {
		return hostInventory{}, fmt.Errorf("write inventory: %w", err)
	}
	if err := writeDirectoryChecksums(outputDirectory); err != nil {
		return hostInventory{}, err
	}
	return inventory, nil
}

type evidenceRunner struct {
	rawDirectory string
	evidence     []commandEvidence
	warnings     []string
}

func (runner *evidenceRunner) capture(name, executable string, arguments ...string) ([]byte, int) {
	stdoutPath := filepath.Join(runner.rawDirectory, name+".stdout")
	stderrPath := filepath.Join(runner.rawDirectory, name+".stderr")
	evidence := commandEvidence{
		Name:       name,
		Command:    strings.Join(append([]string{executable}, arguments...), " "),
		StdoutPath: filepath.ToSlash(filepath.Join("raw", name+".stdout")),
		StderrPath: filepath.ToSlash(filepath.Join("raw", name+".stderr")),
	}

	path, err := exec.LookPath(executable)
	if err != nil {
		evidence.ExitCode = 127
		message := []byte(fmt.Sprintf("%s is not installed\n", executable))
		_ = os.WriteFile(stdoutPath, nil, 0o600)
		_ = os.WriteFile(stderrPath, message, 0o600)
		runner.evidence = append(runner.evidence, evidence)
		runner.warnings = append(runner.warnings,
			fmt.Sprintf("command %s is unavailable", executable))
		return nil, evidence.ExitCode
	}

	stdout := &boundedBuffer{limit: commandOutputLimit}
	stderr := &boundedBuffer{limit: commandOutputLimit}
	command := exec.Command(path, arguments...)
	command.Stdout = stdout
	command.Stderr = stderr
	err = command.Run()
	if err == nil {
		evidence.ExitCode = 0
	} else {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			evidence.ExitCode = exitError.ExitCode()
		} else {
			evidence.ExitCode = 126
		}
		runner.warnings = append(runner.warnings,
			fmt.Sprintf("command %s exited with status %d", name, evidence.ExitCode))
	}
	if stdout.truncated || stderr.truncated {
		runner.warnings = append(runner.warnings,
			fmt.Sprintf("command %s output exceeded %d bytes", name, commandOutputLimit))
	}
	_ = os.WriteFile(stdoutPath, stdout.Bytes(), 0o600)
	_ = os.WriteFile(stderrPath, stderr.Bytes(), 0o600)
	runner.evidence = append(runner.evidence, evidence)
	return stdout.Bytes(), evidence.ExitCode
}

func inspectHost() (hostIdentity, error) {
	memory := parseMeminfo(readTextFile("/proc/meminfo"))
	cgroupVersion := 1
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		cgroupVersion = 2
	}
	machineID := strings.TrimSpace(readTextFile("/etc/machine-id"))
	hostname, _ := os.Hostname()
	bootID := strings.TrimSpace(readTextFile("/proc/sys/kernel/random/boot_id"))
	kernelRelease := strings.TrimSpace(readTextFile("/proc/sys/kernel/osrelease"))
	if machineID == "" || bootID == "" || kernelRelease == "" ||
		memory["MemTotal"] <= 0 {
		return hostIdentity{}, errors.New(
			"host identity requires machine ID, boot ID, kernel release, and physical memory",
		)
	}
	return hostIdentity{
		Hostname:             hostname,
		OperatingSystem:      runtime.GOOS,
		Architecture:         runtime.GOARCH,
		KernelRelease:        kernelRelease,
		MachineIDHash:        digest([]byte(machineID)),
		BootID:               bootID,
		MemoryTotalBytes:     memory["MemTotal"] * 1024,
		MemoryAvailableBytes: memory["MemAvailable"] * 1024,
		SwapTotalBytes:       memory["SwapTotal"] * 1024,
		CgroupVersion:        cgroupVersion,
	}, nil
}

func inspectKernelCPULists() kernelCPULists {
	return kernelCPULists{
		Online:   mustParseCPUList(readTextFile("/sys/devices/system/cpu/online")),
		Isolated: parseCPUListOrEmpty(readTextFile("/sys/devices/system/cpu/isolated")),
		NoHZFull: parseCPUListOrEmpty(readTextFile("/sys/devices/system/cpu/nohz_full")),
	}
}

func inspectCPUs() ([]logicalCPU, error) {
	paths, err := filepath.Glob("/sys/devices/system/cpu/cpu[0-9]*")
	if err != nil {
		return nil, fmt.Errorf("enumerate CPUs: %w", err)
	}
	result := make([]logicalCPU, 0, len(paths))
	for _, path := range paths {
		id, err := strconv.Atoi(strings.TrimPrefix(filepath.Base(path), "cpu"))
		if err != nil {
			continue
		}
		online := true
		if value := strings.TrimSpace(readTextFile(filepath.Join(path, "online"))); value != "" {
			online = value == "1"
		}
		coreID, coreErr := readIntFile(filepath.Join(path, "topology/core_id"))
		socketID, socketErr := readIntFile(filepath.Join(path, "topology/physical_package_id"))
		if coreErr != nil || socketErr != nil {
			return nil, fmt.Errorf("CPU %d lacks core or socket topology", id)
		}
		numaNode := cpuNUMANode(path)
		if numaNode < 0 {
			return nil, fmt.Errorf("CPU %d lacks NUMA topology", id)
		}
		siblings, err := parseCPUList(strings.TrimSpace(
			readTextFile(filepath.Join(path, "topology/thread_siblings_list")),
		))
		if err != nil {
			return nil, fmt.Errorf("CPU %d thread siblings: %w", id, err)
		}
		result = append(result, logicalCPU{
			ID: id, CoreID: coreID, SocketID: socketID, NUMANode: numaNode,
			Online: online, Siblings: siblings,
		})
	}
	if len(result) == 0 {
		return nil, errors.New("sysfs contains no logical CPU topology")
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func inspectNUMANodes() ([]numaNode, error) {
	paths, err := filepath.Glob("/sys/devices/system/node/node[0-9]*")
	if err != nil {
		return nil, fmt.Errorf("enumerate NUMA nodes: %w", err)
	}
	result := make([]numaNode, 0, len(paths))
	for _, path := range paths {
		id, err := strconv.Atoi(strings.TrimPrefix(filepath.Base(path), "node"))
		if err != nil {
			continue
		}
		cpus, err := parseCPUList(strings.TrimSpace(readTextFile(filepath.Join(path, "cpulist"))))
		if err != nil {
			return nil, fmt.Errorf("NUMA node %d CPU list: %w", id, err)
		}
		distance, err := parseIntegerFields(readTextFile(filepath.Join(path, "distance")))
		if err != nil {
			return nil, fmt.Errorf("NUMA node %d distance: %w", id, err)
		}
		memory := parseNodeMemTotal(readTextFile(filepath.Join(path, "meminfo")))
		result = append(result, numaNode{
			ID: id, CPUs: cpus, Distance: distance, MemoryTotalBytes: memory * 1024,
		})
	}
	if len(result) == 0 {
		return nil, errors.New("sysfs contains no NUMA node topology")
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func inspectDefaultRoutes(runner *evidenceRunner) map[string]bool {
	output, status := runner.capture("ip-default-route-json", "ip", "-j", "route", "show", "default")
	routes := make(map[string]bool)
	if status == 0 {
		var records []struct {
			Device string `json:"dev"`
		}
		if json.Unmarshal(output, &records) == nil {
			for _, record := range records {
				if record.Device != "" {
					routes[record.Device] = true
				}
			}
		}
	}
	if len(routes) > 0 {
		return routes
	}
	output, _ = runner.capture("ip-default-route", "ip", "route", "show", "default")
	fields := strings.Fields(string(output))
	for index, field := range fields {
		if field == "dev" && index+1 < len(fields) {
			routes[fields[index+1]] = true
		}
	}
	return routes
}

func inspectInterfaces(
	runner *evidenceRunner,
	defaultRoutes map[string]bool,
	requested string,
) ([]networkInterface, error) {
	paths, err := filepath.Glob("/sys/class/net/*")
	if err != nil {
		return nil, fmt.Errorf("enumerate network interfaces: %w", err)
	}
	result := make([]networkInterface, 0)
	for _, path := range paths {
		name := filepath.Base(path)
		if name == "lo" || (requested != "" && requested != "auto" && name != requested) {
			continue
		}
		devicePath := filepath.Join(path, "device")
		resolvedDevice, err := filepath.EvalSymlinks(devicePath)
		if err != nil {
			continue
		}
		pciAddress := filepath.Base(resolvedDevice)
		numaNode, err := readIntFile(filepath.Join(devicePath, "numa_node"))
		if err != nil {
			numaNode = -1
		}
		driver := ""
		if resolvedDriver, err := filepath.EvalSymlinks(filepath.Join(devicePath, "driver")); err == nil {
			driver = filepath.Base(resolvedDriver)
		}
		rxQueues := globBaseNames(filepath.Join(path, "queues", "rx-*"))
		txQueues := globBaseNames(filepath.Join(path, "queues", "tx-*"))
		irqs := inspectIRQs(filepath.Join(devicePath, "msi_irqs"))
		mtu, mtuErr := readIntFile(filepath.Join(path, "mtu"))
		if mtuErr != nil {
			mtu = 0
		}
		linkSpeed, linkSpeedErr := readIntFile(filepath.Join(path, "speed"))
		if linkSpeedErr != nil || linkSpeed < 0 {
			linkSpeed = 0
		}

		prefix := "nic-" + safeName(name)
		runner.capture(prefix+"-link", "ip", "-details", "link", "show", "dev", name)
		runner.capture(prefix+"-driver", "ethtool", "-i", name)
		runner.capture(prefix+"-channels", "ethtool", "-l", name)
		rssOutput, rssStatus := runner.capture(prefix+"-rss", "ethtool", "-x", name)
		runner.capture(prefix+"-offloads", "ethtool", "-k", name)
		runner.capture(prefix+"-coalescing", "ethtool", "-c", name)
		runner.capture(prefix+"-statistics", "ethtool", "-S", name)

		result = append(result, networkInterface{
			Name:                       name,
			DefaultRoute:               defaultRoutes[name],
			OperationalState:           strings.TrimSpace(readTextFile(filepath.Join(path, "operstate"))),
			Driver:                     driver,
			PCIBusAddress:              pciAddress,
			NUMANode:                   numaNode,
			MTU:                        mtu,
			LinkSpeedMbps:              linkSpeed,
			RXQueues:                   rxQueues,
			TXQueues:                   txQueues,
			IRQs:                       irqs,
			HardwareRSSInventoryPassed: rssStatus == 0 && len(bytes.TrimSpace(rssOutput)) > 0,
		})
	}
	if requested != "" && requested != "auto" && len(result) != 1 {
		return nil, fmt.Errorf("requested interface %q is not a physical sysfs device", requested)
	}
	if len(result) == 0 {
		return nil, errors.New("no physical network interfaces were discovered")
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func inspectIRQs(path string) []irqInventory {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil
	}
	result := make([]irqInventory, 0, len(entries))
	for _, entry := range entries {
		irq, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		result = append(result, irqInventory{
			IRQ:                    irq,
			ConfiguredAffinityList: strings.TrimSpace(readTextFile(fmt.Sprintf("/proc/irq/%d/smp_affinity_list", irq))),
			EffectiveAffinityList:  strings.TrimSpace(readTextFile(fmt.Sprintf("/proc/irq/%d/effective_affinity_list", irq))),
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].IRQ < result[j].IRQ })
	return result
}

func parseCPUList(value string) ([]int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("CPU list is empty")
	}
	seen := make(map[int]bool)
	for _, part := range strings.Split(value, ",") {
		bounds := strings.Split(strings.TrimSpace(part), "-")
		if len(bounds) > 2 {
			return nil, fmt.Errorf("invalid CPU range %q", part)
		}
		start, err := strconv.Atoi(bounds[0])
		if err != nil || start < 0 {
			return nil, fmt.Errorf("invalid CPU %q", part)
		}
		end := start
		if len(bounds) == 2 {
			end, err = strconv.Atoi(bounds[1])
			if err != nil || end < start {
				return nil, fmt.Errorf("invalid CPU range %q", part)
			}
		}
		for cpu := start; cpu <= end; cpu++ {
			seen[cpu] = true
		}
	}
	result := make([]int, 0, len(seen))
	for cpu := range seen {
		result = append(result, cpu)
	}
	sort.Ints(result)
	return result, nil
}

func mustParseCPUList(value string) []int {
	result, err := parseCPUList(value)
	if err != nil {
		return nil
	}
	return result
}

func parseCPUListOrEmpty(value string) []int {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "null") {
		return []int{}
	}
	result, err := parseCPUList(value)
	if err != nil {
		return []int{}
	}
	return result
}

func parseIntegerFields(value string) ([]int, error) {
	fields := strings.Fields(value)
	result := make([]int, 0, len(fields))
	for _, field := range fields {
		parsed, err := strconv.Atoi(field)
		if err != nil {
			return nil, fmt.Errorf("invalid integer %q", field)
		}
		result = append(result, parsed)
	}
	return result, nil
}

func parseMeminfo(value string) map[string]int64 {
	result := make(map[string]int64)
	for _, line := range strings.Split(value, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		parsed, err := strconv.ParseInt(fields[1], 10, 64)
		if err == nil {
			result[strings.TrimSuffix(fields[0], ":")] = parsed
		}
	}
	return result
}

func parseNodeMemTotal(value string) int64 {
	for _, line := range strings.Split(value, "\n") {
		if !strings.Contains(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		for index, field := range fields {
			if field == "MemTotal:" && index+1 < len(fields) {
				parsed, _ := strconv.ParseInt(fields[index+1], 10, 64)
				return parsed
			}
		}
	}
	return 0
}

func cpuNUMANode(cpuPath string) int {
	paths, _ := filepath.Glob(filepath.Join(cpuPath, "node[0-9]*"))
	if len(paths) != 1 {
		return -1
	}
	value, err := strconv.Atoi(strings.TrimPrefix(filepath.Base(paths[0]), "node"))
	if err != nil {
		return -1
	}
	return value
}

func globBaseNames(pattern string) []string {
	paths, _ := filepath.Glob(pattern)
	result := make([]string, 0, len(paths))
	for _, path := range paths {
		result = append(result, filepath.Base(path))
	}
	sort.Strings(result)
	return result
}

func readTextFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func readIntFile(path string) (int, error) {
	value := strings.TrimSpace(readTextFile(path))
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", path, err)
	}
	return parsed, nil
}

func safeName(value string) string {
	var builder strings.Builder
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' {
			builder.WriteRune(character)
		} else {
			builder.WriteByte('-')
		}
	}
	return builder.String()
}

func interfaceFingerprint(interfaces []networkInterface) string {
	parts := make([]string, 0, len(interfaces))
	for _, nic := range interfaces {
		parts = append(parts, fmt.Sprintf(
			"%s:%s:%d:%s", nic.Name, nic.PCIBusAddress, nic.NUMANode, nic.Driver,
		))
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

func writeDirectoryChecksums(directory string) error {
	var names []string
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || entry.Name() == "checksums.sha256" {
			return nil
		}
		relative, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		names = append(names, relative)
		return nil
	})
	if err != nil {
		return fmt.Errorf("enumerate evidence files: %w", err)
	}
	sort.Strings(names)
	lines := make([]string, 0, len(names))
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			return fmt.Errorf("checksum %s: %w", name, err)
		}
		lines = append(lines, fmt.Sprintf("%s  %s", digest(data), filepath.ToSlash(name)))
	}
	return os.WriteFile(
		filepath.Join(directory, "checksums.sha256"),
		[]byte(strings.Join(lines, "\n")+"\n"),
		0o600,
	)
}
