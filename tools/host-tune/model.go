package main

import "time"

const (
	inventorySchemaVersion = 2
	planSchemaVersion      = 1
)

type tuningPolicy struct {
	SchemaVersion           int             `yaml:"schema_version"`
	ID                      string          `yaml:"id"`
	GatewayCPUTargetPercent int             `yaml:"gateway_cpu_target_percent"`
	Discovery               discoveryPolicy `yaml:"discovery"`
	CPU                     cpuPolicy       `yaml:"cpu"`
	Memory                  memoryPolicy    `yaml:"memory"`
	NUMA                    numaPolicy      `yaml:"numa"`
	IRQ                     irqPolicy       `yaml:"irq"`
	Network                 networkPolicy   `yaml:"network"`
	Safety                  safetyPolicy    `yaml:"safety"`
}

type discoveryPolicy struct {
	RequireLinux              bool   `yaml:"require_linux"`
	RequireSysfs              bool   `yaml:"require_sysfs"`
	CollectLSCPU              bool   `yaml:"collect_lscpu"`
	CollectLSPCI              bool   `yaml:"collect_lspci"`
	CollectKernelMessages     bool   `yaml:"collect_kernel_messages"`
	KernelMessageAccess       string `yaml:"kernel_message_access"`
	CollectNetworkDriverState bool   `yaml:"collect_network_driver_state"`
	CollectSystemdAndCgroup   bool   `yaml:"collect_systemd_and_cgroup"`
}

type cpuPolicy struct {
	MinimumReservedPhysicalCores int  `yaml:"minimum_reserved_physical_cores"`
	MinimumReservedPercent       int  `yaml:"minimum_reserved_percent"`
	KeepSMTSiblingsTogether      bool `yaml:"keep_smt_siblings_together"`
	RequireOnlineCPUVerification bool `yaml:"require_online_cpu_verification"`
}

type memoryPolicy struct {
	AllocationMode              string `yaml:"allocation_mode"`
	SeastarMiBPerShard          int64  `yaml:"seastar_mib_per_shard"`
	SeastarMinimumMiB           int64  `yaml:"seastar_minimum_mib"`
	SeastarMaximumHostPercent   int64  `yaml:"seastar_maximum_host_percent"`
	MinimumHostReserveMiB       int64  `yaml:"minimum_host_reserve_mib"`
	SystemdMemoryHighPercent    int64  `yaml:"systemd_memory_high_percent"`
	SystemdMemoryMaxPercent     int64  `yaml:"systemd_memory_max_percent"`
	BenchmarkMode               string `yaml:"benchmark_mode"`
	RequireCgroupV2Verification bool   `yaml:"require_cgroup_v2_verification"`
	RequireSwapStateRecording   bool   `yaml:"require_swap_state_recording"`
}

type numaPolicy struct {
	PreferSingleNode                bool `yaml:"prefer_single_node"`
	PreferNICLocality               bool `yaml:"prefer_nic_locality"`
	RejectAsymmetricPartialCoreSets bool `yaml:"reject_asymmetric_partial_core_sets"`
	RecordDistanceMatrix            bool `yaml:"record_distance_matrix"`
}

type irqPolicy struct {
	Strategy                             string `yaml:"strategy"`
	KeepIRQBalanceEnabled                bool   `yaml:"keep_irqbalance_enabled"`
	ExcludeGatewayCPUs                   bool   `yaml:"exclude_gateway_cpus"`
	MinimumReservedPhysicalCores         int    `yaml:"minimum_reserved_physical_cores"`
	MaximumReservedPhysicalCores         int    `yaml:"maximum_reserved_physical_cores"`
	QueuesPerReservedCore                int    `yaml:"queues_per_reserved_core"`
	RequireQueueIRQInventory             bool   `yaml:"require_queue_irq_inventory"`
	RequireEffectiveAffinityVerification bool   `yaml:"require_effective_affinity_verification"`
}

type networkPolicy struct {
	DiscoverPCINUMALocality    bool   `yaml:"discover_pci_numa_locality"`
	DiscoverRXTXQueues         bool   `yaml:"discover_rx_tx_queues"`
	RPSPolicy                  string `yaml:"rps_policy"`
	XPSPolicy                  string `yaml:"xps_policy"`
	OffloadPolicy              string `yaml:"offload_policy"`
	CoalescingPolicy           string `yaml:"coalescing_policy"`
	RequireBeforeAfterCounters bool   `yaml:"require_before_after_counters"`
}

type safetyPolicy struct {
	DefaultMode             string `yaml:"default_mode"`
	RequireExplicitApply    bool   `yaml:"require_explicit_apply"`
	RequireRollbackPlan     bool   `yaml:"require_rollback_plan"`
	RejectUnverifiedChanges bool   `yaml:"reject_unverified_changes"`
	AllowKernelBootChanges  bool   `yaml:"allow_kernel_boot_changes"`
}

type hostInventory struct {
	SchemaVersion int                `json:"schema_version"`
	CapturedAt    time.Time          `json:"captured_at"`
	Host          hostIdentity       `json:"host"`
	Cloud         *cloudIdentity     `json:"cloud,omitempty"`
	CPULists      kernelCPULists     `json:"cpu_lists"`
	CPUs          []logicalCPU       `json:"cpus"`
	NUMANodes     []numaNode         `json:"numa_nodes"`
	Interfaces    []networkInterface `json:"interfaces"`
	Commands      []commandEvidence  `json:"commands"`
	Warnings      []string           `json:"warnings"`
}

type cloudIdentity struct {
	Provider         string `json:"provider"`
	InstanceID       string `json:"instance_id"`
	InstanceType     string `json:"instance_type"`
	ImageID          string `json:"image_id"`
	PrivateIPv4      string `json:"private_ipv4"`
	AvailabilityZone string `json:"availability_zone"`
	Region           string `json:"region"`
	Architecture     string `json:"architecture"`
	HostID           string `json:"host_id,omitempty"`
}

type hostIdentity struct {
	Hostname             string `json:"hostname"`
	OperatingSystem      string `json:"operating_system"`
	Architecture         string `json:"architecture"`
	KernelRelease        string `json:"kernel_release"`
	MachineIDHash        string `json:"machine_id_sha256"`
	BootID               string `json:"boot_id"`
	Fingerprint          string `json:"fingerprint_sha256"`
	MemoryTotalBytes     int64  `json:"memory_total_bytes"`
	MemoryAvailableBytes int64  `json:"memory_available_bytes"`
	SwapTotalBytes       int64  `json:"swap_total_bytes"`
	CgroupVersion        int    `json:"cgroup_version"`
}

type kernelCPULists struct {
	Online   []int `json:"online"`
	Isolated []int `json:"isolated"`
	NoHZFull []int `json:"nohz_full"`
}

type logicalCPU struct {
	ID       int   `json:"id"`
	CoreID   int   `json:"core_id"`
	SocketID int   `json:"socket_id"`
	NUMANode int   `json:"numa_node"`
	Online   bool  `json:"online"`
	Siblings []int `json:"siblings"`
}

type numaNode struct {
	ID               int   `json:"id"`
	CPUs             []int `json:"cpus"`
	Distance         []int `json:"distance"`
	MemoryTotalBytes int64 `json:"memory_total_bytes"`
}

type networkInterface struct {
	Name                       string         `json:"name"`
	DefaultRoute               bool           `json:"default_route"`
	OperationalState           string         `json:"operational_state"`
	Driver                     string         `json:"driver"`
	PCIBusAddress              string         `json:"pci_bus_address"`
	NUMANode                   int            `json:"numa_node"`
	MTU                        int            `json:"mtu"`
	LinkSpeedMbps              int            `json:"link_speed_mbps"`
	RXQueues                   []string       `json:"rx_queues"`
	TXQueues                   []string       `json:"tx_queues"`
	IRQs                       []irqInventory `json:"irqs"`
	HardwareRSSInventoryPassed bool           `json:"hardware_rss_inventory_passed"`
}

type irqInventory struct {
	IRQ                    int    `json:"irq"`
	ConfiguredAffinityList string `json:"configured_affinity_list"`
	EffectiveAffinityList  string `json:"effective_affinity_list"`
}

type commandEvidence struct {
	Name       string `json:"name"`
	Command    string `json:"command"`
	ExitCode   int    `json:"exit_code"`
	StdoutPath string `json:"stdout_path"`
	StderrPath string `json:"stderr_path"`
}

type tuningPlan struct {
	SchemaVersion   int              `json:"schema_version"`
	GeneratedAt     time.Time        `json:"generated_at"`
	PolicyID        string           `json:"policy_id"`
	PolicySHA256    string           `json:"policy_sha256"`
	InventorySHA256 string           `json:"inventory_sha256"`
	HostFingerprint string           `json:"host_fingerprint_sha256"`
	Mode            string           `json:"mode"`
	Scope           string           `json:"scope,omitempty"`
	Interface       plannedInterface `json:"interface"`
	CPU             plannedCPU       `json:"cpu"`
	Memory          plannedMemory    `json:"memory"`
	IRQ             plannedIRQ       `json:"irq"`
	Recommendations []recommendation `json:"recommendations"`
	Warnings        []string         `json:"warnings"`
}

type plannedInterface struct {
	Name          string `json:"name"`
	Driver        string `json:"driver"`
	PCIBusAddress string `json:"pci_bus_address"`
	NUMANode      int    `json:"numa_node"`
	RXQueueCount  int    `json:"rx_queue_count"`
	TXQueueCount  int    `json:"tx_queue_count"`
}

type plannedCPU struct {
	PhysicalCoreCount         int    `json:"physical_core_count"`
	LogicalCPUCount           int    `json:"logical_cpu_count"`
	GatewayPhysicalCoreCount  int    `json:"gateway_physical_core_count"`
	GatewayLogicalCPUs        []int  `json:"gateway_logical_cpus"`
	GatewayCPUSet             string `json:"gateway_cpuset"`
	HostReservedPhysicalCores int    `json:"host_reserved_physical_cores"`
	HostReservedLogicalCPUs   []int  `json:"host_reserved_logical_cpus"`
	HostReservedCPUSet        string `json:"host_reserved_cpuset"`
	NUMANodes                 []int  `json:"gateway_numa_nodes"`
}

type plannedMemory struct {
	HostTotalMiB         int64  `json:"host_total_mib"`
	SeastarMiB           int64  `json:"seastar_mib"`
	SeastarArgument      string `json:"seastar_argument"`
	SystemdMemoryHighMiB int64  `json:"systemd_memory_high_mib"`
	SystemdMemoryMaxMiB  int64  `json:"systemd_memory_max_mib"`
	HostReserveMiB       int64  `json:"host_reserve_mib"`
}

type plannedIRQ struct {
	ReservedPhysicalCoreCount int             `json:"reserved_physical_core_count"`
	ReservedLogicalCPUs       []int           `json:"reserved_logical_cpus"`
	ReservedCPUSet            string          `json:"reserved_cpuset"`
	Assignments               []irqAssignment `json:"assignments"`
	IRQBalanceBannedCPUList   string          `json:"irqbalance_banned_cpulist"`
}

type irqAssignment struct {
	IRQ        int `json:"irq"`
	LogicalCPU int `json:"logical_cpu"`
}

type recommendation struct {
	ID       string `json:"id"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}
