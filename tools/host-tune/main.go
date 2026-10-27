package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

const toolVersion = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "inspect":
		err = runInspect(os.Args[2:])
	case "plan":
		err = runPlan(os.Args[2:])
	case "rehearsal":
		err = runRehearsal(os.Args[2:])
	case "version", "--version", "-version":
		fmt.Printf("bonvoyage-host-tune %s\n", toolVersion)
		return
	case "help", "--help", "-h":
		usage()
		return
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "bonvoyage-host-tune: %v\n", err)
		os.Exit(1)
	}
}

func runInspect(arguments []string) error {
	flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	output := flags.String("output", "", "new directory for normalized and raw host evidence")
	interfaceName := flags.String("interface", "auto", "route-facing network interface or auto")
	awsIdentity := flags.Bool(
		"aws-instance-identity", false,
		"require and bind AWS IMDSv2 instance identity",
	)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *output == "" {
		return fmt.Errorf("--output is required")
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("inspect does not accept positional arguments")
	}

	inventory, err := collectInventory(*output, *interfaceName, *awsIdentity, time.Now())
	if err != nil {
		return err
	}
	fmt.Printf(
		"captured %d CPUs, %d NUMA nodes, and %d physical NICs in %s\n",
		len(inventory.CPUs),
		len(inventory.NUMANodes),
		len(inventory.Interfaces),
		*output,
	)
	if len(inventory.Warnings) > 0 {
		fmt.Printf("recorded %d evidence warning(s); review inventory.json before planning\n", len(inventory.Warnings))
	}
	return nil
}

func runPlan(arguments []string) error {
	flags := flag.NewFlagSet("plan", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	inventoryPath := flags.String("inventory", "", "inventory.json produced by inspect")
	policyPath := flags.String("policy", "", "versioned host-tuning policy YAML")
	output := flags.String("output", "", "new directory for the plan artifacts")
	interfaceName := flags.String("interface", "auto", "route-facing network interface or auto")
	gatewayCores := flags.Int(
		"gateway-physical-cores",
		0,
		"fixed physical-core count; zero selects the policy percentage",
	)
	scope := flags.String("scope", tuningScopeFullHost, "full-host or experimental vm-cpu-memory")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *inventoryPath == "" || *policyPath == "" || *output == "" {
		return fmt.Errorf("--inventory, --policy, and --output are required")
	}
	if *gatewayCores < 0 {
		return fmt.Errorf("--gateway-physical-cores cannot be negative")
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("plan does not accept positional arguments")
	}

	policy, policyDigest, err := loadPolicy(*policyPath)
	if err != nil {
		return err
	}
	inventory, inventoryDigest, err := loadInventory(*inventoryPath)
	if err != nil {
		return err
	}
	plan, err := buildPlanForScope(
		policy,
		policyDigest,
		inventory,
		inventoryDigest,
		*interfaceName,
		*gatewayCores,
		time.Now(),
		*scope,
	)
	if err != nil {
		return err
	}
	if err := writePlanArtifacts(*output, plan); err != nil {
		return err
	}
	fmt.Printf(
		"planned %d physical cores (%s), %s Seastar memory, and %d NIC IRQ assignments in %s\n",
		plan.CPU.GatewayPhysicalCoreCount,
		plan.CPU.GatewayCPUSet,
		plan.Memory.SeastarArgument,
		len(plan.IRQ.Assignments),
		*output,
	)
	if len(plan.Warnings) > 0 {
		fmt.Printf("recorded %d plan warning(s); resolve them before apply or qualification\n", len(plan.Warnings))
	}
	if plan.Scope == tuningScopeVMCPU {
		fmt.Println("Scope: vm-cpu-memory; NIC IRQ qualification deferred; measurements not authorized.")
	}
	return nil
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage:
  bonvoyage-host-tune inspect --output DIRECTORY [--interface auto|NAME] [--aws-instance-identity]
  bonvoyage-host-tune plan --inventory FILE --policy FILE --output DIRECTORY [--interface auto|NAME] [--gateway-physical-cores N] [--scope full-host|vm-cpu-memory]
  bonvoyage-host-tune version
  bonvoyage-host-tune rehearsal --help

Inspect and plan do not modify host settings. Experimental rehearsal commands
support verified native Ubuntu lab tuning and restoration with explicit approval.
See rehearsal --help. Production apply/verify/rollback commands remain unavailable.`)
}
