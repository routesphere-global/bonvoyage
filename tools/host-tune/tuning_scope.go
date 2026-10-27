package main

import (
	"fmt"
	"time"
)

const (
	tuningScopeFullHost = "full-host"
	tuningScopeVMCPU    = "vm-cpu-memory"
)

// An omitted scope keeps the original strict plan bytes and behavior.
func effectiveTuningScope(scope string) string {
	if scope == "" {
		return tuningScopeFullHost
	}
	return scope
}

func validateTuningScope(scope string) error {
	switch effectiveTuningScope(scope) {
	case tuningScopeFullHost, tuningScopeVMCPU:
		return nil
	default:
		return fmt.Errorf("unsupported tuning scope %q", scope)
	}
}

func validateTuningPlanScope(plan tuningPlan) error {
	if err := validateTuningScope(plan.Scope); err != nil {
		return err
	}
	if plan.Scope == tuningScopeFullHost {
		return fmt.Errorf("strict plan scope must use its canonical omitted field")
	}
	if plan.Scope == tuningScopeVMCPU && (plan.Mode != "benchmark-fixed" || plan.CPU.GatewayPhysicalCoreCount < 1) {
		return fmt.Errorf("VM scope requires an explicit fixed-core rehearsal plan")
	}
	return nil
}

func tuningNICVerification(scope string) string {
	if effectiveTuningScope(scope) == tuningScopeVMCPU {
		return "deferred"
	}
	return "required"
}

func buildPlanForScope(policy tuningPolicy, policyDigest string, inventory hostInventory,
	inventoryDigest, interfaceName string, cores int, now time.Time, scope string) (tuningPlan, error) {
	if err := validateTuningScope(scope); err != nil {
		return tuningPlan{}, err
	}
	if effectiveTuningScope(scope) == tuningScopeVMCPU && cores < 1 {
		return tuningPlan{}, fmt.Errorf("VM scope requires --gateway-physical-cores")
	}
	plan, err := buildResourcePlan(policy, policyDigest, inventory, inventoryDigest,
		interfaceName, cores, now, effectiveTuningScope(scope) == tuningScopeVMCPU)
	if err != nil {
		return tuningPlan{}, err
	}
	if effectiveTuningScope(scope) == tuningScopeVMCPU {
		plan.Scope = tuningScopeVMCPU
		plan.Recommendations = append(plan.Recommendations, recommendation{
			ID: "rehearsal-scope", Decision: tuningScopeVMCPU,
			Reason: "CPU/memory and irqbalance gateway exclusion only; NIC affinity qualification is deferred; no measurements authorized.",
		})
	}
	return plan, nil
}
