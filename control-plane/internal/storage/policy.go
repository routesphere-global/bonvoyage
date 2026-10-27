package storage

import (
	"fmt"
	"slices"
	"time"
)

const (
	maxCanaryNodes       = 128
	minimumPolicyTimeout = time.Second
	maximumPolicyTimeout = 2 * time.Hour
	maximumObservation   = 24 * time.Hour
)

// NormalizeRolloutPolicy validates and deterministically orders one policy
// against its already-normalized target set.
func NormalizeRolloutPolicy(policy RolloutPolicy, targetNodeIDs []string) (RolloutPolicy, error) {
	if !policy.Enabled {
		if policy.Strategy != "" || len(policy.CanaryNodeIDs) != 0 ||
			policy.MinimumHealthyCanaryPercent != 0 || policy.CanaryObservationWindow != 0 ||
			policy.PrepareTimeout != 0 || policy.ActivationTimeout != 0 ||
			policy.HeartbeatStaleAfter != 0 || policy.AutomaticRollback {
			return RolloutPolicy{}, fmt.Errorf("disabled rollout policy contains settings: %w", ErrInvalid)
		}
		return RolloutPolicy{}, nil
	}
	if policy.PrepareTimeout < minimumPolicyTimeout || policy.PrepareTimeout > maximumPolicyTimeout ||
		policy.ActivationTimeout < minimumPolicyTimeout || policy.ActivationTimeout > maximumPolicyTimeout {
		return RolloutPolicy{}, fmt.Errorf("rollout deadlines must be between %s and %s: %w",
			minimumPolicyTimeout, maximumPolicyTimeout, ErrInvalid)
	}

	normalized := policy
	normalized.CanaryNodeIDs = append([]string(nil), policy.CanaryNodeIDs...)
	slices.Sort(normalized.CanaryNodeIDs)
	switch normalized.Strategy {
	case RolloutStrategyImmediate:
		if len(normalized.CanaryNodeIDs) != 0 || normalized.MinimumHealthyCanaryPercent != 0 ||
			normalized.CanaryObservationWindow != 0 || normalized.HeartbeatStaleAfter != 0 {
			return RolloutPolicy{}, fmt.Errorf("immediate rollout policy contains canary settings: %w", ErrInvalid)
		}
	case RolloutStrategyCanary:
		if len(normalized.CanaryNodeIDs) == 0 || len(normalized.CanaryNodeIDs) > maxCanaryNodes ||
			len(normalized.CanaryNodeIDs) >= len(targetNodeIDs) {
			return RolloutPolicy{}, fmt.Errorf("canary policy requires a strict subset of 1-%d targets: %w",
				maxCanaryNodes, ErrInvalid)
		}
		if normalized.MinimumHealthyCanaryPercent == 0 || normalized.MinimumHealthyCanaryPercent > 100 {
			return RolloutPolicy{}, fmt.Errorf("healthy canary percentage must be 1-100: %w", ErrInvalid)
		}
		if normalized.CanaryObservationWindow < minimumPolicyTimeout ||
			normalized.CanaryObservationWindow > maximumObservation {
			return RolloutPolicy{}, fmt.Errorf("canary observation window must be between %s and %s: %w",
				minimumPolicyTimeout, maximumObservation, ErrInvalid)
		}
		if normalized.HeartbeatStaleAfter < minimumPolicyTimeout ||
			normalized.HeartbeatStaleAfter > normalized.CanaryObservationWindow {
			return RolloutPolicy{}, fmt.Errorf("heartbeat freshness must fit the observation window: %w", ErrInvalid)
		}
		targets := make(map[string]struct{}, len(targetNodeIDs))
		for _, nodeID := range targetNodeIDs {
			targets[nodeID] = struct{}{}
		}
		for index, nodeID := range normalized.CanaryNodeIDs {
			if err := validateIdentifier("canary node ID", nodeID); err != nil {
				return RolloutPolicy{}, err
			}
			if index > 0 && normalized.CanaryNodeIDs[index-1] == nodeID {
				return RolloutPolicy{}, fmt.Errorf("duplicate canary node %q: %w", nodeID, ErrInvalid)
			}
			if _, found := targets[nodeID]; !found {
				return RolloutPolicy{}, fmt.Errorf("canary node %q is outside the target set: %w", nodeID, ErrInvalid)
			}
		}
	default:
		return RolloutPolicy{}, fmt.Errorf("unsupported rollout strategy %q: %w", normalized.Strategy, ErrInvalid)
	}
	return normalized, nil
}
