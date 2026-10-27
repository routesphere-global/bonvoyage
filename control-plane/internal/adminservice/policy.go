package adminservice

import (
	"fmt"
	"math"
	"time"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
)

func normalizePolicy(input RolloutPolicyInput, targets []string) (storage.RolloutPolicy, RolloutPolicyInput, error) {
	toDuration := func(name string, seconds uint32) (time.Duration, error) {
		if uint64(seconds) > uint64(math.MaxInt64/int64(time.Second)) {
			return 0, fmt.Errorf("%s overflows duration: %w", name, ErrInvalidInput)
		}
		return time.Duration(seconds) * time.Second, nil
	}
	observation, err := toDuration("canary observation", input.CanaryObservationSeconds)
	if err != nil {
		return storage.RolloutPolicy{}, RolloutPolicyInput{}, err
	}
	prepare, err := toDuration("prepare timeout", input.PrepareTimeoutSeconds)
	if err != nil {
		return storage.RolloutPolicy{}, RolloutPolicyInput{}, err
	}
	activation, err := toDuration("activation timeout", input.ActivationTimeoutSeconds)
	if err != nil {
		return storage.RolloutPolicy{}, RolloutPolicyInput{}, err
	}
	stale, err := toDuration("heartbeat freshness", input.HeartbeatStaleAfterSeconds)
	if err != nil {
		return storage.RolloutPolicy{}, RolloutPolicyInput{}, err
	}
	policy, err := storage.NormalizeRolloutPolicy(storage.RolloutPolicy{
		Enabled: input.Enabled, Strategy: input.Strategy,
		CanaryNodeIDs:               append([]string(nil), input.CanaryNodeIDs...),
		MinimumHealthyCanaryPercent: input.MinimumHealthyCanaryPercent,
		CanaryObservationWindow:     observation, PrepareTimeout: prepare,
		ActivationTimeout: activation, HeartbeatStaleAfter: stale,
		AutomaticRollback: input.AutomaticRollback,
	}, targets)
	if err != nil {
		return storage.RolloutPolicy{}, RolloutPolicyInput{}, fmt.Errorf("safe rollout policy: %w", ErrInvalidInput)
	}
	return policy, policyInput(policy), nil
}

func policyInput(policy storage.RolloutPolicy) RolloutPolicyInput {
	if !policy.Enabled {
		return RolloutPolicyInput{}
	}
	return RolloutPolicyInput{
		Enabled: true, Strategy: policy.Strategy,
		CanaryNodeIDs:               append([]string(nil), policy.CanaryNodeIDs...),
		MinimumHealthyCanaryPercent: policy.MinimumHealthyCanaryPercent,
		CanaryObservationSeconds:    uint32(policy.CanaryObservationWindow / time.Second),
		PrepareTimeoutSeconds:       uint32(policy.PrepareTimeout / time.Second),
		ActivationTimeoutSeconds:    uint32(policy.ActivationTimeout / time.Second),
		HeartbeatStaleAfterSeconds:  uint32(policy.HeartbeatStaleAfter / time.Second),
		AutomaticRollback:           policy.AutomaticRollback,
	}
}

func policyPointer(policy storage.RolloutPolicy) *RolloutPolicyInput {
	if !policy.Enabled {
		return nil
	}
	converted := policyInput(policy)
	return &converted
}
