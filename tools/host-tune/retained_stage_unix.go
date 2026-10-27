//go:build linux || darwin

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
)

// Stage a new immutable review bundle from loaded inputs. The returned digest
// is an integrity reference for operator review; it grants no apply permission.
func stageRetainedTuningInputs(output string, policyData, inventoryData []byte,
	plan tuningPlan) (string, error) {
	if len(policyData) > 1024*1024 || len(inventoryData) > 1024*1024 {
		return "", errors.New("retained input exceeds one MiB")
	}
	policy, err := decodeTuningPolicy(policyData)
	if err != nil {
		return "", err
	}
	var inventory hostInventory
	if err = decodeTuningJSON(inventoryData, &inventory); err != nil {
		return "", err
	}
	if _, err = prepareTuningTransaction(policy, digest(policyData), inventory,
		digest(inventoryData), plan); err != nil {
		return "", err
	}
	execution, err := runningTuningExecution()
	if err != nil {
		return "", err
	}
	files, err := renderPlanArtifacts(plan)
	if err != nil {
		return "", err
	}
	files["policy.yaml"] = append([]byte(nil), policyData...)
	files["inventory.json"] = append([]byte(nil), inventoryData...)
	files["execution.json"], err = json.Marshal(execution)
	if err != nil {
		return "", err
	}
	manifest := tuningFileManifest(files)
	anchor := digest(manifest)
	files["checksums.sha256"] = manifest
	if err = os.Mkdir(output, 0o700); err != nil {
		return "", err
	}
	if err = syncTuningDirectory(filepath.Dir(output)); err != nil {
		return "", err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		f, err := os.OpenFile(filepath.Join(output, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return "", err
		}
		_, writeErr := f.Write(files[name])
		syncErr := f.Sync()
		closeErr := f.Close()
		if err = errors.Join(writeErr, syncErr, closeErr); err != nil {
			return "", err
		}
	}
	if err = syncTuningDirectory(output); err != nil {
		return "", err
	}
	if _, err = loadRetainedTuningInputs(output, anchor); err != nil {
		return "", err
	}
	return anchor, nil
}
