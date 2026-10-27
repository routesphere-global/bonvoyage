package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"runtime"
)

type tuningExecutionBinding struct {
	SchemaVersion          int    `json:"schema_version"`
	ToolVersion            string `json:"tool_version"`
	ServiceContractVersion int    `json:"service_contract_version"`
	ServiceUnitSHA256      string `json:"service_unit_sha256"`
	ExecutableSHA256       string `json:"executable_sha256"`
}

func runningTuningExecution() (tuningExecutionBinding, error) {
	name, err := os.Executable()
	if err != nil {
		return tuningExecutionBinding{}, err
	}
	// Linux exposes the actual running image even if its installation path moved.
	if runtime.GOOS == "linux" {
		name = "/proc/self/exe"
	}
	f, err := os.Open(name)
	if err != nil {
		return tuningExecutionBinding{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, 256*1024*1024+1))
	if err != nil {
		return tuningExecutionBinding{}, err
	}
	if n > 256*1024*1024 {
		return tuningExecutionBinding{}, errors.New("utility image exceeds bound")
	}
	return tuningExecutionBinding{1, toolVersion, nativeServiceContractVersion,
		nativeServiceUnitSHA256, hex.EncodeToString(h.Sum(nil))}, nil
}
