package main

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
)

const nativeServiceContractVersion = 3
const nativeServiceUnit = "/etc/systemd/system/bonvoyage.service"
const nativeServiceUnitSHA256 = "b3439d9b43e42fed39760b7b05d74239a45b43aeccf9e3219086dab4e0aa083c"
const nativeDataplane = "/usr/local/bin/bonvoyage-dataplane"
const nativeFixedArguments = " --snapshot /etc/bonvoyage/snapshot.pb --admin-address 127.0.0.1 --metrics-address 127.0.0.1 --runtime-log-transport unix --runtime-log-socket /dev/log --log-to-syslog 1 --log-to-stdout 0 --log-with-color 0"
const nativeRuntimePrefix = "[Service]\nExecStart=\nExecStart=" + nativeDataplane + nativeFixedArguments + " "
const nativeIRQPrefix = "[Service]\nEnvironment=\""

var nativeControlPaths = map[string]string{
	"service-resources":    "/etc/systemd/system/bonvoyage.service.d/20-bonvoyage-resources.conf",
	"runtime-arguments":    "/etc/systemd/system/bonvoyage.service.d/30-bonvoyage-runtime.conf",
	"irqbalance-exclusion": "/etc/systemd/system/irqbalance.service.d/30-bonvoyage-exclusion.conf",
}
var nativeControlSyntax = map[string]*regexp.Regexp{
	"service-resources":    regexp.MustCompile(`^\[Service\]\nCPUAffinity=[0-9 ]+\nAllowedCPUs=[0-9,-]+\nMemoryHigh=[0-9]+M\nMemoryMax=[0-9]+M\n$`),
	"runtime-arguments":    regexp.MustCompile(`^--smp [1-9][0-9]* --cpuset [0-9,-]+ --memory [1-9][0-9]*M\n$`),
	"irqbalance-exclusion": regexp.MustCompile(`^IRQBALANCE_BANNED_CPULIST=[0-9,-]+\n$`),
}

func encodeNativeControl(control string, value []byte) ([]byte, error) {
	syntax, ok := nativeControlSyntax[control]
	if !ok || !syntax.Match(value) {
		return nil, errors.New("control is not a canonical managed value")
	}
	switch control {
	case "runtime-arguments":
		return append([]byte(nativeRuntimePrefix), value...), nil
	case "irqbalance-exclusion":
		return []byte(nativeIRQPrefix + string(bytes.TrimSuffix(value, []byte("\n"))) + "\"\n"), nil
	default:
		return append([]byte(nil), value...), nil
	}
}
func decodeNativeControl(control string, data []byte) ([]byte, error) {
	value := data
	switch control {
	case "runtime-arguments":
		if !bytes.HasPrefix(data, []byte(nativeRuntimePrefix)) {
			return nil, errors.New("foreign runtime override")
		}
		value = data[len(nativeRuntimePrefix):]
	case "irqbalance-exclusion":
		if !bytes.HasPrefix(data, []byte(nativeIRQPrefix)) || !bytes.HasSuffix(data, []byte("\"\n")) {
			return nil, errors.New("foreign irqbalance override")
		}
		value = append(append([]byte(nil), data[len(nativeIRQPrefix):len(data)-2]...), '\n')
	}
	encoded, err := encodeNativeControl(control, value)
	if err != nil || !bytes.Equal(encoded, data) {
		return nil, fmt.Errorf("unmanaged %s override", control)
	}
	return append([]byte(nil), value...), nil
}
