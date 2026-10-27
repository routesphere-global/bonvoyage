//go:build !linux && !darwin

package main

import "errors"

func runRehearsal([]string) error {
	return errors.New("host rehearsal is supported only on Linux; Darwin supports offline preparation")
}
