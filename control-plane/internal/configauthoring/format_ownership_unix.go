//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package configauthoring

import (
	"errors"
	"os"
	"syscall"
)

func preserveFileOwnership(file *os.File, source os.FileInfo) error {
	metadata, ok := source.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("source ownership metadata is unavailable")
	}
	return file.Chown(int(metadata.Uid), int(metadata.Gid))
}
