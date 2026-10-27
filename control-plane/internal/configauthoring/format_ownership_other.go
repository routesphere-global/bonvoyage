//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package configauthoring

import "os"

func preserveFileOwnership(_ *os.File, _ os.FileInfo) error {
	return nil
}
