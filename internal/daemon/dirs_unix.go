//go:build !windows

package daemon

import (
	"fmt"
	"os"
	"syscall"
)

// deviceID returns the device ID of the filesystem containing path.
func deviceID(path string) (uint64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("unsupported platform for device ID check")
	}
	return uint64(stat.Dev), nil
}
