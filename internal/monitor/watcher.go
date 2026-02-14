package monitor

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// ProcessInfo represents a running process in the agent's tree.
type ProcessInfo struct {
	PID     int
	PPID    int
	Command string // full command line
}

// Watcher discovers child processes and can kill them.
type Watcher interface {
	Children(pid int) ([]ProcessInfo, error)
	Kill(pid int) error
}

// ProcfsWatcher reads /proc to discover processes. Linux-only at runtime.
type ProcfsWatcher struct{}

// Children returns all descendant processes of the given PID.
// Reads /proc/<pid>/task/*/children recursively, then /proc/<child>/cmdline.
func (w *ProcfsWatcher) Children(pid int) ([]ProcessInfo, error) {
	pids, err := descendantPIDs(pid)
	if err != nil {
		return nil, err
	}

	var procs []ProcessInfo
	for _, childPID := range pids {
		cmd := readCmdline(childPID)
		if cmd == "" {
			continue
		}
		procs = append(procs, ProcessInfo{
			PID:     childPID,
			PPID:    pid,
			Command: cmd,
		})
	}
	return procs, nil
}

// Kill sends SIGKILL to the given PID.
func (w *ProcfsWatcher) Kill(pid int) error {
	return syscall.Kill(pid, syscall.SIGKILL)
}

// descendantPIDs finds all descendants of a process by reading /proc/*/children.
func descendantPIDs(root int) ([]int, error) {
	var result []int
	queue := []int{root}

	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]

		children, err := directChildren(pid)
		if err != nil {
			// Process may have exited; skip silently
			continue
		}
		result = append(result, children...)
		queue = append(queue, children...)
	}
	return result, nil
}

// directChildren reads /proc/<pid>/task/*/children for immediate child PIDs.
func directChildren(pid int) ([]int, error) {
	taskDir := fmt.Sprintf("/proc/%d/task", pid)
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return nil, err
	}

	seen := make(map[int]bool)
	for _, entry := range entries {
		childrenFile := filepath.Join(taskDir, entry.Name(), "children")
		data, err := os.ReadFile(childrenFile)
		if err != nil {
			continue
		}
		for _, field := range strings.Fields(string(data)) {
			if childPID, err := strconv.Atoi(field); err == nil && !seen[childPID] {
				seen[childPID] = true
			}
		}
	}

	result := make([]int, 0, len(seen))
	for pid := range seen {
		result = append(result, pid)
	}
	return result, nil
}

// readCmdline reads /proc/<pid>/cmdline and returns it as a space-separated string.
func readCmdline(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	// cmdline uses null bytes as separators
	parts := strings.Split(string(data), "\x00")
	// Filter empty strings (trailing null)
	var nonEmpty []string
	for _, p := range parts {
		if p != "" {
			nonEmpty = append(nonEmpty, p)
		}
	}
	return strings.Join(nonEmpty, " ")
}
