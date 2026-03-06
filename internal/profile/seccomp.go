package profile

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/ppiankov/chainwatch/internal/denylist"
)

const (
	seccompActionAllow = "SCMP_ACT_ALLOW"
	seccompActionErrno = "SCMP_ACT_ERRNO"

	seccompGroupBaseline            = "baseline"
	seccompGroupPrivilegeEscalation = "privilege_escalation"
	seccompGroupMountAdmin          = "mount_admin"
	seccompGroupFileMutation        = "file_mutation"
	seccompGroupNetworkEgress       = "network_egress"
)

// SeccompProfile is a minimal OCI/Docker-compatible seccomp profile.
type SeccompProfile struct {
	DefaultAction string           `json:"defaultAction"`
	Syscalls      []SeccompSyscall `json:"syscalls"`
}

// SeccompSyscall defines an action for a set of syscall names.
type SeccompSyscall struct {
	Names   []string `json:"names"`
	Action  string   `json:"action"`
	Comment string   `json:"comment,omitempty"`
}

var seccompSyscallGroups = map[string][]string{
	seccompGroupBaseline: {
		"mount",
		"ptrace",
		"reboot",
		"umount2",
	},
	seccompGroupPrivilegeEscalation: {
		"capset",
		"keyctl",
		"setfsgid",
		"setfsuid",
		"setgid",
		"setregid",
		"setresgid",
		"setresuid",
		"setreuid",
		"setuid",
	},
	seccompGroupMountAdmin: {
		"delete_module",
		"finit_module",
		"init_module",
		"kexec_load",
		"mount",
		"pivot_root",
		"swapon",
		"swapoff",
		"umount2",
	},
	seccompGroupFileMutation: {
		"chmod",
		"chown",
		"fchmod",
		"fchmodat",
		"fchown",
		"fchownat",
		"ftruncate",
		"mkdir",
		"mkdirat",
		"rename",
		"renameat",
		"renameat2",
		"rmdir",
		"truncate",
		"unlink",
		"unlinkat",
	},
	seccompGroupNetworkEgress: {
		"connect",
		"sendmmsg",
		"sendmsg",
		"sendto",
		"socket",
	},
}

// GenerateSeccompJSON returns a seccomp profile JSON blob generated from
// chainwatch default denylist command patterns + optional profile boundaries.
func GenerateSeccompJSON(p *Profile) ([]byte, error) {
	prof, err := BuildSeccompProfile(p)
	if err != nil {
		return nil, err
	}

	out, err := json.MarshalIndent(prof, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal seccomp profile: %w", err)
	}

	if err := ValidateSeccompJSON(out); err != nil {
		return nil, err
	}

	return out, nil
}

// BuildSeccompProfile maps chainwatch command restrictions into syscall-level
// deny rules. It always includes a conservative baseline deny set.
func BuildSeccompProfile(p *Profile) (*SeccompProfile, error) {
	patterns := make([]string, 0, len(denylist.DefaultPatterns.Commands))
	patterns = append(patterns, denylist.DefaultPatterns.Commands...)
	if p != nil {
		patterns = append(patterns, p.ExecutionBoundaries.Commands...)
	}

	activeGroups := map[string]bool{
		seccompGroupBaseline: true,
	}

	for _, pattern := range patterns {
		lower := strings.ToLower(pattern)

		if hasAnyToken(lower, "sudo", "su", "doas") {
			activeGroups[seccompGroupPrivilegeEscalation] = true
		}
		if hasAnyToken(lower, "mount", "umount", "systemctl", "service", "apt", "yum", "dnf") ||
			strings.Contains(lower, "docker run") || strings.Contains(lower, "docker exec") {
			activeGroups[seccompGroupMountAdmin] = true
		}
		if hasAnyToken(
			lower,
			"rm",
			"mv",
			"cp",
			"chmod",
			"chown",
			"truncate",
			"delete",
			"destroy",
			"terminate",
			"edit",
			"apply",
		) || strings.Contains(lower, "vi /etc/") ||
			strings.Contains(lower, "vim /etc/") ||
			strings.Contains(lower, "nano /etc/") {
			activeGroups[seccompGroupFileMutation] = true
		}
		if hasAnyToken(lower, "curl", "wget", "scp", "rsync", "ssh", "upload", "send", "push") {
			activeGroups[seccompGroupNetworkEgress] = true
		}
	}

	groupNames := make([]string, 0, len(activeGroups))
	for g := range activeGroups {
		groupNames = append(groupNames, g)
	}
	sort.Strings(groupNames)

	syscalls := make([]SeccompSyscall, 0, len(groupNames))
	for _, group := range groupNames {
		names := append([]string(nil), seccompSyscallGroups[group]...)
		sort.Strings(names)
		syscalls = append(syscalls, SeccompSyscall{
			Names:   names,
			Action:  seccompActionErrno,
			Comment: "chainwatch:" + group,
		})
	}

	return &SeccompProfile{
		DefaultAction: seccompActionAllow,
		Syscalls:      syscalls,
	}, nil
}

// ValidateSeccompJSON validates basic seccomp JSON shape before using it.
func ValidateSeccompJSON(data []byte) error {
	var profile SeccompProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return fmt.Errorf("invalid seccomp JSON: %w", err)
	}

	if profile.DefaultAction == "" {
		return fmt.Errorf("invalid seccomp profile: defaultAction is required")
	}

	if len(profile.Syscalls) == 0 {
		return fmt.Errorf("invalid seccomp profile: at least one syscall rule is required")
	}

	for i, entry := range profile.Syscalls {
		if entry.Action == "" {
			return fmt.Errorf("invalid seccomp profile: syscalls[%d].action is required", i)
		}
		if len(entry.Names) == 0 {
			return fmt.Errorf("invalid seccomp profile: syscalls[%d].names is required", i)
		}
	}

	return nil
}

func hasAnyToken(input string, tokens ...string) bool {
	parts := strings.FieldsFunc(input, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_')
	})

	if len(parts) == 0 {
		return false
	}

	seen := make(map[string]bool, len(parts))
	for _, p := range parts {
		seen[p] = true
	}

	for _, token := range tokens {
		if seen[token] {
			return true
		}
	}
	return false
}
