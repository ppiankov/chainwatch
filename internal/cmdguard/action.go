package cmdguard

import (
	"strings"

	"github.com/ppiankov/chainwatch/internal/model"
)

// buildActionFromCommand maps a command invocation to a chainwatch Action.
// The tool name "command" activates denylist.isCommandTool() routing.
func buildActionFromCommand(name string, args []string) *model.Action {
	var fullCommand string
	if len(args) > 0 {
		fullCommand = name + " " + strings.Join(args, " ")
	} else {
		fullCommand = name
	}

	sensitivity, tags := classifyCommandSensitivity(fullCommand)
	egress := model.EgressInternal
	if isNetworkCommand(fullCommand) {
		egress = model.EgressExternal
	}

	return &model.Action{
		Tool:      "command",
		Resource:  fullCommand,
		Operation: "execute",
		Params:    map[string]any{"name": name, "args": args},
		RawMeta: map[string]any{
			"sensitivity": string(sensitivity),
			"tags":        toAnySlice(tags),
			"bytes":       0,
			"rows":        0,
			"egress":      string(egress),
			"destination": "",
		},
	}
}

// classifyCommandSensitivity returns sensitivity level and tags for a command.
func classifyCommandSensitivity(cmd string) (model.Sensitivity, []string) {
	lower := strings.ToLower(cmd)

	// Destructive patterns
	destructive := []string{"rm -rf", "dd if=", "mkfs", "chmod -r 777", "> /dev/sda", ":(){ :|:& };:"}
	for _, p := range destructive {
		if strings.Contains(lower, p) {
			return model.SensHigh, []string{"destructive"}
		}
	}

	// Credential patterns
	credential := []string{"sudo", "passwd", "ssh-keygen", "chpasswd"}
	for _, p := range credential {
		if strings.Contains(lower, p) {
			return model.SensHigh, []string{"credential"}
		}
	}

	// Network patterns
	if isNetworkCommand(lower) {
		return model.SensMedium, []string{"network"}
	}

	// VCS write patterns
	vcsWrite := []string{"git push", "git commit", "git rebase", "git reset"}
	for _, p := range vcsWrite {
		if strings.Contains(lower, p) {
			return model.SensMedium, []string{"vcs_write"}
		}
	}

	return model.SensLow, nil
}

func isNetworkCommand(cmd string) bool {
	lower := strings.ToLower(cmd)
	network := []string{"curl ", "wget ", "nc ", "telnet ", "ssh ", "scp ", "sftp "}
	for _, p := range network {
		if strings.HasPrefix(lower, p) || strings.Contains(lower, " "+p) {
			return true
		}
	}
	// Also check if the command itself is a network tool (no args)
	bare := []string{"curl", "wget", "nc", "telnet", "ssh", "scp", "sftp"}
	for _, p := range bare {
		if lower == p {
			return true
		}
	}
	return false
}

func toAnySlice(ss []string) []any {
	if ss == nil {
		return []any{}
	}
	result := make([]any, len(ss))
	for i, s := range ss {
		result[i] = s
	}
	return result
}
