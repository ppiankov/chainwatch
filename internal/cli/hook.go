package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ppiankov/chainwatch/internal/denylist"
	"github.com/ppiankov/chainwatch/internal/model"
	"github.com/ppiankov/chainwatch/internal/policy"
	"github.com/ppiankov/chainwatch/internal/profile"
)

var (
	hookEvent   string
	hookPolicy  string
	hookDeny    string
	hookProfile string
	hookPreset  string
	hookVerbose bool
)

func init() {
	hookCmd.Flags().StringVar(&hookEvent, "event", "PreToolUse", "Hook event name")
	hookCmd.Flags().StringVar(&hookPolicy, "policy", "", "Path to policy YAML")
	hookCmd.Flags().StringVar(&hookDeny, "denylist", "", "Path to denylist YAML")
	hookCmd.Flags().StringVar(&hookProfile, "profile", "", "Safety profile to apply")
	hookCmd.Flags().StringVar(&hookPreset, "preset", "", "Denylist preset (e.g., supply-chain)")
	hookCmd.Flags().BoolVarP(&hookVerbose, "verbose", "v", false, "Print evaluation details to stderr")
	rootCmd.AddCommand(hookCmd)
	hookCmd.AddCommand(hookInstallCmd)
}

var hookCmd = &cobra.Command{
	Use:   "hook",
	Short: "Claude Code hook integration",
	Long: `Evaluates tool calls from Claude Code PreToolUse hooks.

Reads hook event JSON from stdin, evaluates against chainwatch policy
and denylist, returns a decision in Claude Code hook output format.

Usage in .claude/settings.json:
  {
    "hooks": {
      "PreToolUse": [{
        "matcher": "Bash|Write|Edit|WebFetch|mcp__.*",
        "hooks": [{"type": "command", "command": "chainwatch hook"}]
      }]
    }
  }`,
	RunE: runHook,
}

// hookInput is the JSON structure received from Claude Code on stdin.
type hookInput struct {
	SessionID     string         `json:"session_id"`
	CWD           string         `json:"cwd"`
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name"`
	ToolUseID     string         `json:"tool_use_id"`
	ToolInput     map[string]any `json:"tool_input"`
}

// hookOutput is the JSON structure returned to Claude Code on stdout.
type hookOutput struct {
	HookSpecificOutput hookDecision `json:"hookSpecificOutput"`
}

type hookDecision struct {
	HookEventName            string         `json:"hookEventName"`
	PermissionDecision       string         `json:"permissionDecision"`
	PermissionDecisionReason string         `json:"permissionDecisionReason,omitempty"`
	AdditionalContext        string         `json:"additionalContext,omitempty"`
	UpdatedInput             map[string]any `json:"updatedInput,omitempty"`
}

func runHook(cmd *cobra.Command, args []string) error {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return writeHookAllow("") // fail-open on read error
	}

	var input hookInput
	if err := json.Unmarshal(data, &input); err != nil {
		return writeHookAllow("") // fail-open on parse error
	}

	if input.ToolName == "" {
		return writeHookAllow("")
	}

	action := mapToolToAction(input.ToolName, input.ToolInput)
	if action == nil {
		return writeHookAllow("")
	}

	// Load denylist.
	dl, err := loadHookDenylist()
	if err != nil {
		if hookVerbose {
			fmt.Fprintf(os.Stderr, "chainwatch: denylist load error: %v\n", err)
		}
		return writeHookAllow("")
	}

	// Check denylist first (hard block).
	if blocked, reason := dl.IsBlocked(action.Resource, action.Tool); blocked {
		if hookVerbose {
			fmt.Fprintf(os.Stderr, "chainwatch: DENY %s %q — %s\n", action.Tool, action.Resource, reason)
		}
		return writeHookDeny(reason)
	}

	// Load policy.
	cfg, err := policy.LoadConfig(hookPolicy)
	if err != nil {
		if hookVerbose {
			fmt.Fprintf(os.Stderr, "chainwatch: policy load error: %v\n", err)
		}
		return writeHookAllow("")
	}

	// Apply profile if set.
	if hookProfile != "" {
		prof, err := profile.Load(hookProfile)
		if err == nil {
			profile.ApplyToDenylist(prof, dl)
			cfg = profile.ApplyToPolicy(prof, cfg)
		} else if hookVerbose {
			fmt.Fprintf(os.Stderr, "chainwatch: profile load error: %v\n", err)
		}
	}

	// Evaluate policy.
	state := model.NewTraceState("claude-code-hook")
	result := policy.Evaluate(action, state, "claude-code", "", dl, cfg)

	switch result.Decision {
	case model.Deny:
		if hookVerbose {
			fmt.Fprintf(os.Stderr, "chainwatch: DENY %s %q — %s\n", action.Tool, action.Resource, result.Reason)
		}
		return writeHookDeny(result.Reason)
	case model.RequireApproval:
		// Let Claude Code show its permission dialog.
		if hookVerbose {
			fmt.Fprintf(os.Stderr, "chainwatch: ASK %s %q — %s\n", action.Tool, action.Resource, result.Reason)
		}
		return writeHookAsk(result.Reason)
	default:
		if hookVerbose {
			fmt.Fprintf(os.Stderr, "chainwatch: ALLOW %s %q\n", action.Tool, action.Resource)
		}
		return writeHookAllow("")
	}
}

// mapToolToAction converts Claude Code tool_name + tool_input to a chainwatch Action.
func mapToolToAction(toolName string, input map[string]any) *model.Action {
	switch toolName {
	case "Bash":
		cmd, _ := input["command"].(string)
		if cmd == "" {
			return nil
		}
		return &model.Action{
			Tool:      "command",
			Resource:  cmd,
			Operation: "execute",
		}
	case "Write":
		path, _ := input["file_path"].(string)
		return &model.Action{
			Tool:      "file_write",
			Resource:  path,
			Operation: "write",
		}
	case "Edit":
		path, _ := input["file_path"].(string)
		return &model.Action{
			Tool:      "file_write",
			Resource:  path,
			Operation: "edit",
		}
	case "Read":
		path, _ := input["file_path"].(string)
		return &model.Action{
			Tool:      "file_read",
			Resource:  path,
			Operation: "read",
		}
	case "WebFetch":
		url, _ := input["url"].(string)
		return &model.Action{
			Tool:      "http_proxy",
			Resource:  url,
			Operation: "get",
		}
	case "WebSearch":
		query, _ := input["query"].(string)
		return &model.Action{
			Tool:      "browser",
			Resource:  query,
			Operation: "search",
		}
	case "Agent":
		desc, _ := input["description"].(string)
		return &model.Action{
			Tool:      "agent",
			Resource:  desc,
			Operation: "spawn",
		}
	default:
		// MCP tools: mcp__server__tool
		if strings.HasPrefix(toolName, "mcp__") {
			inputJSON, _ := json.Marshal(input)
			return &model.Action{
				Tool:      "mcp",
				Resource:  toolName + ":" + string(inputJSON),
				Operation: "invoke",
			}
		}
		return nil
	}
}

// loadHookDenylist loads the denylist with optional preset merge.
func loadHookDenylist() (*denylist.Denylist, error) {
	dl, err := denylist.Load(hookDeny)
	if err != nil {
		return nil, err
	}

	if hookPreset != "" {
		for _, name := range strings.Split(hookPreset, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			preset, err := denylist.LoadPreset(name)
			if err != nil {
				return nil, err
			}
			for _, u := range preset.URLs {
				dl.AddPattern("urls", u)
			}
			for _, f := range preset.Files {
				dl.AddPattern("files", f)
			}
			for _, c := range preset.Commands {
				dl.AddPattern("commands", c)
			}
		}
	}

	return dl, nil
}

func writeHookAllow(context string) error {
	out := hookOutput{
		HookSpecificOutput: hookDecision{
			HookEventName:      "PreToolUse",
			PermissionDecision: "allow",
			AdditionalContext:  context,
		},
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func writeHookDeny(reason string) error {
	out := hookOutput{
		HookSpecificOutput: hookDecision{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "deny",
			PermissionDecisionReason: "chainwatch: " + reason,
		},
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func writeHookAsk(reason string) error {
	out := hookOutput{
		HookSpecificOutput: hookDecision{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "ask",
			PermissionDecisionReason: "chainwatch: " + reason,
		},
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}
