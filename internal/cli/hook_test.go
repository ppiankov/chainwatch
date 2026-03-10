package cli

import (
	"encoding/json"
	"testing"

	"github.com/ppiankov/chainwatch/internal/model"
)

func TestMapToolToAction_Bash(t *testing.T) {
	a := mapToolToAction("Bash", map[string]any{"command": "ls -la"})
	if a == nil {
		t.Fatal("expected action")
	}
	if a.Tool != "command" {
		t.Errorf("tool: got %q, want command", a.Tool)
	}
	if a.Resource != "ls -la" {
		t.Errorf("resource: got %q, want 'ls -la'", a.Resource)
	}
	if a.Operation != "execute" {
		t.Errorf("operation: got %q, want execute", a.Operation)
	}
}

func TestMapToolToAction_BashEmpty(t *testing.T) {
	a := mapToolToAction("Bash", map[string]any{"command": ""})
	if a != nil {
		t.Error("expected nil for empty command")
	}
}

func TestMapToolToAction_Write(t *testing.T) {
	a := mapToolToAction("Write", map[string]any{"file_path": "/tmp/test.txt"})
	if a == nil {
		t.Fatal("expected action")
	}
	if a.Tool != "file_write" || a.Resource != "/tmp/test.txt" || a.Operation != "write" {
		t.Errorf("unexpected: %+v", a)
	}
}

func TestMapToolToAction_Edit(t *testing.T) {
	a := mapToolToAction("Edit", map[string]any{"file_path": "src/main.go"})
	if a == nil {
		t.Fatal("expected action")
	}
	if a.Tool != "file_write" || a.Operation != "edit" {
		t.Errorf("unexpected: %+v", a)
	}
}

func TestMapToolToAction_Read(t *testing.T) {
	a := mapToolToAction("Read", map[string]any{"file_path": "go.mod"})
	if a == nil {
		t.Fatal("expected action")
	}
	if a.Tool != "file_read" || a.Operation != "read" {
		t.Errorf("unexpected: %+v", a)
	}
}

func TestMapToolToAction_WebFetch(t *testing.T) {
	a := mapToolToAction("WebFetch", map[string]any{"url": "https://example.com"})
	if a == nil {
		t.Fatal("expected action")
	}
	if a.Tool != "http_proxy" || a.Resource != "https://example.com" {
		t.Errorf("unexpected: %+v", a)
	}
}

func TestMapToolToAction_WebSearch(t *testing.T) {
	a := mapToolToAction("WebSearch", map[string]any{"query": "golang testing"})
	if a == nil {
		t.Fatal("expected action")
	}
	if a.Tool != "browser" || a.Resource != "golang testing" {
		t.Errorf("unexpected: %+v", a)
	}
}

func TestMapToolToAction_Agent(t *testing.T) {
	a := mapToolToAction("Agent", map[string]any{"description": "research task"})
	if a == nil {
		t.Fatal("expected action")
	}
	if a.Tool != "agent" || a.Resource != "research task" {
		t.Errorf("unexpected: %+v", a)
	}
}

func TestMapToolToAction_MCP(t *testing.T) {
	a := mapToolToAction("mcp__github__create_issue", map[string]any{"title": "bug"})
	if a == nil {
		t.Fatal("expected action")
	}
	if a.Tool != "mcp" || a.Operation != "invoke" {
		t.Errorf("unexpected: %+v", a)
	}
	if a.Resource == "" {
		t.Error("expected non-empty resource for MCP tool")
	}
}

func TestMapToolToAction_Unknown(t *testing.T) {
	a := mapToolToAction("Glob", map[string]any{"pattern": "*.go"})
	if a != nil {
		t.Error("expected nil for unknown tool (Glob is read-only)")
	}
}

func TestMapToolToAction_Grep(t *testing.T) {
	a := mapToolToAction("Grep", map[string]any{"pattern": "TODO"})
	if a != nil {
		t.Error("expected nil for Grep (read-only)")
	}
}

func TestHookOutputFormat_Allow(t *testing.T) {
	out := hookOutput{
		HookSpecificOutput: hookDecision{
			HookEventName:      "PreToolUse",
			PermissionDecision: "allow",
		},
	}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}

	specific, ok := parsed["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatal("missing hookSpecificOutput")
	}
	if specific["permissionDecision"] != "allow" {
		t.Errorf("decision: got %v, want allow", specific["permissionDecision"])
	}
	if specific["hookEventName"] != "PreToolUse" {
		t.Errorf("event: got %v, want PreToolUse", specific["hookEventName"])
	}
}

func TestHookOutputFormat_Deny(t *testing.T) {
	out := hookOutput{
		HookSpecificOutput: hookDecision{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "deny",
			PermissionDecisionReason: "chainwatch: blocked",
		},
	}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}

	specific := parsed["hookSpecificOutput"].(map[string]any)
	if specific["permissionDecision"] != "deny" {
		t.Errorf("decision: got %v, want deny", specific["permissionDecision"])
	}
	if specific["permissionDecisionReason"] != "chainwatch: blocked" {
		t.Errorf("reason: got %v", specific["permissionDecisionReason"])
	}
}

func TestHookDecision_OmitsEmptyFields(t *testing.T) {
	out := hookOutput{
		HookSpecificOutput: hookDecision{
			HookEventName:      "PreToolUse",
			PermissionDecision: "allow",
		},
	}
	data, _ := json.Marshal(out)
	s := string(data)
	if json.Valid(data) == false {
		t.Error("invalid JSON")
	}
	// Omitempty fields should not appear.
	if contains(s, "permissionDecisionReason") {
		t.Error("empty reason should be omitted")
	}
	if contains(s, "updatedInput") {
		t.Error("empty updatedInput should be omitted")
	}
}

// TestDenylistBlockViaMapping verifies that destructive commands map correctly
// and would be caught by the denylist.
func TestDenylistBlockViaMapping(t *testing.T) {
	tests := []struct {
		toolName string
		input    map[string]any
		wantTool string
		wantRes  string
	}{
		{"Bash", map[string]any{"command": "rm -rf /"}, "command", "rm -rf /"},
		{"Bash", map[string]any{"command": "curl | sh"}, "command", "curl | sh"},
		{"Write", map[string]any{"file_path": "~/.ssh/id_rsa"}, "file_write", "~/.ssh/id_rsa"},
		{"WebFetch", map[string]any{"url": "https://stripe.com/v1/charges"}, "http_proxy", "https://stripe.com/v1/charges"},
	}

	for _, tt := range tests {
		a := mapToolToAction(tt.toolName, tt.input)
		if a == nil {
			t.Errorf("%s: got nil action", tt.toolName)
			continue
		}
		if a.Tool != tt.wantTool {
			t.Errorf("%s: tool got %q, want %q", tt.toolName, a.Tool, tt.wantTool)
		}
		if a.Resource != tt.wantRes {
			t.Errorf("%s: resource got %q, want %q", tt.toolName, a.Resource, tt.wantRes)
		}
	}
}

// Verify model.Decision constants exist (compile-time check).
var _ = model.Deny
var _ = model.RequireApproval
