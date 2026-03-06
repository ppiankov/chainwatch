package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRunProfileSeccompDefaultWritesValidJSON(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "default-seccomp.json")
	seccompOutput = outPath
	t.Cleanup(func() { seccompOutput = "" })

	if err := runProfileSeccomp(nil, nil); err != nil {
		t.Fatalf("runProfileSeccomp default failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("generated seccomp is not valid JSON: %v", err)
	}

	if doc["defaultAction"] != "SCMP_ACT_ALLOW" {
		t.Fatalf("unexpected defaultAction: %v", doc["defaultAction"])
	}
}

func TestRunProfileSeccompClawbotIncludesPrivilegeSyscalls(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "clawbot-seccomp.json")
	seccompOutput = outPath
	t.Cleanup(func() { seccompOutput = "" })

	if err := runProfileSeccomp(nil, []string{"clawbot"}); err != nil {
		t.Fatalf("runProfileSeccomp clawbot failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	var doc struct {
		Syscalls []struct {
			Names []string `json:"names"`
		} `json:"syscalls"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("generated seccomp is not valid JSON: %v", err)
	}

	foundSetuid := false
	for _, rule := range doc.Syscalls {
		for _, name := range rule.Names {
			if name == "setuid" {
				foundSetuid = true
				break
			}
		}
	}
	if !foundSetuid {
		t.Fatal("expected generated seccomp profile to include setuid restriction")
	}
}
