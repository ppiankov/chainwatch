// Package observe runs read-only investigation runbooks through chainwatch
// and collects structured observations. All reads are policy-gated.
//
// INSPECT-ONLY: This package hard-locks to the clawbot profile. The profile
// cannot be overridden — observe mode is structurally read-only.
package observe

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/ppiankov/chainwatch/internal/wo"
)

// inspectProfile is the only profile observe mode will use.
// This is not configurable — inspect-only is a structural guarantee.
const inspectProfile = "clawbot"

// RunnerConfig holds parameters for an investigation run.
type RunnerConfig struct {
	Scope      string // target directory, e.g. "/var/www/site"
	Type       string // runbook type: "wordpress", "linux"
	Chainwatch string // path to chainwatch binary
	AuditLog   string // path to audit log
}

// StepResult captures the output of a single investigation command.
type StepResult struct {
	Command  string        `json:"command"`
	Purpose  string        `json:"purpose"`
	Output   string        `json:"output"`
	ExitCode int           `json:"exit_code"`
	Blocked  bool          `json:"blocked"`
	Duration time.Duration `json:"duration_ms"`
}

// RunResult is the full output of an investigation.
type RunResult struct {
	Scope   string       `json:"scope"`
	Type    string       `json:"type"`
	Steps   []StepResult `json:"steps"`
	StartAt time.Time    `json:"start_at"`
	EndAt   time.Time    `json:"end_at"`
}

// Step defines a single investigation command with its purpose.
type Step struct {
	Command string
	Purpose string
}

// Runbook is a named set of investigation steps.
type Runbook struct {
	Name  string
	Type  string
	Steps []Step
}

// Run executes a runbook through chainwatch and returns the results.
// Every command is routed through `chainwatch exec --profile clawbot`.
// The profile is hard-locked — observe mode is structurally inspect-only.
func Run(cfg RunnerConfig, rb *Runbook) (*RunResult, error) {
	if cfg.Chainwatch == "" {
		cfg.Chainwatch = "chainwatch"
	}
	if cfg.AuditLog == "" {
		cfg.AuditLog = "/tmp/nullbot-observe.jsonl"
	}

	result := &RunResult{
		Scope:   cfg.Scope,
		Type:    rb.Type,
		StartAt: time.Now().UTC(),
	}

	for _, step := range rb.Steps {
		// Expand scope placeholder in commands.
		cmd := strings.ReplaceAll(step.Command, "{{SCOPE}}", cfg.Scope)

		sr := execStep(cfg, cmd, step.Purpose)
		result.Steps = append(result.Steps, sr)
	}

	result.EndAt = time.Now().UTC()
	return result, nil
}

// execStep runs a single command through chainwatch exec.
func execStep(cfg RunnerConfig, command, purpose string) StepResult {
	start := time.Now()

	args := []string{"exec", "--profile", inspectProfile, "--audit-log", cfg.AuditLog, "--"}
	args = append(args, "sh", "-c", command)

	cmd := exec.Command(cfg.Chainwatch, args...)
	out, err := cmd.CombinedOutput()

	sr := StepResult{
		Command:  command,
		Purpose:  purpose,
		Output:   strings.TrimSpace(string(out)),
		Duration: time.Since(start),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			sr.ExitCode = exitErr.ExitCode()
		} else {
			sr.ExitCode = 1
		}
	}

	if sr.ExitCode == 77 {
		sr.Blocked = true
	}

	return sr
}

// CollectEvidence concatenates all non-blocked step outputs into a single
// evidence string suitable for LLM classification.
func CollectEvidence(result *RunResult) string {
	var b strings.Builder
	for _, sr := range result.Steps {
		if sr.Blocked || sr.Output == "" {
			continue
		}
		b.WriteString(fmt.Sprintf("=== %s ===\n$ %s\n%s\n\n", sr.Purpose, sr.Command, sr.Output))
	}
	return b.String()
}

// ToObservations is a placeholder that converts raw classified output
// into typed wo.Observation structs. In production, this is done by
// the LLM classifier (classify.go). This function provides a manual
// fallback for when no LLM is available.
func ManualObservation(typ wo.ObservationType, severity wo.Severity, detail string) wo.Observation {
	return wo.Observation{
		Type:     typ,
		Severity: severity,
		Detail:   detail,
	}
}
