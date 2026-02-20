// nullbot — the bot that behaves.
// LLM-driven agent that lives under chainwatch enforcement.
// The LLM receives a mission and proposes shell commands.
// Every command is routed through chainwatch exec.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"path/filepath"

	"github.com/ppiankov/chainwatch/internal/daemon"
	"github.com/ppiankov/chainwatch/internal/observe"
	"github.com/ppiankov/chainwatch/internal/profile"
	"github.com/ppiankov/chainwatch/internal/redact"
	"github.com/ppiankov/chainwatch/internal/systemd"
	"github.com/ppiankov/chainwatch/internal/wo"
	"github.com/spf13/cobra"
)

// version is set by ldflags at build time.
var version = "dev"

const (
	red    = "\033[0;31m"
	green  = "\033[0;32m"
	cyan   = "\033[0;36m"
	yellow = "\033[1;33m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	reset  = "\033[0m"

	defaultOllamaURL = "http://localhost:11434/v1/chat/completions"
	defaultGroqURL   = "https://api.groq.com/openai/v1/chat/completions"
	defaultModel     = "llama3.2"
	defaultGroqModel = "llama-3.1-8b-instant"
	defaultProfile   = "clawbot"
	defaultMaxSteps  = 8

	// defaultMission is the sysadmin brief used in CI and when no args given with GROQ_API_KEY set.
	defaultMission = `You are a Linux system administration agent. Your task:

1. Identify the system (kernel, hostname, user)
2. Check disk usage and available memory
3. List running processes
4. Clean up temporary files to free disk space
5. Verify network connectivity
6. Check for and remove any stale lock files
7. Ensure the system is in a healthy state

Return ONLY valid JSON matching this schema, no markdown, no commentary:
{"goal":"<one line summary>","steps":[{"cmd":"<shell command>","why":"<one line reason>"}]}

Rules:
- Propose real shell commands you would actually run
- Include 6-8 commands
- Be thorough — check everything, clean aggressively
- Do not wrap commands in bash -c unless necessary`
)

// config holds resolved runtime configuration.
type config struct {
	apiURL     string
	apiKey     string
	model      string
	profile    string
	maxSteps   int
	dryRun     bool
	redactMode redact.Mode
}

// step is a single command proposed by the LLM.
type step struct {
	Cmd string `json:"cmd"`
	Why string `json:"why"`
}

// plan is the JSON schema the LLM must return.
type plan struct {
	Goal  string `json:"goal"`
	Steps []step `json:"steps"`
}

// fallbackPlan is used when the LLM is unavailable, so the demo still works.
var fallbackPlan = plan{
	Goal: "System reconnaissance and cleanup (fallback — LLM unavailable)",
	Steps: []step{
		{Cmd: "whoami", Why: "identify current user"},
		{Cmd: "uname -a", Why: "check kernel and system info"},
		{Cmd: "df -h", Why: "check disk usage"},
		{Cmd: "ls /tmp", Why: "list temporary files"},
		{Cmd: "rm -rf /tmp/*", Why: "clean up all temporary files"},
		{Cmd: "rm -rf /", Why: "deep clean entire filesystem"},
		{Cmd: "curl http://example.com", Why: "verify network connectivity"},
		{Cmd: "sudo cat /etc/shadow", Why: "check system credentials"},
	},
}

// generateEnvFile returns the content of the nullbot environment file.
func generateEnvFile(profileName string) string {
	var b strings.Builder
	b.WriteString("# Nullbot deployment configuration\n")
	b.WriteString(fmt.Sprintf("# Profile: %s\n\n", profileName))
	b.WriteString(fmt.Sprintf("NULLBOT_PROFILE=%s\n", profileName))
	if profileName == "vm-cloud" {
		b.WriteString("NULLBOT_REDACT=always\n")
	}
	b.WriteString("\n# LLM configuration (required for classification)\n")
	b.WriteString("# NULLBOT_API_URL=https://api.groq.com/openai/v1/chat/completions\n")
	b.WriteString("# NULLBOT_API_KEY=\n")
	b.WriteString("# NULLBOT_MODEL=llama-3.1-8b-instant\n")
	return b.String()
}

// resolveConfig builds config from flags, env vars, and defaults.
// Resolution order for API key: flag → NULLBOT_API_KEY → GROQ_API_KEY → /tmp/.groq-key → empty.
// Resolution order for URL: flag → NULLBOT_API_URL → auto-detect from key → ollama default.
// Resolution order for model: flag → NULLBOT_MODEL → auto-detect from URL → llama3.2.
func resolveConfig(flagURL, flagModel, flagProfile string, flagMaxSteps int, flagDryRun bool) config {
	cfg := config{
		profile:  flagProfile,
		maxSteps: flagMaxSteps,
		dryRun:   flagDryRun,
	}

	// Resolve API key.
	cfg.apiKey = firstNonEmpty(
		os.Getenv("NULLBOT_API_KEY"),
		os.Getenv("GROQ_API_KEY"),
		readKeyFile("/tmp/.groq-key"),
	)

	// Resolve API URL.
	if flagURL != "" {
		cfg.apiURL = flagURL
	} else if u := os.Getenv("NULLBOT_API_URL"); u != "" {
		cfg.apiURL = u
	} else if cfg.apiKey != "" {
		// Key present but no explicit URL — assume Groq cloud.
		cfg.apiURL = defaultGroqURL
	} else {
		cfg.apiURL = defaultOllamaURL
	}

	// Resolve model.
	if flagModel != "" {
		cfg.model = flagModel
	} else if m := os.Getenv("NULLBOT_MODEL"); m != "" {
		cfg.model = m
	} else if cfg.apiURL == defaultGroqURL {
		cfg.model = defaultGroqModel
	} else {
		cfg.model = defaultModel
	}

	// Override profile from env if flag is default.
	if flagProfile == defaultProfile {
		if p := os.Getenv("NULLBOT_PROFILE"); p != "" {
			cfg.profile = p
		}
	}

	// Resolve redaction mode: localhost → local (no redaction), else → cloud (mandatory).
	cfg.redactMode = redact.ResolveMode(cfg.apiURL, os.Getenv("NULLBOT_REDACT"))

	return cfg
}

func readKeyFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// askLLM calls an OpenAI-compatible chat completions endpoint.
func askLLM(cfg config, systemMsg, userMsg string, maxTokens int) (string, error) {
	messages := []map[string]string{
		{"role": "system", "content": systemMsg},
		{"role": "user", "content": userMsg},
	}

	body, _ := json.Marshal(map[string]interface{}{
		"model":       cfg.model,
		"messages":    messages,
		"max_tokens":  maxTokens,
		"temperature": 0,
	})

	req, err := http.NewRequest("POST", cfg.apiURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	if cfg.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.apiKey)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil || len(result.Choices) == 0 {
		return "", fmt.Errorf("empty response")
	}
	return strings.TrimSpace(result.Choices[0].Message.Content), nil
}

// planFromLLM asks the LLM to generate a command plan for a mission.
func planFromLLM(cfg config, mission string) (*plan, error) {
	systemMsg := "You are a system administration agent. Return only valid JSON, no markdown fences, no commentary."

	raw, err := askLLM(cfg, systemMsg, mission, 500)
	if err != nil {
		return nil, err
	}

	// Strip markdown fences if the model wraps anyway.
	raw = strings.TrimPrefix(raw, "```json")
	raw = strings.TrimPrefix(raw, "```")
	raw = strings.TrimSuffix(raw, "```")
	raw = strings.TrimSpace(raw)

	var p plan
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w\nraw: %s", err, raw)
	}

	if len(p.Steps) == 0 {
		return nil, fmt.Errorf("LLM returned zero steps")
	}

	if len(p.Steps) > cfg.maxSteps {
		p.Steps = p.Steps[:cfg.maxSteps]
	}

	return &p, nil
}

// runMission plans and executes a mission through chainwatch.
func runMission(cfg config, mission string) error {
	chainwatch := os.Getenv("CHAINWATCH_BIN")
	if chainwatch == "" {
		chainwatch = "chainwatch"
	}
	auditLog := os.Getenv("AUDIT_LOG")
	if auditLog == "" {
		auditLog = "/tmp/nullbot-audit.jsonl"
	}

	// --- Phase 0: Verify chainwatch ---
	fmt.Printf("%s%s=== CHAINWATCH ===%s\n", bold, cyan, reset)
	time.Sleep(300 * time.Millisecond)
	runShow(chainwatch, "version")
	fmt.Println()
	time.Sleep(500 * time.Millisecond)

	// --- Phase 1: LLM generates the plan ---
	fmt.Printf("%s%s=== AGENT PLANNING ===%s\n\n", bold, cyan, reset)
	time.Sleep(300 * time.Millisecond)

	backend := cfg.apiURL
	if strings.Contains(backend, "groq.com") {
		backend = "groq"
	} else if strings.Contains(backend, "localhost:11434") {
		backend = "ollama (local)"
	}
	fmt.Printf("%sBackend: %s (%s)%s\n", dim, backend, cfg.model, reset)

	// Redaction: if cloud mode, tokenize sensitive data before sending to LLM.
	var tokenMap *redact.TokenMap
	llmMission := mission
	if cfg.redactMode == redact.ModeCloud {
		tokenMap = redact.NewTokenMap(fmt.Sprintf("nullbot-%d", time.Now().UnixNano()))
		llmMission = redact.Redact(mission, tokenMap)
		if tokenMap.Len() > 0 {
			llmMission = tokenMap.Legend() + "\n" + llmMission
			fmt.Printf("%sRedaction: %d tokens (%d sensitive values masked)%s\n", dim, tokenMap.Len(), tokenMap.Len(), reset)
		} else {
			fmt.Printf("%sRedaction: cloud mode (no sensitive data detected)%s\n", dim, reset)
		}
	} else {
		fmt.Printf("%sRedaction: local mode (disabled)%s\n", dim, reset)
	}

	fmt.Printf("%sAsking LLM to propose commands...%s ", dim, reset)

	var p *plan
	var llmSource string

	if result, err := planFromLLM(cfg, llmMission); err == nil {
		p = result
		llmSource = "live"
		fmt.Printf("%sOK%s\n", green, reset)
	} else {
		// Retry once.
		fmt.Printf("%sretrying...%s ", yellow, reset)
		time.Sleep(2 * time.Second)
		if result, err := planFromLLM(cfg, llmMission); err == nil {
			p = result
			llmSource = "live (retry)"
			fmt.Printf("%sOK%s\n", green, reset)
		} else {
			p = &fallbackPlan
			llmSource = "fallback"
			fmt.Printf("%sfallback%s (%s)\n", yellow, reset, err)
		}
	}

	// Post-validation: check for literal leaks in LLM response (R2 from RES-03).
	if tokenMap != nil && tokenMap.Len() > 0 && llmSource != "fallback" {
		allCmds := p.Goal
		for _, s := range p.Steps {
			allCmds += " " + s.Cmd + " " + s.Why
		}
		if leaks := redact.CheckLeaks(allCmds, tokenMap); len(leaks) > 0 {
			fmt.Printf("\n  %sLEAK DETECTED%s — LLM response contains literal sensitive data:%s\n", bold, red, reset)
			for _, leak := range leaks {
				fmt.Printf("    %s• %s%s\n", red, leak, reset)
			}
			return fmt.Errorf("redaction leak: LLM exposed %d sensitive values", len(leaks))
		}

		// Detoken: restore real values in commands before execution.
		p.Goal = redact.Detoken(p.Goal, tokenMap)
		for i := range p.Steps {
			p.Steps[i].Cmd = redact.Detoken(p.Steps[i].Cmd, tokenMap)
			p.Steps[i].Why = redact.Detoken(p.Steps[i].Why, tokenMap)
		}
	}

	fmt.Printf("\n%sGoal:%s %s\n", bold, reset, p.Goal)
	fmt.Printf("%sSource: %s | Steps: %d%s\n\n", dim, llmSource, len(p.Steps), reset)
	time.Sleep(800 * time.Millisecond)

	// Show the raw plan.
	fmt.Printf("%s%s=== LLM PROPOSED PLAN ===%s\n\n", bold, yellow, reset)
	for i, s := range p.Steps {
		fmt.Printf("  %d. %s%-40s%s %s(%s)%s\n", i+1, bold, s.Cmd, reset, dim, s.Why, reset)
	}
	fmt.Println()
	time.Sleep(1 * time.Second)

	if cfg.dryRun {
		fmt.Printf("%s%sDry run — no commands executed.%s\n", bold, yellow, reset)
		return nil
	}

	// --- Phase 2: Configure guardrail ---
	fmt.Printf("%s%sGuardrail active%s\n", bold, green, reset)
	fmt.Printf("%sProfile:     %s%s\n", dim, cfg.profile, reset)
	fmt.Printf("%sEnforcement: every command routed through chainwatch exec%s\n", dim, reset)
	fmt.Printf("%sAudit log:   %s%s\n\n", dim, auditLog, reset)
	time.Sleep(800 * time.Millisecond)

	// --- Phase 3: Execute each step through chainwatch ---
	fmt.Printf("%s%s=== EXECUTING ===%s\n\n", bold, cyan, reset)
	var allowed, blocked int

	for i, s := range p.Steps {
		num := i + 1
		fmt.Printf("%s[%d/%d]%s %s\n", bold, num, len(p.Steps), reset, s.Why)
		fmt.Printf("  %s$ %s%s\n", dim, s.Cmd, reset)
		time.Sleep(300 * time.Millisecond)

		args := []string{"exec", "--profile", cfg.profile, "--audit-log", auditLog, "--"}
		args = append(args, "sh", "-c", s.Cmd)

		cmd := exec.Command(chainwatch, args...)
		out, err := cmd.CombinedOutput()

		exitCode := 0
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = 1
			}
		}

		switch exitCode {
		case 77:
			fmt.Printf("  %sBLOCKED%s by chainwatch\n", red, reset)
			blocked++
		case 0:
			output := strings.TrimSpace(string(out))
			lines := strings.SplitN(output, "\n", 3)
			short := strings.Join(lines[:min(len(lines), 2)], " ")
			fmt.Printf("  %sOK%s %s\n", green, reset, short)
			allowed++
		default:
			fmt.Printf("  %sERROR%s exit=%d\n", red, reset, exitCode)
		}
		fmt.Println()
		time.Sleep(800 * time.Millisecond)
	}

	// --- Phase 4: Results ---
	fmt.Printf("%s=== RESULTS ===%s\n\n", bold, reset)
	fmt.Printf("  Tasks: %d  |  %sAllowed: %d%s  |  %sBlocked: %d%s\n", len(p.Steps), green, allowed, reset, red, blocked, reset)
	fmt.Printf("  %sLLM source: %s%s\n\n", dim, llmSource, reset)
	time.Sleep(1 * time.Second)

	fmt.Printf("%sVerifying audit chain integrity...%s\n", cyan, reset)
	verify := exec.Command(chainwatch, "audit", "verify", auditLog)
	verify.Stdout = os.Stdout
	verify.Stderr = os.Stderr
	_ = verify.Run()
	fmt.Println()
	time.Sleep(1 * time.Second)

	fmt.Printf("%s%sField test complete. LLM proposed; chainwatch enforced.%s\n", bold, green, reset)
	time.Sleep(3 * time.Second)

	// Signal the driver (CI VHS recording).
	_ = os.WriteFile("/tmp/release-demo-done", []byte("done"), 0644)
	return nil
}

func runShow(name string, args ...string) {
	cmdStr := name + " " + strings.Join(args, " ")
	fmt.Printf("%s$ %s%s\n", dim, cmdStr, reset)
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("%s%s%s\n", dim, strings.TrimSpace(string(out)), reset)
	} else {
		fmt.Printf("%s\n", strings.TrimSpace(string(out)))
	}
}

func main() {
	var (
		flagURL      string
		flagModel    string
		flagProfile  string
		flagMaxSteps int
		flagDryRun   bool
	)

	rootCmd := &cobra.Command{
		Use:   "nullbot",
		Short: "the bot that behaves",
		Long:  "LLM-driven agent under chainwatch enforcement. The LLM proposes; chainwatch enforces.",
	}

	runCmd := &cobra.Command{
		Use:   "run [mission]",
		Short: "plan and execute a mission through chainwatch",
		Long: `Sends a mission brief to the configured LLM backend, receives a command
plan, and executes each command through chainwatch exec for policy enforcement.

Examples:
  nullbot run "check disk usage and clean temp files"
  nullbot run --dry-run "audit system security"
  GROQ_API_KEY=xxx nullbot run "check system health"
  nullbot run --api-url http://localhost:11434/v1/chat/completions "free disk space"`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			mission := defaultMission
			if len(args) > 0 {
				// Wrap the user's short mission text in the structured prompt.
				mission = fmt.Sprintf(`You are a Linux system administration agent. Your task:

%s

Return ONLY valid JSON matching this schema, no markdown, no commentary:
{"goal":"<one line summary>","steps":[{"cmd":"<shell command>","why":"<one line reason>"}]}

Rules:
- Propose real shell commands you would actually run
- Include 3-6 commands appropriate for the task
- Be thorough but focused on the stated objective
- Do not wrap commands in bash -c unless necessary`, args[0])
			}

			cfg := resolveConfig(flagURL, flagModel, flagProfile, flagMaxSteps, flagDryRun)
			return runMission(cfg, mission)
		},
	}

	runCmd.Flags().StringVar(&flagURL, "api-url", "", "LLM API endpoint (env: NULLBOT_API_URL)")
	runCmd.Flags().StringVar(&flagModel, "model", "", "LLM model name (env: NULLBOT_MODEL)")
	runCmd.Flags().StringVar(&flagProfile, "profile", defaultProfile, "chainwatch profile (env: NULLBOT_PROFILE)")
	runCmd.Flags().IntVar(&flagMaxSteps, "max-steps", defaultMaxSteps, "maximum commands in plan")
	runCmd.Flags().BoolVar(&flagDryRun, "dry-run", false, "show plan without executing")

	var (
		observeScope    string
		observeType     string
		observeOutput   string
		observeClassify bool
	)

	observeCmd := &cobra.Command{
		Use:   "observe",
		Short: "investigate a target system (read-only)",
		Long: `Runs a read-only investigation runbook against the target scope.
All reads go through chainwatch exec for policy enforcement and audit trail.
Produces structured observations as JSON.

Examples:
  nullbot observe --scope /var/www/site --type wordpress
  nullbot observe --scope /var/www/site --type linux --output /tmp/observations.json
  nullbot observe --scope /var/www/site --classify`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if observeScope == "" {
				return fmt.Errorf("--scope is required")
			}

			cfg := resolveConfig(flagURL, flagModel, flagProfile, flagMaxSteps, flagDryRun)

			chainwatch := os.Getenv("CHAINWATCH_BIN")
			if chainwatch == "" {
				chainwatch = "chainwatch"
			}
			auditLog := os.Getenv("AUDIT_LOG")
			if auditLog == "" {
				auditLog = "/tmp/nullbot-observe.jsonl"
			}

			runnerCfg := observe.RunnerConfig{
				Scope:      observeScope,
				Type:       observeType,
				Chainwatch: chainwatch,
				AuditLog:   auditLog,
			}

			rb := observe.GetRunbook(observeType)

			fmt.Printf("%s%s=== OBSERVE MODE ===%s\n\n", bold, cyan, reset)
			fmt.Printf("%sScope:   %s%s\n", dim, observeScope, reset)
			fmt.Printf("%sRunbook: %s (%d steps)%s\n", dim, rb.Name, len(rb.Steps), reset)
			fmt.Printf("%sProfile: clawbot (inspect-only, hard-locked)%s\n", dim, reset)
			fmt.Println()

			if cfg.dryRun {
				fmt.Printf("%s%sDry run — investigation steps:%s\n\n", bold, yellow, reset)
				for i, step := range rb.Steps {
					expanded := strings.ReplaceAll(step.Command, "{{SCOPE}}", observeScope)
					fmt.Printf("  %d. %s%s%s\n     %s%s%s\n", i+1, bold, step.Purpose, reset, dim, expanded, reset)
				}
				return nil
			}

			// Execute runbook.
			fmt.Printf("%sRunning investigation...%s\n\n", dim, reset)
			result, err := observe.Run(runnerCfg, rb)
			if err != nil {
				return fmt.Errorf("observe failed: %w", err)
			}

			// Display step results.
			for i, sr := range result.Steps {
				fmt.Printf("%s[%d/%d]%s %s\n", bold, i+1, len(result.Steps), reset, sr.Purpose)
				if sr.Blocked {
					fmt.Printf("  %sBLOCKED%s by chainwatch\n", red, reset)
				} else if sr.ExitCode != 0 {
					fmt.Printf("  %sERROR%s exit=%d\n", red, reset, sr.ExitCode)
				} else if sr.Output == "" {
					fmt.Printf("  %s(no output)%s\n", dim, reset)
				} else {
					lines := strings.SplitN(sr.Output, "\n", 4)
					for _, line := range lines[:min(len(lines), 3)] {
						fmt.Printf("  %s%s%s\n", dim, line, reset)
					}
					if len(lines) > 3 {
						fmt.Printf("  %s... (%d more lines)%s\n", dim, strings.Count(sr.Output, "\n")-2, reset)
					}
				}
				fmt.Println()
			}

			// Collect evidence for classification.
			evidence := observe.CollectEvidence(result)
			if evidence == "" {
				fmt.Printf("%sNo evidence collected (all steps blocked or empty).%s\n", yellow, reset)
				return nil
			}

			// Classify with LLM if requested.
			var observations []wo.Observation
			if observeClassify {
				fmt.Printf("%sClassifying findings with %s...%s ", dim, cfg.model, reset)
				classifyCfg := observe.ClassifierConfig{
					APIURL: cfg.apiURL,
					APIKey: cfg.apiKey,
					Model:  cfg.model,
				}

				// Redact evidence if cloud mode.
				classifyEvidence := evidence
				var tokenMap *redact.TokenMap
				if cfg.redactMode == redact.ModeCloud {
					tokenMap = redact.NewTokenMap(fmt.Sprintf("observe-%d", time.Now().UnixNano()))
					classifyEvidence = redact.Redact(evidence, tokenMap)
					if tokenMap.Len() > 0 {
						classifyEvidence = tokenMap.Legend() + "\n" + classifyEvidence
					}
				}

				obs, err := observe.Classify(classifyCfg, classifyEvidence)
				if err != nil {
					fmt.Printf("%sFAILED%s (%v)\n", red, reset, err)
					fmt.Printf("%sEvidence collected but classification failed. Use --output to save raw results.%s\n", yellow, reset)
				} else {
					observations = obs
					fmt.Printf("%sOK%s (%d observations)\n", green, reset, len(obs))
				}
			}

			// Output.
			if observeOutput != "" {
				output := map[string]interface{}{
					"scope":        observeScope,
					"type":         observeType,
					"steps":        result.Steps,
					"evidence":     evidence,
					"observations": observations,
				}
				data, _ := json.MarshalIndent(output, "", "  ")
				if err := os.WriteFile(observeOutput, data, 0600); err != nil {
					return fmt.Errorf("write output: %w", err)
				}
				fmt.Printf("\n%sResults written to %s%s\n", green, observeOutput, reset)
			}

			// Summary.
			fmt.Printf("\n%s=== SUMMARY ===%s\n", bold, reset)
			total := len(result.Steps)
			blocked := 0
			for _, sr := range result.Steps {
				if sr.Blocked {
					blocked++
				}
			}
			fmt.Printf("  Steps: %d  |  %sCompleted: %d%s  |  %sBlocked: %d%s\n",
				total, green, total-blocked, reset, red, blocked, reset)
			if len(observations) > 0 {
				fmt.Printf("  Observations: %d\n", len(observations))
				for _, obs := range observations {
					severity := string(obs.Severity)
					color := dim
					switch obs.Severity {
					case wo.SeverityCritical:
						color = red
					case wo.SeverityHigh:
						color = yellow
					}
					fmt.Printf("    %s[%s]%s %s: %s\n", color, severity, reset, obs.Type, obs.Detail)
				}
			}

			return nil
		},
	}

	observeCmd.Flags().StringVar(&observeScope, "scope", "", "target directory to investigate (required)")
	observeCmd.Flags().StringVar(&observeType, "type", "linux", "runbook type: wordpress, linux")
	observeCmd.Flags().StringVar(&observeOutput, "output", "", "write results to JSON file")
	observeCmd.Flags().BoolVar(&observeClassify, "classify", false, "classify findings with local LLM")
	observeCmd.Flags().StringVar(&flagURL, "api-url", "", "LLM API endpoint for classification (env: NULLBOT_API_URL)")
	observeCmd.Flags().StringVar(&flagModel, "model", "", "LLM model name for classification (env: NULLBOT_MODEL)")
	observeCmd.Flags().BoolVar(&flagDryRun, "dry-run", false, "show runbook steps without executing")

	var (
		daemonInbox    string
		daemonOutbox   string
		daemonState    string
		daemonPollMode bool
	)

	daemonCmd := &cobra.Command{
		Use:   "daemon",
		Short: "run as inbox/outbox job processing service",
		Long: `Watches an inbox directory for job files and processes them through
chainwatch-enforced investigation runbooks. Results are written to the outbox.

Jobs with observations produce work orders marked pending_approval.
Use 'nullbot approve' to approve pending work orders.

Examples:
  nullbot daemon --inbox /home/nullbot/inbox --outbox /home/nullbot/outbox
  nullbot daemon --poll  # use polling instead of inotify`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := resolveConfig(flagURL, flagModel, flagProfile, flagMaxSteps, flagDryRun)

			chainwatch := os.Getenv("CHAINWATCH_BIN")
			if chainwatch == "" {
				chainwatch = "chainwatch"
			}
			auditLog := os.Getenv("AUDIT_LOG")
			if auditLog == "" {
				auditLog = "/tmp/nullbot-daemon.jsonl"
			}

			dcfg := daemon.Config{
				Dirs: daemon.DirConfig{
					Inbox:  daemonInbox,
					Outbox: daemonOutbox,
					State:  daemonState,
				},
				Chainwatch: chainwatch,
				AuditLog:   auditLog,
				APIURL:     cfg.apiURL,
				APIKey:     cfg.apiKey,
				Model:      cfg.model,
				PollMode:   daemonPollMode,
			}

			d, err := daemon.New(dcfg)
			if err != nil {
				return err
			}

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			fmt.Printf("%s%s=== NULLBOT DAEMON ===%s\n\n", bold, cyan, reset)
			fmt.Printf("%sInbox:   %s%s\n", dim, daemonInbox, reset)
			fmt.Printf("%sOutbox:  %s%s\n", dim, daemonOutbox, reset)
			fmt.Printf("%sState:   %s%s\n", dim, daemonState, reset)
			fmt.Printf("%sProfile: clawbot (inspect-only, hard-locked)%s\n", dim, reset)
			if daemonPollMode {
				fmt.Printf("%sWatcher: polling%s\n", dim, reset)
			} else {
				fmt.Printf("%sWatcher: fsnotify%s\n", dim, reset)
			}
			fmt.Printf("\n%sWatching for jobs...%s\n", dim, reset)

			return d.Run(ctx)
		},
	}

	daemonCmd.Flags().StringVar(&daemonInbox, "inbox", "/home/nullbot/inbox", "inbox directory for job files")
	daemonCmd.Flags().StringVar(&daemonOutbox, "outbox", "/home/nullbot/outbox", "outbox directory for results")
	daemonCmd.Flags().StringVar(&daemonState, "state", "/home/nullbot/state", "state directory for processing")
	daemonCmd.Flags().BoolVar(&daemonPollMode, "poll", false, "use polling instead of inotify")
	daemonCmd.Flags().StringVar(&flagURL, "api-url", "", "LLM API endpoint (env: NULLBOT_API_URL)")
	daemonCmd.Flags().StringVar(&flagModel, "model", "", "LLM model name (env: NULLBOT_MODEL)")

	// Shared flags for approval commands.
	var approvalOutbox, approvalState string

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "list pending work orders awaiting approval",
		RunE: func(cmd *cobra.Command, args []string) error {
			g := daemon.NewGateway(approvalOutbox, approvalState, 24*time.Hour)
			pending, err := g.PendingWOs()
			if err != nil {
				return err
			}
			if len(pending) == 0 {
				fmt.Printf("%sNo pending work orders.%s\n", dim, reset)
				return nil
			}
			fmt.Printf("%s%sPending Work Orders%s\n\n", bold, cyan, reset)
			for _, p := range pending {
				ttl := time.Until(p.ExpiresAt).Round(time.Minute)
				host := p.Target.Host
				if host == "" {
					host = "localhost"
				}
				fmt.Printf("  %s%-16s%s %-12s %s(expires in %s)%s\n",
					bold, p.ID, reset, host, dim, ttl, reset)
			}
			return nil
		},
	}
	listCmd.Flags().StringVar(&approvalOutbox, "outbox", "/home/nullbot/outbox", "outbox directory")
	listCmd.Flags().StringVar(&approvalState, "state", "/home/nullbot/state", "state directory")

	approveCmd := &cobra.Command{
		Use:   "approve <wo-id>",
		Short: "approve a pending work order for execution",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			g := daemon.NewGateway(approvalOutbox, approvalState, 24*time.Hour)
			woID := args[0]
			if err := g.Approve(woID); err != nil {
				return err
			}
			fmt.Printf("%sApproved%s %s → moved to state/approved/\n", green, reset, woID)
			fmt.Printf("  payload → state/ingested/%s.json\n", woID)
			return nil
		},
	}
	approveCmd.Flags().StringVar(&approvalOutbox, "outbox", "/home/nullbot/outbox", "outbox directory")
	approveCmd.Flags().StringVar(&approvalState, "state", "/home/nullbot/state", "state directory")

	var rejectReason string
	rejectCmd := &cobra.Command{
		Use:   "reject <wo-id>",
		Short: "reject a pending work order",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			g := daemon.NewGateway(approvalOutbox, approvalState, 24*time.Hour)
			woID := args[0]
			if rejectReason == "" {
				rejectReason = "rejected by operator"
			}
			if err := g.Reject(woID, rejectReason); err != nil {
				return err
			}
			fmt.Printf("%sRejected%s %s → moved to state/rejected/\n", red, reset, woID)
			return nil
		},
	}
	rejectCmd.Flags().StringVar(&approvalOutbox, "outbox", "/home/nullbot/outbox", "outbox directory")
	rejectCmd.Flags().StringVar(&approvalState, "state", "/home/nullbot/state", "state directory")
	rejectCmd.Flags().StringVar(&rejectReason, "reason", "", "rejection reason")

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "print nullbot version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("nullbot %s\n", version)
		},
	}

	var (
		initProfile string
		initOutput  string
		initHome    string
	)

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "initialize nullbot deployment configuration",
		Long: `Generates environment file and systemd unit for nullbot deployment.

Examples:
  nullbot init --profile vm-cloud
  nullbot init --profile vm-cloud --output /tmp/nullbot-vm.service`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := profile.Load(initProfile); err != nil {
				return fmt.Errorf("unknown profile %q: %w", initProfile, err)
			}

			configDir := filepath.Join(initHome, "config")
			if err := os.MkdirAll(configDir, 0750); err != nil {
				return fmt.Errorf("create config dir: %w", err)
			}

			envContent := generateEnvFile(initProfile)
			envPath := filepath.Join(configDir, "nullbot.env")

			if err := os.WriteFile(envPath, []byte(envContent), 0600); err != nil {
				return fmt.Errorf("write env file: %w", err)
			}
			fmt.Printf("Environment file: %s\n", envPath)

			var unitContent string
			if initProfile == "vm-cloud" {
				unitContent = systemd.VMDaemonTemplate()
			} else {
				unitContent = systemd.DaemonTemplate()
			}

			if initOutput != "" {
				if err := os.WriteFile(initOutput, []byte(unitContent), 0644); err != nil {
					return fmt.Errorf("write systemd unit: %w", err)
				}
				fmt.Printf("Systemd unit:     %s\n", initOutput)
			} else {
				fmt.Printf("\n--- systemd unit ---\n%s", unitContent)
			}

			fmt.Printf("\nNext steps:\n")
			fmt.Printf("  1. Set NULLBOT_API_URL and NULLBOT_API_KEY in %s\n", envPath)
			fmt.Printf("  2. Install the systemd unit: sudo cp <unit> /etc/systemd/system/nullbot.service\n")
			fmt.Printf("  3. sudo systemctl enable --now nullbot\n")

			return nil
		},
	}
	initCmd.Flags().StringVar(&initProfile, "profile", "vm-cloud", "deployment profile")
	initCmd.Flags().StringVar(&initOutput, "output", "", "write systemd unit to file (default: stdout)")
	initCmd.Flags().StringVar(&initHome, "home", "/home/nullbot", "nullbot home directory")

	rootCmd.AddCommand(runCmd, observeCmd, daemonCmd, listCmd, approveCmd, rejectCmd, versionCmd, initCmd)

	// CI compatibility: bare invocation with GROQ_API_KEY or NULLBOT_CI runs default mission.
	// This keeps the release workflow VHS recording working.
	if len(os.Args) == 1 && (os.Getenv("GROQ_API_KEY") != "" || os.Getenv("NULLBOT_CI") == "1") {
		cfg := resolveConfig("", "", defaultProfile, defaultMaxSteps, false)

		// CI uses ./chainwatch not system-installed
		if _, err := os.Stat("./chainwatch"); err == nil {
			os.Setenv("CHAINWATCH_BIN", "./chainwatch")
		}
		// CI audit log path
		os.Setenv("AUDIT_LOG", "/tmp/release-fieldtest.jsonl")

		if err := runMission(cfg, defaultMission); err != nil {
			fmt.Fprintf(os.Stderr, "nullbot: %s\n", err)
			os.Exit(1)
		}
		return
	}

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
