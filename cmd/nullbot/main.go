// nullbot — the bot that behaves.
// LLM-driven agent that lives under chainwatch enforcement.
// The LLM receives a mission and proposes shell commands.
// Every command is routed through chainwatch exec.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ppiankov/chainwatch/internal/daemon"
	"github.com/ppiankov/chainwatch/internal/integrity"
	"github.com/ppiankov/chainwatch/internal/inventory"
	"github.com/ppiankov/chainwatch/internal/observe"
	"github.com/ppiankov/chainwatch/internal/profile"
	"github.com/ppiankov/chainwatch/internal/redact"
	"github.com/ppiankov/chainwatch/internal/systemd"
	"github.com/ppiankov/chainwatch/internal/wo"
	"github.com/ppiankov/neurorouter"
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

	defaultOllamaURL                 = "http://localhost:11434/v1/chat/completions"
	defaultGroqURL                   = "https://api.groq.com/openai/v1/chat/completions"
	defaultModel                     = "llama3.2"
	defaultGroqModel                 = "llama-3.1-8b-instant"
	defaultProfile                   = "clawbot"
	defaultMaxSteps                  = 8
	defaultObserveScopeFromInventory = "/var/lib/clickhouse"

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
	apiURL        string
	apiKey        string
	model         string
	profile       string
	maxSteps      int
	dryRun        bool
	alertChannels []string
	redactMode    redact.Mode
	redactCfg     *redact.RedactConfig
	extraPatterns []redact.ExtraPattern
	llmRateLimit  int // requests per minute; 0 = unlimited
	llmFallbacks  []observe.LLMProvider
	llmPool       []observe.LLMProvider
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
	b.WriteString("# NULLBOT_LLM_RPM=30  # LLM requests per minute limit (0 = unlimited)\n")
	b.WriteString("\n# Fallback LLM provider (optional, used when primary fails)\n")
	b.WriteString("# NULLBOT_LLM_FALLBACK_URL=http://localhost:11434/v1/chat/completions\n")
	b.WriteString("# NULLBOT_LLM_FALLBACK_KEY=\n")
	b.WriteString("# NULLBOT_LLM_FALLBACK_MODEL=llama3.2\n")
	b.WriteString("\n# LLM provider pool (optional, round-robin distribution)\n")
	b.WriteString("# Format: comma-separated URL|KEY|MODEL entries\n")
	b.WriteString("# NULLBOT_LLM_POOL=http://localhost:11434/v1/chat/completions||llama3.2,https://api.groq.com/openai/v1/chat/completions|gsk_xxx|llama-3.1-8b-instant\n")
	b.WriteString("\n# Alert channels (optional, comma-separated)\n")
	b.WriteString("# Controls which configured policy alert channels are active.\n")
	b.WriteString("# Example: NULLBOT_ALERT_CHANNELS=webhook,telegram,email\n")
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

	// Resolve LLM rate limit: NULLBOT_LLM_RPM env var (requests per minute).
	if rpm := os.Getenv("NULLBOT_LLM_RPM"); rpm != "" {
		if n, err := strconv.Atoi(rpm); err == nil && n > 0 {
			cfg.llmRateLimit = n
		}
	}

	// Resolve fallback LLM provider (optional).
	if fbURL := os.Getenv("NULLBOT_LLM_FALLBACK_URL"); fbURL != "" {
		fb := observe.LLMProvider{
			URL:   fbURL,
			Key:   os.Getenv("NULLBOT_LLM_FALLBACK_KEY"),
			Model: os.Getenv("NULLBOT_LLM_FALLBACK_MODEL"),
		}
		if fb.Model == "" {
			fb.Model = cfg.model
		}
		cfg.llmFallbacks = append(cfg.llmFallbacks, fb)
	}

	// Resolve LLM provider pool (optional, comma-separated URL|KEY|MODEL entries).
	if poolStr := os.Getenv("NULLBOT_LLM_POOL"); poolStr != "" {
		for _, entry := range strings.Split(poolStr, ",") {
			parts := strings.SplitN(strings.TrimSpace(entry), "|", 3)
			if len(parts) < 1 || parts[0] == "" {
				continue
			}
			p := observe.LLMProvider{URL: parts[0]}
			if len(parts) > 1 {
				p.Key = parts[1]
			}
			if len(parts) > 2 && parts[2] != "" {
				p.Model = parts[2]
			} else {
				p.Model = cfg.model
			}
			cfg.llmPool = append(cfg.llmPool, p)
		}
	}

	// Resolve alert channel filter (optional, comma-separated names).
	// Channels are consumed by the internal alert dispatcher setup.
	cfg.alertChannels = parseCSVList(os.Getenv("NULLBOT_ALERT_CHANNELS"))

	// Load operator redaction config (optional).
	rcfg, err := redact.LoadConfig("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: redact config: %v\n", err)
	}
	if rcfg != nil {
		extra, err := redact.CompilePatterns(rcfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: redact patterns: %v\n", err)
		} else {
			cfg.redactCfg = rcfg
			cfg.extraPatterns = extra
		}
	}

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

func parseCSVList(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

// newLLMClient creates a neurorouter client from nullbot config.
func newLLMClient(cfg config) *neurorouter.Client {
	return &neurorouter.Client{
		BaseURL: cfg.apiURL,
		APIKey:  cfg.apiKey,
		Model:   cfg.model,
	}
}

// planFromLLM asks the LLM to generate a command plan for a mission.
func planFromLLM(cfg config, mission string) (*plan, error) {
	client := newLLMClient(cfg)
	temp := float64(0)
	resp, err := client.Complete(context.Background(), &neurorouter.CompletionRequest{
		Messages: []neurorouter.ChatMessage{
			{Role: "system", Content: "You are a system administration agent. Return only valid JSON, no markdown fences, no commentary."},
			{Role: "user", Content: mission},
		},
		MaxTokens:   500,
		Temperature: &temp,
	})
	if err != nil {
		return nil, err
	}

	// Strip markdown fences if the model wraps anyway.
	raw := resp.Content
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
		llmMission = redact.RedactWithConfig(mission, tokenMap, cfg.redactCfg, cfg.extraPatterns)
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

func cloneParams(params map[string]string) map[string]string {
	if len(params) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(params))
	for key, value := range params {
		cloned[key] = value
	}
	return cloned
}

func runnerConfigForHost(
	baseCfg observe.RunnerConfig,
	cluster inventory.Cluster,
	host inventory.Host,
) observe.RunnerConfig {
	cfg := baseCfg
	cfg.ClusterName = cluster.Name
	cfg.Host = host.Name
	cfg.SSHUser = host.SSHUser
	cfg.Port = host.ClickHousePort
	cfg.ConfigRepo = cluster.ConfigRepoPath()
	cfg.ConfigPath = cluster.ConfigPathResolved()

	params := cloneParams(baseCfg.Params)
	if params == nil {
		params = make(map[string]string, 6)
	}
	params["CLUSTER"] = cluster.Name
	params["HOST"] = host.Name
	params["SSH_USER"] = host.SSHUser
	params["CLICKHOUSE_PORT"] = strconv.Itoa(host.ClickHousePort)
	params["CONFIG_REPO"] = cfg.ConfigRepo
	params["CONFIG_PATH"] = cfg.ConfigPath
	cfg.Params = params

	return cfg
}

func runObserveWithInventory(
	baseCfg observe.RunnerConfig,
	runbookTypes []string,
	inv *inventory.Inventory,
) (*observe.RunResult, error) {
	if len(runbookTypes) == 0 {
		return nil, fmt.Errorf("at least one runbook type is required")
	}

	result := &observe.RunResult{
		Scope:   baseCfg.Scope,
		Type:    strings.Join(runbookTypes, "+"),
		StartAt: time.Now().UTC(),
	}
	multiMode := len(runbookTypes) > 1

	for _, cluster := range inv.Clusters() {
		for _, host := range cluster.Hosts() {
			hostCfg := runnerConfigForHost(baseCfg, cluster, host)
			var hostResult *observe.RunResult
			var err error

			if multiMode {
				hostResult, err = observe.RunMulti(hostCfg, runbookTypes)
			} else {
				hostResult, err = observe.Run(hostCfg, observe.GetRunbook(runbookTypes[0]))
			}
			if err != nil {
				result.Steps = append(result.Steps, observe.StepResult{
					Command:  strings.Join(runbookTypes, ","),
					Purpose:  fmt.Sprintf("run runbook(s) for %s/%s", cluster.Name, host.Name),
					Output:   err.Error(),
					ExitCode: 1,
					Cluster:  cluster.Name,
					Host:     host.Name,
				})
				continue
			}

			result.Steps = append(result.Steps, hostResult.Steps...)
		}
	}

	result.EndAt = time.Now().UTC()
	return result, nil
}

func resolveRunbookTypes(cmd *cobra.Command, observeTypes, observeType string, hasInventory bool) []string {
	if observeTypes != "" {
		var runbookTypes []string
		for _, raw := range strings.Split(observeTypes, ",") {
			trimmed := strings.TrimSpace(raw)
			if trimmed == "" {
				continue
			}
			runbookTypes = append(runbookTypes, trimmed)
		}
		return runbookTypes
	}

	if hasInventory && !cmd.Flags().Changed("type") {
		return []string{"clickhouse"}
	}

	return []string{observeType}
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
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := integrity.Verify(); err != nil {
				fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
				os.Exit(78) // EX_CONFIG
			}
			return nil
		},
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
		observeScope       string
		observeType        string
		observeTypes       string
		observeInventory   string
		observeOutput      string
		observeFormat      string
		observeClassify    bool
		observeDiagnostic  bool
		observeCluster     bool
		observeNoDedup     bool
		observeDedupWindow time.Duration
		observeQuery       string
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
  nullbot observe --scope /var/www/site --types kubernetes,prometheus --classify
  nullbot observe --scope /var/lib/clickhouse --type clickhouse --cluster
  nullbot observe --inventory inventory.yaml
  nullbot observe --scope /var/www/site --classify`,
		RunE: func(cmd *cobra.Command, args []string) error {
			outputFormat, formatErr := normalizeObserveFormat(observeFormat)
			if formatErr != nil {
				return formatErr
			}
			logOut := os.Stdout
			if outputFormat == observeFormatWO {
				logOut = os.Stderr
			}
			logf := func(format string, args ...any) {
				_, _ = fmt.Fprintf(logOut, format, args...)
			}
			logln := func(args ...any) {
				_, _ = fmt.Fprintln(logOut, args...)
			}
			if outputFormat == observeFormatWO {
				observeClassify = true
			}

			chainwatch := os.Getenv("CHAINWATCH_BIN")
			if chainwatch == "" {
				chainwatch = "chainwatch"
			}
			auditLog := os.Getenv("AUDIT_LOG")
			if auditLog == "" {
				auditLog = "/tmp/nullbot-observe.jsonl"
			}

			var inv *inventory.Inventory
			if observeInventory != "" {
				loaded, err := inventory.Load(observeInventory)
				if err != nil {
					return fmt.Errorf("load inventory: %w", err)
				}
				inv = loaded
			}

			if observeScope == "" {
				if inv != nil {
					observeScope = defaultObserveScopeFromInventory
				} else {
					return fmt.Errorf("--scope is required unless --inventory is set")
				}
			}

			runbookTypes := resolveRunbookTypes(cmd, observeTypes, observeType, inv != nil)
			if len(runbookTypes) == 0 {
				return fmt.Errorf("at least one runbook type is required")
			}

			cfg := resolveConfig(flagURL, flagModel, flagProfile, flagMaxSteps, flagDryRun)
			modelExplicit := cmd.Flags().Changed("model") || os.Getenv("NULLBOT_MODEL") != ""
			if inv != nil && !modelExplicit {
				if model := strings.TrimSpace(inv.BedrockConfig().Models.NullbotAnalysis); model != "" {
					cfg.model = model
				}
			}

			runnerCfg := observe.RunnerConfig{
				Scope:      observeScope,
				Type:       runbookTypes[0],
				Types:      runbookTypes,
				Cluster:    observeCluster,
				Chainwatch: chainwatch,
				AuditLog:   auditLog,
			}
			if observeQuery != "" {
				runnerCfg.Params = map[string]string{"QUERY": observeQuery}
			}

			multiMode := len(runbookTypes) > 1

			logf("%s%s=== OBSERVE MODE ===%s\n\n", bold, cyan, reset)
			logf("%sScope:   %s%s\n", dim, observeScope, reset)
			if inv != nil {
				logf("%sInventory: %s%s\n", dim, inv.Path(), reset)
				logf("%sClusters: %d%s\n", dim, len(inv.Clusters()), reset)
			}
			if multiMode {
				logf("%sRunbooks: %s%s\n", dim, strings.Join(runbookTypes, ", "), reset)
			} else {
				rb := observe.GetRunbook(runbookTypes[0])
				logf("%sRunbook: %s (%d steps)%s\n", dim, rb.Name, len(rb.Steps), reset)
			}
			if inv != nil {
				bedrockCfg := inv.BedrockConfig()
				if bedrockCfg.Region != "" {
					logf("%sBedrock: %s%s\n", dim, bedrockCfg.Region, reset)
				}
			}
			if observeQuery != "" {
				logf("%sQuery:   %s%s\n", dim, observeQuery, reset)
			}
			if observeCluster {
				logf("%sMode:    cluster-aware%s\n", dim, reset)
			}
			logf("%sProfile: clawbot (inspect-only, hard-locked)%s\n", dim, reset)
			logln()

			if cfg.dryRun {
				logf("%s%sDry run — investigation steps:%s\n\n", bold, yellow, reset)
				stepNum := 0
				if inv != nil {
					for _, cluster := range inv.Clusters() {
						logf("  %sCluster:%s %s\n", bold, reset, cluster.Name)
						logf("    %sconfig repo: %s%s\n", dim, cluster.ConfigRepoPath(), reset)
						for _, host := range cluster.Hosts() {
							hostCfg := runnerConfigForHost(runnerCfg, cluster, host)
							logf("    %sHost:%s %s\n", bold, reset, host.Name)
							for _, rbType := range runbookTypes {
								rb := observe.GetRunbook(rbType)
								if rb == nil {
									logf("      %sRunbook %q not found%s\n", red, rbType, reset)
									continue
								}
								if multiMode {
									logf("      %s--- %s ---%s\n", dim, rb.Name, reset)
								}
								for _, step := range rb.Steps {
									if step.Cluster && !hostCfg.Cluster {
										continue
									}
									stepNum++
									expanded := strings.ReplaceAll(step.Command, "{{SCOPE}}", hostCfg.Scope)
									for k, v := range hostCfg.Params {
										expanded = strings.ReplaceAll(expanded, "{{"+k+"}}", v)
									}
									logf("      %d. %s%s%s\n         %s%s%s\n", stepNum, bold, step.Purpose, reset, dim, expanded, reset)
								}
							}
						}
					}
				} else {
					for _, rbType := range runbookTypes {
						rb := observe.GetRunbook(rbType)
						if rb == nil {
							logf("  %sRunbook %q not found%s\n", red, rbType, reset)
							continue
						}
						if multiMode {
							logf("  %s--- %s ---%s\n", dim, rb.Name, reset)
						}
						for _, step := range rb.Steps {
							if step.Cluster && !runnerCfg.Cluster {
								continue
							}
							stepNum++
							expanded := strings.ReplaceAll(step.Command, "{{SCOPE}}", observeScope)
							for k, v := range runnerCfg.Params {
								expanded = strings.ReplaceAll(expanded, "{{"+k+"}}", v)
							}
							logf("  %d. %s%s%s\n     %s%s%s\n", stepNum, bold, step.Purpose, reset, dim, expanded, reset)
						}
					}
				}
				return nil
			}

			// Diagnostic mode: write full pipeline data to file for operator inspection.
			var diagFile *os.File
			if observeDiagnostic {
				if !observeClassify {
					return fmt.Errorf("--diagnostic requires --classify")
				}
				diagPath := fmt.Sprintf("/tmp/nullbot-diagnostic-%d.txt", time.Now().Unix())
				var err error
				diagFile, err = os.OpenFile(diagPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
				if err != nil {
					return fmt.Errorf("create diagnostic file: %w", err)
				}
				defer func() {
					_ = diagFile.Close()
				}()
				if _, err := fmt.Fprintf(diagFile, "NULLBOT DIAGNOSTIC OUTPUT — NON-PRODUCTION\n"); err != nil {
					return fmt.Errorf("write diagnostic header: %w", err)
				}
				if _, err := fmt.Fprintf(diagFile, "WARNING: Contains sensitive pre-redaction data.\n"); err != nil {
					return fmt.Errorf("write diagnostic warning: %w", err)
				}
				if _, err := fmt.Fprintf(diagFile, "Generated: %s\n\n", time.Now().UTC().Format(time.RFC3339)); err != nil {
					return fmt.Errorf("write diagnostic timestamp: %w", err)
				}
				logf("%s%sWARNING: Diagnostic mode — sensitive data will be written to:%s\n", bold, yellow, reset)
				logf("  %s\n\n", diagPath)
			}

			// Execute runbook(s).
			logf("%sRunning investigation...%s\n\n", dim, reset)
			var result *observe.RunResult
			var err error
			if inv != nil {
				result, err = runObserveWithInventory(runnerCfg, runbookTypes, inv)
			} else if multiMode {
				result, err = observe.RunMulti(runnerCfg, runbookTypes)
			} else {
				result, err = observe.Run(runnerCfg, observe.GetRunbook(runbookTypes[0]))
			}
			if err != nil {
				return fmt.Errorf("observe failed: %w", err)
			}

			// Display step results.
			for i, sr := range result.Steps {
				stepContext := ""
				if sr.Cluster != "" || sr.Host != "" {
					var contextParts []string
					if sr.Cluster != "" {
						contextParts = append(contextParts, sr.Cluster)
					}
					if sr.Host != "" {
						contextParts = append(contextParts, sr.Host)
					}
					stepContext = fmt.Sprintf(" [%s]", strings.Join(contextParts, "/"))
				}
				logf("%s[%d/%d]%s %s%s\n", bold, i+1, len(result.Steps), reset, sr.Purpose, stepContext)
				if sr.Blocked {
					logf("  %sBLOCKED%s by chainwatch\n", red, reset)
				} else if sr.ExitCode != 0 {
					logf("  %sERROR%s exit=%d\n", red, reset, sr.ExitCode)
				} else if sr.Output == "" {
					logf("  %s(no output)%s\n", dim, reset)
				} else {
					lines := strings.SplitN(sr.Output, "\n", 4)
					for _, line := range lines[:min(len(lines), 3)] {
						logf("  %s%s%s\n", dim, line, reset)
					}
					if len(lines) > 3 {
						logf("  %s... (%d more lines)%s\n", dim, strings.Count(sr.Output, "\n")-2, reset)
					}
				}
				logln()
			}

			// Collect evidence for classification.
			evidence := observe.CollectEvidence(result)

			if diagFile != nil {
				if _, err := fmt.Fprintf(diagFile, "=== COLLECTED: RAW EVIDENCE ===\n%s\n=== END COLLECTED ===\n\n", evidence); err != nil {
					return fmt.Errorf("write diagnostic raw evidence: %w", err)
				}
			}

			if evidence == "" {
				if outputFormat != observeFormatWO {
					logf("%sNo evidence collected (all steps blocked or empty).%s\n", yellow, reset)
					return nil
				}
			}

			// Classify with LLM if requested.
			var observations []wo.Observation
			if observeClassify && evidence != "" {
				logf("%sClassifying findings with %s...%s ", dim, cfg.model, reset)

				// Resolve sensitivity: strictest across all runbooks.
				sensitivity := ""
				for _, rbType := range runbookTypes {
					if rb := observe.GetRunbook(rbType); rb != nil && rb.Sensitivity == "local" {
						sensitivity = "local"
						break
					}
				}

				classifyCfg := observe.ClassifierConfig{
					APIURL:           cfg.apiURL,
					APIKey:           cfg.apiKey,
					Model:            cfg.model,
					Pool:             cfg.llmPool,
					Sensitivity:      sensitivity,
					DiagnosticWriter: diagFile, // nil when --diagnostic not used
				}

				// Redact evidence if cloud mode.
				classifyEvidence := evidence
				var tokenMap *redact.TokenMap
				if cfg.redactMode == redact.ModeCloud {
					tokenMap = redact.NewTokenMap(fmt.Sprintf("observe-%d", time.Now().UnixNano()))
					classifyEvidence = redact.RedactWithConfig(evidence, tokenMap, cfg.redactCfg, cfg.extraPatterns)
					if tokenMap.Len() > 0 {
						classifyEvidence = tokenMap.Legend() + "\n" + classifyEvidence
					}
				}

				if diagFile != nil {
					if _, err := fmt.Fprintf(diagFile, "=== SENT: REDACTED EVIDENCE ===\n%s\n=== END SENT ===\n\n", classifyEvidence); err != nil {
						return fmt.Errorf("write diagnostic redacted evidence: %w", err)
					}
				}

				obs, err := observe.Classify(classifyCfg, classifyEvidence)
				if err != nil {
					logf("%sFAILED%s (%v)\n", red, reset, err)
					logf("%sEvidence collected but classification failed. Use --output to save raw results.%s\n", yellow, reset)
				} else {
					// Post-validation: check for leaks and de-redact.
					if tokenMap != nil && tokenMap.Len() > 0 {
						var allDetails string
						for _, o := range obs {
							allDetails += " " + o.Detail
						}
						if leaks := redact.CheckLeaks(allDetails, tokenMap); len(leaks) > 0 {
							logf("%sFAILED%s (LLM leaked %d sensitive values)\n", red, reset, len(leaks))
							return fmt.Errorf("classification leak: LLM exposed %d sensitive values", len(leaks))
						}
						for i := range obs {
							obs[i].Detail = redact.Detoken(obs[i].Detail, tokenMap)
						}
					}
					observations = obs
					logf("%sOK%s (%d observations)\n", green, reset, len(obs))
				}

				if diagFile != nil {
					logf("%sDiagnostic written to: %s%s\n", dim, diagFile.Name(), reset)
				}
			}

			typeLabel := runbookTypes[0]
			if multiMode {
				typeLabel = strings.Join(runbookTypes, ",")
			}

			if outputFormat == observeFormatWO {
				repo := ""
				if inv != nil && len(inv.Clusters()) == 1 {
					repo = inv.Clusters()[0].ConfigRepoPath()
				}

				woTasks, err := buildWOTasks(observations, woTaskBuildConfig{
					Scope:        observeScope,
					Runbook:      typeLabel,
					Repo:         repo,
					DedupDBPath:  observe.CacheDir(resolveObserveStateDir()),
					DedupWindow:  observeDedupWindow,
					DisableDedup: observeNoDedup,
					Now:          time.Now().UTC(),
				})
				if err != nil {
					return fmt.Errorf("build WO tasks: %w", err)
				}

				data, err := json.MarshalIndent(woTasks.Payload, "", "  ")
				if err != nil {
					return fmt.Errorf("marshal WO output: %w", err)
				}
				if observeOutput != "" {
					if err := os.WriteFile(observeOutput, data, 0600); err != nil {
						return fmt.Errorf("write output: %w", err)
					}
					logf("\n%sResults written to %s%s\n", green, observeOutput, reset)
				}
				logf(
					"%sDedup: emitted=%d suppressed=%d reopened=%d%s\n",
					dim,
					woTasks.Emitted,
					woTasks.Suppressed,
					woTasks.Reopened,
					reset,
				)
				fmt.Printf("%s\n", data)
				return nil
			}

			// Output.
			if observeOutput != "" {
				output := map[string]interface{}{
					"scope":        observeScope,
					"type":         typeLabel,
					"steps":        result.Steps,
					"evidence":     evidence,
					"observations": observations,
				}
				if inv != nil {
					output["inventory"] = inv.Path()
				}
				data, _ := json.MarshalIndent(output, "", "  ")
				if err := os.WriteFile(observeOutput, data, 0600); err != nil {
					return fmt.Errorf("write output: %w", err)
				}
				logf("\n%sResults written to %s%s\n", green, observeOutput, reset)
			}

			// Summary.
			logf("\n%s=== SUMMARY ===%s\n", bold, reset)
			total := len(result.Steps)
			blocked := 0
			for _, sr := range result.Steps {
				if sr.Blocked {
					blocked++
				}
			}
			logf("  Steps: %d  |  %sCompleted: %d%s  |  %sBlocked: %d%s\n",
				total, green, total-blocked, reset, red, blocked, reset)
			if len(observations) > 0 {
				logf("  Observations: %d\n", len(observations))
				for _, obs := range observations {
					severity := string(obs.Severity)
					color := dim
					switch obs.Severity {
					case wo.SeverityCritical:
						color = red
					case wo.SeverityHigh:
						color = yellow
					}
					logf("    %s[%s]%s %s: %s\n", color, severity, reset, obs.Type, obs.Detail)
				}
			}

			return nil
		},
	}

	observeCmd.Flags().StringVar(&observeScope, "scope", "", "target directory to investigate (required unless --inventory is set)")
	observeCmd.Flags().StringVar(&observeType, "type", "linux", "runbook type (see 'nullbot runbooks')")
	observeCmd.Flags().StringVar(&observeTypes, "types", "", "comma-separated runbook types for multi-runbook investigation")
	observeCmd.Flags().StringVar(&observeInventory, "inventory", "", "path to inventory.yaml for cluster/host discovery")
	observeCmd.Flags().StringVar(&observeOutput, "output", "", "write results to JSON file")
	observeCmd.Flags().StringVar(&observeFormat, "format", observeFormatText, "output format: text, wo")
	observeCmd.Flags().BoolVar(&observeClassify, "classify", false, "classify findings with local LLM")
	observeCmd.Flags().StringVar(&flagURL, "api-url", "", "LLM API endpoint for classification (env: NULLBOT_API_URL)")
	observeCmd.Flags().StringVar(&flagModel, "model", "", "LLM model name for classification (env: NULLBOT_MODEL)")
	observeCmd.Flags().BoolVar(&flagDryRun, "dry-run", false, "show runbook steps without executing")
	observeCmd.Flags().BoolVar(&observeDiagnostic, "diagnostic", false, "write full pipeline data to file (non-production)")
	observeCmd.Flags().BoolVar(&observeCluster, "cluster", false, "enable cluster-only runbook steps")
	observeCmd.Flags().BoolVar(&observeNoDedup, "no-dedup", false, "bypass WO deduplication for this run")
	observeCmd.Flags().DurationVar(&observeDedupWindow, "dedup-window", defaultObserveDedupWindow, "time window to suppress recurrences after closure")
	observeCmd.Flags().StringVar(&observeQuery, "query", "", "email address or search term for trace runbooks")

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
				Chainwatch:    chainwatch,
				AuditLog:      auditLog,
				APIURL:        cfg.apiURL,
				APIKey:        cfg.apiKey,
				Model:         cfg.model,
				PollMode:      daemonPollMode,
				RedactConfig:  cfg.redactCfg,
				ExtraPatterns: cfg.extraPatterns,
				LLMRateLimit:  cfg.llmRateLimit,
				LLMFallbacks:  cfg.llmFallbacks,
				LLMPool:       cfg.llmPool,
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

	runbooksCmd := &cobra.Command{
		Use:   "runbooks",
		Short: "list available investigation runbooks",
		RunE: func(cmd *cobra.Command, args []string) error {
			list := observe.ListRunbooks()
			fmt.Printf("%s%s=== AVAILABLE RUNBOOKS ===%s\n\n", bold, cyan, reset)
			for _, info := range list {
				aliases := ""
				if len(info.Aliases) > 0 {
					aliases = fmt.Sprintf(" (aliases: %s)", strings.Join(info.Aliases, ", "))
				}
				fmt.Printf("  %s%-12s%s %s%s%s  %s%d steps  [%s]%s\n",
					bold, info.Type, reset,
					green, info.Name, reset,
					dim, info.Steps, info.Source, reset)
				if aliases != "" {
					fmt.Printf("  %s%s%s%s\n", strings.Repeat(" ", 13), dim, aliases, reset)
				}
			}
			fmt.Printf("\n%sUser runbooks: ~/.chainwatch/runbooks/<type>.yaml%s\n", dim, reset)
			return nil
		},
	}

	rootCmd.AddCommand(runCmd, observeCmd, daemonCmd, listCmd, approveCmd, rejectCmd, versionCmd, initCmd, runbooksCmd)

	// CI compatibility: bare invocation with GROQ_API_KEY or NULLBOT_CI runs default mission.
	// This keeps the release workflow VHS recording working.
	if len(os.Args) == 1 && (os.Getenv("GROQ_API_KEY") != "" || os.Getenv("NULLBOT_CI") == "1") {
		cfg := resolveConfig("", "", defaultProfile, defaultMaxSteps, false)

		// CI uses ./chainwatch not system-installed
		if _, err := os.Stat("./chainwatch"); err == nil {
			if err := os.Setenv("CHAINWATCH_BIN", "./chainwatch"); err != nil {
				fmt.Fprintf(os.Stderr, "nullbot: set CHAINWATCH_BIN: %v\n", err)
				os.Exit(1)
			}
		}
		// CI audit log path
		if err := os.Setenv("AUDIT_LOG", "/tmp/release-fieldtest.jsonl"); err != nil {
			fmt.Fprintf(os.Stderr, "nullbot: set AUDIT_LOG: %v\n", err)
			os.Exit(1)
		}

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
