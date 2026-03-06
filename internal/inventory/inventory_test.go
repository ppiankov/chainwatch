package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validInventoryYAML = `
clickhouse:
  clusters:
    - name: dev-analytics
      hosts: [ch-dev-01, ch-dev-02]
      config_repo: infra/clickhouse-dev-analytics
bedrock:
  models:
    nullbot_analysis: anthropic.claude-3-5-haiku-20241022-v1:0
orchestrator:
  jira:
    project: INFRA
    base_url: https://company.atlassian.net
    token_env: TEST_JIRA_TOKEN
  dispatch:
    backend: tokencontrol
`

func TestLoadAppliesDefaultsAndSupportsIteration(t *testing.T) {
	t.Setenv("TEST_JIRA_TOKEN", "token-from-env")

	path := writeInventoryFile(t, validInventoryYAML)
	inv, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if inv.Path() != path {
		t.Fatalf("Path() = %q, want %q", inv.Path(), path)
	}
	if inv.Dir() != filepath.Dir(path) {
		t.Fatalf("Dir() = %q, want %q", inv.Dir(), filepath.Dir(path))
	}

	clusters := inv.Clusters()
	if len(clusters) != 1 {
		t.Fatalf("expected 1 cluster, got %d", len(clusters))
	}

	cluster := clusters[0]
	if cluster.SSHUser != defaultSSHUser {
		t.Fatalf("SSHUser = %q, want %q", cluster.SSHUser, defaultSSHUser)
	}
	if cluster.ClickHousePort != defaultClickHousePort {
		t.Fatalf(
			"ClickHousePort = %d, want %d",
			cluster.ClickHousePort,
			defaultClickHousePort,
		)
	}
	if cluster.ConfigPath != defaultConfigPath {
		t.Fatalf("ConfigPath = %q, want %q", cluster.ConfigPath, defaultConfigPath)
	}

	hosts := cluster.Hosts()
	if len(hosts) != 2 {
		t.Fatalf("Hosts() count = %d, want 2", len(hosts))
	}
	if hosts[0].Name != "ch-dev-01" || hosts[1].Name != "ch-dev-02" {
		t.Fatalf("unexpected host list: %+v", hosts)
	}
	if hosts[0].SSHUser != defaultSSHUser {
		t.Fatalf("host SSHUser = %q, want %q", hosts[0].SSHUser, defaultSSHUser)
	}

	expectedRepoPath := filepath.Join(filepath.Dir(path), "infra", "clickhouse-dev-analytics")
	if cluster.ConfigRepoPath() != expectedRepoPath {
		t.Fatalf("ConfigRepoPath() = %q, want %q", cluster.ConfigRepoPath(), expectedRepoPath)
	}

	expectedConfigPath := filepath.Join(expectedRepoPath, defaultConfigPath)
	if cluster.ConfigPathResolved() != expectedConfigPath {
		t.Fatalf(
			"ConfigPathResolved() = %q, want %q",
			cluster.ConfigPathResolved(),
			expectedConfigPath,
		)
	}

	if inv.BedrockConfig().Region != defaultBedrockRegion {
		t.Fatalf(
			"BedrockConfig().Region = %q, want %q",
			inv.BedrockConfig().Region,
			defaultBedrockRegion,
		)
	}
	if inv.Orchestrator.JIRA.Token != "token-from-env" {
		t.Fatalf("JIRA token = %q, want token-from-env", inv.Orchestrator.JIRA.Token)
	}
	if inv.Notifications.Slack.WebhookEnv != defaultSlackWebhookEnv {
		t.Fatalf(
			"WebhookEnv = %q, want %q",
			inv.Notifications.Slack.WebhookEnv,
			defaultSlackWebhookEnv,
		)
	}
	if inv.Notifications.Slack.Channel != defaultSlackChannel {
		t.Fatalf("Channel = %q, want %q", inv.Notifications.Slack.Channel, defaultSlackChannel)
	}
	if inv.Notifications.Slack.CriticalChannel != defaultCriticalChannel {
		t.Fatalf(
			"CriticalChannel = %q, want %q",
			inv.Notifications.Slack.CriticalChannel,
			defaultCriticalChannel,
		)
	}
	if inv.Notifications.Slack.DigestSchedule != defaultDigestSchedule {
		t.Fatalf(
			"DigestSchedule = %q, want %q",
			inv.Notifications.Slack.DigestSchedule,
			defaultDigestSchedule,
		)
	}
	if inv.Notifications.Slack.StalePRHours != defaultStalePRHours {
		t.Fatalf(
			"StalePRHours = %d, want %d",
			inv.Notifications.Slack.StalePRHours,
			defaultStalePRHours,
		)
	}
}

func TestLoadJIRATokenOverridePriority(t *testing.T) {
	t.Setenv("TEST_JIRA_TOKEN", "from-token-env")
	t.Setenv(envJIRAToken, "from-chainwatch-env")

	path := writeInventoryFile(t, validInventoryYAML)
	inv, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if inv.Orchestrator.JIRA.Token != "from-chainwatch-env" {
		t.Fatalf(
			"JIRA token override = %q, want from-chainwatch-env",
			inv.Orchestrator.JIRA.Token,
		)
	}
}

func TestLoadAppliesBedrockEnvOverrides(t *testing.T) {
	t.Setenv(envBedrockRegion, "us-west-2")
	t.Setenv(envBedrockNullbotModel, "model-nullbot")
	t.Setenv(envBedrockExecutionModel, "model-exec")

	path := writeInventoryFile(t, validInventoryYAML)
	inv, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	cfg := inv.BedrockConfig()
	if cfg.Region != "us-west-2" {
		t.Fatalf("Bedrock region = %q, want us-west-2", cfg.Region)
	}
	if cfg.Models.NullbotAnalysis != "model-nullbot" {
		t.Fatalf("Nullbot model = %q, want model-nullbot", cfg.Models.NullbotAnalysis)
	}
	if cfg.Models.ExecutionAgent != "model-exec" {
		t.Fatalf("Execution model = %q, want model-exec", cfg.Models.ExecutionAgent)
	}
}

func TestLoadRespectsNotificationSettings(t *testing.T) {
	path := writeInventoryFile(t, `
clickhouse:
  clusters:
    - name: dev-analytics
      hosts: [ch-dev-01]
      config_repo: infra/clickhouse-dev-analytics
notifications:
  slack:
    webhook_env: ALERT_HOOK
    channel: "#ops"
    critical_channel: "#critical"
    digest_schedule: "0 8 * * *"
    stale_pr_hours: 36
`)

	inv, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	cfg := inv.Notifications.Slack
	if cfg.WebhookEnv != "ALERT_HOOK" {
		t.Fatalf("WebhookEnv = %q, want ALERT_HOOK", cfg.WebhookEnv)
	}
	if cfg.Channel != "#ops" {
		t.Fatalf("Channel = %q, want #ops", cfg.Channel)
	}
	if cfg.CriticalChannel != "#critical" {
		t.Fatalf("CriticalChannel = %q, want #critical", cfg.CriticalChannel)
	}
	if cfg.DigestSchedule != "0 8 * * *" {
		t.Fatalf("DigestSchedule = %q, want 0 8 * * *", cfg.DigestSchedule)
	}
	if cfg.StalePRHours != 36 {
		t.Fatalf("StalePRHours = %d, want 36", cfg.StalePRHours)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := writeInventoryFile(t, `
clickhouse:
  clusters:
    - name: dev
      hosts: [ch-dev-01]
      config_repo: infra/clickhouse-dev
      unknown_field: value
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected Load to fail for unknown fields")
	}
	if !strings.Contains(err.Error(), "field unknown_field not found") {
		t.Fatalf("expected unknown-field parse error, got: %v", err)
	}
}

func TestValidateErrors(t *testing.T) {
	tests := []struct {
		name   string
		yaml   string
		errSub string
	}{
		{
			name: "missing clusters",
			yaml: `
clickhouse:
  clusters: []
`,
			errSub: "must contain at least one cluster",
		},
		{
			name: "duplicate cluster names",
			yaml: `
clickhouse:
  clusters:
    - name: dev
      hosts: [h1]
      config_repo: infra/a
    - name: dev
      hosts: [h2]
      config_repo: infra/b
`,
			errSub: "duplicate cluster name",
		},
		{
			name: "duplicate host names",
			yaml: `
clickhouse:
  clusters:
    - name: dev
      hosts: [h1, h1]
      config_repo: infra/a
`,
			errSub: "duplicate host",
		},
		{
			name: "missing config repo",
			yaml: `
clickhouse:
  clusters:
    - name: dev
      hosts: [h1]
`,
			errSub: "config_repo is required",
		},
		{
			name: "invalid jira base url",
			yaml: `
clickhouse:
  clusters:
    - name: dev
      hosts: [h1]
      config_repo: infra/a
orchestrator:
  jira:
    base_url: not-a-url
`,
			errSub: "base_url is invalid",
		},
		{
			name: "invalid port",
			yaml: `
clickhouse:
  clusters:
    - name: dev
      hosts: [h1]
      config_repo: infra/a
      clickhouse_port: 70000
`,
			errSub: "clickhouse_port must be between 1 and 65535",
		},
		{
			name: "invalid webhook env",
			yaml: `
clickhouse:
  clusters:
    - name: dev
      hosts: [h1]
      config_repo: infra/a
notifications:
  slack:
    webhook_env: https://hooks.slack.com/services/T000/B000/XXX
`,
			errSub: "must be a valid environment variable name",
		},
		{
			name: "invalid stale pr hours",
			yaml: `
clickhouse:
  clusters:
    - name: dev
      hosts: [h1]
      config_repo: infra/a
notifications:
  slack:
    stale_pr_hours: -1
`,
			errSub: "stale_pr_hours must be >= 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeInventoryFile(t, tt.yaml)
			_, err := Load(path)
			if err == nil {
				t.Fatalf("expected error containing %q", tt.errSub)
			}
			if !strings.Contains(err.Error(), tt.errSub) {
				t.Fatalf("error = %v, want substring %q", err, tt.errSub)
			}
		})
	}
}

func TestClusterSupports(t *testing.T) {
	cluster := Cluster{HostEntries: []string{"h1", "h2"}}
	if !cluster.Supports("h2") {
		t.Fatal("expected Supports to return true for existing host")
	}
	if cluster.Supports("h3") {
		t.Fatal("expected Supports to return false for missing host")
	}
}

func writeInventoryFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(content)+"\n"), 0600); err != nil {
		t.Fatalf("write inventory file: %v", err)
	}
	return path
}
