package inventory

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	defaultClickHousePort  = 9000
	defaultSSHUser         = "nullbot"
	defaultConfigPath      = "config/users.d/"
	defaultBedrockRegion   = "us-east-1"
	defaultJIRATokenEnv    = "JIRA_API_TOKEN"
	defaultSlackWebhookEnv = "SLACK_WEBHOOK_URL"
	defaultSlackChannel    = "#infra-ops"
	defaultCriticalChannel = "#infra-critical"
	defaultDigestSchedule  = "0 9 * * 1-5"
	defaultStalePRHours    = 24

	envJIRAToken             = "CHAINWATCH_JIRA_TOKEN"
	envBedrockRegion         = "CHAINWATCH_BEDROCK_REGION"
	envBedrockNullbotModel   = "CHAINWATCH_BEDROCK_NULLBOT_MODEL"
	envBedrockExecutionModel = "CHAINWATCH_BEDROCK_EXECUTION_MODEL"
	envOrchestratorDispatch  = "CHAINWATCH_ORCHESTRATOR_DISPATCH_BACKEND"
)

// Inventory is the centralized topology/configuration definition for nullbot.
type Inventory struct {
	ClickHouse    ClickHouseConfig    `yaml:"clickhouse"`
	Bedrock       BedrockConfig       `yaml:"bedrock"`
	Orchestrator  OrchestratorConfig  `yaml:"orchestrator"`
	Notifications NotificationsConfig `yaml:"notifications"`

	path string
	dir  string
}

// ClickHouseConfig holds inventory data for ClickHouse clusters.
type ClickHouseConfig struct {
	ClusterEntries []Cluster `yaml:"clusters"`
}

// Cluster represents one ClickHouse cluster in inventory.
type Cluster struct {
	Name           string   `yaml:"name"`
	HostEntries    []string `yaml:"hosts"`
	ConfigRepo     string   `yaml:"config_repo"`
	ConfigPath     string   `yaml:"config_path"`
	SSHUser        string   `yaml:"ssh_user"`
	ClickHousePort int      `yaml:"clickhouse_port"`

	baseDir string
}

// Host is a host entry derived from a cluster definition.
type Host struct {
	Name           string
	SSHUser        string
	ClickHousePort int
}

// BedrockConfig stores Bedrock model/runtime settings.
type BedrockConfig struct {
	Region      string        `yaml:"region"`
	VPCEndpoint bool          `yaml:"vpc_endpoint"`
	Models      BedrockModels `yaml:"models"`
	IAMRole     string        `yaml:"iam_role"`
}

// BedrockModels stores model IDs per agent role.
type BedrockModels struct {
	NullbotAnalysis string `yaml:"nullbot_analysis"`
	ExecutionAgent  string `yaml:"execution_agent"`
}

// OrchestratorConfig stores dispatch and ticketing settings.
type OrchestratorConfig struct {
	JIRA     JIRAConfig     `yaml:"jira"`
	Dispatch DispatchConfig `yaml:"dispatch"`
}

// JIRAConfig stores JIRA integration settings.
type JIRAConfig struct {
	Project     string            `yaml:"project"`
	BaseURL     string            `yaml:"base_url"`
	Token       string            `yaml:"token"`
	TokenEnv    string            `yaml:"token_env"`
	Assignee    string            `yaml:"assignee"`
	PriorityMap map[string]string `yaml:"priority_map"`
}

// DispatchConfig stores orchestrator dispatch backend settings.
type DispatchConfig struct {
	Backend string `yaml:"backend"`
}

// NotificationsConfig stores delivery channels for findings and lifecycle updates.
type NotificationsConfig struct {
	Slack SlackConfig `yaml:"slack"`
}

// SlackConfig stores Slack webhook/channel routing settings.
type SlackConfig struct {
	WebhookEnv      string `yaml:"webhook_env"`
	Channel         string `yaml:"channel"`
	CriticalChannel string `yaml:"critical_channel"`
	DigestSchedule  string `yaml:"digest_schedule"`
	StalePRHours    int    `yaml:"stale_pr_hours"`
}

// Load reads, applies defaults and environment overrides, and validates inventory.
func Load(path string) (*Inventory, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("inventory path is required")
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve inventory path %q: %w", path, err)
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("read inventory %q: %w", absPath, err)
	}

	inv, err := Parse(data, filepath.Dir(absPath))
	if err != nil {
		return nil, err
	}
	inv.path = absPath
	return inv, nil
}

// Parse parses inventory from YAML bytes with a known source directory.
func Parse(data []byte, sourceDir string) (*Inventory, error) {
	var inv Inventory
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&inv); err != nil {
		return nil, fmt.Errorf("parse inventory YAML: %w", err)
	}

	baseDir := sourceDir
	if strings.TrimSpace(baseDir) == "" {
		baseDir = "."
	}
	absBaseDir, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, fmt.Errorf("resolve inventory base directory %q: %w", baseDir, err)
	}

	inv.dir = absBaseDir
	inv.applyDefaults()
	inv.applyEnvOverrides()
	inv.attachClusterBaseDir()

	if err := inv.Validate(); err != nil {
		return nil, err
	}

	return &inv, nil
}

// Validate validates inventory invariants.
func (inv *Inventory) Validate() error {
	clusters := inv.ClickHouse.ClusterEntries
	if len(clusters) == 0 {
		return fmt.Errorf("inventory clickhouse.clusters must contain at least one cluster")
	}

	seenNames := make(map[string]struct{}, len(clusters))
	for i, cluster := range clusters {
		if strings.TrimSpace(cluster.Name) == "" {
			return fmt.Errorf("inventory clickhouse.clusters[%d].name is required", i)
		}
		if _, ok := seenNames[cluster.Name]; ok {
			return fmt.Errorf("duplicate cluster name %q", cluster.Name)
		}
		seenNames[cluster.Name] = struct{}{}

		if len(cluster.HostEntries) == 0 {
			return fmt.Errorf("cluster %q must have at least one host", cluster.Name)
		}

		seenHosts := make(map[string]struct{}, len(cluster.HostEntries))
		for hostIndex, host := range cluster.HostEntries {
			trimmed := strings.TrimSpace(host)
			if trimmed == "" {
				return fmt.Errorf("cluster %q hosts[%d] is empty", cluster.Name, hostIndex)
			}
			if _, ok := seenHosts[trimmed]; ok {
				return fmt.Errorf("cluster %q has duplicate host %q", cluster.Name, trimmed)
			}
			seenHosts[trimmed] = struct{}{}
		}

		if strings.TrimSpace(cluster.ConfigRepo) == "" {
			return fmt.Errorf("cluster %q config_repo is required", cluster.Name)
		}

		if cluster.ClickHousePort < 1 || cluster.ClickHousePort > 65535 {
			return fmt.Errorf(
				"cluster %q clickhouse_port must be between 1 and 65535, got %d",
				cluster.Name,
				cluster.ClickHousePort,
			)
		}
	}

	if strings.TrimSpace(inv.Bedrock.Region) == "" {
		return fmt.Errorf("bedrock.region is required")
	}

	if inv.Orchestrator.JIRA.BaseURL != "" {
		parsed, err := url.ParseRequestURI(inv.Orchestrator.JIRA.BaseURL)
		if err != nil {
			return fmt.Errorf("orchestrator.jira.base_url is invalid: %w", err)
		}
		if parsed.Scheme != "https" && parsed.Scheme != "http" {
			return fmt.Errorf(
				"orchestrator.jira.base_url must use http or https, got %q",
				parsed.Scheme,
			)
		}
	}

	if strings.TrimSpace(inv.Notifications.Slack.WebhookEnv) == "" {
		return fmt.Errorf("notifications.slack.webhook_env is required")
	}
	if !isValidEnvVarName(inv.Notifications.Slack.WebhookEnv) {
		return fmt.Errorf(
			"notifications.slack.webhook_env must be a valid environment variable name, got %q",
			inv.Notifications.Slack.WebhookEnv,
		)
	}
	if strings.TrimSpace(inv.Notifications.Slack.Channel) == "" {
		return fmt.Errorf("notifications.slack.channel is required")
	}
	if strings.TrimSpace(inv.Notifications.Slack.CriticalChannel) == "" {
		return fmt.Errorf("notifications.slack.critical_channel is required")
	}
	if inv.Notifications.Slack.StalePRHours < 1 {
		return fmt.Errorf(
			"notifications.slack.stale_pr_hours must be >= 1, got %d",
			inv.Notifications.Slack.StalePRHours,
		)
	}

	return nil
}

// Path returns the absolute path to the inventory file when loaded from disk.
func (inv *Inventory) Path() string {
	return inv.path
}

// Dir returns the absolute directory that inventory path resolution is relative to.
func (inv *Inventory) Dir() string {
	return inv.dir
}

// Clusters returns all ClickHouse clusters.
func (inv *Inventory) Clusters() []Cluster {
	clusters := make([]Cluster, len(inv.ClickHouse.ClusterEntries))
	copy(clusters, inv.ClickHouse.ClusterEntries)
	return clusters
}

// BedrockConfig returns Bedrock settings from inventory.
func (inv *Inventory) BedrockConfig() BedrockConfig {
	return inv.Bedrock
}

// Hosts returns host definitions for this cluster.
func (cluster Cluster) Hosts() []Host {
	hosts := make([]Host, 0, len(cluster.HostEntries))
	for _, host := range cluster.HostEntries {
		hosts = append(hosts, Host{
			Name:           host,
			SSHUser:        cluster.SSHUser,
			ClickHousePort: cluster.ClickHousePort,
		})
	}
	return hosts
}

// ConfigRepoPath returns an absolute config repo path for the cluster.
func (cluster Cluster) ConfigRepoPath() string {
	if filepath.IsAbs(cluster.ConfigRepo) {
		return filepath.Clean(cluster.ConfigRepo)
	}
	return filepath.Clean(filepath.Join(cluster.baseDir, cluster.ConfigRepo))
}

// ConfigPathResolved returns a resolved path to cluster config_path.
func (cluster Cluster) ConfigPathResolved() string {
	if filepath.IsAbs(cluster.ConfigPath) {
		return filepath.Clean(cluster.ConfigPath)
	}
	return filepath.Clean(filepath.Join(cluster.ConfigRepoPath(), cluster.ConfigPath))
}

func (inv *Inventory) applyDefaults() {
	if inv.Bedrock.Region == "" {
		inv.Bedrock.Region = defaultBedrockRegion
	}

	for i := range inv.ClickHouse.ClusterEntries {
		cluster := &inv.ClickHouse.ClusterEntries[i]
		if cluster.ClickHousePort == 0 {
			cluster.ClickHousePort = defaultClickHousePort
		}
		if cluster.SSHUser == "" {
			cluster.SSHUser = defaultSSHUser
		}
		if cluster.ConfigPath == "" {
			cluster.ConfigPath = defaultConfigPath
		}
	}

	if inv.Orchestrator.JIRA.TokenEnv == "" {
		inv.Orchestrator.JIRA.TokenEnv = defaultJIRATokenEnv
	}

	if inv.Notifications.Slack.WebhookEnv == "" {
		inv.Notifications.Slack.WebhookEnv = defaultSlackWebhookEnv
	}
	if inv.Notifications.Slack.Channel == "" {
		inv.Notifications.Slack.Channel = defaultSlackChannel
	}
	if inv.Notifications.Slack.CriticalChannel == "" {
		inv.Notifications.Slack.CriticalChannel = defaultCriticalChannel
	}
	if inv.Notifications.Slack.DigestSchedule == "" {
		inv.Notifications.Slack.DigestSchedule = defaultDigestSchedule
	}
	if inv.Notifications.Slack.StalePRHours == 0 {
		inv.Notifications.Slack.StalePRHours = defaultStalePRHours
	}
}

func (inv *Inventory) applyEnvOverrides() {
	if value := strings.TrimSpace(os.Getenv(envBedrockRegion)); value != "" {
		inv.Bedrock.Region = value
	}
	if value := strings.TrimSpace(os.Getenv(envBedrockNullbotModel)); value != "" {
		inv.Bedrock.Models.NullbotAnalysis = value
	}
	if value := strings.TrimSpace(os.Getenv(envBedrockExecutionModel)); value != "" {
		inv.Bedrock.Models.ExecutionAgent = value
	}
	if value := strings.TrimSpace(os.Getenv(envOrchestratorDispatch)); value != "" {
		inv.Orchestrator.Dispatch.Backend = value
	}

	inv.Orchestrator.JIRA.Token = resolveJIRAToken(inv.Orchestrator.JIRA)
}

func (inv *Inventory) attachClusterBaseDir() {
	for i := range inv.ClickHouse.ClusterEntries {
		inv.ClickHouse.ClusterEntries[i].baseDir = inv.dir
	}
}

func resolveJIRAToken(cfg JIRAConfig) string {
	candidates := []string{
		os.Getenv(envJIRAToken),
	}
	if cfg.TokenEnv != "" {
		candidates = append(candidates, os.Getenv(cfg.TokenEnv))
	}
	if cfg.TokenEnv != defaultJIRATokenEnv {
		candidates = append(candidates, os.Getenv(defaultJIRATokenEnv))
	}
	candidates = append(candidates, cfg.Token)

	for _, candidate := range candidates {
		token := strings.TrimSpace(candidate)
		if token != "" {
			return token
		}
	}
	return ""
}

func isValidEnvVarName(name string) bool {
	if name == "" {
		return false
	}

	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			continue
		}
		if i > 0 && c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}

// Supports reports whether the cluster includes the host.
func (cluster Cluster) Supports(host string) bool {
	return slices.Contains(cluster.HostEntries, host)
}
