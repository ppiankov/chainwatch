package alert

import "strings"

const (
	channelWebhook  = "webhook"
	channelTelegram = "telegram"
	channelEmail    = "email"
)

// AlertConfig defines an alert destination channel.
type AlertConfig struct {
	Channel string `yaml:"channel" json:"channel"` // webhook (default), telegram, email

	URL     string            `yaml:"url"     json:"url"`
	Format  string            `yaml:"format"  json:"format"` // "generic", "slack", "pagerduty"
	Events  []string          `yaml:"events"  json:"events"` // ["deny", "require_approval", "break_glass_used"]
	Headers map[string]string `yaml:"headers" json:"headers"`

	Telegram TelegramConfig `yaml:"telegram" json:"telegram"`
	Email    EmailConfig    `yaml:"email"    json:"email"`
}

// TelegramConfig configures Telegram Bot API delivery.
type TelegramConfig struct {
	BotToken  string `yaml:"bot_token"    json:"bot_token"`
	ChatID    string `yaml:"chat_id"      json:"chat_id"`
	APIURL    string `yaml:"api_url"      json:"api_url"` // default: https://api.telegram.org
	ParseMode string `yaml:"parse_mode"   json:"parse_mode"`
}

// EmailConfig configures SMTP alert delivery.
type EmailConfig struct {
	SMTPHost string   `yaml:"smtp_host"      json:"smtp_host"`
	SMTPPort int      `yaml:"smtp_port"      json:"smtp_port"` // default: 587
	Username string   `yaml:"username"       json:"username"`
	Password string   `yaml:"password"       json:"password"`
	From     string   `yaml:"from"           json:"from"`
	To       []string `yaml:"to"             json:"to"`
	Subject  string   `yaml:"subject"        json:"subject"` // optional fixed subject
}

// ChannelName returns the normalized channel name, defaulting to webhook.
func (c AlertConfig) ChannelName() string {
	channel := strings.ToLower(strings.TrimSpace(c.Channel))
	if channel == "" {
		return channelWebhook
	}
	return channel
}

// AlertEvent is the payload sent to alert channels.
type AlertEvent struct {
	Timestamp  string `json:"timestamp"`
	TraceID    string `json:"trace_id"`
	Tool       string `json:"tool"`
	Resource   string `json:"resource"`
	Decision   string `json:"decision"`
	Reason     string `json:"reason"`
	Tier       int    `json:"tier"`
	PolicyHash string `json:"policy_hash"`
	Type       string `json:"type,omitempty"` // "break_glass_used" etc.
}
