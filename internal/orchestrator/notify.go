package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	eventCreated  = "created"
	eventPROpened = "pr_opened"
	eventStale    = "stale"
	eventFailed   = "failed"
	eventVerified = "verified"
)

// Input is the payload consumed by `orchestrator notify`.
type Input struct {
	Findings        []FindingEvent   `json:"findings"`
	Lifecycle       []LifecycleEvent `json:"lifecycle"`
	LifecycleEvents []LifecycleEvent `json:"lifecycle_events"`
}

// AllLifecycleEvents returns lifecycle entries from both supported JSON keys.
func (in Input) AllLifecycleEvents() []LifecycleEvent {
	total := len(in.Lifecycle) + len(in.LifecycleEvents)
	events := make([]LifecycleEvent, 0, total)
	events = append(events, in.Lifecycle...)
	events = append(events, in.LifecycleEvents...)
	return events
}

// FindingEvent describes an observation notification candidate.
type FindingEvent struct {
	Cluster  string `json:"cluster"`
	Summary  string `json:"summary"`
	Finding  string `json:"finding,omitempty"`
	WOID     string `json:"wo_id"`
	JIRALink string `json:"jira_link"`
	Severity string `json:"severity"`
}

// LifecycleEvent describes a WO lifecycle transition.
type LifecycleEvent struct {
	Event          string    `json:"event"`
	Cluster        string    `json:"cluster"`
	Summary        string    `json:"summary"`
	WOID           string    `json:"wo_id"`
	JIRALink       string    `json:"jira_link"`
	PRLink         string    `json:"pr_link,omitempty"`
	Severity       string    `json:"severity"`
	FailureDetails string    `json:"failure_details,omitempty"`
	EventTime      time.Time `json:"event_time,omitempty"`
	FindingTime    time.Time `json:"finding_time,omitempty"`
	LastReviewTime time.Time `json:"last_review_time,omitempty"`
}

// Config controls message routing behavior.
type Config struct {
	Channel         string
	CriticalChannel string
	DigestSchedule  string
	StalePRHours    int
}

// Message is a rendered Slack notification.
type Message struct {
	Channel string `json:"channel"`
	Text    string `json:"text"`
}

// Result captures notify execution results.
type Result struct {
	Messages []Message
	Sent     int
}

// Sender delivers one message to Slack.
type Sender interface {
	Send(context.Context, Message) error
}

// Service plans and sends notifications.
type Service struct {
	sender Sender
	nowFn  func() time.Time
}

// NewService constructs a notification service.
func NewService(sender Sender, nowFn func() time.Time) *Service {
	if nowFn == nil {
		nowFn = time.Now
	}
	return &Service{
		sender: sender,
		nowFn:  nowFn,
	}
}

// ParseInput decodes input JSON. Empty input returns an empty payload.
func ParseInput(r io.Reader) (Input, error) {
	var in Input
	if r == nil {
		return in, nil
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return in, fmt.Errorf("read input: %w", err)
	}
	if strings.TrimSpace(string(data)) == "" {
		return in, nil
	}

	if err := json.Unmarshal(data, &in); err != nil {
		return in, fmt.Errorf("parse input JSON: %w", err)
	}
	return in, nil
}

// Notify plans messages and sends them unless dryRun is enabled.
func (s *Service) Notify(ctx context.Context, in Input, cfg Config, dryRun bool) (Result, error) {
	if s == nil {
		return Result{}, fmt.Errorf("service is nil")
	}

	messages := BuildMessages(in, cfg, s.nowFn())
	result := Result{Messages: messages}
	if dryRun {
		return result, nil
	}

	if s.sender == nil {
		return Result{}, fmt.Errorf("sender is required when dry-run is disabled")
	}

	for _, msg := range messages {
		if err := s.sender.Send(ctx, msg); err != nil {
			return Result{}, fmt.Errorf("send message: %w", err)
		}
		result.Sent++
	}
	return result, nil
}

// BuildMessages converts findings/lifecycle events to routed Slack messages.
func BuildMessages(in Input, cfg Config, now time.Time) []Message {
	digestFindings := make([]FindingEvent, 0)
	messages := make([]Message, 0)

	for _, finding := range in.Findings {
		severity := normalizeSeverity(finding.Severity)
		if severity == "critical" || severity == "high" {
			messages = append(messages, Message{
				Channel: routeChannel(severity, cfg),
				Text:    formatImmediateFinding(finding, severity),
			})
			continue
		}
		digestFindings = append(digestFindings, finding)
	}

	if len(digestFindings) > 0 {
		messages = append(messages, Message{
			Channel: cfg.Channel,
			Text:    formatDigest(digestFindings, cfg.DigestSchedule, now),
		})
	}

	lifecycle := in.AllLifecycleEvents()
	explicitStale := make(map[string]struct{}, len(lifecycle))
	for _, event := range lifecycle {
		if normalizeEvent(event.Event) == eventStale && strings.TrimSpace(event.WOID) != "" {
			explicitStale[event.WOID] = struct{}{}
		}
	}

	for _, event := range lifecycle {
		evtType := normalizeEvent(event.Event)
		if evtType == "" {
			continue
		}

		severity := normalizeSeverity(event.Severity)
		if severity == "" {
			severity = "medium"
		}
		messages = append(messages, Message{
			Channel: routeChannel(severity, cfg),
			Text:    formatLifecycleEvent(event, evtType, severity, now),
		})

		if evtType != eventPROpened {
			continue
		}
		if !isStalePROpen(event, cfg.StalePRHours, now) {
			continue
		}
		if _, found := explicitStale[event.WOID]; found {
			continue
		}

		staleEvent := event
		staleEvent.Event = eventStale
		messages = append(messages, Message{
			Channel: routeChannel(severity, cfg),
			Text:    formatLifecycleEvent(staleEvent, eventStale, severity, now),
		})
	}

	return messages
}

func formatImmediateFinding(finding FindingEvent, severity string) string {
	cluster := valueOrUnknown(finding.Cluster)
	summary := valueOrUnknown(finding.Summary)
	findingLine := strings.TrimSpace(finding.Finding)
	if findingLine == "" {
		findingLine = summary
	}

	return strings.TrimSpace(fmt.Sprintf(
		"[%s] [%s] %s\nFinding: %s\nWO: %s\nJIRA: %s\nSeverity: %s",
		strings.ToUpper(severity),
		cluster,
		summary,
		findingLine,
		valueOrUnknown(finding.WOID),
		valueOrUnknown(finding.JIRALink),
		severity,
	))
}

func formatDigest(findings []FindingEvent, schedule string, now time.Time) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf(
		"Daily findings digest (%d item(s), schedule=%s, generated=%s)\n",
		len(findings),
		valueOrUnknown(strings.TrimSpace(schedule)),
		now.UTC().Format(time.RFC3339),
	))
	for _, finding := range findings {
		severity := normalizeSeverity(finding.Severity)
		if severity == "" {
			severity = "medium"
		}
		b.WriteString(fmt.Sprintf(
			"- [%s] %s | WO: %s | JIRA: %s | Severity: %s\n",
			valueOrUnknown(finding.Cluster),
			valueOrUnknown(finding.Summary),
			valueOrUnknown(finding.WOID),
			valueOrUnknown(finding.JIRALink),
			severity,
		))
	}
	return strings.TrimSpace(b.String())
}

func formatLifecycleEvent(event LifecycleEvent, eventType, severity string, now time.Time) string {
	cluster := valueOrUnknown(event.Cluster)
	summary := valueOrUnknown(event.Summary)
	woID := valueOrUnknown(event.WOID)
	jira := valueOrUnknown(event.JIRALink)
	pr := strings.TrimSpace(event.PRLink)
	timestamp := event.EventTime
	if timestamp.IsZero() {
		timestamp = now
	}
	timeLine := timestamp.UTC().Format(time.RFC3339)

	switch eventType {
	case eventCreated:
		return fmt.Sprintf(
			"WO lifecycle event: created\nSummary: %s\nWO: %s\nJIRA: %s\nSeverity: %s\nCluster: %s\nAt: %s",
			summary, woID, jira, severity, cluster, timeLine,
		)
	case eventPROpened:
		return fmt.Sprintf(
			"WO lifecycle event: pr_opened\nSummary: %s\nWO: %s\nJIRA: %s\nSeverity: %s\nCluster: %s\nPR: %s\nAt: %s",
			summary, woID, jira, severity, cluster, valueOrUnknown(pr), timeLine,
		)
	case eventStale:
		hours := "unknown"
		if !event.EventTime.IsZero() {
			duration := now.Sub(event.EventTime)
			if duration < 0 {
				duration = 0
			}
			hours = fmt.Sprintf("%dh", int(duration.Round(time.Hour)/time.Hour))
		}
		return fmt.Sprintf(
			"WO lifecycle event: stale\nSummary: %s\nWO: %s\nJIRA: %s\nSeverity: %s\nCluster: %s\nPR: %s\nAge: %s",
			summary, woID, jira, severity, cluster, valueOrUnknown(pr), hours,
		)
	case eventFailed:
		return fmt.Sprintf(
			"WO lifecycle event: failed\nSummary: %s\nWO: %s\nJIRA: %s\nSeverity: %s\nCluster: %s\nDetails: %s",
			summary, woID, jira, severity, cluster, valueOrUnknown(event.FailureDetails),
		)
	case eventVerified:
		return fmt.Sprintf(
			"WO lifecycle event: verified\nSummary: %s\nWO: %s\nJIRA: %s\nSeverity: %s\nCluster: %s\nTime to resolve: %s",
			summary, woID, jira, severity, cluster, formatResolveDuration(event),
		)
	default:
		return fmt.Sprintf(
			"WO lifecycle event: %s\nSummary: %s\nWO: %s\nJIRA: %s\nSeverity: %s\nCluster: %s",
			eventType, summary, woID, jira, severity, cluster,
		)
	}
}

func formatResolveDuration(event LifecycleEvent) string {
	if event.FindingTime.IsZero() || event.EventTime.IsZero() {
		return "unknown"
	}
	duration := event.EventTime.Sub(event.FindingTime)
	if duration < 0 {
		duration = 0
	}
	hours := int(duration / time.Hour)
	minutes := int((duration % time.Hour) / time.Minute)
	return fmt.Sprintf("%dh %dm", hours, minutes)
}

func isStalePROpen(event LifecycleEvent, staleHours int, now time.Time) bool {
	if normalizeEvent(event.Event) != eventPROpened {
		return false
	}
	if !event.LastReviewTime.IsZero() {
		return false
	}
	if event.EventTime.IsZero() {
		return false
	}
	if staleHours < 1 {
		staleHours = 24
	}

	return !event.EventTime.After(now.Add(-time.Duration(staleHours) * time.Hour))
}

func routeChannel(severity string, cfg Config) string {
	if severity == "critical" {
		return cfg.CriticalChannel
	}
	return cfg.Channel
}

func normalizeEvent(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case eventCreated:
		return eventCreated
	case eventPROpened:
		return eventPROpened
	case eventStale:
		return eventStale
	case eventFailed:
		return eventFailed
	case eventVerified:
		return eventVerified
	default:
		return ""
	}
}

func normalizeSeverity(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return ""
	}
}

func valueOrUnknown(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "unknown"
	}
	return v
}

// SlackWebhookSender sends text payloads to a Slack webhook endpoint.
type SlackWebhookSender struct {
	webhookURL string
	client     *http.Client
}

// NewSlackWebhookSender constructs a Slack webhook sender.
func NewSlackWebhookSender(webhookURL string, client *http.Client) *SlackWebhookSender {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}

	return &SlackWebhookSender{
		webhookURL: webhookURL,
		client:     client,
	}
}

// Send posts a single message to Slack.
func (s *SlackWebhookSender) Send(ctx context.Context, msg Message) error {
	if s == nil {
		return fmt.Errorf("slack sender is nil")
	}
	if strings.TrimSpace(s.webhookURL) == "" {
		return fmt.Errorf("slack webhook URL is required")
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		s.webhookURL,
		bytes.NewReader(payload),
	)
	if err != nil {
		return fmt.Errorf("create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("post webhook: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("slack webhook rejected request: HTTP %d", resp.StatusCode)
}
