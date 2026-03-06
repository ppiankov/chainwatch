package alert

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultSMTPPort  = 587
	defaultEmailSubj = "chainwatch alert"
)

type emailSenderFunc func(ctx context.Context, cfg EmailConfig, msg []byte, recipients []string) error

// EmailAlerter delivers alerts through SMTP (STARTTLS).
type EmailAlerter struct {
	cfg    AlertConfig
	sender emailSenderFunc
}

// NewEmailAlerter returns an SMTP alerter for a single alert config.
func NewEmailAlerter(cfg AlertConfig) *EmailAlerter {
	return &EmailAlerter{
		cfg:    cfg,
		sender: sendSMTPMessage,
	}
}

// Name returns the transport name.
func (a *EmailAlerter) Name() string {
	return channelEmail
}

// Send posts an alert event as an email.
func (a *EmailAlerter) Send(ctx context.Context, event AlertEvent) error {
	if shouldRedactEmail(a.cfg.Email.SMTPHost) {
		event = redactEventForChannel(event, channelEmail)
	}

	cfg := a.cfg.Email
	if strings.TrimSpace(cfg.SMTPHost) == "" {
		return fmt.Errorf("email smtp_host is required")
	}
	if strings.TrimSpace(cfg.From) == "" {
		return fmt.Errorf("email from is required")
	}

	recipients := normalizeRecipients(cfg.To)
	if len(recipients) == 0 {
		return fmt.Errorf("email to is required")
	}

	message := formatEmailMessage(cfg, event, recipients)
	return a.sender(ctx, cfg, message, recipients)
}

func shouldRedactEmail(smtpHost string) bool {
	return shouldRedactEndpoint(smtpHost)
}

func formatEmailMessage(cfg EmailConfig, event AlertEvent, recipients []string) []byte {
	subject := strings.TrimSpace(cfg.Subject)
	if subject == "" {
		subject = fmt.Sprintf("%s: %s", defaultEmailSubj, event.Decision)
	}

	body := formatEmailBody(event)
	headers := []string{
		fmt.Sprintf("From: %s", strings.TrimSpace(cfg.From)),
		fmt.Sprintf("To: %s", strings.Join(recipients, ", ")),
		fmt.Sprintf("Subject: %s", subject),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}
	return []byte(strings.Join(headers, "\r\n"))
}

func formatEmailBody(event AlertEvent) string {
	return fmt.Sprintf(
		"chainwatch alert\nDecision: %s\nTool: %s\nResource: %s\nTier: %d\nReason: %s\nTraceID: %s\nPolicyHash: %s\nTimestamp: %s",
		event.Decision,
		event.Tool,
		event.Resource,
		event.Tier,
		event.Reason,
		event.TraceID,
		event.PolicyHash,
		event.Timestamp,
	)
}

func sendSMTPMessage(ctx context.Context, cfg EmailConfig, msg []byte, recipients []string) error {
	port := cfg.SMTPPort
	if port == 0 {
		port = defaultSMTPPort
	}

	host := strings.TrimSpace(cfg.SMTPHost)
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: requestTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("connect smtp %s: %w", addr, err)
	}

	deadline := time.Now().Add(requestTimeout)
	if dl, ok := ctx.Deadline(); ok {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return fmt.Errorf("set smtp deadline: %w", err)
	}

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer func() {
		_ = client.Close()
	}()

	ok, _ := client.Extension("STARTTLS")
	if !ok {
		return fmt.Errorf("smtp server %s does not support STARTTLS", host)
	}

	tlsCfg := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}
	if err := client.StartTLS(tlsCfg); err != nil {
		return fmt.Errorf("smtp starttls: %w", err)
	}

	if strings.TrimSpace(cfg.Username) != "" || strings.TrimSpace(cfg.Password) != "" {
		auth := smtp.PlainAuth("", cfg.Username, cfg.Password, host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}

	if err := client.Mail(strings.TrimSpace(cfg.From)); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	for _, rcpt := range recipients {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("smtp rcpt %s: %w", rcpt, err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		_ = w.Close()
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close data: %w", err)
	}

	if err := client.Quit(); err != nil {
		return fmt.Errorf("smtp quit: %w", err)
	}
	return nil
}

func normalizeRecipients(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}
