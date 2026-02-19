// Package maildrop handles email-to-job conversion for the nullbot inbox.
// Emails piped through Postfix/sendmail are parsed, validated, and converted
// to job JSON files that the nullbot daemon processes.
package maildrop

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"net/mail"
	"strings"
)

// Email holds extracted fields from a raw email.
type Email struct {
	From    string
	Subject string
	Body    string
}

// ParseEmail extracts sender, subject, and plain-text body from a raw email.
// Rejects multipart messages and HTML content — only plain text is processed.
func ParseEmail(raw []byte) (*Email, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parse email: %w", err)
	}

	from := msg.Header.Get("From")
	if from == "" {
		return nil, fmt.Errorf("email missing From header")
	}
	// Extract just the email address from "Name <addr>" format.
	addr, err := mail.ParseAddress(from)
	if err != nil {
		return nil, fmt.Errorf("invalid From address: %w", err)
	}

	// Check Content-Type: reject HTML and multipart.
	contentType := msg.Header.Get("Content-Type")
	if contentType != "" {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err == nil {
			if strings.HasPrefix(mediaType, "multipart/") {
				return nil, fmt.Errorf("multipart emails are not supported")
			}
			if mediaType == "text/html" {
				return nil, fmt.Errorf("HTML emails are not supported")
			}
		}
	}

	body, err := io.ReadAll(msg.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	// Strip email signature (lines after "-- \n").
	bodyStr := stripSignature(string(body))

	return &Email{
		From:    addr.Address,
		Subject: msg.Header.Get("Subject"),
		Body:    strings.TrimSpace(bodyStr),
	}, nil
}

// stripSignature removes the email signature block.
// The standard delimiter is "-- \n" (dash, dash, space, newline).
func stripSignature(body string) string {
	idx := strings.Index(body, "\n-- \n")
	if idx >= 0 {
		return body[:idx]
	}
	return body
}
