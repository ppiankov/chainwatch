package maildrop

import (
	"strings"
	"testing"
)

func TestParseEmailValid(t *testing.T) {
	raw := "From: admin@example.com\r\nSubject: Check server\r\nContent-Type: text/plain\r\n\r\nPlease investigate the web server."

	email, err := ParseEmail([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if email.From != "admin@example.com" {
		t.Errorf("From = %q", email.From)
	}
	if email.Subject != "Check server" {
		t.Errorf("Subject = %q", email.Subject)
	}
	if email.Body != "Please investigate the web server." {
		t.Errorf("Body = %q", email.Body)
	}
}

func TestParseEmailNamedFrom(t *testing.T) {
	raw := "From: Admin User <admin@example.com>\r\nSubject: test\r\n\r\nbody"

	email, err := ParseEmail([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if email.From != "admin@example.com" {
		t.Errorf("From = %q, want just the address", email.From)
	}
}

func TestParseEmailMissingFrom(t *testing.T) {
	raw := "Subject: No from\r\n\r\nbody"

	_, err := ParseEmail([]byte(raw))
	if err == nil {
		t.Error("expected error for missing From")
	}
}

func TestParseEmailHTMLRejected(t *testing.T) {
	raw := "From: admin@example.com\r\nSubject: test\r\nContent-Type: text/html\r\n\r\n<b>html</b>"

	_, err := ParseEmail([]byte(raw))
	if err == nil {
		t.Error("expected error for HTML email")
	}
}

func TestParseEmailMultipartRejected(t *testing.T) {
	raw := "From: admin@example.com\r\nSubject: test\r\nContent-Type: multipart/mixed; boundary=xyz\r\n\r\n--xyz\r\nContent-Type: text/plain\r\n\r\nhello\r\n--xyz--"

	_, err := ParseEmail([]byte(raw))
	if err == nil {
		t.Error("expected error for multipart email")
	}
}

func TestParseEmailSignatureStripped(t *testing.T) {
	raw := "From: admin@example.com\r\nSubject: test\r\n\r\nMain body here\n-- \nBest regards\nAdmin"

	email, err := ParseEmail([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(email.Body, "Best regards") {
		t.Error("signature should be stripped")
	}
	if email.Body != "Main body here" {
		t.Errorf("Body = %q", email.Body)
	}
}

func TestParseEmailNoContentType(t *testing.T) {
	raw := "From: admin@example.com\r\nSubject: test\r\n\r\nplain body"

	email, err := ParseEmail([]byte(raw))
	if err != nil {
		t.Fatalf("should accept email without Content-Type: %v", err)
	}
	if email.Body != "plain body" {
		t.Errorf("Body = %q", email.Body)
	}
}
