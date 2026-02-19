// nullbot-maildrop reads an email from stdin and creates a job in the nullbot
// inbox directory. Designed to be called by Postfix or sendmail as a pipe transport.
//
// Usage in /etc/aliases:
//
//	nullbot: |/usr/local/bin/nullbot-maildrop
//
// Environment variables:
//
//	NULLBOT_INBOX      inbox directory (default: /home/nullbot/inbox)
//	NULLBOT_ALLOWLIST  sender allowlist file (default: /home/nullbot/config/allowlist.txt)
//	NULLBOT_STATE      state directory for rate limiting (default: /home/nullbot/state)
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/ppiankov/chainwatch/internal/maildrop"
)

func main() {
	cfg := maildrop.Config{
		InboxDir:      envOrDefault("NULLBOT_INBOX", "/home/nullbot/inbox"),
		AllowlistFile: envOrDefault("NULLBOT_ALLOWLIST", "/home/nullbot/config/allowlist.txt"),
		RateLimitDir:  filepath.Join(envOrDefault("NULLBOT_STATE", "/home/nullbot/state"), "ratelimit"),
		RateLimit:     10,
		RateWindow:    1 * time.Hour,
	}

	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nullbot-maildrop: read stdin: %v\n", err)
		os.Exit(1)
	}

	if len(raw) == 0 {
		fmt.Fprintf(os.Stderr, "nullbot-maildrop: empty input\n")
		os.Exit(1)
	}

	if err := maildrop.ProcessEmail(cfg, raw); err != nil {
		fmt.Fprintf(os.Stderr, "nullbot-maildrop: %v\n", err)
		os.Exit(1)
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
