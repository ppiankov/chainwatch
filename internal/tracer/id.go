package tracer

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// NewTraceID generates a trace ID with the given prefix (default "t").
func NewTraceID() string {
	return prefixedID("t", 12)
}

// NewSpanID generates a span ID with the given prefix (default "s").
func NewSpanID() string {
	return prefixedID("s", 8)
}

// UTCNowISO returns the current UTC time in ISO format with Z suffix.
func UTCNowISO() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}

func prefixedID(prefix string, hexLen int) string {
	b := make([]byte, (hexLen+1)/2)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID if crypto/rand fails
		return fmt.Sprintf("%s-%x", prefix, time.Now().UnixNano())
	}
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b)[:hexLen])
}
