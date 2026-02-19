package redact

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// TokenMap provides bidirectional mapping between sensitive values and tokens.
// It is safe for sequential use within a single job. Not goroutine-safe.
type TokenMap struct {
	forward   map[string]string   // sensitive value → "<<TYPE_N>>"
	reverse   map[string]string   // "<<TYPE_N>>" → sensitive value
	counters  map[PatternType]int // next number per pattern type
	JobID     string              `json:"job_id"`
	CreatedAt time.Time           `json:"created_at"`
}

// NewTokenMap creates an empty token map for a job.
func NewTokenMap(jobID string) *TokenMap {
	return &TokenMap{
		forward:   make(map[string]string),
		reverse:   make(map[string]string),
		counters:  make(map[PatternType]int),
		JobID:     jobID,
		CreatedAt: time.Now().UTC(),
	}
}

// Token returns the token for a sensitive value. Idempotent: the same value
// always returns the same token within a map.
func (tm *TokenMap) Token(typ PatternType, value string) string {
	if tok, ok := tm.forward[value]; ok {
		return tok
	}
	tm.counters[typ]++
	tok := fmt.Sprintf("<<%s_%d>>", typ, tm.counters[typ])
	tm.forward[value] = tok
	tm.reverse[tok] = value
	return tok
}

// Resolve returns the original value for a token.
func (tm *TokenMap) Resolve(token string) (string, bool) {
	v, ok := tm.reverse[token]
	return v, ok
}

// Len returns the number of token mappings.
func (tm *TokenMap) Len() int {
	return len(tm.forward)
}

// Values returns all sensitive values in the map.
func (tm *TokenMap) Values() []string {
	vals := make([]string, 0, len(tm.forward))
	for v := range tm.forward {
		vals = append(vals, v)
	}
	// Sort longest first for greedy replacement.
	sort.Slice(vals, func(i, j int) bool {
		return len(vals[i]) > len(vals[j])
	})
	return vals
}

// Tokens returns all token strings (e.g., "<<PATH_1>>").
func (tm *TokenMap) Tokens() []string {
	toks := make([]string, 0, len(tm.reverse))
	for t := range tm.reverse {
		toks = append(toks, t)
	}
	sort.Strings(toks)
	return toks
}

// Legend returns a human-readable legend suitable for prepending to LLM prompts.
// Tokens are listed by type, sorted alphabetically.
func (tm *TokenMap) Legend() string {
	if len(tm.forward) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("IMPORTANT: All sensitive data below is replaced with tokens like <<PATH_1>>, <<IP_1>>, etc.\n")
	b.WriteString("You MUST use these exact tokens in your commands. Do NOT invent real paths or IPs.\n\n")
	b.WriteString("Token legend:\n")

	toks := tm.Tokens()
	for _, tok := range toks {
		b.WriteString(fmt.Sprintf("  %s = [redacted]\n", tok))
	}

	return b.String()
}

// tokenMapJSON is the serialization format for TokenMap.
type tokenMapJSON struct {
	JobID     string            `json:"job_id"`
	CreatedAt time.Time         `json:"created_at"`
	Mappings  map[string]string `json:"mappings"` // token → value
}

// MarshalJSON serializes the token map.
func (tm *TokenMap) MarshalJSON() ([]byte, error) {
	return json.Marshal(tokenMapJSON{
		JobID:     tm.JobID,
		CreatedAt: tm.CreatedAt,
		Mappings:  tm.reverse,
	})
}

// UnmarshalJSON deserializes a token map.
func (tm *TokenMap) UnmarshalJSON(data []byte) error {
	var raw tokenMapJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	tm.JobID = raw.JobID
	tm.CreatedAt = raw.CreatedAt
	tm.forward = make(map[string]string, len(raw.Mappings))
	tm.reverse = make(map[string]string, len(raw.Mappings))
	tm.counters = make(map[PatternType]int)

	for tok, val := range raw.Mappings {
		tm.forward[val] = tok
		tm.reverse[tok] = val
		// Reconstruct counters from existing tokens like "<<PATH_1>>".
		if typ, num, ok := parseToken(tok); ok {
			if num > tm.counters[typ] {
				tm.counters[typ] = num
			}
		}
	}

	return nil
}

// parseToken extracts the type and number from a token string like "<<PATH_1>>".
func parseToken(tok string) (PatternType, int, bool) {
	s := strings.TrimPrefix(tok, "<<")
	s = strings.TrimSuffix(s, ">>")
	idx := strings.LastIndex(s, "_")
	if idx < 0 {
		return "", 0, false
	}
	typ := s[:idx]
	var num int
	if _, err := fmt.Sscanf(s[idx+1:], "%d", &num); err != nil {
		return "", 0, false
	}
	return PatternType(typ), num, true
}
