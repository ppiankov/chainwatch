package redact

import (
	"encoding/json"
	"testing"
)

func TestTokenIdempotent(t *testing.T) {
	tm := NewTokenMap("test-job")

	tok1 := tm.Token(PatternPath, "/var/www/site")
	tok2 := tm.Token(PatternPath, "/var/www/site")

	if tok1 != tok2 {
		t.Errorf("idempotency failed: %s != %s", tok1, tok2)
	}
	if tok1 != "<<PATH_1>>" {
		t.Errorf("unexpected token format: %s", tok1)
	}
}

func TestTokenIncrementsPerType(t *testing.T) {
	tm := NewTokenMap("test-job")

	p1 := tm.Token(PatternPath, "/var/www/a")
	p2 := tm.Token(PatternPath, "/var/www/b")
	ip1 := tm.Token(PatternIP, "10.0.0.1")

	if p1 != "<<PATH_1>>" {
		t.Errorf("expected <<PATH_1>>, got %s", p1)
	}
	if p2 != "<<PATH_2>>" {
		t.Errorf("expected <<PATH_2>>, got %s", p2)
	}
	if ip1 != "<<IP_1>>" {
		t.Errorf("expected <<IP_1>>, got %s", ip1)
	}
}

func TestTokenResolve(t *testing.T) {
	tm := NewTokenMap("test-job")
	tm.Token(PatternPath, "/var/www/site")

	val, ok := tm.Resolve("<<PATH_1>>")
	if !ok || val != "/var/www/site" {
		t.Errorf("resolve failed: ok=%v, val=%s", ok, val)
	}

	_, ok = tm.Resolve("<<PATH_99>>")
	if ok {
		t.Error("resolve should fail for nonexistent token")
	}
}

func TestTokenMapLen(t *testing.T) {
	tm := NewTokenMap("test-job")
	if tm.Len() != 0 {
		t.Error("new map should have len 0")
	}

	tm.Token(PatternPath, "/var/www")
	tm.Token(PatternIP, "10.0.0.1")
	tm.Token(PatternPath, "/var/www") // duplicate, no increment

	if tm.Len() != 2 {
		t.Errorf("expected len 2, got %d", tm.Len())
	}
}

func TestTokenMapValues(t *testing.T) {
	tm := NewTokenMap("test-job")
	tm.Token(PatternPath, "/var/www")
	tm.Token(PatternPath, "/var/www/site/config.php")
	tm.Token(PatternIP, "10.0.0.1")

	vals := tm.Values()
	if len(vals) != 3 {
		t.Fatalf("expected 3 values, got %d", len(vals))
	}
	// Values should be sorted longest first for greedy replacement.
	if len(vals[0]) < len(vals[1]) {
		t.Errorf("values not sorted longest first: %v", vals)
	}
}

func TestTokenMapLegend(t *testing.T) {
	tm := NewTokenMap("test-job")
	tm.Token(PatternPath, "/var/www")
	tm.Token(PatternIP, "10.0.0.1")

	legend := tm.Legend()
	if legend == "" {
		t.Error("legend should not be empty")
	}
	if !containsStr(legend, "<<PATH_1>>") {
		t.Error("legend should contain <<PATH_1>>")
	}
	if !containsStr(legend, "<<IP_1>>") {
		t.Error("legend should contain <<IP_1>>")
	}
	// Legend should NOT contain the actual values.
	if containsStr(legend, "/var/www") {
		t.Error("legend must not contain actual sensitive values")
	}
}

func TestTokenMapLegendEmpty(t *testing.T) {
	tm := NewTokenMap("test-job")
	if tm.Legend() != "" {
		t.Error("empty map should return empty legend")
	}
}

func TestTokenMapJSON(t *testing.T) {
	tm := NewTokenMap("job-123")
	tm.Token(PatternPath, "/var/www/site")
	tm.Token(PatternIP, "192.168.1.1")
	tm.Token(PatternHost, "evil.com")

	data, err := json.Marshal(tm)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	tm2 := &TokenMap{}
	if err := json.Unmarshal(data, tm2); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if tm2.JobID != "job-123" {
		t.Errorf("job ID mismatch: %s", tm2.JobID)
	}
	if tm2.Len() != 3 {
		t.Errorf("expected 3 mappings, got %d", tm2.Len())
	}

	// Verify round-trip: resolve works on deserialized map.
	val, ok := tm2.Resolve("<<PATH_1>>")
	if !ok || val != "/var/www/site" {
		t.Errorf("round-trip resolve failed: ok=%v, val=%s", ok, val)
	}

	// Verify counters are reconstructed: new token should be <<PATH_2>>, not <<PATH_1>>.
	newTok := tm2.Token(PatternPath, "/etc/nginx")
	if newTok != "<<PATH_2>>" {
		t.Errorf("counter not reconstructed: expected <<PATH_2>>, got %s", newTok)
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsSubstr(s, sub))
}

func containsSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
