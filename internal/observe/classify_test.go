package observe

import (
	"testing"

	"github.com/ppiankov/chainwatch/internal/wo"
)

func TestParseClassificationWrapped(t *testing.T) {
	raw := `{"observations":[
		{"type":"suspicious_code","detail":"eval(base64_decode found","severity":"high"},
		{"type":"unauthorized_user","detail":"rogue UID 0 user wpadmin2","severity":"critical"}
	]}`

	obs, err := parseClassification(raw)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(obs) != 2 {
		t.Fatalf("expected 2 observations, got %d", len(obs))
	}
	if obs[0].Type != wo.SuspiciousCode {
		t.Errorf("obs[0] type: got %s, want suspicious_code", obs[0].Type)
	}
	if obs[1].Severity != wo.SeverityCritical {
		t.Errorf("obs[1] severity: got %s, want critical", obs[1].Severity)
	}
}

func TestParseClassificationRawArray(t *testing.T) {
	raw := `[
		{"type":"cron_anomaly","detail":"wget beacon in crontab","severity":"high"},
		{"type":"process_anomaly","detail":"nc listening on port 4444","severity":"critical"}
	]`

	obs, err := parseClassification(raw)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(obs) != 2 {
		t.Fatalf("expected 2 observations, got %d", len(obs))
	}
	if obs[0].Type != wo.CronAnomaly {
		t.Errorf("obs[0] type: got %s, want cron_anomaly", obs[0].Type)
	}
}

func TestParseClassificationMarkdownFenced(t *testing.T) {
	raw := "```json\n{\"observations\":[{\"type\":\"unknown_file\",\"detail\":\"shell.php in uploads\",\"severity\":\"high\"}]}\n```"

	obs, err := parseClassification(raw)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if obs[0].Type != wo.UnknownFile {
		t.Errorf("type: got %s, want unknown_file", obs[0].Type)
	}
}

func TestParseClassificationEmpty(t *testing.T) {
	raw := `{"observations":[]}`
	obs, err := parseClassification(raw)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(obs) != 0 {
		t.Errorf("expected 0 observations, got %d", len(obs))
	}
}

func TestParseClassificationInvalid(t *testing.T) {
	_, err := parseClassification("this is not json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseClassificationAllTypes(t *testing.T) {
	types := []string{
		"file_hash_mismatch", "redirect_detected", "unauthorized_user",
		"suspicious_code", "config_modified", "unknown_file",
		"permission_anomaly", "cron_anomaly", "process_anomaly", "network_anomaly",
	}

	for _, typ := range types {
		raw := `{"observations":[{"type":"` + typ + `","detail":"test","severity":"medium"}]}`
		obs, err := parseClassification(raw)
		if err != nil {
			t.Errorf("parse failed for type %s: %v", typ, err)
			continue
		}
		if len(obs) != 1 {
			t.Errorf("type %s: expected 1 observation, got %d", typ, len(obs))
			continue
		}
		if string(obs[0].Type) != typ {
			t.Errorf("type mismatch: got %s, want %s", obs[0].Type, typ)
		}
	}
}

func TestCleanJSON(t *testing.T) {
	cases := []struct {
		input, want string
	}{
		{`{"a":1}`, `{"a":1}`},
		{"```json\n{\"a\":1}\n```", `{"a":1}`},
		{"```\n{\"a\":1}\n```", `{"a":1}`},
		{"  \n{\"a\":1}\n  ", `{"a":1}`},
	}
	for _, c := range cases {
		got := cleanJSON(c.input)
		if got != c.want {
			t.Errorf("cleanJSON(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("hello", 10); got != "hello" {
		t.Errorf("short string: got %q", got)
	}
	if got := truncate("hello world", 5); got != "hello..." {
		t.Errorf("long string: got %q", got)
	}
}
