package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestVerifySkipsWhenNoExpectedHash(t *testing.T) {
	old := ExpectedHash
	oldPaths := ChecksumPaths
	ExpectedHash = ""
	ChecksumPaths = []string{"/nonexistent/path"}
	defer func() {
		ExpectedHash = old
		ChecksumPaths = oldPaths
	}()

	if err := Verify(); err != nil {
		t.Fatalf("expected nil error for empty ExpectedHash, got %v", err)
	}
}

func TestVerifyPassesWithCorrectHash(t *testing.T) {
	// Create a temp file and hash it to simulate a matching binary
	tmp := t.TempDir() + "/test-bin"
	content := []byte("test binary content")
	if err := os.WriteFile(tmp, content, 0755); err != nil {
		t.Fatal(err)
	}

	h := sha256.Sum256(content)
	expected := hex.EncodeToString(h[:])

	actual, err := hashFile(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("expected %s, got %s", expected, actual)
	}
}

func TestVerifyFailsWithWrongHash(t *testing.T) {
	old := ExpectedHash
	oldDir := TamperLogDir
	ExpectedHash = "deadbeef"
	TamperLogDir = t.TempDir()
	defer func() {
		ExpectedHash = old
		TamperLogDir = oldDir
	}()

	err := Verify()
	if err == nil {
		t.Fatal("expected error for wrong hash, got nil")
	}
}

func TestTamperEventWrittenOnMismatch(t *testing.T) {
	old := ExpectedHash
	oldDir := TamperLogDir
	tmpDir := t.TempDir()
	ExpectedHash = "deadbeef"
	TamperLogDir = tmpDir
	defer func() {
		ExpectedHash = old
		TamperLogDir = oldDir
	}()

	Verify()

	logPath := filepath.Join(tmpDir, "tamper.jsonl")
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("expected tamper log to exist: %v", err)
	}

	var event TamperEvent
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &event); err != nil {
		t.Fatalf("failed to parse tamper event: %v", err)
	}
	if event.Type != "binary_tamper" {
		t.Errorf("expected type binary_tamper, got %s", event.Type)
	}
	if event.ExpectedHash != "deadbeef" {
		t.Errorf("expected hash deadbeef, got %s", event.ExpectedHash)
	}
	if event.ActualHash == "" {
		t.Error("expected actual hash to be populated")
	}
	if event.Binary == "" {
		t.Error("expected binary path to be populated")
	}
	if event.Timestamp == "" {
		t.Error("expected timestamp to be populated")
	}
}

func TestTamperLogPermissions(t *testing.T) {
	old := ExpectedHash
	oldDir := TamperLogDir
	tmpDir := filepath.Join(t.TempDir(), "tamper-perms")
	ExpectedHash = "deadbeef"
	TamperLogDir = tmpDir
	defer func() {
		ExpectedHash = old
		TamperLogDir = oldDir
	}()

	Verify()

	// Check directory permissions
	dirInfo, err := os.Stat(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0700 {
		t.Errorf("expected dir perm 0700, got %04o", dirInfo.Mode().Perm())
	}

	// Check file permissions
	logPath := filepath.Join(tmpDir, "tamper.jsonl")
	fileInfo, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if fileInfo.Mode().Perm() != 0600 {
		t.Errorf("expected file perm 0600, got %04o", fileInfo.Mode().Perm())
	}
}

func TestWebhookFiredOnTamper(t *testing.T) {
	var mu sync.Mutex
	var received []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		received = body
		w.WriteHeader(200)
	}))
	defer srv.Close()

	// Write a policy.yaml with alerts pointing to test server
	tmpHome := t.TempDir()
	configDir := filepath.Join(tmpHome, ".chainwatch")
	os.MkdirAll(configDir, 0700)
	policyContent := `alerts:
  - url: "` + srv.URL + `"
    format: generic
    events: ["binary_tamper"]
`
	os.WriteFile(filepath.Join(configDir, "policy.yaml"), []byte(policyContent), 0600)

	// Override HOME so loadAlertConfigs finds our policy
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", oldHome)

	event := TamperEvent{
		Timestamp:    "2026-01-01T00:00:00.000Z",
		Binary:       "/usr/local/bin/chainwatch",
		ExpectedHash: "aaa",
		ActualHash:   "bbb",
		Hostname:     "test-host",
		Type:         "binary_tamper",
	}

	// TamperLogDir must be writable
	oldDir := TamperLogDir
	TamperLogDir = t.TempDir()
	defer func() { TamperLogDir = oldDir }()

	writeTamperEvent(event)

	mu.Lock()
	defer mu.Unlock()

	if len(received) == 0 {
		t.Fatal("expected webhook to receive tamper alert")
	}

	var payload tamperAlertPayload
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("failed to parse webhook payload: %v", err)
	}
	if payload.Type != "binary_tamper" {
		t.Errorf("expected type binary_tamper, got %s", payload.Type)
	}
	if payload.Decision != "deny" {
		t.Errorf("expected decision deny, got %s", payload.Decision)
	}
	if payload.Tier != 3 {
		t.Errorf("expected tier 3, got %d", payload.Tier)
	}
}

func TestAlertEventFromTamper(t *testing.T) {
	event := TamperEvent{
		Timestamp:    "2026-01-01T00:00:00.000Z",
		Binary:       "/usr/bin/chainwatch",
		ExpectedHash: "abc",
		ActualHash:   "def",
		Hostname:     "prod-1",
		Type:         "binary_tamper",
	}
	payload := alertEventFromTamper(event)
	if payload.Type != "binary_tamper" {
		t.Errorf("expected type binary_tamper, got %s", payload.Type)
	}
	if payload.Decision != "deny" {
		t.Errorf("expected decision deny, got %s", payload.Decision)
	}
	if payload.Tier != 3 {
		t.Errorf("expected tier 3, got %d", payload.Tier)
	}
	if !strings.Contains(payload.Reason, "abc") || !strings.Contains(payload.Reason, "def") {
		t.Errorf("expected reason to contain both hashes, got %s", payload.Reason)
	}
}

func TestHashSelfReturns64CharHex(t *testing.T) {
	h, err := HashSelf()
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 64 {
		t.Fatalf("expected 64 char hex, got %d: %s", len(h), h)
	}
}

func TestHashFileNonExistent(t *testing.T) {
	_, err := hashFile("/nonexistent/path/to/binary")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestVerifyUsesChecksumFile(t *testing.T) {
	old := ExpectedHash
	oldPaths := ChecksumPaths
	oldDir := TamperLogDir
	ExpectedHash = ""
	TamperLogDir = t.TempDir()
	defer func() {
		ExpectedHash = old
		ChecksumPaths = oldPaths
		TamperLogDir = oldDir
	}()

	// Write a checksum file with a wrong hash — should trigger tamper event.
	tmpDir := t.TempDir()
	checksumFile := filepath.Join(tmpDir, "binary.sha256")
	os.WriteFile(checksumFile, []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"), 0600)
	ChecksumPaths = []string{checksumFile}

	err := Verify()
	if err == nil {
		t.Fatal("expected error for checksum file mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("expected checksum mismatch error, got %v", err)
	}
}

func TestLoadChecksumFileValid(t *testing.T) {
	oldPaths := ChecksumPaths
	defer func() { ChecksumPaths = oldPaths }()

	tmpDir := t.TempDir()
	checksumFile := filepath.Join(tmpDir, "binary.sha256")
	hash := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	os.WriteFile(checksumFile, []byte(hash+"\n"), 0600)
	ChecksumPaths = []string{checksumFile}

	got := loadChecksumFile()
	if got != hash {
		t.Errorf("expected %s, got %s", hash, got)
	}
}

func TestLoadChecksumFileInvalidContent(t *testing.T) {
	oldPaths := ChecksumPaths
	defer func() { ChecksumPaths = oldPaths }()

	tmpDir := t.TempDir()
	checksumFile := filepath.Join(tmpDir, "binary.sha256")
	os.WriteFile(checksumFile, []byte("not-a-valid-hash\n"), 0600)
	ChecksumPaths = []string{checksumFile}

	got := loadChecksumFile()
	if got != "" {
		t.Errorf("expected empty string for invalid hash, got %s", got)
	}
}

func TestLoadChecksumFileFallsThrough(t *testing.T) {
	oldPaths := ChecksumPaths
	defer func() { ChecksumPaths = oldPaths }()

	tmpDir := t.TempDir()
	// First path doesn't exist, second has valid hash.
	checksumFile := filepath.Join(tmpDir, "binary.sha256")
	hash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	os.WriteFile(checksumFile, []byte(hash), 0600)
	ChecksumPaths = []string{"/nonexistent/path", checksumFile}

	got := loadChecksumFile()
	if got != hash {
		t.Errorf("expected %s, got %s", hash, got)
	}
}

func TestIsHex(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"abcdef0123456789", true},
		{"ABCDEF0123456789", true},
		{"abcdefg", false},
		{"", true},
		{"xyz", false},
	}
	for _, tt := range tests {
		if got := isHex(tt.in); got != tt.want {
			t.Errorf("isHex(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
