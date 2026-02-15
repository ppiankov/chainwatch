package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestLog(t *testing.T) (*Log, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test-audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("failed to open audit log: %v", err)
	}
	return l, path
}

func testEntry(decision string) AuditEntry {
	return AuditEntry{
		Timestamp:  time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		TraceID:    "t-test123",
		Action:     AuditAction{Tool: "command", Resource: "echo hello"},
		Decision:   decision,
		Reason:     "test reason",
		PolicyHash: "sha256:abc123",
	}
}

func TestSequentialWritesProduceValidChain(t *testing.T) {
	l, path := newTestLog(t)

	for i := 0; i < 5; i++ {
		if err := l.Record(testEntry("allow")); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	l.Close()

	result := Verify(path)
	if !result.Valid {
		t.Fatalf("expected valid chain, got error at line %d: %s", result.ErrorLine, result.Error)
	}
	if result.Lines != 5 {
		t.Fatalf("expected 5 lines, got %d", result.Lines)
	}
}

func TestVerifyDetectsTamperedEntry(t *testing.T) {
	l, path := newTestLog(t)

	for i := 0; i < 3; i++ {
		if err := l.Record(testEntry("allow")); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	l.Close()

	// Tamper: change decision in line 2
	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	lines[1] = strings.Replace(lines[1], `"allow"`, `"deny"`, 1)
	os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0644)

	result := Verify(path)
	if result.Valid {
		t.Fatal("expected tampered chain to be invalid")
	}
	if result.ErrorLine != 3 {
		t.Fatalf("expected error at line 3, got line %d", result.ErrorLine)
	}
}

func TestVerifyDetectsDeletedEntry(t *testing.T) {
	l, path := newTestLog(t)

	for i := 0; i < 3; i++ {
		if err := l.Record(testEntry("allow")); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	l.Close()

	// Delete line 2 (middle entry)
	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	remaining := []string{lines[0], lines[2]}
	os.WriteFile(path, []byte(strings.Join(remaining, "\n")+"\n"), 0644)

	result := Verify(path)
	if result.Valid {
		t.Fatal("expected chain with deleted entry to be invalid")
	}
	if result.ErrorLine != 2 {
		t.Fatalf("expected error at line 2, got line %d", result.ErrorLine)
	}
}

func TestVerifyDetectsInsertedEntry(t *testing.T) {
	l, path := newTestLog(t)

	for i := 0; i < 3; i++ {
		if err := l.Record(testEntry("allow")); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	l.Close()

	// Insert a fabricated entry between lines 1 and 2
	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	fake := testEntry("deny")
	fake.PrevHash = "sha256:fake"
	fakeJSON, _ := json.Marshal(fake)
	inserted := []string{lines[0], string(fakeJSON), lines[1], lines[2]}
	os.WriteFile(path, []byte(strings.Join(inserted, "\n")+"\n"), 0644)

	result := Verify(path)
	if result.Valid {
		t.Fatal("expected chain with inserted entry to be invalid")
	}
}

func TestEmptyLogPassesVerification(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.jsonl")
	os.WriteFile(path, []byte{}, 0644)

	result := Verify(path)
	if !result.Valid {
		t.Fatalf("expected empty log to be valid, got: %s", result.Error)
	}
	if result.Lines != 0 {
		t.Fatalf("expected 0 lines, got %d", result.Lines)
	}
}

func TestConcurrentWritesSerializeCorrectly(t *testing.T) {
	l, path := newTestLog(t)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.Record(testEntry("allow"))
		}()
	}
	wg.Wait()
	l.Close()

	result := Verify(path)
	if !result.Valid {
		t.Fatalf("expected valid chain after concurrent writes, got error at line %d: %s", result.ErrorLine, result.Error)
	}
	if result.Lines != 100 {
		t.Fatalf("expected 100 lines, got %d", result.Lines)
	}
}

func TestGenesisHashIsCorrect(t *testing.T) {
	l, path := newTestLog(t)
	l.Record(testEntry("allow"))
	l.Close()

	data, _ := os.ReadFile(path)
	var entry AuditEntry
	json.Unmarshal([]byte(strings.TrimSpace(string(data))), &entry)

	if entry.PrevHash != GenesisHash {
		t.Fatalf("expected genesis hash %s, got %s", GenesisHash, entry.PrevHash)
	}
}

func TestHashLineIsDeterministic(t *testing.T) {
	line := []byte(`{"ts":"2025-01-15T10:30:00.000Z","trace_id":"t-abc","action":{"tool":"cmd","resource":"echo"},"decision":"allow","reason":"ok","policy_hash":"sha256:abc","prev_hash":"sha256:def"}`)
	h1 := HashLine(line)
	h2 := HashLine(line)
	if h1 != h2 {
		t.Fatalf("expected same hash, got %s and %s", h1, h2)
	}
	if !strings.HasPrefix(h1, "sha256:") {
		t.Fatalf("expected sha256: prefix, got %s", h1)
	}
	if len(h1) != 7+64 { // "sha256:" + 64 hex chars
		t.Fatalf("expected 71 char hash string, got %d", len(h1))
	}
}

func TestOpenExistingLogContinuesChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reopen.jsonl")

	// Write 3 entries, close
	l1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		l1.Record(testEntry("allow"))
	}
	l1.Close()

	// Reopen and write 2 more
	l2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		l2.Record(testEntry("deny"))
	}
	l2.Close()

	// Verify entire chain
	result := Verify(path)
	if !result.Valid {
		t.Fatalf("expected valid chain after reopen, got error at line %d: %s", result.ErrorLine, result.Error)
	}
	if result.Lines != 5 {
		t.Fatalf("expected 5 lines, got %d", result.Lines)
	}
}

func TestVerify10KEntriesUnder1Second(t *testing.T) {
	l, path := newTestLog(t)

	entry := testEntry("allow")
	for i := 0; i < 10000; i++ {
		if err := l.Record(entry); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	l.Close()

	start := time.Now()
	result := Verify(path)
	elapsed := time.Since(start)

	if !result.Valid {
		t.Fatalf("expected valid chain, got error at line %d: %s", result.ErrorLine, result.Error)
	}
	if result.Lines != 10000 {
		t.Fatalf("expected 10000 lines, got %d", result.Lines)
	}
	if elapsed > time.Second {
		t.Fatalf("verification took %v, expected < 1s", elapsed)
	}
}

func TestPolicyHashChangesWhenConfigChanges(t *testing.T) {
	// Two different inputs produce different hashes
	h1 := HashLine([]byte("policy_v1"))
	h2 := HashLine([]byte("policy_v2"))
	if h1 == h2 {
		t.Fatal("expected different hashes for different inputs")
	}
}
