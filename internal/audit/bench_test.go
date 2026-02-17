package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkRecord_Single(b *testing.B) {
	path := filepath.Join(b.TempDir(), "bench.jsonl")
	al, err := Open(path)
	if err != nil {
		b.Fatal(err)
	}
	defer al.Close()

	entry := AuditEntry{
		TraceID:    "t-bench",
		Action:     AuditAction{Tool: "command", Resource: "echo hello"},
		Decision:   "allow",
		Tier:       0,
		PolicyHash: "sha256:bench",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		al.Record(entry)
	}
}

func BenchmarkRecord_Sequential100(b *testing.B) {
	entry := AuditEntry{
		TraceID:    "t-bench",
		Action:     AuditAction{Tool: "command", Resource: "echo hello"},
		Decision:   "allow",
		Tier:       0,
		PolicyHash: "sha256:bench",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		path := filepath.Join(b.TempDir(), "bench.jsonl")
		al, err := Open(path)
		if err != nil {
			b.Fatal(err)
		}
		for j := 0; j < 100; j++ {
			al.Record(entry)
		}
		al.Close()
	}
}

func benchVerify(b *testing.B, n int) {
	b.Helper()
	path := filepath.Join(b.TempDir(), "bench.jsonl")
	al, err := Open(path)
	if err != nil {
		b.Fatal(err)
	}
	entry := AuditEntry{
		TraceID:    "t-bench",
		Action:     AuditAction{Tool: "command", Resource: "echo hello"},
		Decision:   "allow",
		Tier:       0,
		PolicyHash: "sha256:bench",
	}
	for i := 0; i < n; i++ {
		al.Record(entry)
	}
	al.Close()

	// Verify the file exists and has content
	info, _ := os.Stat(path)
	b.ResetTimer()
	b.SetBytes(info.Size())

	for i := 0; i < b.N; i++ {
		result := Verify(path)
		if !result.Valid {
			b.Fatal("invalid chain:", result.Error)
		}
	}
}

func BenchmarkVerify_1000(b *testing.B) {
	benchVerify(b, 1000)
}

func BenchmarkVerify_10000(b *testing.B) {
	benchVerify(b, 10000)
}
