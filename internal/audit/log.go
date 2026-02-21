package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// GenesisHash is the prev_hash for the first entry in a new audit log.
const GenesisHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// Log is an append-only JSONL audit log with SHA-256 hash chaining.
// Each entry's prev_hash is the hash of the previous entry's JSON line,
// forming a tamper-evident chain.
type Log struct {
	path     string
	file     *os.File
	prevHash string
	mu       sync.Mutex
}

// Open opens (or creates) an audit log file for appending.
// If the file already exists, it reads the last line to recover the chain tail.
func Open(path string) (*Log, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("audit: create directory: %w", err)
	}

	prevHash := GenesisHash

	// Read existing file to find chain tail
	if info, err := os.Stat(path); err == nil && info.Size() > 0 {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("audit: read existing log: %w", err)
		}
		scanner := bufio.NewScanner(f)
		var lastLine []byte
		for scanner.Scan() {
			lastLine = make([]byte, len(scanner.Bytes()))
			copy(lastLine, scanner.Bytes())
		}
		f.Close()
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("audit: scan existing log: %w", err)
		}
		if len(lastLine) > 0 {
			prevHash = HashLine(lastLine)
		}
	}

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("audit: open file: %w", err)
	}

	return &Log{
		path:     path,
		file:     file,
		prevHash: prevHash,
	}, nil
}

// Record appends an AuditEntry to the log with hash chaining.
// It sets the entry's PrevHash and Timestamp (if empty), marshals to JSON,
// writes the line, and syncs to disk.
func (l *Log) Record(entry AuditEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	}
	entry.PrevHash = l.prevHash

	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("audit: marshal entry: %w", err)
	}

	if _, err := l.file.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("audit: write entry: %w", err)
	}

	if err := l.file.Sync(); err != nil {
		return fmt.Errorf("audit: sync: %w", err)
	}

	l.prevHash = HashLine(line)
	return nil
}

// Close flushes and closes the underlying file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

// HashLine returns "sha256:<hex>" of the given bytes.
func HashLine(line []byte) string {
	h := sha256.Sum256(line)
	return "sha256:" + hex.EncodeToString(h[:])
}
