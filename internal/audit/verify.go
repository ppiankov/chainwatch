package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

// VerifyResult holds the outcome of a hash chain verification.
type VerifyResult struct {
	Valid     bool   `json:"valid"`
	Lines     int    `json:"lines"`
	Error     string `json:"error,omitempty"`
	ErrorLine int    `json:"error_line,omitempty"`
}

// Verify reads a JSONL audit log and validates the hash chain.
// Returns Valid=true if the chain is intact, or details about
// the first broken link.
func Verify(path string) VerifyResult {
	f, err := os.Open(path)
	if err != nil {
		return VerifyResult{Error: fmt.Sprintf("open: %v", err)}
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	var prevLineBytes []byte

	for scanner.Scan() {
		lineNum++
		raw := scanner.Bytes()

		// Make a copy since scanner reuses the buffer
		line := make([]byte, len(raw))
		copy(line, raw)

		var entry AuditEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return VerifyResult{
				Error:     fmt.Sprintf("parse error: %v", err),
				ErrorLine: lineNum,
			}
		}

		if lineNum == 1 {
			// First entry must reference genesis hash
			if entry.PrevHash != GenesisHash {
				return VerifyResult{
					Error:     fmt.Sprintf("first entry prev_hash is %q, expected genesis hash", entry.PrevHash),
					ErrorLine: 1,
				}
			}
		} else {
			// Subsequent entries must reference hash of previous line
			expectedHash := HashLine(prevLineBytes)
			if entry.PrevHash != expectedHash {
				return VerifyResult{
					Error:     fmt.Sprintf("hash mismatch: expected %s, got %s", expectedHash, entry.PrevHash),
					ErrorLine: lineNum,
				}
			}
		}

		prevLineBytes = line
	}

	if err := scanner.Err(); err != nil {
		return VerifyResult{Error: fmt.Sprintf("scan: %v", err)}
	}

	return VerifyResult{Valid: true, Lines: lineNum}
}
