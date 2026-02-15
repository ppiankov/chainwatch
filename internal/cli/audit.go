package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ppiankov/chainwatch/internal/audit"
)

var tailLines int

func init() {
	rootCmd.AddCommand(auditCmd)
	auditCmd.AddCommand(auditVerifyCmd)
	auditCmd.AddCommand(auditTailCmd)
	auditTailCmd.Flags().IntVarP(&tailLines, "lines", "n", 10, "Number of recent entries to show")
}

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit log operations",
	Long:  "Commands for verifying and inspecting the hash-chained audit log.",
}

var auditVerifyCmd = &cobra.Command{
	Use:   "verify <path>",
	Short: "Verify hash chain integrity of an audit log",
	Long:  "Walks the JSONL audit log and validates that every entry's prev_hash\nmatches the SHA-256 of the previous entry. Exits 0 if valid, 1 if tampered.",
	Args:  cobra.ExactArgs(1),
	RunE:  runAuditVerify,
}

var auditTailCmd = &cobra.Command{
	Use:   "tail <path>",
	Short: "Show recent audit log entries",
	Long:  "Reads the last N entries from the JSONL audit log and pretty-prints them.",
	Args:  cobra.ExactArgs(1),
	RunE:  runAuditTail,
}

func runAuditVerify(cmd *cobra.Command, args []string) error {
	result := audit.Verify(args[0])
	if result.Valid {
		fmt.Printf("OK: %d entries verified\n", result.Lines)
		return nil
	}
	fmt.Fprintf(os.Stderr, "FAILED at line %d: %s\n", result.ErrorLine, result.Error)
	os.Exit(1)
	return nil
}

func runAuditTail(cmd *cobra.Command, args []string) error {
	f, err := os.Open(args[0])
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()

	// Read all lines, keep last N
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read audit log: %w", err)
	}

	start := len(lines) - tailLines
	if start < 0 {
		start = 0
	}

	for _, line := range lines[start:] {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			fmt.Println(line)
			continue
		}
		out, _ := json.MarshalIndent(entry, "", "  ")
		fmt.Println(string(out))
	}

	return nil
}
