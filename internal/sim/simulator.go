package sim

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ppiankov/chainwatch/internal/audit"
	"github.com/ppiankov/chainwatch/internal/denylist"
	"github.com/ppiankov/chainwatch/internal/model"
	"github.com/ppiankov/chainwatch/internal/policy"
)

// Simulate replays an audit log against a new policy and returns decision diffs.
// Entries are grouped by trace ID and replayed in order with accumulated TraceState.
func Simulate(logPath, policyPath, denylistPath, purpose, agentOverride string) (*SimResult, error) {
	cfg, err := policy.LoadConfig(policyPath)
	if err != nil {
		return nil, fmt.Errorf("load policy: %w", err)
	}

	var dl *denylist.Denylist
	if denylistPath != "" {
		loaded, err := denylist.Load(denylistPath)
		if err != nil {
			return nil, fmt.Errorf("load denylist: %w", err)
		}
		dl = loaded
	}

	// Read and group entries by trace ID, preserving order.
	traceOrder, traceEntries, err := readAndGroup(logPath)
	if err != nil {
		return nil, err
	}

	result := &SimResult{
		PolicyPath: policyPath,
	}

	for _, traceID := range traceOrder {
		entries := traceEntries[traceID]
		state := model.NewTraceState(traceID)

		for _, entry := range entries {
			result.TotalActions++

			action := &model.Action{
				Tool:     entry.Action.Tool,
				Resource: entry.Action.Resource,
			}

			agentID := agentOverride
			if agentID == "" {
				agentID = entry.AgentID
			}

			evalPurpose := purpose

			newResult := policy.Evaluate(action, state, evalPurpose, agentID, dl, cfg)
			newDecision := string(newResult.Decision)
			oldDecision := strings.ToLower(entry.Decision)

			if newDecision != oldDecision {
				diff := DiffEntry{
					Timestamp:   entry.Timestamp,
					TraceID:     entry.TraceID,
					Tool:        entry.Action.Tool,
					Resource:    entry.Action.Resource,
					OldDecision: oldDecision,
					NewDecision: newDecision,
					OldReason:   entry.Reason,
					NewReason:   newResult.Reason,
					OldTier:     entry.Tier,
					NewTier:     newResult.Tier,
				}
				result.Changes = append(result.Changes, diff)
				result.ChangedActions++

				if isPermissive(oldDecision) && isRestrictive(newDecision) {
					result.NewlyBlocked++
				}
				if isRestrictive(oldDecision) && isPermissive(newDecision) {
					result.NewlyAllowed++
				}
			}
		}
	}

	return result, nil
}

// readAndGroup reads the audit log and groups entries by trace ID.
// Returns trace IDs in order of first appearance and a map of entries per trace.
func readAndGroup(logPath string) ([]string, map[string][]audit.AuditEntry, error) {
	f, err := os.Open(logPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()

	var traceOrder []string
	traceEntries := make(map[string][]audit.AuditEntry)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var entry audit.AuditEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}

		if _, seen := traceEntries[entry.TraceID]; !seen {
			traceOrder = append(traceOrder, entry.TraceID)
		}
		traceEntries[entry.TraceID] = append(traceEntries[entry.TraceID], entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("read audit log: %w", err)
	}

	return traceOrder, traceEntries, nil
}
