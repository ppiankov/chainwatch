package chainwatch

import (
	"fmt"

	"github.com/ppiankov/chainwatch/internal/model"
)

// Decision is the policy enforcement outcome.
type Decision string

const (
	Allow              Decision = Decision(model.Allow)
	Deny               Decision = Decision(model.Deny)
	AllowWithRedaction Decision = Decision(model.AllowWithRedaction)
	RequireApproval    Decision = Decision(model.RequireApproval)
)

// Action describes what a tool intends to do.
type Action struct {
	Tool      string         // tool category: "command", "http_request", "file_read"
	Resource  string         // target: URL, file path, command string
	Operation string         // operation type: "execute", "read", "write", "GET", "POST"
	Meta      map[string]any // optional: sensitivity, tags, bytes, rows, egress, destination
}

// Result is a policy evaluation outcome.
type Result struct {
	Decision    Decision
	Reason      string
	PolicyID    string
	ApprovalKey string
	Redactions  map[string]any
}

// Allowed returns true if the decision permits the action.
func (r Result) Allowed() bool {
	return r.Decision == Allow || r.Decision == AllowWithRedaction
}

// BlockedError is returned when policy denies or requires approval for an action.
type BlockedError struct {
	Action      Action
	Decision    Decision
	Reason      string
	PolicyID    string
	ApprovalKey string
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("chainwatch blocked (%s): %s", e.Decision, e.Reason)
}

// toInternalAction maps an SDK Action to an internal model.Action.
func toInternalAction(a Action) *model.Action {
	rawMeta := a.Meta
	if rawMeta == nil {
		rawMeta = model.DefaultResultMeta().ToMap()
	}
	return &model.Action{
		Tool:      a.Tool,
		Resource:  a.Resource,
		Operation: a.Operation,
		Params:    rawMeta,
		RawMeta:   rawMeta,
	}
}

// toResult maps an internal PolicyResult to an SDK Result.
func toResult(pr model.PolicyResult) Result {
	return Result{
		Decision:    Decision(pr.Decision),
		Reason:      pr.Reason,
		PolicyID:    pr.PolicyID,
		ApprovalKey: pr.ApprovalKey,
		Redactions:  pr.Redactions,
	}
}
