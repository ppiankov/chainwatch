package chainwatch

import (
	"context"

	"github.com/ppiankov/chainwatch/internal/approval"
	"github.com/ppiankov/chainwatch/internal/model"
	"github.com/ppiankov/chainwatch/internal/policy"
)

// ToolFunc is the function signature that Wrap guards.
// The caller provides an Action describing the intended operation.
type ToolFunc func(ctx context.Context, action Action) (any, error)

// Wrap returns a new ToolFunc that evaluates policy before calling fn.
// If policy denies the action, returns a *BlockedError without calling fn.
func (c *Client) Wrap(fn ToolFunc, opts ...WrapOption) ToolFunc {
	wcfg := wrapConfig{purpose: c.cfg.purpose, agentID: c.cfg.agentID}
	for _, o := range opts {
		o(&wcfg)
	}

	return func(ctx context.Context, action Action) (any, error) {
		internal := toInternalAction(action)

		c.mu.Lock()
		result := policy.Evaluate(internal, c.tracer.State, wcfg.purpose, wcfg.agentID, c.dl, c.policyCfg)
		c.tracer.RecordAction(c.cfg.actor, wcfg.purpose, internal, map[string]any{
			"result":       string(result.Decision),
			"reason":       result.Reason,
			"policy_id":    result.PolicyID,
			"approval_key": result.ApprovalKey,
		}, "")
		c.mu.Unlock()

		switch result.Decision {
		case model.Deny:
			return nil, &BlockedError{
				Action:      action,
				Decision:    Decision(result.Decision),
				Reason:      result.Reason,
				PolicyID:    result.PolicyID,
				ApprovalKey: result.ApprovalKey,
			}

		case model.RequireApproval:
			if result.ApprovalKey != "" {
				status, _ := c.approvals.Check(result.ApprovalKey)
				if status == approval.StatusApproved {
					c.approvals.Consume(result.ApprovalKey)
					return fn(ctx, action)
				}
				if status != approval.StatusPending && status != approval.StatusDenied {
					c.approvals.Request(result.ApprovalKey, result.Reason, result.PolicyID, action.Resource)
				}
			}
			return nil, &BlockedError{
				Action:      action,
				Decision:    Decision(result.Decision),
				Reason:      result.Reason,
				PolicyID:    result.PolicyID,
				ApprovalKey: result.ApprovalKey,
			}
		}

		return fn(ctx, action)
	}
}
