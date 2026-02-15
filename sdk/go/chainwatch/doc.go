// Package chainwatch provides in-process policy enforcement for Go agent
// frameworks. It wraps tool functions, evaluates deterministic policy against
// denylist, risk scoring, and monotonic irreversibility boundaries, and
// enforces decisions (allow, deny, redact, require-approval) at boundaries
// agents cannot bypass.
//
// Usage:
//
//	cw, err := chainwatch.New(chainwatch.WithProfile("clawbot"))
//	wrapped := cw.Wrap(myTool, chainwatch.WrapWithPurpose("research"))
//	result, err := wrapped(ctx, chainwatch.Action{
//	    Tool:      "file_read",
//	    Resource:  "/etc/passwd",
//	    Operation: "read",
//	})
//
// The SDK links directly against internal packages for zero-subprocess
// overhead. External users import github.com/ppiankov/chainwatch/sdk/go/chainwatch.
package chainwatch
