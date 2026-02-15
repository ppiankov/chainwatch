package chainwatch

import (
	"fmt"
	"sync"

	"github.com/ppiankov/chainwatch/internal/approval"
	"github.com/ppiankov/chainwatch/internal/denylist"
	"github.com/ppiankov/chainwatch/internal/policy"
	"github.com/ppiankov/chainwatch/internal/profile"
	"github.com/ppiankov/chainwatch/internal/tracer"
)

// Client holds the policy evaluation pipeline for in-process enforcement.
// Thread-safe for concurrent tool calls.
type Client struct {
	cfg       clientConfig
	dl        *denylist.Denylist
	policyCfg *policy.PolicyConfig
	approvals *approval.Store
	tracer    *tracer.TraceAccumulator
	mu        sync.Mutex
}

// New creates a Client with the given options.
func New(opts ...Option) (*Client, error) {
	cfg := clientConfig{
		purpose: "general",
		actor:   map[string]any{"sdk": "chainwatch-go"},
	}
	for _, o := range opts {
		o(&cfg)
	}

	dl, err := denylist.Load(cfg.denylistPath)
	if err != nil {
		return nil, fmt.Errorf("chainwatch: failed to load denylist: %w", err)
	}

	policyCfg, err := policy.LoadConfig(cfg.policyPath)
	if err != nil {
		return nil, fmt.Errorf("chainwatch: failed to load policy config: %w", err)
	}

	if cfg.profileName != "" {
		prof, err := profile.Load(cfg.profileName)
		if err != nil {
			return nil, fmt.Errorf("chainwatch: failed to load profile %q: %w", cfg.profileName, err)
		}
		profile.ApplyToDenylist(prof, dl)
		policyCfg = profile.ApplyToPolicy(prof, policyCfg)
	}

	approvalStore, err := approval.NewStore(approval.DefaultDir())
	if err != nil {
		return nil, fmt.Errorf("chainwatch: failed to create approval store: %w", err)
	}
	approvalStore.Cleanup()

	return &Client{
		cfg:       cfg,
		dl:        dl,
		policyCfg: policyCfg,
		approvals: approvalStore,
		tracer:    tracer.NewAccumulator(tracer.NewTraceID()),
	}, nil
}

// Check evaluates policy for an action without executing anything.
func (c *Client) Check(action Action) Result {
	internal := toInternalAction(action)

	c.mu.Lock()
	pr := policy.Evaluate(internal, c.tracer.State, c.cfg.purpose, c.dl, c.policyCfg)
	c.mu.Unlock()

	return toResult(pr)
}

// TraceSummary exports the accumulated trace for debugging/audit.
func (c *Client) TraceSummary() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tracer.ToJSON()
}
