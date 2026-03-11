# FAQ

## Is this anomaly detection or behavioral ML?
No.

Chainwatch does not attempt to learn “normal” agent behavior.
Autonomous agents do not have stable behavioral baselines,
and treating variance as anomaly breaks legitimate workflows.

Chainwatch enforces explicit, deterministic boundaries
based on sensitivity, purpose, and execution context.

See: docs/why-not-ml.md

---

## Could ML improve detection accuracy?
Possibly, but accuracy is not the primary problem.

The primary failure mode in agent security is loss of context
across execution chains, not lack of signal.

ML cannot restore lost context.
Tracing and correlation can.

---

## Why not use an LLM to judge intent?
Because intent must be explainable and enforceable.

A runtime control plane must justify blocking or modifying actions
with concrete reasons a human can understand and audit.

Probabilistic intent inference is not a sufficient enforcement basis.

---

## Is this a replacement for IAM / DLP / CASB?
No.

Chainwatch assumes those controls exist.
It addresses a different layer: chain-aware runtime enforcement
for autonomous agents.

---

## Does this work only with specific LLMs?
No.

Chainwatch operates at tool, network, or output boundaries.
It does not depend on model internals.

---

## Is this production-ready?
No.

This is an experimental prototype intended to explore a missing
control plane abstraction.

---

## How do I choose a profile?

Chainwatch ships 9 built-in profiles, each tuned for a specific agent type:

- `coding-agent` -- general-purpose development agent
- `research-agent` -- read-heavy, restricted writes
- `customer-support` -- no credential access, no exec
- `data-analyst` -- read-only data access, no egress
- `terraform-planner` -- allows plan/init/validate, blocks apply/destroy
- `sre-infra` -- blocks manual ops/SSH, requires approval for terraform apply
- `finops` -- read-only cost analysis, blocks all mutation
- `clawbot` -- adversarial testing profile
- `vm-cloud` -- cloud VM operations

Start with the profile closest to your agent's purpose and customize from there.

```bash
chainwatch init --profile coding-agent
chainwatch profile list   # see all available profiles
```

See the [profiles guide](guides/profiles.md) for detailed descriptions and configuration options.

---

## How do I add supply chain protection?

Use the `supply-chain` preset when initializing:

```bash
chainwatch init --preset supply-chain
```

This adds 52 denylist patterns covering npm, pip, cargo, gem, and Docker attack vectors -- blocking `npm publish`, `pip --index-url` from untrusted sources, credential file access, and more.

Combine with a profile:

```bash
chainwatch init --profile coding-agent --preset supply-chain
```

---

## How do I integrate with Claude Code?

Install chainwatch as a native PreToolUse hook:

```bash
chainwatch hook install --profile coding-agent --preset supply-chain
```

This writes to `.claude/settings.local.json` (project-scoped, gitignored). Every tool call -- Bash, Write, Edit, WebFetch, MCP tools -- is evaluated against policy before execution. The agent cannot bypass enforcement.

For global installation across all projects:

```bash
chainwatch hook install --global --preset supply-chain
```

---

## How do I integrate with Claude Desktop?

Run chainwatch as an MCP tool server:

```bash
chainwatch mcp
```

Then configure Claude Desktop to connect to it. The MCP server exposes the same policy engine through MCP tool calls, so Claude Desktop evaluates every action against your policy and denylist.

See `docs/integrations/claude-desktop-mcp.md` for the full setup guide.

---

## What is PromptGuard and do I need it?

PromptGuard is an optional input filter using Meta's PromptGuard 2 model. It classifies untrusted text for prompt injection before it reaches your agent. It is off by default and has zero impact when disabled.

You need it if your agent processes untrusted input (user messages, GitHub issues, emails) and you want a pre-reasoning injection filter. You do not need it if your agent only processes trusted input.

Requirements: Python 3, `transformers`, `torch` (`pip install -r scripts/promptguard/requirements.txt`). Model downloads on first run (~88MB for the 22M variant).

Enable in `policy.yaml`:

```yaml
guard:
  enabled: true
  model: "22m"
```

PromptGuard is an input classifier, not a policy engine. Chainwatch's deterministic policy still makes all enforcement decisions at the execution boundary.

---

## How do I test my policy before deploying?

Two commands:

**Certify** validates that your policy and denylist files are well-formed and internally consistent:

```bash
chainwatch certify
```

**Check** evaluates a specific action against current policy without executing anything:

```bash
chainwatch check --tool command --resource "rm -rf /" --operation execute
# Shows: decision, reason, risk score, matched denylist patterns
```

You can also use `--dry-run` with `exec` to test real commands:

```bash
chainwatch exec --dry-run --profile coding-agent -- curl https://example.com
```

For systematic testing, see `tests/scenarios/` for YAML-based attack scenario definitions that validate policy coverage.

---

## How do I handle false positives?

Three approaches, from simplest to most thorough:

1. **Custom profile** -- copy a built-in profile and adjust thresholds or denylist patterns for your use case.

2. **Scenario testing** -- write a YAML scenario in `tests/scenarios/` that captures the false positive, then adjust policy until it passes.

3. **Dry-run** -- use `chainwatch exec --dry-run` to test specific commands against policy before changing configuration.

False positives in the denylist are fixed by editing `~/.chainwatch/denylist.yaml` -- remove or narrow the pattern that is matching incorrectly. Policy rule false positives are fixed by adjusting thresholds or adding purpose-specific rules in `policy.yaml`.

---

## What happens when chainwatch is unavailable?

Chainwatch is fail-closed by default. If the policy engine cannot be reached (gRPC server down, binary missing, configuration corrupt), the decision is deny. No action executes without an explicit policy evaluation.

For emergencies, use break-glass:

```bash
chainwatch breakglass create --reason "incident response"
chainwatch exec --breakglass <token> -- <emergency-command>
```

Break-glass tokens are single-use, time-limited, and recorded in the audit log. They bypass policy but not audit -- every break-glass action is traceable.

---

## Can I use chainwatch with Cursor, Windsurf, or other editors?

Not yet. Chainwatch currently supports Claude Code hooks (`chainwatch hook install`) and MCP-compatible agents (`chainwatch mcp`).

For other editors, you can use the CLI wrapper (`chainwatch exec -- <cmd>`), the HTTP proxy (`chainwatch proxy`), or the gRPC server (`chainwatch serve`) as integration points. Native hook support for additional editors is planned.

---

## How do I approve a blocked action?

When chainwatch returns `require-approval`, the action is pending human review.

```bash
# List pending approvals
chainwatch pending

# Approve with a time-to-live
chainwatch approve <approval-key> --ttl 5m

# Deny
chainwatch deny <approval-key>
```

Approvals are scoped, time-limited, and single-use. The agent retries the action after approval, and chainwatch re-evaluates with the approval token present.

Anti-circular rule: the agent that requested approval cannot approve its own request.
