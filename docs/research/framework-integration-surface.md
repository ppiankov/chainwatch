# RES-12: Framework Integration Surface

## Question

How do major AI agent frameworks handle tool execution, and where should chainwatch intercept for each?

## Findings

### Current Integration Mechanisms

Chainwatch has four runtime integration paths, each with different enforcement guarantees:

| Mechanism | Location | Bypassable | Best For |
|-----------|----------|------------|----------|
| **Intercept proxy** | `internal/intercept/` | No | HTTP LLM APIs (Anthropic, OpenAI) |
| **MCP server** | `internal/mcp/` | Yes (cooperative) | Any MCP-capable agent |
| **Command guard** | `internal/cmdguard/` | No (in-process) | Subprocess execution |
| **Forward proxy** | `internal/proxy/` | Depends (proxy config) | Outbound HTTP gating |

Plus `internal/scenario/` for policy testing (not runtime).

### Intercept Proxy (non-bypassable)

Reverse proxy between LLM API and agent. Parses streaming SSE responses, extracts tool calls mid-stream, evaluates policy, rewrites blocked calls before the agent sees them.

- Supports Anthropic (`/v1/messages`) and OpenAI (`/v1/chat/completions`) formats
- `StreamBuffer` accumulates `content_block_delta` chunks until tool call is complete
- Blocked calls rewritten to text blocks (Anthropic) or removed from tool_calls array (OpenAI)
- Only path where the agent literally cannot bypass enforcement

### MCP Server (cooperative)

Exposes 5 tools: `chainwatch_exec`, `chainwatch_http`, `chainwatch_check`, `chainwatch_approve`, `chainwatch_pending`. Agent must be instructed to use these instead of system tools.

- Works with Claude Code, OpenClaw 0.3+, LangChain (via MCP adapter), LlamaIndex 0.9+
- Limitation: prompt injection can override system prompt and call system tools directly
- This is exactly the Cline supply chain attack vector (malicious package instructions override MCP tool preference)

### Command Guard (subprocess boundary)

Wraps `exec.CommandContext()` with policy evaluation. Strips sensitive env vars, caps output at 4MB, scans stdout/stderr for leaked secrets.

- Environment sanitization: strips OPENAI_API*, AWS_*, ANTHROPIC_API*, GITHUB_TOKEN, etc.
- Output redaction: detects AWS key IDs (AKIA...), private keys, API key patterns
- Returns `BlockedError` with approval key for require_approval decisions

### Forward Proxy (network boundary)

HTTP/HTTPS forward proxy. HTTP requests get full inspection. HTTPS CONNECT gets hostname-only check (no MITM).

- Requires agent to be configured with HTTP_PROXY/HTTPS_PROXY
- Not all frameworks support proxy configuration

### Framework Integration Matrix

| Framework | Intercept Proxy | MCP | Command Guard | Forward Proxy |
|-----------|----------------|-----|---------------|---------------|
| **Claude Code** | Yes (HTTP) | Yes (native MCP) | Yes (wrap subprocess) | Yes |
| **OpenClaw/Cline** | Yes (HTTP) | Yes (MCP 0.3+) | No (Node.js) | Yes |
| **LangChain** | Yes (HTTP) | Yes (MCP adapter) | Yes (tool wrapper) | Yes |
| **LlamaIndex** | Yes (HTTP) | Yes (MCP 0.9+) | Yes (tool wrapper) | Yes |
| **CrewAI** | Yes (HTTP) | No | Yes (tool wrapper) | Yes |
| **AutoGen** | Yes (HTTP) | No | Yes (tool wrapper) | Yes |
| **Local LLM (ollama)** | No | No | Yes | Yes |

### Deployment Tiers

**Tier 1 — Cooperative** (low effort, bypassable): MCP server + system prompt guidance. Agent chooses to use chainwatch tools. Sufficient for trusted agents, insufficient for untrusted code.

**Tier 2 — Structural** (medium effort, non-bypassable at LLM boundary): Intercept proxy between agent and LLM API. Agent cannot see blocked tool calls. Does not protect against direct system calls.

**Tier 3 — Hardened** (high effort, defense in depth): Intercept proxy + command guard + forward proxy. Covers LLM boundary, subprocess boundary, and network boundary. Only gap: direct file system access.

### Gaps

1. **File system boundary** — No file access interception yet. Python `FileGuard` exists in `wrappers/file_ops.py` but no Go equivalent for the proxy/guard pipeline
2. **Database query interception** — Not implemented. Would require SQL parsing or database proxy
3. **Local LLM bypass** — Agents using ollama/llama.cpp directly skip HTTP interception entirely
4. **OpenClaw exec.wrapper** — Does not exist (RES-10 finding). Cannot wrap tool execution structurally

### Recommendations for WO-105 through WO-108

**WO-105 (Claude Code hooks)**: Claude Code supports pre/post hooks on tool calls. Write a chainwatch hook that calls `chainwatch check` before each tool execution. This is Tier 1.5 — cooperative but enforced by the hook system, not the LLM.

**WO-106 (Cursor/Windsurf)**: Both use OpenAI-compatible APIs. Intercept proxy works directly. Write setup guides + installer scripts.

**WO-107 (LangChain/CrewAI)**: Write a `ChainwatchToolWrapper` that wraps any LangChain `BaseTool` with policy evaluation. Similar pattern for CrewAI tool definitions.

**WO-108 (Universal installer)**: `chainwatch install --framework <name>` that auto-configures the right integration path. Detects framework from project files (package.json, pyproject.toml, go.mod).

## Verdict

The integration surface is comprehensive for HTTP-based agents. The primary gap is framework-native tool wrapping (WO-107) and auto-configuration (WO-108). The intercept proxy remains the strongest enforcement mechanism.

Priority order: WO-105 (Claude Code hooks — highest value, direct access to largest agent user base) > WO-107 (LangChain — largest framework ecosystem) > WO-108 (installer — reduces adoption friction) > WO-106 (Cursor/Windsurf — setup guides).
