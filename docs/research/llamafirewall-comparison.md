# RES-01: LlamaFirewall Comparison — Content vs Runtime Enforcement

**Date:** 2026-03-09
**Status:** Complete
**Verdict:** Complementary, not competing. LlamaFirewall protects the agent's reasoning from corruption. Chainwatch protects the world from the agent's actions. PromptGuard 2 is viable as a standalone input filter for nullbot mission parsing.

## Question

Meta's LlamaFirewall is the most visible open-source agent guardrail (2025). What does it do that we don't? What do we do that it doesn't? Where could they complement each other?

## Findings

### 1. What LlamaFirewall Enforces

Three threat categories:

- **Prompt injection** (direct + indirect) — PromptGuard 2, a DeBERTa-based classifier (86M or 22M params), detects jailbreaks in user inputs and in untrusted third-party content (web pages, emails, tool responses)
- **Chain-of-thought misalignment / goal hijacking** — AlignmentCheck (experimental) audits the agent's reasoning trace using Llama 4 Maverick 17B via Together API. Detects when injected instructions redirect the agent away from the user's original goal
- **Insecure code generation** — CodeShield performs static analysis via Semgrep + regex rules across 50+ CWEs in 8 languages

What it does **not** enforce: tool execution boundaries, irreversible operations, credential access, data destruction, payment processing, or external communication. The paper explicitly acknowledges "malicious code execution and unsafe tool-use" as future work.

### 2. Runtime, Not Build-Time

LlamaFirewall runs at runtime as a synchronous inline scanner. The developer calls `firewall.scan(message)` at each step of the agent pipeline. There is no daemon, sidecar, or automatic interception — it is **call-site integration**:

```python
from llamafirewall import LlamaFirewall, UserMessage, Role, ScannerType

firewall = LlamaFirewall(scanners={
    Role.USER: [ScannerType.PROMPT_GUARD],
    Role.ASSISTANT: [ScannerType.CODE_SHIELD],
    Role.TOOL: [ScannerType.CODE_SHIELD, ScannerType.PROMPT_GUARD],
})

result = firewall.scan(UserMessage(content="..."))
# result.decision: ALLOW, BLOCK, or HUMAN_IN_THE_LOOP_REQUIRED
```

If the developer forgets to add the scan call, no protection exists.

### 3. No Tool Execution Interception

LlamaFirewall operates purely at the content/prompt/reasoning level. It scans text — user input, assistant output, tool output, execution traces. It does **not**:
- Wrap `open()` or `subprocess` calls
- Intercept HTTP clients
- Sit in the execution path of actual tool invocations
- Distinguish between reading a file and deleting a database

The agent framework must call `firewall.scan()` explicitly. The enforcement is cooperative, not structural.

### 4. Core Components

| Scanner | Type | Mechanism | Latency |
|---------|------|-----------|---------|
| **PromptGuard 2 (86M)** | ML classifier | Fine-tuned mDeBERTa-base, multilingual | ~92ms (A100) |
| **PromptGuard 2 (22M)** | ML classifier | Fine-tuned DeBERTa-xsmall, low-latency | ~19ms |
| **AlignmentCheck** | LLM inference | Llama 4 Maverick 17B via Together API (experimental) | 100s of ms–seconds |
| **CodeShield** | Static analysis | Two-tier: pattern match (~60ms) → Semgrep (~300ms, 10% escalation) | <70ms typical |
| **Regex** | Pattern matching | Configurable patterns for known attack signatures | Fast |
| **HiddenASCII** | Pattern detection | Unicode/ASCII injection evasion detection | Fast |

AlignmentCheck is explicitly labeled **experimental** and requires an external API call to Together AI (or self-hosted Llama 4 Maverick). This adds network latency and a third-party dependency.

### 5. Deployment Story

**Python library only.** `pip install llamafirewall` (v1.0.3, MIT license).

Dependencies: HuggingFace Transformers (for model download), Together API key (for AlignmentCheck), Pydantic. Optional framework integrations for OpenAI Agents SDK and LangChain.

No server, sidecar, gRPC service, or standalone daemon. No CLI. No YAML configuration. No audit log.

### 6. Architecture: Predominantly ML

| Component | Approach |
|-----------|----------|
| PromptGuard 2 | ML (probabilistic classification) |
| AlignmentCheck | ML (LLM inference) |
| CodeShield | Rule-based (deterministic) |
| Regex/HiddenASCII | Rule-based (deterministic) |

The two flagship components are ML-based. The paper positions this as necessary: "given the higher stakes and the absence of deterministic solutions to mitigate these risks, there is a critical need for a real-time guardrail monitor." This is philosophically opposite to chainwatch's position that safety decisions must be deterministic.

### 7. No Irreversible Boundaries or Deterministic Policy

LlamaFirewall has **no concept of**:
- Irreversible boundaries (no action classification by reversibility)
- Monotonic risk escalation (no SAFE → SENSITIVE → COMMITMENT → IRREVERSIBLE)
- Deterministic policy with explicit weights (no numeric risk scores)
- Hard denylists on actions or resources (only regex on content)
- Configurable threshold-based policy (no human-editable YAML rules)

Decision enum: `ALLOW`, `BLOCK`, `HUMAN_IN_THE_LOOP_REQUIRED`. Binary ML outputs, not weighted risk accumulation.

### 8. PromptGuard as Standalone Input Filter

**Yes — this is viable and valuable.** PromptGuard 2 runs entirely locally (no API calls), works on CPU or GPU, and the 22M variant achieves ~19ms latency. The 86M variant achieves 97.5% attack detection at 1% false positive rate.

For chainwatch/nullbot, PromptGuard could filter mission inputs before parsing — detecting prompt injection in untrusted content (GitHub issues, support tickets, monitoring alerts) before the agent begins reasoning about them. This is exactly the attack vector in the Cline supply chain incident.

### 9. License and Status

- MIT license for code; Llama Community License for models (free under 700M MAU)
- PyPI v1.0.3 (May 2025), active development
- PurpleLlama repo: ~4,000 stars
- AlignmentCheck explicitly experimental
- Framework integrations for OpenAI Agents SDK and LangChain

## Architectural Comparison

| Dimension | LlamaFirewall | chainwatch |
|-----------|--------------|------------|
| **Protects against** | Corrupted reasoning | Dangerous actions |
| **Enforcement target** | Content: prompts, traces, code | Actions: tool calls at boundaries |
| **Intercepts tool execution?** | No — scans text | Yes — wraps execution path |
| **Core approach** | ML classifiers + LLM inference | Deterministic policy + explicit weights |
| **Irreversibility concept** | None | Monotonic 4-tier escalation |
| **Decision model** | Binary ML classification | Numeric risk scoring (human-editable) |
| **Denylists** | Regex on content | Patterns on URLs, files, commands |
| **Deployment** | Python library (in-process) | Go binary + Python library + CLI |
| **External dependencies** | HuggingFace + Together API | None |
| **Cooperation model** | Cooperative (developer adds scan calls) | Structural (wraps execution boundary) |
| **Audit trail** | None | Hash-chained audit log |
| **Configuration** | Code-level scanner assignment | YAML policy, profiles, denylist |

## Complementary Integration

They solve different problems at different layers:

```
Untrusted input → [PromptGuard 2] → Agent reasoning → Tool call → [chainwatch] → Execution
                   ↑ content layer                                  ↑ action layer
```

- **PromptGuard filters what goes in** — catches prompt injection before the agent reasons about it
- **Chainwatch enforces what comes out** — blocks dangerous actions regardless of why the agent wants them

Neither replaces the other. The Cline attack succeeded because both layers were missing: no input filtering (PromptGuard) AND no execution boundary (chainwatch). With both, the attack is blocked at two independent points.

## Recommendations

1. **Do not adopt LlamaFirewall's architecture.** Its ML-first approach is philosophically incompatible with chainwatch's deterministic enforcement. Content classification is not our problem space.

2. **Evaluate PromptGuard 2 as an input filter for nullbot.** The 22M variant (~19ms, local, no API) could pre-scan mission inputs from untrusted sources (GitHub issues, monitoring alerts) before nullbot parses them. This hardens against the exact attack vector in the Cline incident.

3. **Document the complementary architecture.** "Content guardrails + execution boundaries" is a stronger story than either alone. Position chainwatch as the execution layer that catches what content filters miss (or when they are bypassed).

4. **Do not add AlignmentCheck.** It requires external LLM inference (Together API), is experimental, adds seconds of latency, and introduces a probabilistic decision into the enforcement chain. Chainwatch's policy engine must remain deterministic.
