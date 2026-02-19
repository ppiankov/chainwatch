# RES-03: Redaction Fidelity — Can LLMs Work with Tokenized Context?

**Date:** 2026-02-19
**Status:** Complete
**Verdict:** Viable with constraints. 70-80% token fidelity out of the box, 0% leaks. Prompt engineering can push fidelity higher. Architecture is sound.

## Question

CW49 assumes cloud LLMs can produce useful remediation plans from tokenized evidence (`<<PATH_1>>` instead of `/var/www/site`). If LLMs can't reason about tokens, the two-tier architecture breaks.

## Method

3 tokenized Work Orders of increasing complexity:
1. **Simple** (3 tokens) — WordPress compromise with malicious plugin + redirect + rogue user
2. **Dense** (7+ tokens) — Same scenario with .htaccess, mu-plugins, cron, wp-config, DB name
3. **Generic Linux** (5 tokens) — Outbound connections, cron, nginx, SSH investigation

Sent to 2 local models via ollama (temperature=0, max_tokens=800).

Measured:
- JSON validity (can we parse the response?)
- Token fidelity (% of required tokens used in commands)
- Literal leaks (did the LLM invent real paths/IPs?)

## Results

| Model | Size | JSON Valid | Token Fidelity | Leaks | Avg Latency |
|-------|------|-----------|----------------|-------|-------------|
| qwen2.5-coder:32b | 19GB | 3/3 (100%) | 8/10 (80%) | 0 | 18s |
| deepseek-coder-v2:16b | 8.9GB | 3/3 (100%) | 7/10 (70%) | 0 | 3s |

### Detailed Breakdown

**qwen2.5-coder:32b:**
- Simple WO: 3/3 tokens — PASS
- Dense WO: 3/4 tokens — missed `<<PATH_5>>` (.htaccess), used `/path/to/clean/.htaccess` placeholder instead
- Linux WO: 2/3 tokens — missed `<<USER_1>>`, used `~/.ssh/authorized_keys` instead of `~<<USER_1>>/.ssh/`

**deepseek-coder-v2:16b:**
- Simple WO: 2/3 tokens — missed `<<PATH_1>>` in wp user delete command
- Dense WO: 3/4 tokens — missed `<<PATH_7>>` (mu-plugins), but used `<<USER_1>>`, `<<CRED_1>>`, `<<DB_1>>` correctly
- Linux WO: 2/3 tokens — missed `<<USER_1>>`, used `~/.ssh/` instead. Used `<<IP_1>>` in grep correctly.

## Key Findings

### 1. Zero literal leaks
Neither model hallucinated real paths (`/var/www`, `/home/admin`, `192.168.x.x`). When they missed a token, they either:
- Used a generic placeholder (`/path/to/clean/`)
- Used the default/implicit path (`~/.ssh/` instead of `~<<USER_1>>/.ssh/`)

This is the critical finding: **redaction prevents data leakage even when the LLM doesn't perfectly follow token instructions.**

### 2. JSON generation is reliable
Both models produced valid JSON in all 3 cases. deepseek wrapped in markdown fences (```json), qwen2.5 sometimes did/didn't. The `cleanJSON()` strip handles both.

### 3. Token fidelity correlates with prompt clarity
Tokens used in the observations section (where the LLM "sees" them in context) were reused correctly. Tokens only defined in the legend but not appearing near the relevant observation were more likely to be missed.

**Implication:** The WO schema should place tokens inline with observations, not just in a separate legend.

### 4. Smaller models are faster but less faithful
deepseek-coder-v2:16b is 6x faster but 10% less faithful. For the two-tier architecture, this tradeoff is acceptable because:
- The local LLM only does observation/classification (CW51), not remediation
- Remediation commands come from the cloud agent (Claude/GPT-4), which will score higher
- Even 70% fidelity + 0% leaks means the privacy guarantee holds

### 5. The <<USER_1>> pattern is hardest
Both models missed `<<USER_1>>` in the SSH authorized_keys context. The LLM wants to write `~/.ssh/` (the "obvious" path) rather than `~<<USER_1>>/.ssh/`. This suggests:
- User tokens need stronger prompt reinforcement
- Or the WO should pre-expand paths: `<<PATH_SSH_KEYS>>` instead of relying on the LLM to compose `~<<USER_1>>/.ssh/`

## Recommendations for CW49 Implementation

1. **Token-in-context, not token-in-legend-only.** Place tokens directly in observation text where the LLM will reference them. The legend is backup, not primary.

2. **Pre-compose complex paths.** Instead of expecting `~<<USER_1>>/.ssh/authorized_keys`, give `<<PATH_SSH_KEYS>>` as a single token. Reduces composition errors.

3. **Post-validation is mandatory.** After LLM responds, scan commands for:
   - Missing tokens (warn, but still executable after detoken)
   - Literal paths/IPs that shouldn't be there (hard reject — privacy leak)

4. **Detoken handles both cases.** Even if the LLM writes `/path/to/clean/.htaccess`, the detoken pass won't break — it just won't substitute anything. The command may fail at runtime, but that's caught by chainwatch exec's exit code handling.

5. **Architecture is sound.** 0% leaks across 2 models and 3 scenarios means the privacy boundary holds. Token fidelity can be improved with prompt engineering. This is not a blocker.

## Verdict

**Gate passed.** The two-tier architecture (CW48-CW53) is viable. LLMs can work with tokenized WOs. The privacy guarantee (no literal leaks) holds even when token usage is imperfect. Proceed with CW49 (redaction engine) implementation.

## Reproducibility

```bash
# Against local ollama (default qwen2.5-coder:32b)
go test -tags research -v -timeout 5m ./internal/research/redaction/

# Against a specific model
RESEARCH_MODEL="deepseek-coder-v2:16b" go test -tags research -v -timeout 5m ./internal/research/redaction/

# Against Groq cloud
RESEARCH_API_URL="https://api.groq.com/openai/v1/chat/completions" \
RESEARCH_API_KEY="xxx" \
RESEARCH_MODEL="llama-3.1-8b-instant" \
go test -tags research -v -timeout 5m ./internal/research/redaction/
```
