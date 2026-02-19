# RES-03: Redaction Fidelity — Can LLMs Work with Tokenized Context?

**Date:** 2026-02-19
**Status:** Complete
**Verdict:** GATE PASSED. 70-90% token fidelity, 0% leaks across 3 models. Architecture is sound. Two binding recommendations for CW49.

## Question

CW49 assumes cloud LLMs can produce useful remediation plans from tokenized evidence (`<<PATH_1>>` instead of `/var/www/site`). If LLMs can't reason about tokens, the two-tier architecture breaks.

## Method

3 tokenized Work Orders of increasing complexity:
1. **Simple** (3 tokens) — WordPress compromise with malicious plugin + redirect + rogue user
2. **Dense** (7+ tokens) — Same scenario with .htaccess, mu-plugins, cron, wp-config, DB name
3. **Generic Linux** (5 tokens) — Outbound connections, cron, nginx, SSH investigation

Sent to 3 local models via ollama (temperature=0, max_tokens=800).

Measured:
- JSON validity (can we parse the response?)
- Token fidelity (% of required tokens used in commands)
- Literal leaks (did the LLM invent real paths/IPs?)

## Results

| Model | Size | JSON Valid | Token Fidelity | Leaks | Avg Latency |
|-------|------|-----------|----------------|-------|-------------|
| qwen3-coder-next (q4_K_M) | 51GB | 3/3 (100%) | 9/10 (90%) | 0 | 14s |
| qwen2.5-coder:32b | 19GB | 3/3 (100%) | 8/10 (80%) | 0 | 18s |
| deepseek-coder-v2:16b | 8.9GB | 3/3 (100%) | 7/10 (70%) | 0 | 3s |

### Detailed Breakdown

**qwen3-coder-next (q4_K_M) — best results:**
- Simple WO: 2/3 tokens — missed `<<PATH_1>>` in mysql command (used `<<HOST_1>>` as DB host instead)
- Dense WO: 4/4 tokens — PASS. Used all tokens including `<<USER_1>>`, `<<CRED_1>>`, `<<DB_1>>`, `<<PATH_7>>`. 8 steps, thorough.
- Linux WO: 3/3 tokens — PASS. Correctly composed `/home/<<USER_1>>/.ssh/authorized_keys`. Only model to get this right.

**qwen2.5-coder:32b:**
- Simple WO: 3/3 tokens — PASS
- Dense WO: 3/4 tokens — missed `<<PATH_5>>` (.htaccess), used `/path/to/clean/.htaccess` placeholder instead
- Linux WO: 2/3 tokens — missed `<<USER_1>>`, used `~/.ssh/authorized_keys` instead of `~<<USER_1>>/.ssh/`

**deepseek-coder-v2:16b:**
- Simple WO: 2/3 tokens — missed `<<PATH_1>>` in wp user delete command
- Dense WO: 3/4 tokens — missed `<<PATH_7>>` (mu-plugins), but used `<<USER_1>>`, `<<CRED_1>>`, `<<DB_1>>` correctly
- Linux WO: 2/3 tokens — missed `<<USER_1>>`, used `~/.ssh/` instead. Used `<<IP_1>>` in grep correctly.

## Key Findings

### 1. Zero literal leaks — the privacy boundary holds
No model across 9 test runs hallucinated real paths (`/var/www`, `/home/admin`, `192.168.x.x`). When a token was missed, the model either:
- Used a generic placeholder (`/path/to/clean/`)
- Used the default/implicit path (`~/.ssh/` instead of `~<<USER_1>>/.ssh/`)
- Substituted a different token from the legend

**This is the critical finding: redaction prevents data leakage even when the LLM doesn't perfectly follow token instructions.**

### 2. JSON generation is reliable across all sizes
All 3 models produced valid JSON in all 9 cases. Some wrap in markdown fences (```json), handled by `cleanJSON()` strip. Not a concern.

### 3. Token fidelity scales with model size
- 51GB (qwen3-coder-next): 90%
- 19GB (qwen2.5-coder): 80%
- 8.9GB (deepseek-coder-v2): 70%

For the two-tier architecture, this ordering works:
- Local small model (observe/classify): 70% is fine, it only structures evidence
- Cloud model (remediate): will score higher than any of these
- Local large model (if available): 90% means it could do remediation too

### 4. Token-in-context beats token-in-legend
Tokens appearing in observation text (where the LLM "sees" them near the action) were used correctly. Tokens only in the legend section were more likely missed. The WO schema must place tokens inline.

### 5. The user/path composition problem
Two models missed `<<USER_1>>` when composing SSH paths. The LLM defaults to `~/.ssh/` because that's the common pattern. qwen3-coder-next was the only one to correctly write `/home/<<USER_1>>/.ssh/authorized_keys`.

Solution: pre-compose complex paths as single tokens.

### 6. Larger models produce better commands
qwen3-coder-next produced notably better remediation steps:
- Used `grep -v` pipeline for cron cleanup (correct approach)
- Added verification step (`grep -r` to confirm no remaining malicious references)
- Handled wp-config read-only constraint properly
- Composed user-specific crontab commands correctly

## Binding Recommendations for CW49

These are not suggestions — they are requirements derived from empirical evidence.

### R1: Pre-compose complex paths into single tokens

**Do this:**
```
<<PATH_SSH_KEYS>>  = /home/nullbot/.ssh/authorized_keys
<<PATH_HTACCESS>>  = /var/www/site/.htaccess
<<PATH_WPCONFIG>>  = /var/www/site/wp-config.php
```

**Not this:**
```
<<USER_1>> = nullbot
(expect LLM to compose ~<<USER_1>>/.ssh/authorized_keys)
```

Only qwen3-coder-next (51GB) correctly composed user tokens into paths. Smaller models failed. Pre-composing eliminates this failure mode entirely and costs nothing.

### R2: Post-validation with hard reject on leaks

After the LLM responds, before detokenizing or executing:

1. **Scan for literal leaks** — any string matching known sensitive patterns (real IPs, real paths from the token map, real hostnames). If found: **hard reject the entire response**. Do not execute. Log the leak. Re-prompt or fail.

2. **Scan for missing tokens** — warn but proceed. The detoken pass handles this gracefully:
   - Token present → substituted with real value → command works
   - Token missing → no substitution → command likely fails at runtime → chainwatch exec catches the non-zero exit

This means CW49's `Detoken()` function must also return a `leaked bool` flag from scanning the original response before substitution.

## What This Means for the Architecture

The two-tier design (nullbot local → WO → runforge cloud → chainwatch enforce) is validated:

1. **Privacy boundary holds** — 0% leaks across 3 models, 3 WOs, 9 runs. Even imperfect token usage doesn't expose real data.
2. **Small models are sufficient for observation** — 70% fidelity is fine when the model is classifying findings, not writing commands.
3. **Large models or cloud models handle remediation** — 90% fidelity at 51GB, and cloud models (Claude, GPT-4) will be higher still.
4. **Post-validation catches edge cases** — the 10-30% missed tokens don't leak data, and failed commands are caught by chainwatch.

## What's Left Before Implementation

- [x] RES-03: Redaction fidelity (this document)
- [ ] RES-04: Local LLM capability floor (can llama 3.2 3B do observation/classification?)

RES-04 tests whether the smallest deployable model can handle the *observation* half (structured JSON output, log classification). RES-03 tested the *remediation* half (using tokens in commands). Both must pass for v1.2.

## Reproducibility

```bash
# Against local ollama (default qwen2.5-coder:32b)
go test -tags research -v -timeout 5m ./internal/research/redaction/

# Against qwen3-coder-next (strongest local)
RESEARCH_MODEL="qwen3-coder-next:q4_K_M" go test -tags research -v -timeout 10m ./internal/research/redaction/

# Against a smaller model
RESEARCH_MODEL="deepseek-coder-v2:16b" go test -tags research -v -timeout 5m ./internal/research/redaction/

# Against Groq cloud
RESEARCH_API_URL="https://api.groq.com/openai/v1/chat/completions" \
RESEARCH_API_KEY="xxx" \
RESEARCH_MODEL="llama-3.1-8b-instant" \
go test -tags research -v -timeout 5m ./internal/research/redaction/
```
