# RES-08: Nullbot Sparring Mode — Idea Purifier with Structured Hostility

**Date:** 2026-03-10
**Status:** Complete
**Verdict:** Build it. Empty niche (no CLI idea evaluation tool exists). 3-pass pipeline with single model, structurally distinct prompts. ~400-500 lines of Go. The prompts are the product, not the code.

## Question

How to design a structured idea purification pipeline? What prompt engineering produces genuinely hostile critique? Should multi-model triangulation be used?

## Findings

### 1. Prompt Engineering for Hostile Critique

**Pre-mortem is the strongest technique.** Klein (HBR, 2007) showed prospective hindsight increases failure identification by 30%. The mechanism: "what did go wrong" (creative, generates specific failure modes) vs "what might go wrong" (defensive, generates weak objections).

**Devil's advocate must be structurally assigned.** The DEBATE framework (ACL 2024) showed LLMs default to sycophancy unless the adversarial role is architecturally enforced — not just requested.

**Effective hostile prompt patterns (ranked):**

1. **Pre-mortem**: "This idea was built and shipped. It failed completely within 6 months. Generate the 5 most likely specific reasons for failure."
2. **YC Killer Questions**: "Why hasn't this been built? What does the builder know that everyone else doesn't? What is the hardest unsolved technical problem?"
3. **Steelman-then-destroy**: "State the strongest version in 2 sentences. Then identify the single assumption that, if false, makes the entire idea worthless."
4. **Resource constraint**: "You have $0 budget and 2 weeks. What is the minimum version that proves or disproves the core hypothesis?"
5. **Competitive autopsy**: "Name 3 existing solutions that solve 80% of this. Why would anyone switch?"

**Anti-patterns:** "List everything wrong" (generic), personality-based hostility (theatrical), unbounded scope (noise).

### 2. Multi-Model Triangulation

**Not worth it for v1.** Research shows diverse role prompts are the key variable, not diverse models (ChatEval, ICLR 2024). Single model with structurally distinct system prompts (attacker, defender, judge) matches the benefit at 1/3 the cost and complexity.

Multi-model is a v2 optimization if single-model proves insufficient.

### 3. Scoring Framework

Modified ICE + Pre-mortem hybrid designed for CLI:

```
SPARRING SCORECARD
==================
1. Impact (1-5):        If this works perfectly, how much does it matter?
2. Falsifiability (1-5): Can you test the core hypothesis in <2 weeks?
3. Moat (1-5):          Why can't someone copy this in a weekend?
4. Conviction (1-5):    Would you still build this after 72 hours?
5. Kill count (0-N):    Unmitigated pre-mortem failure modes

COMPOSITE: (Impact × Falsifiability × Moat × Conviction) / (1 + Kill count)
```

Differs from RICE/ICE: "Reach" replaced by "Moat" (defensibility is assessable at idea stage, reach is a guess). "Confidence" replaced by "Falsifiability" (can you prove/disprove cheaply?). Kill count penalizes unmitigated risks.

### 4. 72-Hour Cooldown

**Research supports it, but the mechanism is ownership bias, not fatigue.** Ego depletion (Baumeister 1998) has replication issues. The real mechanism: the endowment/IKEA effect — once you've invested time articulating an idea, you overvalue it. The delay lets emotional attachment decay.

The incubation effect (unconscious processing during dormancy) is well-supported — REM sleep enhances integration of unassociated information (PNAS, 2009).

**Implementation:** 48-72 hours, configurable (`--cooldown 72h`). Save sparring output with timestamp. On re-review, show elapsed time and re-present the kill count. Not a hard gate — an informed friction point.

### 5. No Existing CLI Tools

The landscape is empty. Existing tools are either capture-only (idea-cli), scoring-only (PrometAI, enterprise SaaS), or purpose-built for specific domains (LinqAlpha for investment theses). No CLI tool combines adversarial critique with structured scoring.

### 6. Anti-Patterns: Preventing Intellectual Playground

1. **Hard output cap.** 3 LLM calls total (attacker, defender, judge). No extended dialogue.
2. **Mandatory binary verdict.** `PROCEED` or `SHELVE`. Not "needs more thought."
3. **No re-sparring without cooldown.** Prevents iterative pitch refinement (using LLM as writing assistant, not filter).
4. **60-second time limit.** Fast feedback prevents settling in for brainstorming.
5. **Sparse output.** Numbers, one-line failure modes, binary verdict. Dense, not narrative.
6. **Idea graveyard with accountability.** Periodic: "You have N shelved ideas. 0 revisited."

## Design

### `nullbot spar` Subcommand

```bash
nullbot spar "one-line idea description"
  --cooldown 72h          # default cooldown before re-evaluation
  --threshold 12          # minimum composite score to PROCEED
  --provider ollama       # LLM provider (reuse existing neurorouter)
```

### Pipeline (3 LLM calls, sequential)

```
Pass 1: ATTACKER
  System: Pre-mortem + killer questions
  Input: Raw idea
  Output: 5 failure modes, 3 killer questions

Pass 2: DEFENDER
  System: Steelman prompt
  Input: Raw idea + attacker output
  Output: Strongest 2-sentence version + responses to top 3 failure modes

Pass 3: JUDGE
  System: Scoring framework
  Input: Raw idea + attacker + defender
  Output: Scorecard + binary PROCEED/SHELVE
```

### Storage

JSON file in `~/.nullbot/sparring/` keyed by content hash. Contains: idea text, timestamp, scorecard, verdict, override history.

### Implementation Surface

- `cmd/nullbot/spar.go` — Cobra subcommand
- `internal/spar/` — pipeline, scoring, storage
- Reuse: `neurorouter` for LLM calls
- System prompts: embedded as constants (the prompts are the product)
- ~400-500 lines of Go

### What This Is NOT

- Not a brainstorming tool (evaluates one idea, does not generate ideas)
- Not a writing assistant (does not help refine the idea)
- Not an approval workflow (user can override; tool records, not blocks)
- Not a project management tool (no task tracking)
