# Monotonic Irreversibility: Chainwatch's Evolution Axis

**Core Principle:** Chainwatch should never become smarter — only more conservative as execution progresses.

---

## What Chainwatch Optimizes For

Chainwatch is **not** trying to be:
- Smarter than humans
- Predictive
- Adaptive
- Clever

Chainwatch is trying to be:

**Correct under uncertainty and hostile conditions.**

That single constraint governs every evolution step.

The question is never: "What is more advanced?"

The question is always: "What preserves correctness when the model lies, persuades, or drifts?"

---

## The Single Axis of Evolution

Chainwatch evolves along **one axis only**:

```
Local → Historical → Structural irreversibility awareness
```

Everything else (graphs, policies, DSLs) is **secondary**.

This is not a feature roadmap. This is a **correctness ladder**.

---

## The Correctness Ladder

### v0.1.x (Current: Pattern-Based Boundaries)

**Question answered:**
> "Is this action itself irreversible?"

**Implementation:**
```yaml
# Pattern matching
/checkout → DENY
~/.ssh/id_rsa → DENY
rm -rf → DENY
```

**Properties:**
- Local reasoning (single action)
- No history dependency
- Deterministic
- Primitive but **correct**

**Limitation:**
Cannot detect compound irreversibility:
```
browse → pricing → cart → checkout
         ^^^ each step alone is reversible
         ^^^ chain becomes irreversible
```

---

### v0.2.0 (Next: Monotonic Boundary Accumulation)

**This is the real missing primitive.**

**Question answered:**
> "Has the chain already entered a zone where new actions become irreversible?"

**Key Concept: Monotonicity**

Boundaries **accumulate**, never disappear.

Once a chain enters:
- "Commercial intent zone"
- "Credential-adjacent zone"
- "External exposure zone"

The boundary severity **only increases**.

**Not a Graph. A Lattice.**

```
SAFE
  ↓ (one-way)
SENSITIVE
  ↓ (one-way)
COMMITMENT
  ↓ (one-way)
IRREVERSIBLE
```

Transitions only go **down**, never up.

**Example:**

```python
# Action history
actions = [
    "read pricing page",      # SAFE → SENSITIVE
    "scrape product details", # SENSITIVE → COMMITMENT (intent established)
    "add to cart",            # COMMITMENT (persisted)
]

# Now visiting /checkout is not just a URL
# It is COMMITMENT → IRREVERSIBLE escalation
# Block even if /checkout wasn't in original denylist
```

**Properties:**
- Historical reasoning (chain-aware)
- Monotonic state transitions
- No backtracking
- Compound boundary detection

**What this unlocks:**
- "This was safe earlier, but not now"
- Prevention of gradual drift toward irreversibility
- Detection of intent escalation
- Compound boundaries (credentials + network = exfiltration)

**What this does NOT require:**
- Graphs
- ML
- Prediction
- Model reasoning

**Implementation sketch:**

```python
class IrreversibilityLevel(Enum):
    SAFE = 0
    SENSITIVE = 1
    COMMITMENT = 2
    IRREVERSIBLE = 3

class TraceState:
    irreversibility_level: IrreversibilityLevel

    def escalate(self, action: Action) -> IrreversibilityLevel:
        """Monotonic: can only increase, never decrease"""
        new_level = self._compute_escalation(action)
        if new_level > self.irreversibility_level:
            self.irreversibility_level = new_level
        return self.irreversibility_level
```

**Still refusal logic. Not planning.**

---

### v0.3.0 (Later: Boundary Graphs)

**Important:** These are **not** execution graphs.

They are **irreversibility graphs**.

**Nodes:** States of recoverability (not actions)

**Edges:** Loss of reversibility (not execution paths)

**Example:**

```
[SAFE]
   |
   v (read credentials)
[OBSERVED SENSITIVE DATA]
   |
   v (network call initiated)
[EXTERNAL COMMUNICATION POSSIBLE]
   |
   v (POST to external API)
[IRREVERSIBLE EXFILTRATION]
```

**What Chainwatch does with this graph:**

Chainwatch does **not**:
- Search the graph
- Optimize paths
- Predict outcomes
- Plan routes

Chainwatch **only** answers:

> "Does the next edge cross a boundary marked 'no return'?"

**This is still refusal logic, not planning.**

**Graph is used for:**
- Detecting multi-step irreversibility patterns
- Identifying compound boundaries
- Declaring structural constraints

**Graph is NOT used for:**
- Predicting agent behavior
- Scoring action safety
- Recommending alternatives
- Learning patterns

---

### v0.4.0 (Much Later: Distance-to-Boundary Signaling)

**This is non-enforcing. Visibility only.**

**What it does:**
- "You are 1 step from a payment boundary"
- "Credential exposure + network egress would become irreversible"

**What it does NOT do:**
- Block actions
- Score risk
- Use ML
- Persuade the model

**Think:**
- Yellow traffic light (not speed control)
- Fuel gauge (not throttle)
- Proximity sensor (not brake)

**Purpose:**
- Human operators see chain trajectory
- Audit logs show "distance to boundary" metrics
- Debugging policy rules

**Not:**
- Model-visible warnings
- Friction reduction
- Smart assistance

---

## Anti-Patterns (What NOT to Build)

These are **tempting but anti-Chainwatch**:

### ❌ Graph Search to Predict Risk

**Wrong:**
```python
paths = graph.find_all_paths_to_irreversibility(current_state)
risk_score = min(len(path) for path in paths)
if risk_score < threshold:
    return DENY
```

**Why wrong:** Prediction, not refusal. Chainwatch doesn't predict.

### ❌ Learning Which Boundaries Matter

**Wrong:**
```python
if boundary_violation_count[boundary_id] == 0:
    # This boundary never triggered, maybe it's not important
    weaken_enforcement(boundary_id)
```

**Why wrong:** Boundaries are structural facts, not statistical patterns.

### ❌ Letting the Model Explain Transitions

**Wrong:**
```python
if chain.approaching_boundary():
    explanation = model.explain_why_transition_is_safe()
    if explanation.is_convincing():
        allow_transition()
```

**Why wrong:** Model negotiation. The boundary doesn't care about explanations.

### ❌ Scoring Irreversibility Probabilistically

**Wrong:**
```python
irreversibility_probability = ml_model.predict(chain_history)
if irreversibility_probability > 0.7:
    return DENY
```

**Why wrong:** ML. Soft boundaries. Non-deterministic.

### ❌ Softening Boundaries Based on Confidence

**Wrong:**
```python
if model.confidence > 0.9 and boundary.severity == "medium":
    return ALLOW  # Model seems sure, weaken boundary
```

**Why wrong:** Boundaries are absolute. Confidence is irrelevant.

**All of these turn control into negotiation.**

---

## The Monotonicity Guarantee

**Formal property (must preserve):**

For any trace `T` and actions `a1`, `a2`:

```
irreversibility_level(T) ≤ irreversibility_level(T + a1)
irreversibility_level(T + a1) ≤ irreversibility_level(T + a1 + a2)
```

**In English:**

Adding more actions to a trace can **only increase** (or maintain) the irreversibility level.

Never decrease.

**Why this matters:**

This is the same guarantee as:
- Type systems (type safety never weakens)
- Memory safety (allocated memory can't become unallocated)
- Transaction isolation (commit state persists)
- Capability security (capabilities can't be forged)

**This is not a heuristic. This is a correctness property.**

---

## Why Monotonicity Is Chainwatch-ish

Monotonicity mirrors **structural safety guarantees** in programming languages and distributed systems:

| Concept | Monotonic Property |
|---------|-------------------|
| Type systems | Type safety never weakens during execution |
| Memory safety | References can't point to freed memory |
| Transaction isolation | Committed writes persist |
| Capability security | Unforgeable authority tokens |
| **Chainwatch** | **Irreversibility only increases** |

All of these are:
- **Deterministic** (not probabilistic)
- **Structural** (not learned)
- **Conservative** (false positives tolerated)
- **Non-negotiable** (no override by cleverness)

This is why monotonic irreversibility feels right for Chainwatch.

It's not ML. It's not smart. It's **correct**.

---

## Implementation Sketch: Monotonic Boundaries (v0.2.0)

### Minimal TraceState Fields

```python
class TraceState:
    trace_id: str
    irreversibility_level: IrreversibilityLevel  # NEW
    zones_entered: Set[str]  # NEW: "commercial", "credential", "egress"

    # Existing fields
    volume_bytes: int
    sensitive_sources: Set[str]
    new_sources_count: int
    external_egress: bool
```

### Transition Table (Not a Graph Yet)

```python
ZONE_ESCALATIONS = {
    # Zone entry triggers
    "pricing_page": {"commercial"},
    "add_to_cart": {"commercial"},
    "/checkout": {"commercial", "commitment"},

    "read_ssh_key": {"credential"},
    "read_env_file": {"credential"},

    "external_post": {"egress"},
    "smtp_send": {"egress"},
}

IRREVERSIBILITY_RULES = {
    # Zone combinations → irreversibility level
    frozenset({"commercial", "commitment"}): IrreversibilityLevel.IRREVERSIBLE,
    frozenset({"credential", "egress"}): IrreversibilityLevel.IRREVERSIBLE,
}
```

### Enforcement Logic

```python
def evaluate_monotonic(action: Action, state: TraceState) -> PolicyResult:
    # 1. Determine which zones this action enters
    new_zones = ZONE_ESCALATIONS.get(action.resource, set())

    # 2. Update zones (monotonic: only add, never remove)
    all_zones = state.zones_entered | new_zones

    # 3. Check if zone combination crosses irreversibility boundary
    for zone_combo, level in IRREVERSIBILITY_RULES.items():
        if zone_combo.issubset(all_zones):
            if level == IrreversibilityLevel.IRREVERSIBLE:
                return PolicyResult(
                    decision=Decision.DENY,
                    reason=f"Irreversibility boundary crossed: {zone_combo}",
                    policy_id="monotonic.irreversible"
                )

    # 4. Update state (monotonic escalation)
    new_level = max(state.irreversibility_level, compute_level(all_zones))
    state.irreversibility_level = new_level
    state.zones_entered = all_zones

    return PolicyResult(decision=Decision.ALLOW)
```

**No graphs. No ML. No prediction.**

**Just monotonic state transitions.**

---

## Evolution Summary

### v0.1.x: Local Irreversibility
- **Question:** Is this action irreversible?
- **Primitive:** Pattern matching
- **Property:** Deterministic refusal

### v0.2.0: Historical Irreversibility
- **Question:** Has the chain entered a zone where this becomes irreversible?
- **Primitive:** Monotonic state accumulation
- **Property:** History-dependent refusal

### v0.3.0: Structural Irreversibility
- **Question:** Does this edge cross a structural boundary?
- **Primitive:** Irreversibility graphs (not execution graphs)
- **Property:** Multi-step refusal

### v0.4.0: Proximity Awareness
- **Question:** How close are we to a boundary?
- **Primitive:** Distance metrics (non-enforcing)
- **Property:** Visibility, not control

**Each step preserves correctness.**

**Each step adds conservatism.**

**None use ML or prediction.**

---

## The North Star

**One-sentence principle for all future evolution:**

> Chainwatch should never become smarter — only more conservative as execution progresses.

If a feature proposal violates this, it's not Chainwatch.

---

## Next Steps

For v0.2.0 implementation:

1. **Define zone taxonomy**
   - Commercial intent
   - Credential exposure
   - External communication
   - Data sensitivity tiers

2. **Build transition table**
   - Action → zones mapping
   - Zone combinations → irreversibility levels
   - No graph structure yet (just lookup tables)

3. **Extend TraceState**
   - Add `irreversibility_level`
   - Add `zones_entered`
   - Preserve monotonicity invariant

4. **Update policy.evaluate()**
   - Check zone escalations first
   - Enforce monotonic transitions
   - Return DENY for irreversibility crossings

5. **Write tests**
   - Verify monotonicity property
   - Test compound boundaries
   - Ensure no level decreases

**No graphs. No ML. Just tables and sets.**

---

**Status:** Design document for v0.2.0 evolution
**Philosophy:** Monotonic irreversibility, not smart prediction
**Correctness:** Boundaries accumulate, never weaken

---

*Last updated: 2026-02-01*
