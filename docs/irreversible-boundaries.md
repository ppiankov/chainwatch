# Irreversible Boundaries

**Core Concept:** Some actions cannot be undone. Once executed, no subsequent policy can reverse their effects.

Chainwatch treats these transitions as **hard execution boundaries** where the system must refuse continuation regardless of model intent.

---

## The Problem

Traditional security controls evaluate actions in isolation:
- "Can this user access this file?" (IAM)
- "Is this API call allowed?" (RBAC)
- "Does this match a signature?" (IDS)

But execution chains create **irreversible state transitions** that single-action policies miss:

```
browse → pricing → cart → checkout → payment → COMMITTED
```

Each individual step looks innocent. The chain becomes irreversible.

**Once payment is committed, no policy can retrieve the money.**

---

## Chainwatch's Answer

Chainwatch identifies **two classes of structural boundaries**:

### Class 1: Execution Boundaries

Actions that cannot be undone once executed:

1. **Points of no return** - Actions that cannot be undone
   - Submitting payment
   - Sending external email
   - Deleting data
   - Deploying to production

2. **Credential crossings** - Exposing authentication secrets
   - Reading SSH private keys
   - Accessing cloud credentials
   - Extracting API tokens

3. **Destructive transitions** - System-level mutations
   - Running `rm -rf`
   - Formatting disks
   - Force-pushing code

### Class 2: Authority Boundaries

Instructions that cannot be "un-accepted" once admitted into the execution chain:

4. **Authority ingress** - Control that cannot be revoked once granted
   - Proxied commands from untrusted origins
   - Injected instructions into agent control flow
   - Cross-context command steering
   - Replayed commands from compromised sessions

These are not "bad actions" or "bad commands" — they are **irreversible transitions in execution context**.

---

## Why This Matters

### Traditional Approach (Fails)

```
Model intent: "helpful"
Action: navigate to /checkout
Policy: "Is checkout URL allowed?"
Answer: "Yes, user can access any public URL"
Result: $3000 charge
```

The policy evaluated the action, not the **boundary crossing**.

### Chainwatch Approach (Succeeds)

```
Chain state: [browse, pricing, cart]
Next action: navigate to /checkout
Boundary check: Entering payment flow (IRREVERSIBLE)
Decision: REFUSE (hard stop, no negotiation)
Result: Chain halts before commitment
```

Chainwatch **never asks the model** whether an irreversible action is safe.

If the chain crosses a hard boundary, **the system refuses**.

---

## Authority Boundaries: The Second Limb

**Core insight:** Accepting an instruction into the execution chain is itself an irreversible boundary.

### The Problem (Real Incident: Clawdbot, 2025)

**System design:**
- Clawdbot has full system access (files, OS, browser, chat history)
- Designed to accept commands through a control interface
- Processes instructions without distinguishing origin

**The attack:**
1. Attacker proxies commands through the user's device
2. Commands reach Clawdbot's "trusted channel"
3. System treats them as legitimate user instructions
4. Attacker gains full control: read history, send messages, execute arbitrary commands

**Traditional security perspective:**
"This is an authentication/authorization failure. Fix the auth layer."

**Chainwatch perspective:**
"This is an irreversible boundary crossing. Once the instruction is accepted as authoritative, the chain is compromised."

### Why This Is Irreversible

Once a malicious instruction is:
- Accepted into the control flow
- Contextualized with trace state
- Mixed with legitimate execution history

**You cannot "un-infect" the execution chain.**

The attacker's command becomes part of the agent's reasoning context. Even if you detect the intrusion later:
- The agent has already executed commands
- History is contaminated
- Secrets may be exposed
- Outputs may be manipulated

This is the same irreversibility as payment commitment or credential exposure — just earlier in the lifecycle.

### The Unifying Concept

**Two limbs, same organism:**

| Limb | Question | Boundary Type |
|------|----------|---------------|
| **Execution Irreversibility** | "Should this action be allowed even if the instruction is valid?" | Actions that cannot be undone |
| **Authority Irreversibility** | "Should this instruction be treated as legitimate at all?" | Control that cannot be revoked |

Both are **irreversible transitions in execution context**.

Different surface. Same species.

### Traditional vs Chainwatch Response

**Traditional approach (fails):**
```
Authenticate the request
Verify IP address
Check token validity
If all pass → trust instruction
```

**Problem:** The agent assumes "if it reached me, it must be okay."

This assumption is invisible to classic tools:
- Logs look normal
- Permissions are correct
- No single rule is violated

Exactly like: `browse → cart → checkout → payment`

Each step looks innocent. The chain becomes irreversible.

**Chainwatch approach (succeeds):**
```
Instruction origin crosses trust boundary (IRREVERSIBLE)
→ Boundary detected
→ REFUSE or REQUIRE_APPROVAL (out-of-band human verification)
→ No continuation without explicit consent
```

### Authority Boundary Examples

**Proxied control:**
- Command arrives through proxy/relay instead of direct user interaction
- System cannot verify instruction originated from legitimate human

**Boundary:** Once proxied command is accepted, authority is compromised.

**Injected instructions:**
- Attacker injects commands into agent's input stream
- Commands appear syntactically valid but semantically malicious

**Boundary:** Once injection is processed, execution chain is contaminated.

**Cross-context steering:**
- Agent receives commands from one security context (e.g., public web)
- Commands affect resources in another context (e.g., internal systems)

**Boundary:** Once cross-context command is accepted, isolation is broken.

**Replayed sessions:**
- Attacker captures and replays legitimate command sequence
- System treats replay as fresh instruction

**Boundary:** Once replay is accepted as current, temporal integrity is lost.

### What Chainwatch Does NOT Do

**❌ WRONG approaches (traditional security):**

```python
# ❌ Inspect IP reputation
if ip_reputation.is_suspicious(request.ip):
    block()  # Bypassed by proxy rotation

# ❌ Ask model to classify intent
if model.classify_command_intent(instruction) == "malicious":
    block()  # Model can be fooled by adversarial phrasing

# ❌ Trust prompts
if instruction.contains("only accept user commands"):
    allow()  # Prompt injection bypasses this
```

All of these fail under adversarial conditions.

**✅ CORRECT approach (structural boundary detection):**

```python
# ✅ Detect structural boundary crossing
if instruction.origin_crosses_trust_boundary():
    return Decision.REQUIRE_APPROVAL  # Human verifies out-of-band

# ✅ Detect control flow contamination
if instruction.mixed_with_untrusted_context():
    return Decision.DENY  # Refuse to continue contaminated chain

# ✅ Detect replay/injection
if instruction.temporal_integrity_violated():
    return Decision.DENY  # Hard stop
```

No model reasoning. No IP heuristics. **Structural refusal.**

### How This Would Have Stopped Clawdbot Attack

**With Chainwatch authority boundaries:**

1. **Detect ingress boundary:**
   ```
   Instruction arrives via proxy relay
   → Authority boundary detected: command origin crosses trust boundary
   ```

2. **Refuse continuation:**
   ```
   → Decision: REQUIRE_APPROVAL
   → Execution halts
   → Out-of-band notification to legitimate user
   ```

3. **Human verifies:**
   ```
   User sees: "Command received through proxy. Did you authorize this?"
   User response: "No, I did not send this command."
   → Instruction rejected, attack prevented
   ```

4. **Attack fails before execution:**
   - No history leaked
   - No commands executed
   - No chain contamination

**Key point:** The boundary was enforced **before** the instruction entered the execution chain, not after damage was done.

### Why This Is Still Chainwatch, Not IAM

Traditional IAM/Zero Trust asks:
- "Is this user authenticated?"
- "Does this token have the right permissions?"
- "Is this IP address trusted?"

Chainwatch asks:
- "Is accepting this instruction an irreversible transition?"
- "Can we recover if this instruction is malicious?"
- "Can this instruction be 'un-accepted' from the execution chain?"

If the answer is "no, we cannot recover," **refuse**.

This is control plane logic, not identity verification.

### Authority Boundaries in v0.2.0

**Planned implementation:**

Authority boundaries will be detected through **structural signals**, not heuristics:

```python
AUTHORITY_BOUNDARIES = {
    "proxy_relay": {
        "pattern": "instruction.origin != direct_user_interface",
        "decision": Decision.REQUIRE_APPROVAL,
        "reason": "Command proxied through untrusted relay"
    },
    "context_crossing": {
        "pattern": "instruction.context != execution.context",
        "decision": Decision.DENY,
        "reason": "Cross-context command steering detected"
    },
    "temporal_violation": {
        "pattern": "instruction.timestamp < session.start_time",
        "decision": Decision.DENY,
        "reason": "Replay attack or temporal integrity violation"
    }
}
```

**No ML. No sentiment analysis. No "does this look suspicious?"**

Just: "Did this instruction cross a structural authority boundary?"

### The Unified Philosophy

**Chainwatch enforces both execution boundaries and authority boundaries.**

Both answer the same fundamental question:

> "Is this transition in execution context irreversible?"

Whether the transition is:
- An action (payment, credential read, file delete)
- An instruction (proxied command, injected steering, replayed session)

If it's irreversible, **refuse** or **require human override**.

**The system never asks the model:**
- "Is this action safe?"
- "Is this command legitimate?"
- "Does this instruction seem user-like?"

The model's opinion is irrelevant. The boundary is absolute.

---

## Implementation (v0.1.2)

The denylist in v0.1.2 is a primitive implementation of irreversible boundary detection.

### What It Does

Declares patterns that indicate boundary crossings:

```yaml
# ~/.chainwatch/denylist.yaml

# Payment boundaries (irreversible commitment)
urls:
  - /checkout
  - /payment
  - stripe.com/checkout

# Credential boundaries (irreversible exposure)
files:
  - ~/.ssh/id_rsa
  - ~/.aws/credentials

# Destructive boundaries (irreversible mutation)
commands:
  - rm -rf
  - sudo su
```

### How It Works

When policy evaluation detects a boundary crossing:

```python
if action crosses irreversible_boundary:
    return DENY  # Hard stop, no approval, no override
```

This is not policy logic. **This is a control plane interrupt.**

Think of it as:
- **SIGKILL**, not if/else
- **Circuit breaker**, not classifier
- **Fuse**, not firewall

---

## Why "Denylist" is Temporary Language

The current implementation uses "denylist" because it's familiar and fast to build.

But the concept is:

**Irreversible boundary guard based on chain state.**

Future versions will evolve this into:
- Boundary graphs (directed paths toward irreversibility)
- State-aware boundary detection (not just pattern matching)
- Chain-specific boundaries (what's irreversible depends on purpose)

---

## Key Principles

### 1. Boundaries Are Structural, Not Moral

We don't block `/checkout` because it's "bad."

We block it because **entering a payment flow is a point of no return**.

The system architecture makes it irreversible (money leaves account, vendor is notified, legal commitment forms).

### 2. Refusal Happens Before Crossing

Chainwatch intervenes **before** the boundary is crossed:

```
Safe state → [boundary] → irreversible state
              ↑
         Chainwatch refuses here
```

Not here:
```
Safe state → irreversible state → [detect damage] → too late
                                      ↑
                                 Wrong place to intervene
```

### 3. No Negotiation with the Model

Traditional safety:
```
System: "Are you sure you want to proceed?"
Model: "Yes, the user said to do it."
System: "OK then."
```

Chainwatch:
```
System: "This crosses an irreversible boundary. REFUSED."
[Chain halts]
```

The model's intent is irrelevant. The boundary is absolute.

### 4. Human Approval Does Not Weaken Boundaries

When v0.2.0 adds approval workflows, the boundary remains:

```
Chain reaches boundary
→ System halts
→ Generates approval token (out-of-band)
→ Human explicitly consents
→ ONLY THEN: single action proceeds
→ Token expires immediately
```

The boundary still exists. Approval is **human override**, not model bypass.

---

## ⚠️ Critical Warning: Approval Boundaries (v0.2.0 Design Risk)

**DANGER:** Implementing approval workflows incorrectly will break Chainwatch's entire philosophy.

### Terminology Note

Before proceeding, clarify the distinction between two decision types:

- **`DENY`**: Absolute refusal. This execution must not proceed under any circumstances.
- **`REQUIRE_APPROVAL`**: Human override required. This execution may proceed only via explicit, single-use human consent.

Both are boundaries. `DENY` means "never without code change." `REQUIRE_APPROVAL` means "never without human override."

Neither means "ask the model if it's safe."

### The Risk

When v0.2.0 adds `REQUIRE_APPROVAL` as a decision type, there is a critical risk of turning boundaries into **negotiation points** instead of **control interrupts**.

**WRONG approach (breaks everything):**
```python
# ANTI-PATTERN: Asking the model if boundary crossing is safe
if action.crosses_boundary():
    explanation = model.explain_why_safe()
    if explanation.is_convincing():
        return ALLOW  # ❌ Model convinced system to bypass boundary
    else:
        return REQUIRE_APPROVAL
```

This is **not control**. This is **model persuasion**.

**CORRECT approach (preserves philosophy):**
```python
# CORRECT: Boundary forces human-in-loop, no model negotiation
if action.crosses_boundary():
    return REQUIRE_APPROVAL  # ✅ Hard stop, human decides, boundary remains
```

### What "Approval" Actually Means

**Approval is NOT:**
- ❌ Asking the model to justify the action
- ❌ Letting the model explain why it's safe
- ❌ Weakening the boundary based on model confidence
- ❌ Making the boundary "soft" or negotiable

**Approval IS:**
- ✅ Hard stop at boundary (chain halts immediately)
- ✅ Out-of-band human notification
- ✅ Human explicitly consents with full context
- ✅ One-time token for single action
- ✅ Boundary remains absolute for all subsequent actions

**Critical requirement for out-of-band approval:**

Approval must occur **outside the agent's execution context**.

The model must not:
- Observe the approval process
- Influence how the approval request is presented
- Narrate or explain the approval to the human
- Receive feedback about whether approval was granted

The approval interface is a separate control surface. The model sees only: "execution halted at boundary" or "execution resumed with token." Nothing in between.

### The Line That Cannot Be Crossed

**Chainwatch's core principle:**
> The system NEVER asks the model whether an irreversible action is safe.

If v0.2.0 implementation allows the model to influence approval decisions, **Chainwatch becomes observability**, not control.

**Examples of what breaks the philosophy:**

```python
# ❌ WRONG: Model convinces system
if model.says_its_safe():
    return ALLOW

# ❌ WRONG: Model provides "context" that weakens boundary
if model.confidence > 0.9:
    return ALLOW
else:
    return REQUIRE_APPROVAL

# ❌ WRONG: Model explains action to reduce friction
approval_request = model.generate_justification()
human.review(approval_request)  # Human trusts model's framing
```

**Examples of what preserves the philosophy:**

```python
# ✅ CORRECT: Boundary is absolute, approval is human override
if action.crosses_boundary():
    return REQUIRE_APPROVAL  # No model input, no negotiation

# ✅ CORRECT: Approval token is one-time, expires immediately
approval = human.review(full_chain_context)
if approval.granted:
    execute_with_token(approval.token)  # Token valid for this action only

# ✅ CORRECT: Boundary still active after approval
# Next action that crosses boundary still requires new approval
```

### How to Implement Approval Without Breaking Everything

**v0.2.0 implementation MUST:**

1. **Boundary detection happens first** (before any model reasoning)
2. **Hard stop** when boundary detected (no continuation without approval)
3. **Out-of-band approval** (human sees full chain, not model summary)
4. **Single-use tokens** (approval doesn't grant blanket access)
5. **Boundary remains active** (next crossing still requires approval)

**v0.2.0 implementation MUST NOT:**

1. Let model generate approval requests
2. Let model "explain" why boundary crossing is safe
3. Reduce approval friction based on model confidence
4. Allow model to bypass boundaries with "context"
5. Make boundaries negotiable or conditional

### The Test

**If you can answer "yes" to ANY of these, approval is broken:**

- Can the model convince the system to bypass a boundary?
- Can the model reduce the strictness of boundary enforcement?
- Can the model frame the approval request in a way that influences the human?
- Can one approval grant access to multiple boundary crossings?
- Does the boundary "disappear" after approval?

**All answers must be "NO" for Chainwatch to remain a control plane.**

### Non-Goal: Chainwatch Does Not Judge "Good" vs "Bad"

**Chainwatch does not attempt to determine whether irreversible actions are "good" or "bad."**

It only determines whether they are **recoverable**.

Examples:
- Buying a $3000 course might be a legitimate business expense (good) or a mistake (bad)
- Chainwatch doesn't care. It only knows: **money leaves account, cannot be undone**
- The boundary exists because of structural irreversibility, not moral judgment

This keeps Chainwatch:
- **Technical**, not ethical
- **Deterministic**, not interpretive
- **Architectural**, not policy-driven

The question is never "should this happen?" The question is always "can this be undone?"

### Why This Matters

Chainwatch is not:
- A "smart" system that learns when boundaries are "actually" safe
- A friction-reduction layer that minimizes approval requests
- A context-aware system that weakens boundaries based on intent

Chainwatch is:
- A **structural interrupt** when irreversibility is detected
- A **control plane** that refuses to negotiate with models
- A **boundary enforcer** where boundaries are absolute until humans override

**Approval workflows are for humans to override boundaries.**

**Approval workflows are NOT for models to persuade systems to weaken boundaries.**

---

## Examples of Irreversible Boundaries

### Payment Commitment

**Boundary:** Transitioning from "browsing" to "committed purchase"

**Why irreversible:**
- Money leaves account immediately
- Vendor receives payment notification
- Legal contract formed
- Refund requires separate process (not guaranteed)

**Chainwatch response:** Block navigation to `/checkout`, `/payment`, `stripe.com/checkout`

### Credential Exposure

**Boundary:** Reading authentication secrets

**Why irreversible:**
- Once credential is read into agent context, it can be leaked
- Cannot "un-read" a secret
- Rotating credentials is expensive and disruptive
- Damage persists until rotation completes

**Chainwatch response:** Block access to `~/.ssh/id_rsa`, `~/.aws/credentials`, `**/.env`

### Data Destruction

**Boundary:** Executing commands that mutate system state

**Why irreversible:**
- `rm -rf /data` cannot be undone
- Backups may not exist or be stale
- Recovery is expensive and incomplete
- Trust in system integrity is permanently damaged

**Chainwatch response:** Block `rm -rf`, `dd if=/dev/zero`, `mkfs`

### Authority Compromise (Clawdbot Incident)

**Boundary:** Accepting untrusted instruction as authoritative control

**Why irreversible:**
- Once malicious instruction enters execution chain, context is contaminated
- Agent cannot distinguish legitimate vs injected commands in trace history
- Attacker gains full control: read history, execute commands, manipulate outputs
- Cannot "un-accept" instruction once it's part of reasoning context

**Real incident (2025):**
- Attacker proxied commands through user's device
- Clawdbot treated proxied commands as legitimate
- Result: full system compromise without auth bypass

**Chainwatch response:**
- Detect instruction origin boundary crossing (v0.2.0)
- Require out-of-band human approval for proxied/relayed commands
- Refuse execution if instruction context crosses trust boundary

### External Communication

**Boundary:** Sending messages outside the controlled environment

**Why irreversible:**
- Email sent to external recipient cannot be recalled
- Message may be forwarded, screenshotted, archived
- Reputation damage is instant and permanent
- No technical mechanism to "unsend" at protocol level

**Chainwatch response:** Block SMTP egress, external POST requests (v0.2.0)

---

## Evolution Path

**See `docs/monotonic-irreversibility.md` for complete evolution design.**

**Single axis:** Local → Historical → Structural irreversibility awareness

### v0.1.2 (Current)

**Primitive:** Pattern-based boundary detection (local irreversibility)
- URL patterns (`/checkout`)
- File patterns (`~/.ssh/id_rsa`)
- Command patterns (`rm -rf`)

**Question answered:** "Is this action itself irreversible?"

**Limitation:** Static patterns, no chain context

### v0.2.0 (Planned)

**Improvement:** Monotonic boundary accumulation (historical irreversibility)
- Boundaries accumulate, never disappear
- Zone-based detection: commercial intent, credential exposure, external egress
- Correctness ladder: SAFE → SENSITIVE → COMMITMENT → IRREVERSIBLE (one-way only)
- Compound boundaries: credentials + network = exfiltration

**Question answered:** "Has the chain entered a zone where this becomes irreversible?"

**Not graphs yet. Just monotonic state transitions.**

### v0.3.0 (Future)

**Evolution:** Irreversibility graphs (structural irreversibility)
- Nodes are recoverability states (not actions)
- Edges are loss of reversibility (not execution paths)
- Still refusal logic, not planning

**Question answered:** "Does the next edge cross a structural boundary?"

### v0.4.0 (Later)

**Visibility:** Distance-to-boundary signaling (non-enforcing)
- Proximity metrics for human operators
- Non-enforcing: yellow light, not brake

### v1.0.0 (Vision)

**Goal:** Formal boundary calculus
- Provable monotonicity properties
- Compositional boundary reasoning
- Boundary-aware policy language

**North Star:** Chainwatch should never become smarter — only more conservative as execution progresses.

---

## Relationship to Other Chainwatch Concepts

### TraceState

TraceState tracks **where the chain has been**.
Boundaries define **where the chain cannot go**.

Together: "Given this chain history, these boundaries are now active."

### PolicyResult

PolicyResult can return:
- `ALLOW` - Safe continuation
- `DENY` - Boundary crossed, refuse
- `REQUIRE_APPROVAL` - Boundary requires human override (v0.2.0)

Boundaries force DENY or REQUIRE_APPROVAL, never ALLOW.

### Enforcement

Enforcement implements the hard stop:
```python
if policy_result.decision == DENY:
    raise EnforcementError  # Chain halts
```

This is the actual interrupt. Boundaries declare intent; enforcement implements mechanism.

---

## Why This Is Control Plane, Not Observability

**Observability says:**
"I saw the agent buy a course. Here's the log."

**Control plane says:**
"The agent tried to cross the payment boundary. I stopped it."

Chainwatch irreversible boundaries are **control**, not **detection**.

The denylist is not a monitoring rule. It's a **circuit breaker**.

---

## Comparison to Traditional Security

| Concept | Traditional Security | Chainwatch Boundaries |
|---------|---------------------|----------------------|
| What | Permissions, ACLs | Irreversibility zones |
| When | Pre-action authorization | Pre-boundary refusal |
| Why | "Does user have access?" | "Can this be undone?" |
| Scope | Single action | Execution chain |
| Bypass | Escalate privileges | Human approval only |
| Goal | Prevent unauthorized access | Prevent irreversible damage |

Traditional security answers: "Is this allowed?"
Chainwatch answers: "Can we recover if this proceeds?"

If recovery is impossible, **refuse**.

---

## Misconceptions

### ❌ "This is just a blocklist"

No. A blocklist says "these are bad things."
Irreversible boundaries say "these are points of structural no return."

### ❌ "Better prompting could solve this"

No. Prompts can be bypassed, misunderstood, or ignored.
Boundaries are architectural properties, not linguistic suggestions.

### ❌ "This is too restrictive"

Boundaries don't restrict useful work.
They prevent **irreversible damage**.

If an action is reversible, it's not a boundary.

### ❌ "Humans make mistakes too"

Correct. But humans:
- Have financial liability
- Can be held accountable
- Can't act at agent speed/scale

Boundaries + human approval = human-speed irreversibility.

---

## Design Philosophy

### 1. Explicit Over Implicit

Boundaries must be declared, not inferred.

We don't want ML to "learn" that `/checkout` is dangerous.
We **declare** that payment commitment is irreversible.

### 2. Conservative Defaults

If unsure whether something is a boundary, **treat it as one**.

False positive: Agent asks for approval, human proceeds.
False negative: Money gone, credentials leaked, data destroyed.

Bias toward safety.

### 3. Composable Boundaries

Future versions will support:
```python
boundary = PaymentBoundary() & CredentialBoundary()
if chain.crosses(boundary):
    refuse()
```

Boundaries should compose like functions, not like config.

### 4. Boundaries Are Not Policy

Policy evaluates risk and decides responses.
Boundaries are **structural facts about the execution environment**.

Policy can use boundary proximity to inform decisions.
But boundaries themselves are not negotiable.

---

## Summary

**Chainwatch enforces two classes of irreversible boundaries:**

### 1. Execution Boundaries
Some **actions** cannot be undone:
- Payment commitment
- Credential exposure
- Data destruction
- External communication

### 2. Authority Boundaries
Some **instructions** cannot be un-accepted once admitted to the execution chain:
- Proxied commands
- Injected control flow
- Cross-context steering
- Replayed sessions

**Both answer the same question:**

> "Is this transition in execution context irreversible?"

If yes, **refuse** or **require human override**.

**Chainwatch does not treat boundaries as "bad things."**

**Chainwatch treats them as structural points where recovery becomes impossible.**

This is not security theater.
This is **irreversibility awareness** across both execution and control.

---

**Status:** v0.1.2 implements this as pattern-based denylist (primitive)
**Future:** v0.2.0+ evolves toward formal boundary calculus
**Philosophy:** Irreversibility-aware execution control

---

*Last updated: 2026-02-01*
