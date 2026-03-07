# Agentic Runtime Control Plane

*Protocol specification for governed agent execution. v0.5 — 2026-03-07.*

---

## 1. Purpose

Agents are useful. Ungoverned agents are unsafe. Runtime systems need explicit control loops.

This document defines the contract between components in an agentic execution pipeline. It is artifact-first: it specifies what must exist at each stage, not how any particular tool implements it. The protocol does not care whether execution comes from Claude, Codex, a local model, or a caffeinated squirrel with shell access.

**The problem this solves:** without a shared protocol, each tool in the stack implements its own interpretation of safety, lineage, and approval. The result is four neighboring kingdoms instead of one governed system.

---

## 2. Core Principles

1. **Agents may propose. Agents may not apply irreversible actions.** The irreversible boundary is crossed only by a human or a human-approved automation with explicit scope.

2. **Intent must be serialized before execution.** If the operator's constraints exist only in their head, they do not exist.

3. **Reasoning must be observable.** Long-running sessions accumulate noise. Unobserved reasoning is untrustworthy reasoning.

4. **Every action must produce evidence.** No silent execution. Every stage emits an artifact that can be inspected after the fact.

5. **Lineage must be reconstructable.** Given any execution, it must be possible to trace back: what was the intent, who approved it, what ran, what happened.

6. **Production safety must never depend on the intelligence of the actor.** It must depend on the structure of the system.

7. **Artifacts are immutable once emitted.** New information produces a new artifact referencing the previous one. Editing a vector after a WO is derived from it does not change the WO — it creates a new vector and a new WO.

8. **Integrity is hash chains and signatures, not consensus.** Each artifact includes its own content hash and the hash of its parent artifact. Signatures prove authorship. Append-only storage prevents deletion. No blockchain required — tamper evidence, not decentralization.

---

## 3. Runtime Stages

```
Intent → Work Order → Proposal → Approval → Execution → Verification → Receipt
```

| Stage | Input | Output artifact | Owner |
|-------|-------|----------------|-------|
| Intent | Operator's idea | Vector | Operator (via intent serializer) |
| Work Order | Vector | WO | Operator or scheduling system |
| Proposal | WO | PR / plan / diff | Execution agent |
| Approval | Proposal + approval packet | Approval record | Human approver |
| Execution | Approved proposal | Execution log | Execution system |
| Verification | Execution output | Verification report | Verifier (automated or human) |
| Receipt | All prior artifacts | Lineage receipt | System (automatic) |

Each stage references the previous stage's artifact ID. No stage may skip its predecessor.

### Observation Pipeline

When intent targets investigation rather than execution, the pipeline branches:

```
Intent → Observation WO → Swarm Dispatch → Findings Packet → [Synthesis WO → Execution Pipeline]
```

| Stage | Input | Output artifact | Owner |
|-------|-------|----------------|-------|
| Intent | Operator's idea | Vector | Operator (via intent serializer) |
| Observation WO | Vector | SWO | Operator or VectorPad |
| Swarm Dispatch | SWO | Dispatch record | Dispatcher (tokencontrol) |
| Evidence Collection | SWO + environment access | Raw findings | Observer swarm (nullbots) |
| Aggregation | Raw findings | Findings Packet | Dispatcher (central) |
| Synthesis | Findings Packet | Candidate remediation WOs | Synthesis agent |

The observation pipeline does not reach the Approval → Execution → Verification stages. It produces evidence and candidate WOs. Those candidate WOs enter the standard execution pipeline as new work orders — each requiring its own approval.

**Hard rule:** Observation pipelines are read-only. No stage in the observation pipeline may mutate target environment state.

### Abort States

Every stage has a terminal failure state. Aborted artifacts are still emitted (with `status: aborted` and a reason) to preserve lineage.

| Stage | Abort state | Trigger |
|-------|------------|---------|
| Intent | Vector rejected | Operator abandons or nudge protocol flags as unsafe |
| Work Order | WO closed | Scope no longer valid, dependency changed |
| Proposal | Proposal abandoned | Agent cannot satisfy WO requirements |
| Approval | Approval denied | Approver rejects |
| Execution | Execution halted | Runtime error, policy violation, hold triggered |
| Verification | Verification failed | Build, tests, lint, or secrets scan fails |
| Receipt | Receipt incomplete | Any upstream artifact in abort state |
| Observation WO | Observation cancelled | Scope invalid, environment unreachable |
| Evidence Collection | Collection halted | Constraint violation, runtime exceeded, mutation attempted |
| Findings Packet | Packet incomplete | Swarm returned partial results, aggregation failed |

---

## 4. Artifact Definitions

### ID Format

All artifact IDs must be globally unique across repos and systems.

| Artifact | Format | Example |
|----------|--------|---------|
| Vector | `vp-<timestamp>-<short-hash>` | `vp-20260307-a4e9` |
| Work Order | `wo-<repo>-<number>` | `wo-chainwatch-083` |
| Proposal | `pr-<platform>-<number>` | `pr-gh-218` |
| Approval | `ap-<uuid>` | `ap-c91f3e02` |
| Execution | `ex-<uuid>` | `ex-7d441a0b` |
| Verification | `vr-<uuid>` | `vr-902e8f1c` |
| Receipt | `rc-<uuid>` | `rc-b3f09a77` |
| Observation WO | `swo-<id>` | `swo-dev-014` |
| Findings Packet | `fp-<uuid>` | `fp-8c3a21e0` |
| Synthesis WO | `syn-<uuid>` | `syn-a2c4e801` |

### Immutability

Artifacts are write-once. Once emitted, an artifact cannot be modified. If the underlying information changes, a new artifact is created with a new ID and a reference to the previous one.

### Integrity

Every artifact carries:

| Field | Description |
|-------|-------------|
| `content_hash` | SHA-256 of the artifact's canonical JSON representation |
| `parent_hash` | Content hash of the previous artifact in the chain |
| `actor_id` | Who created this artifact |
| `signature` | Ed25519 or KMS-backed signature over `content_hash + parent_hash + actor_id` |

Storage is append-only. Deletion of artifacts is a protocol violation.

### 4.1 Vector

The serialized intent of the operator. Created before execution begins.

| Field | Required | Description |
|-------|----------|-------------|
| `vector_id` | yes | Unique identifier (e.g., `vp-4e92`) |
| `timestamp` | yes | Creation time |
| `operator` | yes | Who created this vector |
| `scope` | yes | What this vector targets (files, repos, infrastructure) |
| `constraints` | yes | What the transformation must satisfy |
| `preservation` | yes | What must NOT change |
| `blast_radius` | yes | Count and type of target artifacts |
| `ambiguity_score` | yes | Structural measurement: brevity-to-scope ratio |
| `pastewatch_status` | if available | Secret scan result on outbound payload |
| `vector_hash` | yes | Content hash for integrity |

**Invariant:** If `preservation` is empty and `blast_radius > 1`, the vector is flagged as potentially ambiguous.

### 4.2 Work Order (WO)

A scoped unit of work derived from a vector or observation.

| Field | Required | Description |
|-------|----------|-------------|
| `wo_id` | yes | Unique identifier (e.g., `cw-083`) |
| `vector_id` | if derived from vector | Reference to source vector |
| `title` | yes | One-line description |
| `scope` | yes | Files to create or modify |
| `acceptance_criteria` | yes | What "done" means |
| `verification_command` | yes | How to verify completion |
| `rollback_strategy` | yes | How to undo. If empty: ⚠ rollback undefined |
| `environment` | yes | Target environment identity |
| `priority` | yes | Scheduling priority |

**Invariant:** A WO with empty `rollback_strategy` must be visually flagged in any approval UI.

#### WO Type Taxonomy

Work orders carry a `type` field that determines which pipeline they enter:

| Type | Mode | Pipeline | Mutation allowed |
|------|------|----------|-----------------|
| `execution` | — | Standard (§3) | Yes, within scope |
| `observation` | `single` | Standard with observer agent | No |
| `observation` | `swarm` | Observation pipeline (§3) | No |
| `synthesis` | — | Generates candidate WOs from findings | No (output only) |

Type determines constraints. An `observation` WO with `mode: swarm` enters the observation pipeline and must satisfy the stricter fields defined in §4.8.

### 4.3 Proposal

The agent's proposed changes. A PR, a plan output, a diff — the format varies by domain.

| Field | Required | Description |
|-------|----------|-------------|
| `proposal_id` | yes | Unique identifier (e.g., `pr-218`) |
| `wo_id` | yes | Reference to source WO |
| `diff` | yes | The proposed changes |
| `plan_output` | if infra | Terraform plan, migration plan, etc. |
| `blast_radius` | yes | Computed from diff (files, lines, resources) |
| `environment` | yes | Must match WO environment |
| `rollback_strategy` | yes | Inherited from WO, may be refined |

### 4.4 Approval Record

The human decision to proceed.

| Field | Required | Description |
|-------|----------|-------------|
| `approval_id` | yes | Unique identifier (e.g., `ap-991`) |
| `proposal_id` | yes | What was approved |
| `proposal_hash` | yes | Content hash of the proposal at approval time — freezes the proposal |
| `approver` | yes | Who approved |
| `timestamp` | yes | When |
| `decision` | yes | `approved` / `denied` / `approved_with_conditions` |
| `conditions` | if conditional | What conditions were attached |
| `environment_confirmed` | yes | Approver explicitly confirmed environment |

**Invariant:** Approval without `environment_confirmed = true` is invalid for production.

**Invariant:** If the proposal's current content hash does not match `proposal_hash`, the approval is stale and execution must not proceed. Proposals cannot drift after approval.

### 4.5 Execution Log

Evidence that the approved proposal was applied.

| Field | Required | Description |
|-------|----------|-------------|
| `execution_id` | yes | Unique identifier (e.g., `ex-441`) |
| `approval_id` | yes | Reference to approval |
| `started_at` | yes | Execution start |
| `completed_at` | yes | Execution end |
| `exit_code` | yes | Success or failure |
| `output` | yes | Stdout/stderr or structured log |
| `artifacts_modified` | yes | List of files/resources changed |

### 4.6 Verification Report

Confirmation that the execution produced the expected result.

| Field | Required | Description |
|-------|----------|-------------|
| `verification_id` | yes | Unique identifier (e.g., `vr-902`) |
| `execution_id` | yes | What was verified |
| `environment_id` | yes | Where verification ran — must match execution environment |
| `verification_method` | yes | Command or process used (e.g., `make verify`) |
| `build` | yes | Pass/fail |
| `tests` | yes | Pass/fail with count |
| `lint` | yes | Pass/fail with count |
| `secrets_scan` | yes | Pass/fail |
| `overall` | yes | `PASS` / `FAIL` |
| `timestamp` | yes | When verification completed |

### 4.7 Lineage Receipt

The complete chain for one unit of work. Generated automatically from prior artifacts.

| Field | Required | Description |
|-------|----------|-------------|
| `receipt_id` | yes | Unique identifier |
| `vector_id` | if applicable | Intent origin |
| `wo_id` | yes | Work order |
| `proposal_id` | yes | What was proposed |
| `approval_id` | yes | Who approved |
| `execution_id` | yes | What ran |
| `verification_id` | yes | What was verified |
| `chain_hash` | yes | Hash of all artifact IDs for integrity |

### 4.8 Observation Work Order (SWO)

A scoped investigation request for observer agents or swarms. Extends the base WO (§4.2) with observation-specific fields.

| Field | Required | Description |
|-------|----------|-------------|
| `wo_id` | yes | Unique identifier (e.g., `swo-dev-014`) |
| `type` | yes | Must be `observation` |
| `mode` | yes | `single` or `swarm` |
| `vector_id` | if derived from vector | Reference to source vector |
| `title` | yes | One-line description |
| `goal` | yes | What the observation should determine |
| **Scope** | | |
| `scope.environments` | yes | Explicit list of target environments |
| `scope.repos` | if applicable | Repositories to examine |
| `scope.clusters` | if applicable | Infrastructure clusters |
| `scope.regions` | if applicable | Cloud regions |
| **Constraints** | | |
| `constraints.access_mode` | yes | Must be `read-only` for observation |
| `constraints.no_mutation` | yes | Must be `true` |
| `constraints.no_remediation` | yes | Must be `true` |
| `constraints.max_fanout` | if swarm | Maximum parallel observers |
| `constraints.max_runtime` | yes | Time bound for the observation |
| `constraints.allowed_tools` | yes | Whitelist of tools observers may use |
| `constraints.forbidden_tools` | yes | Blacklist of tools observers must never use |
| `constraints.max_findings` | yes | Maximum findings per packet (default: system limit) |
| `constraints.max_evidence_bytes` | yes | Maximum raw evidence size per finding |
| `constraints.max_candidate_wos` | if enabled | Maximum candidate remediation WOs to generate |
| **Focus** | | |
| `focus.finding_classes` | yes | What classes of signal matter (e.g., `stale-user`, `orphaned-grant`) |
| `focus.exclude_classes` | if applicable | What to explicitly ignore |
| **Evidence requirements** | | |
| `evidence_requirements.minimum_confidence` | yes | `low` / `medium` / `high` |
| `evidence_requirements.include_raw_evidence` | yes | Whether to include raw query output |
| `evidence_requirements.include_queries` | yes | Whether to include the queries that produced evidence |
| `evidence_requirements.include_timestamps` | yes | Whether to timestamp each finding |
| `evidence_requirements.include_environment_identity` | yes | Whether to tag each finding with its environment |
| **Deduplication** | | |
| `deduplication.strategy` | yes | How to collapse duplicate findings (e.g., `by-resource-and-finding-class`) |
| `deduplication.collapse_similar` | yes | Whether to merge near-duplicates |
| **Output** | | |
| `output.format` | yes | Must be `findings-packet` |
| `output.candidate_wo_generation` | yes | Whether to generate candidate remediation WOs |
| `output.include_severity` | yes | Whether findings carry severity |
| `output.include_blast_radius` | yes | Whether findings carry blast radius |
| `output.include_remediation_hints` | yes | Whether findings carry suggested fixes |
| **Routing** | | |
| `routing.target_profile` | if swarm | Which observer profile to dispatch to |
| `routing.dispatch_strategy` | if swarm | `fanout-aggregate` / `sequential` |
| `routing.aggregation_mode` | if swarm | `central` / `distributed` |
| **Lineage** | | |
| `lineage.parent_vector_id` | yes | Vector that spawned this observation |
| `lineage.parent_hash` | yes | Content hash of parent vector |
| `lineage.dispatch_id` | after dispatch | Set by dispatcher — identifies which swarm run produced results |

**Minimal viable SWO** (for MVP implementations):

`wo_id`, `type`, `mode`, `title`, `goal`, `scope.environments`, `constraints.access_mode`, `constraints.no_mutation`, `focus.finding_classes`, `output.format`, `routing.target_profile`, `lineage.parent_vector_id`

**Invariant:** If `constraints.access_mode` is not `read-only` or `constraints.no_mutation` is not `true`, the SWO is invalid and must be rejected.

**Invariant:** If `mode: swarm` and `constraints.max_fanout` is absent, the dispatcher must apply a system default (not unlimited).

#### Observation Preflight (VectorPad display)

Before launching an SWO, the intent serializer must surface:

```
Swarm Observation WO
Target environments: [count]
Access mode: read-only
Allowed tools: [list]
Finding classes: [list]
Output: findings packet [+ candidate WOs if enabled]
Blast radius: [estimated]
```

If the SWO is under-specified, nudge with:
- What environments exactly?
- What classes of findings matter?
- Do you want candidate remediation WOs generated?
- What must the swarm ignore?

### 4.9 Findings Packet

The structured output of an observation. The handoff artifact into WO generation, human review, or remediation planning.

| Field | Required | Description |
|-------|----------|-------------|
| `findings_packet_id` | yes | Unique identifier (e.g., `fp-8c3a21e0`) |
| `source_wo_id` | yes | The SWO that produced this packet |
| `source_dispatch_id` | yes | Which swarm dispatch run produced this packet |
| **Summary** | | |
| `summary.environments_scanned` | yes | Count of environments observed |
| `summary.findings_total` | yes | Raw finding count before deduplication |
| `summary.deduplicated_findings_total` | yes | Finding count after deduplication |
| `summary.candidate_wos_generated` | yes | Count of candidate remediation WOs |
| `summary.nodes_attempted` | yes | Swarm members dispatched |
| `summary.nodes_succeeded` | yes | Swarm members that completed |
| `summary.nodes_failed` | yes | Swarm members that failed |
| **Findings** (array) | | |
| `findings[].finding_id` | yes | Unique finding identifier (e.g., `f-001`) |
| `findings[].class` | yes | Finding class (must match SWO focus) |
| `findings[].resource` | yes | What resource the finding concerns |
| `findings[].environment_id` | yes | Where the finding was observed |
| `findings[].severity` | yes | `critical` / `high` / `medium` / `low` |
| `findings[].confidence` | yes | `high` / `medium` / `low` |
| `findings[].evidence.query` | yes | The query or command that produced evidence |
| `findings[].evidence.observed_at` | yes | Timestamp of observation |
| `findings[].evidence.raw_excerpt` | yes | Raw output excerpt |
| `findings[].blast_radius.environments` | yes | How many environments affected |
| `findings[].blast_radius.clusters` | if applicable | How many clusters affected |
| `findings[].remediation_hint` | if enabled | Suggested fix (human decides whether to act) |
| `findings[].candidate_wo_id` | if enabled | Reference to generated candidate WO |

**Invariant:** Every finding must carry evidence. Evidence-free findings are invalid — "trust me bro" is not an evidence model.

**Invariant:** Every finding must carry `environment_id`. Findings without environment identity cannot be acted upon safely.

**Partial failure rule:** Partial swarm failure does not invalidate successful findings. The Findings Packet is emitted with whatever succeeded, but `summary.nodes_failed > 0` marks the packet as incomplete. Confidence of aggregate conclusions must be degraded proportionally. Systems consuming an incomplete packet must surface the gap — silent optimism is a failure mode.

### 4.10 Synthesis Work Order (future)

Takes a Findings Packet and generates candidate remediation WOs. Each candidate WO enters the standard execution pipeline — requiring its own approval, execution, and verification.

*Schema to be defined.*

**Invariant:** Synthesis may generate candidate WOs and remediation proposals. Synthesis may not mutate infrastructure, approve actions, or alter prior evidence artifacts. The synthesis agent is a proposer, not an executor — creativity stops at the proposal boundary.

---

## 5. Trust Model

### Roles

| Role | Description |
|------|-------------|
| **Operator** | Human who defines intent, approves proposals, owns decisions |
| **Observer agent** | Read-only agent that investigates, diagnoses, reports. Cannot modify. |
| **Observer swarm** | Multiple observer agents dispatched via SWO. Read-only, bounded fanout, centrally aggregated. |
| **Execution agent** | Agent that implements proposals. Can modify files within WO scope. Cannot apply to production. |
| **Synthesis agent** | Agent that generates candidate WOs from findings. Cannot modify — output only. |
| **Verifier** | Automated system that checks execution output. Cannot modify. |
| **Approver** | Human (or human-delegated automation) that authorizes boundary crossings. |

### Permission Matrix

| Action | Operator | Observer | Execution agent | Verifier | Approver |
|--------|----------|----------|----------------|----------|----------|
| Define intent | ✓ | — | — | — | — |
| Read source / state | ✓ | ✓ | ✓ | ✓ | ✓ |
| Propose changes | ✓ | — | ✓ | — | — |
| Execute safe operations | ✓ | — | ✓ | — | — |
| Execute irreversible operations | — | — | — | — | ✓ |
| Approve proposals | ✓ | — | — | — | ✓ |
| Verify results | ✓ | ✓ | — | ✓ | ✓ |
| Hold / pause execution | ✓ | — | — | — | ✓ |

**Hard rule:** No agent role may execute an irreversible operation. Irreversible operations require human approval, always.

---

## 6. Control Loops

### 6.1 Ambiguity Loop (pre-flight)

**Purpose:** Catch under-specified intent before execution.

**When:** Before WO creation. Runs on every vector.

```
operator intent → serialization → ambiguity check → pass / nudge
```

Triggers:
- Brevity-to-scope ratio exceeds threshold
- Preservation field is empty with blast radius > 1
- Vague verb + wide scope

Action: Surface nudge questions, not block. Non-blocking by default.

### 6.2 Enforcement Loop (runtime)

**Purpose:** Gate irreversible operations.

**When:** Before every tool call / command execution during agent work.

```
agent proposes action → policy evaluation → allow / deny / require-approval
```

Irreversibility classification: `SAFE → SENSITIVE → COMMITMENT → IRREVERSIBLE`

Monotonic: risk level can only increase within a session, never decrease.

Action: Hard block at irreversible boundary. No override without explicit approval or breakglass.

### 6.3 Reasoning Hygiene Loop (runtime)

**Purpose:** Maintain session quality during long-running agent work.

**When:** Continuously during sessions exceeding 50 turns or 30% context utilization.

```
session state → signal measurement → noise detection → cleanup / compact / alert
```

Triggers:
- Context utilization above threshold
- Signal-to-noise ratio declining
- Decision density dropping
- Cost per decision rising

Action: Automated cleanup of redundant context. Alert operator when compaction quality is uncertain.

### 6.4 Verification Loop (post-execution)

**Purpose:** Confirm execution produced expected results.

**When:** After every execution completes. Mandatory — not optional.

```
execution output → build → test → lint → secrets scan → report
```

Failed verification blocks the lineage receipt from being marked complete.

### 6.5 Rollback Loop (on failure)

**Purpose:** Ensure every change has a declared undo path.

**When:** At proposal creation (declare) and after failed verification (surface).

```
proposal → rollback strategy declared? → yes: proceed / no: ⚠ flag
```

Rollback is not automatic. It is declared. The system surfaces the rollback path; the human decides whether to invoke it.

If rollback strategy is blank, the system must visually flag this at approval time.

### 6.6 Observation Preflight Loop (pre-dispatch)

**Purpose:** Validate swarm observation WOs before fan-out. Swarm dispatch gets stricter preflight, not looser.

**When:** Before dispatching any SWO to an observer swarm.

```
SWO received → constraint validation → scope check → fanout bound → dispatch / reject
```

Required validations:
- `access_mode` is `read-only` and `no_mutation` is `true`
- Target environments are explicitly listed (not inferred)
- `max_fanout` is present and within system limits
- `max_runtime` is present and within system limits
- `allowed_tools` contains only read-capable tools
- `forbidden_tools` is not empty
- `finding_classes` is not empty (unfocused swarms are rejected)

Action: Hard reject on any constraint violation. No partial dispatch.

**Hard rule:** If the SWO preflight passes but a swarm member attempts mutation at runtime, the member is halted and the finding is flagged as a constraint violation.

---

## 7. Environment Identity

Environment is not inferred. It is declared and persistent.

| Property | Requirement |
|----------|-------------|
| `environment_id` | Explicit, unique, human-readable (e.g., `prod-eu-west-1`) |
| Persistence | Survives session restarts, agent changes, tool changes |
| Visual treatment | Production must be visually distinct in every UI and log |
| Approval | Production changes require stronger approval (explicit environment confirmation) |
| Agent inference | Agents may NOT infer environment from path names, hostnames, or context |

**Hard rule:** Environment identity must appear in every proposal, approval, and execution artifact. If absent, the artifact is invalid.

---

## 8. Approval Packet Standard

When a human reviews a proposal, they see one canonical shape:

```
## Proposal: [proposal_id]
Source WO: [wo_id]
Environment: [environment_id]    ← visually distinct if production

## Changes
[diff or plan output]

## Blast Radius
[count of files/resources affected]

## Rollback Strategy
[declared rollback path]          ← ⚠ if empty

## Verification Target
[command that will verify success]

## Approval
- [ ] Changes reviewed
- [ ] Environment confirmed
- [ ] Rollback path acceptable
- [ ] Ready to apply
```

All fields are required. Missing fields must be surfaced, not silently omitted.

---

## 9. Verification Receipt Standard

After execution and verification, the system emits:

```
## Receipt: [receipt_id]
Lineage: [vector_id] → [wo_id] → [proposal_id] → [approval_id] → [execution_id]

## Verification
Build:    [OK/FAIL]
Tests:    [X/Y passed]
Lint:     [OK/X issues]
Secrets:  [OK/FAIL]
Overall:  [PASS/FAIL]

## Execution
Duration: [Xm Ys]
Exit:     [0/N]
Artifacts modified: [list]

## Chain integrity
Hash: [chain_hash]
```

---

## 10. Failure Modes

| Failure | Definition | Detection | Prevention | Artifact involved |
|---------|-----------|-----------|------------|-------------------|
| **Ambiguous vector** | Intent compressed below safe execution resolution | Brevity-to-scope ratio, empty preservation | Nudge protocol, reference examples | Vector |
| **Vector hijacking** | External content rotates agent reasoning | CDR spike, decision conflict | Input sanitization, session isolation | Vector, Execution |
| **Missing rollback** | Change proposed with no declared undo path | Empty rollback field | Flag at approval time | Proposal, Approval |
| **Environment misidentification** | Agent targets wrong environment | Environment field mismatch | Persistent environment identity, explicit confirmation | Proposal, Approval, Execution |
| **Irreversible action without gate** | Destructive operation executes without approval | Policy evaluation miss | Deterministic policy, fail-closed enforcement | Execution |
| **Reasoning decay** | Session quality degrades from noise accumulation | Signal ratio, decision density, cost per decision | Automated cleanup, compaction monitoring | Execution, Verification |
| **Scope escalation** | Agent expands beyond WO scope during execution | Diff vs WO scope comparison | Scoped credentials, file-level access control | WO, Proposal, Execution |
| **Approval fatigue** | Human rubber-stamps without reviewing | Non-standard approval packets, missing fields | Canonical packet format, required fields | Approval |
| **Stale approval** | Proposal changed after approval was granted | `proposal_hash` mismatch | Hash freeze on approval | Approval, Proposal |
| **Unbounded fanout** | Swarm dispatched without fanout limit | Missing `max_fanout` | Observation preflight rejection | SWO |
| **Evidence-free finding** | Swarm reports finding without supporting evidence | Empty evidence fields | Findings Packet validation | Findings Packet |
| **Swarm mutation attempt** | Observer agent attempts to modify target environment | Tool call outside allowed set | Constraint enforcement, member halt | SWO, Findings Packet |
| **Unfocused observation** | Swarm returns noise across all signal classes | Empty `finding_classes` | Observation preflight rejection | SWO |
| **Aggregation failure** | Swarm partial results cannot be combined | Missing environment identity, inconsistent schema | Deduplication validation, packet marked incomplete | Findings Packet |
| **Observation scope drift** | Swarm collects evidence from environments or resources not explicitly authorized in SWO scope | Finding `environment_id` not in `scope.environments`, resource outside declared scope | Scope validation on each finding, reject out-of-scope evidence | SWO, Findings Packet |
| **Vector drift cascade** | System gradually stops executing original intent and begins solving a different problem. Happens slowly over many turns — earlier reasoning becomes invalid, RHL collapses, tokens spike, LOC output drops | CDR spike, RHL collapse, scope expansion without new WO, assumption changes detected by reasoning diff | WO-scoped execution (locks vector), context cleanup (removes tangent pollution), intent serialization (detects drift before code runs) | Vector, WO, Execution |

---

## 11. Component Mapping

This spec is tool-agnostic. The current implementation maps as:

| Stage | Component | Role |
|-------|-----------|------|
| Intent serialization | VectorPad | Ambiguity detection, nudge protocol, blast radius, SWO emission |
| Work scheduling | tokencontrol | Parallel dispatch, conflict detection, cost tracking, swarm fanout |
| Boundary enforcement | Chainwatch | Policy evaluation, zone detection, approval workflow |
| Secret scanning | Pastewatch | Pre-flight and copy-out payload scanning |
| Reasoning observation | ContextSpectre | Signal measurement, noise cleanup, decay detection |
| Distributed observation | nullbot swarm | Read-only evidence collection, findings aggregation |

The protocol does not require all components. Any subset provides value. All five provide defense in depth.

---

## 12. Open Questions

- **Credential isolation depth.** Should observe/propose/apply use separate credentials, or is profile-based isolation sufficient? Swarm observers likely need distinct read-only credentials per environment.
- **Approval delegation.** Can a human pre-approve classes of changes (e.g., "all non-prod changes under 10 lines")? What are the safety bounds?
- **Cross-repo lineage.** When a vector spawns WOs in multiple repos, how does lineage compose? One receipt per WO, or one receipt per vector?
- **Cost ceiling.** Should the scheduling system enforce a global token budget per run? Per day? Per project? Swarm fanout multiplies cost — per-SWO budgets may be needed.
- **Semantic conflict detection.** tokencontrol catches file-level conflicts. Is semantic overlap detection (two WOs changing the same interface differently) worth the complexity?
- **Automatic rollback triggers.** Should failed verification automatically invoke the declared rollback, or always require human decision?
- **Receipt storage.** Where do receipts live? Per-repo? Central store? Git-tracked or ephemeral?
- **Synthesis WO schema.** What fields does the synthesis agent need to generate candidate remediation WOs from a findings packet? How are generated WOs distinguished from human-authored WOs in the approval UI?
- **Swarm partial failure.** Interim rule defined in §4.9: emit with partial results, degrade confidence, surface the gap. Open question: should confidence degradation be proportional (linear to node failure rate) or stepped (threshold-based)?
- **Observation-to-execution handoff.** When a findings packet generates candidate WOs, how are they queued? Batch approval or individual?

---

*This specification defines the contract. Implementation details belong in each component's documentation. The spec changes when the contract changes, not when the implementation changes.*
