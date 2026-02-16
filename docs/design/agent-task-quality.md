# Agent Task Quality

Standards for writing agent-executable work orders, skill definitions, and task templates.

---

## The Agent-Ready Rule

> "Write tasks as if another company will run them blindly. If they could execute without you, wouldn't need clarification, and success is objectively verifiable — then it's agent-ready."

---

## Contract-Style Documentation

Every skill, task, or work order must declare:

| Field | Description |
|-------|-------------|
| **Inputs** | What the agent receives (files, params, context) |
| **Outputs** | What the agent must produce (diff, report, JSON, markdown) |
| **Side effects** | What changes in the environment (files written, services called) |
| **Failure modes** | How and why it can fail, and what happens then |
| **Examples** | At least one concrete input → output example |

No lore. No "see also." No aspirational prose. Inputs, outputs, side effects, failure modes, examples.

---

## Structured I/O

Force agents to produce **only** one of these output types:

1. **Diff** — code change with commit message
2. **PR description** — summary, test plan, risk assessment
3. **JSON report** — structured data, machine-parseable
4. **One markdown file** — human-readable analysis

Forbid everything else. If an agent produces "helpful" commentary, reformatting, or unsolicited improvements — the task definition is too loose.

---

## Think/Do Split

Separate planning from execution:

**Pass A (cheap model):**
- Extract tasks from requirements
- Build dependency DAG
- Generate work orders
- Estimate scope and risk

**Pass B (expensive model):**
- Execute bounded, verifiable work orders only
- No planning, no scope expansion
- Success measured against declared outputs

This split prevents expensive models from wasting tokens on planning and cheap models from attempting complex execution.

---

## Work Order Templates

Instantiate structures instead of crafting prompts from scratch.

### Refactor Template
```json
{
  "type": "refactor",
  "intent": "rename X to Y across codebase",
  "scope": ["src/**/*.ts"],
  "inputs": {"old_name": "X", "new_name": "Y"},
  "outputs": ["diff"],
  "verification": ["npm run build", "npm test"],
  "constraints": ["no behavior change", "no new dependencies"]
}
```

### Bugfix Template
```json
{
  "type": "bugfix",
  "intent": "fix issue #N",
  "scope": ["src/module/**"],
  "inputs": {"issue_url": "...", "repro_steps": "..."},
  "outputs": ["diff", "test covering the fix"],
  "verification": ["make test", "make lint"],
  "constraints": ["minimal change", "no refactoring"]
}
```

### Migration Template
```json
{
  "type": "migration",
  "intent": "migrate from library A to library B",
  "scope": ["src/**"],
  "inputs": {"from": "A", "to": "B", "version": "2.x"},
  "outputs": ["diff", "migration notes"],
  "verification": ["make test", "make build"],
  "constraints": ["must have rollback path", "no feature changes"]
}
```

### Investigation Template
```json
{
  "type": "investigate",
  "intent": "analyze why X happens",
  "scope": ["src/**", "logs/**"],
  "inputs": {"symptom": "...", "context": "..."},
  "outputs": ["markdown report"],
  "verification": ["report contains root cause", "report contains proposed fix"],
  "constraints": ["read-only", "no code changes"]
}
```

---

## Agentic Leverage Levels

From least to most autonomous:

1. **Tool-as-Assistant** — linear, single-step commands (human drives)
2. **Structured Prompting** — format constraints, output templates (human designs)
3. **Delegated Work Units** — bounded work orders with verification (agent executes)
4. **Parallel Orchestration** — dependency graphs, worker pools (Runforge)
5. **Self-correcting Systems** — agents verify agents (Chainwatch enforces)

Most teams are at level 1-2. Runforge enables level 4. Chainwatch enables level 5.

---

## Self-Generating Documentation

Tasks and skills should produce their own docs:

```bash
make docs
```

This should generate:
- Input/output tables from task metadata
- CLI help text into README sections
- Template catalog from template directory
- Coverage of documented vs undocumented tasks

Documentation that requires manual maintenance will rot. Documentation generated from source stays current.

---

## Related Documents

- [Governance Doctrine](../governance-doctrine.md) — ecosystem positioning
- [Five Invariant Categories](invariants.md) — mutation manifest format
