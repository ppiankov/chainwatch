# Design Baseline: Principiis obsta

**Principiis obsta** — resist the beginnings.

Chainwatch is designed to intervene early, at the point where small, acceptable actions begin to form irreversible outcomes.

It does not optimize dashboards, alerts, or post-mortems.
It operates at the root of the event, not its aftermath.

The goal is not prediction or persuasion, but early, structural restraint — before recovery becomes expensive or impossible.

---

## The Principle

Some transitions cannot be undone:
- Payment commitment (money leaves account)
- Credential exposure (secrets cannot be "unread")
- Data destruction (files cannot be recovered)
- Authority acceptance (instructions enter execution chain)

Traditional security asks: "Is this allowed?"

Chainwatch asks: "Can we recover if this proceeds?"

If recovery is impossible, **refuse**.

---

## Application to Chainwatch

Chainwatch applies *Principiis obsta* to execution chains:

**Refuse irreversible actions before commitment.**

- **Authority boundaries** - refuse untrusted instructions before they enter the chain
- **Execution boundaries** - refuse actions that cannot be undone

Both ask: "Is this transition irreversible?"

If yes, enforce boundary (DENY or REQUIRE_APPROVAL).

---

## Design Priorities

Chainwatch prioritizes:
- **Execution-time interception** over logging
- **Structural boundaries** over anomaly detection
- **Deterministic control** over probabilistic interpretation
- **Silence when healthy** over continuous reporting

Non-goals:
- Dashboards that explain incidents after they happen
- Alerting or observability focused on post-mortem analysis
- Monetizing failure through reports, metrics, or narratives
- Optimization of reaction speed instead of prevention

---

## Why This Matters

Most tools today:
- Monetize the aftermath
- Celebrate visibility over control
- Sell comfort instead of restraint

Chainwatch re-centers on:
- Irreversibility
- Early intervention
- Refusal as a feature

**You don't get applause for a fire that never started.**

---

## Related Projects

This principle is applied across different surfaces:

- **[Chainwatch](https://github.com/ppiankov/chainwatch)** - Execution chain control for AI agents
- **[kubenow](https://github.com/ppiankov/kubenow)** - Cluster health intervention (not exploration)
- **[infranow](https://github.com/ppiankov/infranow)** - Metric-driven triage (silence as success)

Same principle. Different surfaces.

---

**If an outcome cannot be undone, the system should refuse to proceed.**

---

