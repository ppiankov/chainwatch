# FAQ

## Is this anomaly detection or behavioral ML?
No.

Chainwatch does not attempt to learn “normal” agent behavior.
Autonomous agents do not have stable behavioral baselines,
and treating variance as anomaly breaks legitimate workflows.

Chainwatch enforces explicit, deterministic boundaries
based on sensitivity, purpose, and execution context.

See: docs/why-not-ml.md

---

## Could ML improve detection accuracy?
Possibly, but accuracy is not the primary problem.

The primary failure mode in agent security is loss of context
across execution chains, not lack of signal.

ML cannot restore lost context.
Tracing and correlation can.

---

## Why not use an LLM to judge intent?
Because intent must be explainable and enforceable.

A runtime control plane must justify blocking or modifying actions
with concrete reasons a human can understand and audit.

Probabilistic intent inference is not a sufficient enforcement basis.

---

## Is this a replacement for IAM / DLP / CASB?
No.

Chainwatch assumes those controls exist.
It addresses a different layer: chain-aware runtime enforcement
for autonomous agents.

---

## Does this work only with specific LLMs?
No.

Chainwatch operates at tool, network, or output boundaries.
It does not depend on model internals.

---

## Is this production-ready?
No.

This is an experimental prototype intended to explore a missing
control plane abstraction.
