# Why not ML (yet)

Chainwatch deliberately does **not** use machine learning or anomaly detection
to make enforcement decisions in its initial design.

This is not an oversight. It is a constraint.

## The problem is not lack of signal
Agent executions already produce rich, structured signals:
- which tools were used
- which resources were accessed
- what data classes were involved
- how much data was touched
- where outputs were sent

The failure mode in agent security today is **not insufficient data**,
but insufficient **context preservation and enforcement**.

Before learning patterns, the system must first *see the whole chain*.

## Enforcement requires explainability
Chainwatch is a runtime control plane.
It must be able to:
- block an action,
- modify an action,
- or rewrite an output,

and then explain *why* to a human in real time.

Probabilistic decisions such as:
> “This action scored 0.83 anomalous”

are not acceptable enforcement justifications.

Users and operators need answers like:
- “This combined HR and salary data for a SOC task”
- “This exceeded the allowed data volume for the stated purpose”
- “This attempted to export sensitive data externally”

Deterministic, rule-based decisions are explainable by construction.
ML decisions are not.

## There is no stable baseline to learn from
ML-based anomaly detection assumes:
- repeatable behavior,
- stable distributions,
- and a clear definition of “normal”.

Autonomous agents violate all three.

The same user request may:
- touch 10 records today,
- 500 records tomorrow,
- and a different set of systems next week,

without being malicious.

Training a model on this behavior either:
- produces constant false positives, or
- silently normalizes dangerous behavior.

Neither outcome is acceptable for a control plane.

## False positives are more dangerous than false negatives
In observability, false positives are annoying.
In runtime enforcement, false positives break workflows.

A system that unpredictably blocks agent actions
will be bypassed, disabled, or ignored.

Chainwatch prioritizes:
- predictable behavior
- explicit boundaries
- human-understandable rules

over speculative detection accuracy.

## ML does not solve the core problem
The core problem Chainwatch addresses is:

> Existing security controls lose context across agent execution chains.

ML does not restore lost context.
Tracing, correlation, and semantic enrichment do.

Applying ML before fixing context loss
is optimizing the wrong layer.

## Where ML may be used later
ML is not rejected forever.

Potential future uses include:
- ranking traces for post-hoc review
- assisting policy authorship
- summarizing large execution histories
- detecting novel combinations *after* enforcement boundaries exist

ML may assist humans.
It does not replace explicit control.

## Design principle
Chainwatch follows a strict ordering:

1. Preserve execution context
2. Enforce deterministic boundaries
3. Make decisions explainable
4. Only then consider learning from behavior

This project intentionally stops at step 3.
