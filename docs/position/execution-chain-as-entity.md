# Execution Chains as a First-Class Security Boundary

## Abstract

Modern autonomous systems and AI agents do not operate as isolated requests
or predictable sessions. Instead, they execute evolving chains of actions,
where each step depends on the accumulated context, data, and side effects
of previous steps.

Existing security and governance tools are not designed to reason about such
chains. They validate identities, requests, sessions, or content in isolation,
but lose context across execution boundaries.

This document argues that the execution chain itself must be treated as a
first-class entity for security enforcement. It introduces the concept of
chain-aware enforcement and explains why traditional controls are insufficient
for autonomous systems.

---

## 1. The problem

AI agents and autonomous workflows behave fundamentally differently from
traditional software:

- The sequence of actions is not fully known in advance
- The scope of data access expands dynamically
- Intermediate results influence future decisions
- Risk accumulates over time rather than appearing in a single request

A single high-level request (e.g. “analyze SOC efficiency”) can result in:
- dozens or hundreds of tool invocations
- access to multiple independent systems
- aggregation of data with different sensitivity levels
- irreversible outputs (reports, exports, decisions)

Despite this, most security controls still assume a request-centric or
session-centric execution model.

This mismatch is the root of many agent-related security failures.

---

## 2. Why existing tools fail by design

Existing security tools are not “bad” — they answer different questions.

### Identity and Access Management (IAM)
IAM answers:
> “Is this identity allowed to access this resource?”

IAM does not answer:
> “Should this identity still be allowed to perform this action given everything
> it has already accessed and combined during this execution?”

### Network and Perimeter Controls (NGFW, NDR)
These tools answer:
> “Where did this request come from?”
> “Is this connection allowed?”

They do not retain semantic context across multiple requests or reason about
the intent and consequences of an evolving workflow.

### PAM / JIT Access
PAM systems assume:
> request → approval → execution → revocation

Autonomous agents do not follow this pattern. Their access patterns change
during execution, and approval cannot be meaningfully requested in advance
for actions that are discovered dynamically.

### DLP / CASB
DLP systems inspect content at specific choke points:
- uploads
- downloads
- emails
- API responses

They do not reason about:
- cumulative sensitivity
- joins between datasets
- purpose drift across steps
- whether an output is acceptable given how it was produced

### Observability and tracing
Tracing systems can show *what happened*, but they do not decide *whether it
should have happened*. Observability is descriptive; enforcement is normative.

---

## 3. The missing abstraction: the execution chain

An execution chain is the ordered sequence of actions performed by an agent
or autonomous system in pursuit of a goal.

An execution chain has the following properties:

- **Stateful**: each step changes the context for the next step
- **Cumulative**: risk and sensitivity increase over time
- **Non-deterministic in shape**: the path is discovered during execution
- **Deterministic in consequence**: side effects cannot be undone
- **Cross-boundary**: spans files, APIs, tools, networks, and outputs

Crucially, the chain is neither:
- a single request
- a static session
- a fixed workflow definition

Treating the chain as an implicit or emergent property causes loss of control.

---

## 4. Why the chain must be first-class

Security decisions that ignore prior steps inevitably fail in autonomous systems.

Examples:
- Access to HR data may be acceptable alone, but not after joining with incident data
- A file read may be safe early in execution but dangerous after aggregation
- Exporting results may be acceptable until sensitivity crosses a threshold

In these cases, the correctness of the decision depends on **history**, not
just the current request.

First-class treatment of the execution chain enables:
- enforcement based on accumulated sensitivity
- detection of purpose drift
- dynamic revocation of previously acceptable actions
- output control based on provenance, not content alone

Without this, least-privilege either breaks agents or becomes meaningless.

---

## 5. Chain-aware enforcement

Chain-aware enforcement evaluates each action in the context of the entire
execution chain to date.

It answers the question:
> “Given everything that has already happened, is this next action still allowed?”

Key characteristics:
- enforcement is runtime, not post-hoc
- decisions are deterministic and explainable
- policies operate on chain state, not isolated events
- enforcement can block, redact, rewrite, or require approval

Importantly, this approach does not require:
- intent prediction
- probabilistic risk scoring
- machine learning classifiers

The chain provides sufficient context for deterministic control.

---

## 6. Relationship to AI and LLMs

Language models introduce additional risks (hallucination, prompt injection,
unintended synthesis), but they are not the root cause of the problem.

Execution chains exist:
- with or without LLMs
- in scripted automation
- in report generation
- in data analysis pipelines

Therefore, chain-aware enforcement must be **mode-agnostic**. Disabling an LLM
does not eliminate the risk of over-collection, leakage, or improper aggregation.

---

## 7. Chainwatch as a reference implementation

Chainwatch is a reference implementation of chain-aware enforcement for
autonomous systems.

It demonstrates:
- explicit modeling of execution chains
- accumulation of sensitivity and volume over time
- runtime enforcement at concrete boundaries
- deterministic decisions without ML

Chainwatch is not a complete solution, but a proof that chain-aware control
is feasible and necessary.

---

## 8. What this is not

To avoid confusion, chain-aware enforcement is not:
- observability or tracing
- policy-as-code for static workflows
- ML-based anomaly detection
- intent inference or trust scoring
- a replacement for IAM, DLP, or network controls

It complements existing controls by addressing a layer they cannot reach.

---

## 9. Future extension: embodied systems and intention reporting

The execution-chain abstraction is not limited to purely digital systems.
As autonomous agents become embedded in physical systems (robots, vehicles,
industrial automation), execution chains will increasingly span both digital
and physical actions.

In such systems, runtime enforcement may require not only observation of
performed actions, but also explicit reporting of intended actions or goals
prior to execution. These intention signals are not treated as authoritative,
but as additional context that can be evaluated against accumulated chain
state, environmental constraints, and safety policies.

This document does not attempt to define intention vectors or embodied
enforcement mechanisms. It merely notes that treating execution chains as
first-class entities provides a necessary foundation for governing autonomous
systems whose actions have irreversible physical consequences.

The appropriate abstractions for intention reporting and physical enforcement
should emerge from real-world failures and operational experience, rather than
premature formalization.

## 10. Conclusion

Autonomous systems require a shift in how security boundaries are defined.
As long as execution chains remain implicit, enforcement will remain reactive
and incomplete.

Treating the execution chain as a first-class entity enables deterministic,
context-aware control without sacrificing agent usefulness.

This abstraction is missing from most current tools. Its introduction is
necessary for secure operation of autonomous systems at scale.
