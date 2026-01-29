# Decision 003: Enforcement is mode-agnostic (LLM vs no-LLM)

## Decision
Chainwatch enforcement applies regardless of whether a workflow uses an LLM.

## Rationale
PII exposure, over-collection, and improper aggregation can occur without LLM involvement
(e.g., report generation, exports, artifacts shared with humans). Treating `--llm` as the
security boundary creates a false sense of safety.

## Implications
- Reports in no-LLM mode may be redacted or blocked based on purpose and sensitivity.
- LLM mode may add additional risks, but does not change enforcement fundamentals.

## Status
Accepted.
