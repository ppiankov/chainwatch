from __future__ import annotations

from typing import Optional

from .denylist import Denylist
from .types import Action, Decision, PolicyResult, ResultMeta, TraceState

# Deterministic weights, not probabilities.
SENSITIVITY_WEIGHT = {
    "low": 1,
    "medium": 3,
    "high": 6,
}

# Explicit thresholds. Changing these is a policy decision, not tuning.
RISK_ALLOW_MAX = 5
RISK_REDACT_MAX = 10
RISK_APPROVAL_MIN = 11


def _risk_score(
    *,
    meta: ResultMeta,
    state: TraceState,
    is_new_source: bool,
) -> int:
    """
    Compute a simple, explainable risk score.

    This is NOT anomaly detection.
    This is cumulative, deterministic scoring based on semantics.
    """
    risk = 0

    # Sensitivity dominates.
    risk += SENSITIVITY_WEIGHT.get(meta.sensitivity, 1)

    # Volume escalation.
    if meta.rows > 1_000:
        risk += 3
    if meta.rows > 10_000:
        risk += 6

    # New source in the chain increases uncertainty.
    if is_new_source:
        risk += 2

    # External egress is always expensive.
    if meta.egress == "external":
        risk += 6

    return risk


def evaluate(
    *,
    action: Action,
    state: TraceState,
    purpose: str,
    denylist: Optional[Denylist] = None,
) -> PolicyResult:
    """
    Evaluate a single action in the context of the current trace state.

    Decisions must be:
    - deterministic
    - explainable
    - attributable to explicit conditions
    """
    # ---- Denylist check (hard block, highest priority) ----
    if denylist is None:
        try:
            denylist = Denylist.load()
        except Exception:
            # If denylist can't be loaded, continue without it
            pass

    if denylist:
        is_blocked, reason = denylist.is_blocked(action.resource, action.tool)
        if is_blocked:
            return PolicyResult(
                decision=Decision.DENY,
                reason=f"Denylisted: {reason}",
                policy_id="denylist.block",
            )

    action.normalize_meta()
    meta = action.normalized_meta()

    source = action.tool or action.resource.split("/", 1)[0]
    is_new_source = source not in state.seen_sources

    risk = _risk_score(
        meta=meta,
        state=state,
        is_new_source=is_new_source,
    )

    # ---- Purpose-bound hard rules (explicit > scoring) ----

    if purpose == "SOC_efficiency":
        if "salary" in action.resource.lower():
            return PolicyResult(
                decision=Decision.REQUIRE_APPROVAL,
                reason=(
                    "Access to salary data is not allowed for SOC efficiency "
                    "tasks without approval."
                ),
                approval_key="soc_salary_access",
                policy_id="purpose.SOC_efficiency.salary",
            )

    # ---- Risk-based enforcement ----

    if risk >= RISK_APPROVAL_MIN:
        return PolicyResult(
            decision=Decision.REQUIRE_APPROVAL,
            reason=(
                f"High cumulative risk (risk={risk}) based on sensitivity, "
                "volume, and chain context."
            ),
            approval_key="high_risk_action",
            policy_id="risk.high",
        )

    if risk > RISK_ALLOW_MAX:
        return PolicyResult(
            decision=Decision.ALLOW_WITH_REDACTION,
            reason=f"Moderate risk (risk={risk}); sensitive fields must be redacted.",
            redactions={"auto": True},
            policy_id="risk.moderate",
        )

    return PolicyResult(
        decision=Decision.ALLOW,
        reason=f"Low risk action (risk={risk}).",
        policy_id="risk.low",
    )
