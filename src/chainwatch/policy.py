from .types import Action, TraceState, PolicyResult, Decision

SENS_WEIGHT = {"low": 1, "medium": 3, "high": 6}

def evaluate(action: Action, state: TraceState, purpose: str) -> PolicyResult:
    sensitivity = action.result_meta.get("sensitivity", "low")
    rows = int(action.result_meta.get("rows", 0))
    egress = action.result_meta.get("egress", "internal")

    # update-like logic lives in tracer in a fuller version; here keep it simple
    risk = SENS_WEIGHT.get(sensitivity, 1)
    if rows > 1000:
        risk += 3
    if rows > 10000:
        risk += 6
    if egress == "external":
        risk += 6

    # purpose-bound rule examples
    if purpose == "SOC_efficiency" and "salary" in action.resource.lower():
        return PolicyResult(Decision.REQUIRE_APPROVAL, "Salary access requires approval for this purpose.", approval_key="salary-access")

    if risk >= 12:
        return PolicyResult(Decision.REQUIRE_APPROVAL, f"High risk action (risk={risk}).", approval_key="high-risk")
    if risk >= 7:
        return PolicyResult(Decision.ALLOW_WITH_REDACTION, f"Medium risk action (risk={risk}), redacting sensitive fields.", redactions={"mask_fields": True})
    return PolicyResult(Decision.ALLOW, f"Low risk action (risk={risk}).")
