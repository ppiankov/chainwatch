"""Unit tests for policy evaluation logic."""

from chainwatch.policy import evaluate
from chainwatch.types import Action, Decision, TraceState


def test_low_risk_action_allows():
    """Low sensitivity + low volume should allow."""
    action = Action(
        tool="org_chart",
        resource="orgchart/read",
        operation="read",
        result_meta={"sensitivity": "low", "rows": 10, "bytes": 1000},
    )
    state = TraceState(trace_id="test")
    result = evaluate(action=action, state=state, purpose="SOC_efficiency")

    assert result.decision == Decision.ALLOW
    assert "Low risk" in result.reason or "risk" in result.reason.lower()


def test_high_sensitivity_triggers_redaction():
    """High sensitivity should trigger redaction."""
    action = Action(
        tool="hr_api",
        resource="hr/employees",
        operation="read",
        result_meta={"sensitivity": "high", "rows": 100, "bytes": 50000},
    )
    state = TraceState(trace_id="test")
    result = evaluate(action=action, state=state, purpose="SOC_efficiency")

    assert result.decision == Decision.ALLOW_WITH_REDACTION


def test_salary_access_requires_approval():
    """Salary resource access should require approval (hard rule)."""
    action = Action(
        tool="hr_api",
        resource="hr/salary_bands",
        operation="read",
        result_meta={"sensitivity": "high", "rows": 50, "bytes": 10000},
    )
    state = TraceState(trace_id="test")
    result = evaluate(action=action, state=state, purpose="SOC_efficiency")

    assert result.decision == Decision.REQUIRE_APPROVAL
    assert result.approval_key == "soc_salary_access"


def test_external_egress_high_risk():
    """External egress + high sensitivity should require approval."""
    action = Action(
        tool="api_call",
        resource="external/service",
        operation="write",
        result_meta={
            "sensitivity": "high",
            "rows": 10,
            "bytes": 5000,
            "egress": "external",
            "destination": "api.example.com",
        },
    )
    state = TraceState(trace_id="test")
    result = evaluate(action=action, state=state, purpose="SOC_efficiency")

    # External egress adds +6 risk, high sensitivity adds +6, should be >10
    assert result.decision in [Decision.REQUIRE_APPROVAL, Decision.DENY]


def test_medium_sensitivity_allows():
    """Medium sensitivity with reasonable volume should allow."""
    action = Action(
        tool="siem_api",
        resource="siem/incidents",
        operation="read",
        result_meta={"sensitivity": "medium", "rows": 500, "bytes": 100000},
    )
    state = TraceState(trace_id="test")
    result = evaluate(action=action, state=state, purpose="SOC_efficiency")

    # Medium = 3, volume < 1K rows, should be ≤5 (allow)
    assert result.decision == Decision.ALLOW


def test_large_volume_escalates_risk():
    """Large volume should escalate risk even for low sensitivity."""
    action = Action(
        tool="data_export",
        resource="data/export",
        operation="read",
        result_meta={"sensitivity": "low", "rows": 15000, "bytes": 5000000},
    )
    state = TraceState(trace_id="test")
    result = evaluate(action=action, state=state, purpose="SOC_efficiency")

    # Low = 1, but >10K rows = +6, total = 7, should trigger redaction
    assert result.decision in [Decision.ALLOW_WITH_REDACTION, Decision.REQUIRE_APPROVAL]


def test_new_source_adds_risk():
    """New source in trace should add risk."""
    # First action establishes source
    action1 = Action(
        tool="api1",
        resource="source1",
        operation="read",
        result_meta={"sensitivity": "medium", "rows": 10},
    )
    state = TraceState(trace_id="test")
    evaluate(action=action1, state=state, purpose="test")

    # Second action from new source should have higher risk
    action2 = Action(
        tool="api2",
        resource="source2",
        operation="read",
        result_meta={"sensitivity": "medium", "rows": 10},
    )
    result2 = evaluate(action=action2, state=state, purpose="test")

    # New source adds +2, so medium (3) + new source (2) = 5 (allow threshold)
    assert result2.decision == Decision.ALLOW
