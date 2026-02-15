"""Tests for chainwatch_sdk.types."""

from chainwatch_sdk.types import BlockedError, CheckResult, ExecResult


def test_check_result_from_json_allow():
    data = {"decision": "allow", "reason": "low risk", "policy_id": "risk.low"}
    r = CheckResult.from_json(data)
    assert r.decision == "allow"
    assert r.reason == "low risk"
    assert r.policy_id == "risk.low"
    assert r.approval_key == ""


def test_check_result_from_json_deny():
    data = {"decision": "deny", "reason": "blocked", "approval_key": "key123"}
    r = CheckResult.from_json(data)
    assert r.decision == "deny"
    assert r.approval_key == "key123"


def test_check_result_allowed_property():
    assert CheckResult(decision="allow", reason="ok").allowed is True
    assert CheckResult(decision="allow_with_redaction", reason="ok").allowed is True
    assert CheckResult(decision="deny", reason="no").allowed is False
    assert CheckResult(decision="require_approval", reason="wait").allowed is False


def test_check_result_from_empty_json():
    r = CheckResult.from_json({})
    assert r.decision == "deny"
    assert r.reason == ""


def test_blocked_error_from_json():
    data = {
        "blocked": True,
        "command": "rm -rf /",
        "decision": "deny",
        "reason": "dangerous",
        "policy_id": "denylist",
        "approval_key": "",
    }
    err = BlockedError.from_json(data)
    assert err.decision == "deny"
    assert err.reason == "dangerous"
    assert err.command == "rm -rf /"
    assert err.policy_id == "denylist"


def test_blocked_error_message():
    err = BlockedError(reason="bad command", decision="deny")
    assert "chainwatch blocked (deny): bad command" in str(err)


def test_exec_result_fields():
    r = ExecResult(stdout="hello\n", stderr="", exit_code=0)
    assert r.stdout == "hello\n"
    assert r.exit_code == 0
