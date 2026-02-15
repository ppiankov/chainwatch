"""Shared fixtures for SDK tests."""

import json
from unittest.mock import patch

import pytest

ALLOW_JSON = json.dumps(
    {
        "decision": "allow",
        "reason": "low risk action (risk=1)",
        "policy_id": "risk.low",
    }
)

DENY_JSON = json.dumps(
    {
        "decision": "deny",
        "reason": "denylisted: matches pattern rm -rf",
        "policy_id": "denylist.block",
    }
)

REQUIRE_APPROVAL_JSON = json.dumps(
    {
        "decision": "require_approval",
        "reason": "high cumulative risk (risk=12)",
        "policy_id": "risk.high",
        "approval_key": "high_risk_action",
    }
)

BLOCKED_STDERR_JSON = json.dumps(
    {
        "blocked": True,
        "command": "rm -rf /",
        "decision": "deny",
        "reason": "denylisted: matches pattern rm -rf",
        "policy_id": "denylist.block",
    }
)


@pytest.fixture
def mock_binary():
    """Mock find_binary to return a fake path."""
    with patch(
        "chainwatch_sdk._subprocess.find_binary",
        return_value="/usr/local/bin/chainwatch",
    ):
        yield
