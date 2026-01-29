"""Unit tests for enforcement logic."""

import pytest
from chainwatch.types import PolicyResult, Decision
from chainwatch.enforcement import enforce, EnforcementError


def test_allow_decision_passes_through():
    """ALLOW decision should return data unchanged."""
    policy_result = PolicyResult(
        decision=Decision.ALLOW,
        reason="Low risk",
        policy_id="allow_test",
    )
    data = {"test": "data", "value": 123}

    result = enforce(policy_result, data)

    assert result == data


def test_deny_decision_raises():
    """DENY decision should raise EnforcementError."""
    policy_result = PolicyResult(
        decision=Decision.DENY,
        reason="Access denied",
        policy_id="deny_test",
    )
    data = {"test": "data"}

    with pytest.raises(EnforcementError) as exc_info:
        enforce(policy_result, data)

    assert "Access denied" in str(exc_info.value)


def test_require_approval_raises():
    """REQUIRE_APPROVAL decision should raise EnforcementError with approval key."""
    policy_result = PolicyResult(
        decision=Decision.REQUIRE_APPROVAL,
        reason="Needs approval",
        policy_id="approval_test",
        approval_key="test_approval_key",
    )
    data = {"test": "data"}

    with pytest.raises(EnforcementError) as exc_info:
        enforce(policy_result, data)

    error_str = str(exc_info.value)
    assert "approval" in error_str.lower()
    assert "test_approval_key" in error_str


def test_redaction_on_dict():
    """ALLOW_WITH_REDACTION should redact PII fields from dict."""
    policy_result = PolicyResult(
        decision=Decision.ALLOW_WITH_REDACTION,
        reason="High sensitivity",
        policy_id="redact_test",
        redactions={"extra_keys": ["phone"]},  # email and name are in DEFAULT_PII_KEYS
    )
    data = {
        "name": "Alice",
        "email": "alice@example.com",
        "phone": "555-1234",
        "team": "Engineering",
    }

    result = enforce(policy_result, data)

    # DEFAULT_PII_KEYS includes "name", "email", "phone" - all will be redacted
    assert result["name"] == "***"  # name is in DEFAULT_PII_KEYS
    assert result["team"] == "Engineering"  # team is not PII
    assert result["email"] == "***"  # email is in DEFAULT_PII_KEYS
    assert result["phone"] == "***"  # phone is in DEFAULT_PII_KEYS + extra_keys


def test_redaction_on_list():
    """ALLOW_WITH_REDACTION should redact PII fields from list of dicts."""
    policy_result = PolicyResult(
        decision=Decision.ALLOW_WITH_REDACTION,
        reason="High sensitivity",
        policy_id="redact_test",
        redactions={"extra_keys": []},  # empty extra_keys, DEFAULT_PII_KEYS still apply
    )
    data = [
        {"name": "Alice", "email": "alice@example.com"},
        {"name": "Bob", "email": "bob@example.com"},
    ]

    result = enforce(policy_result, data)

    assert len(result) == 2
    # Both "name" and "email" are in DEFAULT_PII_KEYS, so both get redacted
    assert result[0]["name"] == "***"
    assert result[0]["email"] == "***"
    assert result[1]["name"] == "***"
    assert result[1]["email"] == "***"


def test_redaction_with_empty_keys_uses_defaults():
    """ALLOW_WITH_REDACTION with no extra_keys should still redact DEFAULT_PII_KEYS."""
    policy_result = PolicyResult(
        decision=Decision.ALLOW_WITH_REDACTION,
        reason="Redaction with defaults",
        policy_id="redact_test",
        redactions=None,  # No extra_keys specified
    )
    data = {"name": "Alice", "email": "alice@example.com", "team": "Engineering"}

    result = enforce(policy_result, data)

    # With no extra_keys, redact_auto still uses DEFAULT_PII_KEYS
    assert result["name"] == "***"  # name is in DEFAULT_PII_KEYS
    assert result["email"] == "***"  # email is in DEFAULT_PII_KEYS
    assert result["team"] == "Engineering"  # team is not in DEFAULT_PII_KEYS


def test_rewrite_output_redacts_patterns():
    """REWRITE_OUTPUT should mask patterns in text."""
    policy_result = PolicyResult(
        decision=Decision.REWRITE_OUTPUT,
        reason="Contains PII",
        policy_id="rewrite_test",
        redactions={"patterns": ["email"]},
    )
    data = "Contact alice@example.com or bob@test.org for details."

    result = enforce(policy_result, data)

    assert "alice@example.com" not in result
    assert "bob@test.org" not in result
    assert "***" in result  # MASK constant is "***"


def test_rewrite_output_on_non_string_returns_empty():
    """REWRITE_OUTPUT on non-string data should return empty string."""
    policy_result = PolicyResult(
        decision=Decision.REWRITE_OUTPUT,
        reason="Output rewrite",
        policy_id="rewrite_test",
        output_rewrite="",  # Should be string, not dict
    )
    data = {"test": "data"}

    result = enforce(policy_result, data)

    assert result == ""  # Returns output_rewrite or empty string for non-string data
