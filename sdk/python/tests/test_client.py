"""Tests for chainwatch_sdk.client."""

from unittest.mock import patch

import pytest

from chainwatch_sdk.client import ChainwatchClient
from chainwatch_sdk.types import BinaryNotFoundError, BlockedError

from .conftest import (
    ALLOW_JSON,
    BLOCKED_STDERR_JSON,
    DENY_JSON,
    REQUIRE_APPROVAL_JSON,
)


def test_binary_not_found():
    with patch("chainwatch_sdk._subprocess.find_binary", side_effect=BinaryNotFoundError("nope")):
        with pytest.raises(BinaryNotFoundError):
            ChainwatchClient()


def test_check_allow(mock_binary):
    with patch("chainwatch_sdk._subprocess.run", return_value=(0, ALLOW_JSON, "")):
        client = ChainwatchClient()
        result = client.check("echo", ["hello"])
    assert result.decision == "allow"
    assert result.allowed is True
    assert result.policy_id == "risk.low"


def test_check_deny(mock_binary):
    with patch("chainwatch_sdk._subprocess.run", return_value=(77, DENY_JSON, "")):
        client = ChainwatchClient()
        result = client.check("rm", ["-rf", "/"])
    assert result.decision == "deny"
    assert result.allowed is False
    assert result.policy_id == "denylist.block"


def test_check_require_approval(mock_binary):
    with patch("chainwatch_sdk._subprocess.run", return_value=(77, REQUIRE_APPROVAL_JSON, "")):
        client = ChainwatchClient()
        result = client.check("sensitive_op")
    assert result.decision == "require_approval"
    assert result.approval_key == "high_risk_action"
    assert result.allowed is False


def test_check_passes_flags(mock_binary):
    calls = []

    def capture_run(args, **kwargs):
        calls.append(args)
        return (0, ALLOW_JSON, "")

    with patch("chainwatch_sdk._subprocess.run", side_effect=capture_run):
        client = ChainwatchClient(
            profile="clawbot", purpose="test", policy="/tmp/p.yaml", denylist="/tmp/d.yaml"
        )
        client.check("ls", ["/tmp"])

    args = calls[0]
    assert "--profile" in args
    assert "clawbot" in args
    assert "--purpose" in args
    assert "test" in args
    assert "--policy" in args
    assert "/tmp/p.yaml" in args
    assert "--denylist" in args
    assert "/tmp/d.yaml" in args
    assert "--dry-run" in args
    # Command after --
    dash_idx = args.index("--")
    assert args[dash_idx + 1] == "ls"
    assert args[dash_idx + 2] == "/tmp"


def test_check_unexpected_error(mock_binary):
    with patch("chainwatch_sdk._subprocess.run", return_value=(1, "", "segfault")):
        client = ChainwatchClient()
        with pytest.raises(RuntimeError, match="segfault"):
            client.check("bad_cmd")


def test_exec_allow(mock_binary):
    with patch("chainwatch_sdk._subprocess.run", return_value=(0, "hello\n", "")):
        client = ChainwatchClient()
        result = client.exec("echo", ["hello"])
    assert result.stdout == "hello\n"
    assert result.exit_code == 0


def test_exec_blocked(mock_binary):
    with patch("chainwatch_sdk._subprocess.run", return_value=(77, "", BLOCKED_STDERR_JSON)):
        client = ChainwatchClient()
        with pytest.raises(BlockedError) as exc_info:
            client.exec("rm", ["-rf", "/"])
    err = exc_info.value
    assert err.decision == "deny"
    assert err.command == "rm -rf /"
    assert err.policy_id == "denylist.block"


def test_exec_nonzero_exit(mock_binary):
    with patch("chainwatch_sdk._subprocess.run", return_value=(42, "", "error output")):
        client = ChainwatchClient()
        result = client.exec("false")
    assert result.exit_code == 42
    assert result.stderr == "error output"


def test_approve_success(mock_binary):
    with patch("chainwatch_sdk._subprocess.run", return_value=(0, "Approved\n", "")):
        client = ChainwatchClient()
        client.approve("test_key")


def test_approve_with_duration(mock_binary):
    calls = []

    def capture_run(args, **kwargs):
        calls.append(args)
        return (0, "", "")

    with patch("chainwatch_sdk._subprocess.run", side_effect=capture_run):
        client = ChainwatchClient()
        client.approve("test_key", duration="5m")

    args = calls[0]
    assert "approve" in args
    assert "test_key" in args
    assert "--duration" in args
    assert "5m" in args


def test_approve_failure(mock_binary):
    with patch("chainwatch_sdk._subprocess.run", return_value=(1, "", "not found")):
        client = ChainwatchClient()
        with pytest.raises(RuntimeError, match="not found"):
            client.approve("bad_key")


def test_pending(mock_binary):
    table = "KEY    STATUS    RESOURCE\nk1     pending   /tmp\n"
    with patch("chainwatch_sdk._subprocess.run", return_value=(0, table, "")):
        client = ChainwatchClient()
        result = client.pending()
    assert "k1" in result
    assert "pending" in result
