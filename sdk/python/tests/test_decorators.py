"""Tests for chainwatch_sdk.decorators."""

from unittest.mock import patch

import pytest

import chainwatch_sdk.decorators as dec
from chainwatch_sdk.client import ChainwatchClient
from chainwatch_sdk.types import BlockedError, CheckResult

from .conftest import ALLOW_JSON, DENY_JSON


@pytest.fixture(autouse=True)
def reset_default_client():
    """Reset the module-level default client between tests."""
    dec._default_client = None
    yield
    dec._default_client = None


def test_guard_allows_execution(mock_binary):
    with patch("chainwatch_sdk._subprocess.run", return_value=(0, ALLOW_JSON, "")):
        client = ChainwatchClient()

    called = []

    @dec.guard("echo", client=client)
    def my_fn(x):
        called.append(x)
        return x * 2

    with patch("chainwatch_sdk._subprocess.run", return_value=(0, ALLOW_JSON, "")):
        result = my_fn(5)

    assert result == 10
    assert called == [5]


def test_guard_blocks_execution(mock_binary):
    with patch("chainwatch_sdk._subprocess.run", return_value=(0, ALLOW_JSON, "")):
        client = ChainwatchClient()

    called = []

    @dec.guard("rm", client=client)
    def dangerous_fn():
        called.append(True)

    with patch("chainwatch_sdk._subprocess.run", return_value=(77, DENY_JSON, "")):
        with pytest.raises(BlockedError) as exc_info:
            dangerous_fn()

    assert exc_info.value.decision == "deny"
    assert called == []


def test_guard_no_client_raises():
    @dec.guard("echo")
    def my_fn():
        pass

    with pytest.raises(RuntimeError, match="No ChainwatchClient configured"):
        my_fn()


def test_guard_with_configure(mock_binary):
    with patch("chainwatch_sdk._subprocess.run", return_value=(0, ALLOW_JSON, "")):
        dec.configure(profile="clawbot")

    @dec.guard("echo")
    def my_fn():
        return "ok"

    with patch("chainwatch_sdk._subprocess.run", return_value=(0, ALLOW_JSON, "")):
        assert my_fn() == "ok"


def test_guard_with_args_builder(mock_binary):
    calls = []

    def capture_run(args, **kwargs):
        calls.append(args)
        return (0, ALLOW_JSON, "")

    with patch("chainwatch_sdk._subprocess.run", return_value=(0, ALLOW_JSON, "")):
        client = ChainwatchClient()

    @dec.guard("curl", client=client, args_builder=lambda url, **kw: [url])
    def fetch(url, timeout=30):
        return f"fetched {url}"

    with patch("chainwatch_sdk._subprocess.run", side_effect=capture_run):
        result = fetch("https://example.com")

    assert result == "fetched https://example.com"
    args = calls[0]
    dash_idx = args.index("--")
    assert args[dash_idx + 1] == "curl"
    assert args[dash_idx + 2] == "https://example.com"


def test_guard_preserves_metadata(mock_binary):
    with patch("chainwatch_sdk._subprocess.run", return_value=(0, ALLOW_JSON, "")):
        client = ChainwatchClient()

    @dec.guard("echo", client=client)
    def documented_fn():
        """This function has docs."""
        pass

    assert documented_fn.__name__ == "documented_fn"
    assert documented_fn.__doc__ == "This function has docs."


def test_guard_with_explicit_client_overrides_default(mock_binary):
    with patch("chainwatch_sdk._subprocess.run", return_value=(0, ALLOW_JSON, "")):
        default_client = ChainwatchClient()
        explicit_client = ChainwatchClient()

    dec._default_client = default_client

    check_calls = []

    def tracking_check(self, command, args=None):
        check_calls.append(self)
        return CheckResult(decision="allow", reason="ok")

    @dec.guard("echo", client=explicit_client)
    def my_fn():
        return "ok"

    with patch.object(ChainwatchClient, "check", tracking_check):
        my_fn()

    assert check_calls[0] is explicit_client
