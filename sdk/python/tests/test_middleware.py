"""Tests for chainwatch_sdk.middleware."""

import sys
from unittest.mock import MagicMock, patch

import pytest

from chainwatch_sdk.types import BlockedError, CheckResult


def test_langchain_import_error():
    """langchain_tool_wrapper raises ImportError when langchain-core is not installed."""
    # Ensure langchain_core is not importable
    with patch.dict(sys.modules, {"langchain_core": None, "langchain_core.tools": None}):
        from chainwatch_sdk.middleware import langchain_tool_wrapper

        mock_client = MagicMock()
        with pytest.raises(ImportError, match="langchain-core"):
            langchain_tool_wrapper(mock_client)


def test_crewai_import_error():
    """crewai_tool_wrapper raises ImportError when crewai is not installed."""
    with patch.dict(sys.modules, {"crewai": None, "crewai.tools": None}):
        from chainwatch_sdk.middleware import crewai_tool_wrapper

        mock_client = MagicMock()
        with pytest.raises(ImportError, match="crewai"):
            crewai_tool_wrapper(mock_client)


def test_langchain_wrapper_blocks():
    """LangChain wrapper raises BlockedError when policy denies."""
    # Create a mock langchain_core.tools module
    mock_tools = MagicMock()

    class FakeBaseTool:
        name: str = "test_tool"

        def invoke(self, input, config=None, **kwargs):
            return "should not reach here"

    mock_tools.BaseTool = FakeBaseTool

    mock_lc = MagicMock()
    mock_lc.tools = mock_tools

    with patch.dict(sys.modules, {"langchain_core": mock_lc, "langchain_core.tools": mock_tools}):
        from chainwatch_sdk.middleware import langchain_tool_wrapper

        mock_client = MagicMock()
        mock_client.check.return_value = CheckResult(
            decision="deny", reason="blocked by policy", policy_id="test"
        )

        guarded_tool_cls = langchain_tool_wrapper(mock_client, tool_name="dangerous_tool")
        tool = guarded_tool_cls()
        tool.name = "dangerous_tool"

        with pytest.raises(BlockedError) as exc_info:
            tool.invoke("test input")

        assert exc_info.value.decision == "deny"
        assert exc_info.value.reason == "blocked by policy"


def test_crewai_wrapper_blocks():
    """CrewAI wrapper raises BlockedError when policy denies."""
    mock_crewai_tools = MagicMock()
    mock_crewai = MagicMock()
    mock_crewai.tools = mock_crewai_tools

    with patch.dict(sys.modules, {"crewai": mock_crewai, "crewai.tools": mock_crewai_tools}):
        from chainwatch_sdk.middleware import crewai_tool_wrapper

        mock_client = MagicMock()
        mock_client.check.return_value = CheckResult(
            decision="deny", reason="not allowed", policy_id="test"
        )

        class MyTool:
            name = "risky_tool"

            def _run(self, *args, **kwargs):
                return "should not run"

        wrapped_cls = crewai_tool_wrapper(mock_client)(MyTool)
        tool = wrapped_cls()

        with pytest.raises(BlockedError) as exc_info:
            tool._run("test")

        assert exc_info.value.decision == "deny"
