"""Optional framework integrations for LangChain and CrewAI.

These require their respective packages installed. Import errors are handled
gracefully — the wrappers are only usable if the framework is available.
"""

from __future__ import annotations

from typing import Any, Optional, Type

from .client import ChainwatchClient
from .types import BlockedError


def langchain_tool_wrapper(
    client: ChainwatchClient,
    tool_name: Optional[str] = None,
) -> Any:
    """Create a LangChain BaseTool subclass that enforces chainwatch policy.

    Args:
        client: ChainwatchClient instance
        tool_name: Override tool name (defaults to the tool's name attribute)

    Returns:
        A base class for LangChain tools with chainwatch enforcement.

    Raises:
        ImportError: If langchain-core is not installed.
    """
    try:
        from langchain_core.tools import BaseTool as LCBaseTool
    except ImportError:
        raise ImportError(
            "langchain-core is required for LangChain integration. "
            "Install with: pip install langchain-core"
        )

    class ChainwatchGuardedTool(LCBaseTool):
        """BaseTool subclass that checks chainwatch policy before execution."""

        def invoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
            name = tool_name or self.name
            result = client.check(command=name)
            if not result.allowed:
                raise BlockedError(
                    reason=result.reason,
                    decision=result.decision,
                    command=name,
                    policy_id=result.policy_id,
                    approval_key=result.approval_key,
                )
            return super().invoke(input, config, **kwargs)

    return ChainwatchGuardedTool


def crewai_tool_wrapper(
    client: ChainwatchClient,
    tool_name: Optional[str] = None,
) -> Any:
    """Create a CrewAI tool class decorator that enforces chainwatch policy.

    Args:
        client: ChainwatchClient instance
        tool_name: Override tool name

    Returns:
        A class decorator for CrewAI tools.

    Raises:
        ImportError: If crewai is not installed.
    """
    try:
        import crewai.tools  # noqa: F401
    except ImportError:
        raise ImportError(
            "crewai is required for CrewAI integration. " "Install with: pip install crewai"
        )

    def decorator(cls: Type) -> Type:
        original_run = cls._run

        def guarded_run(self: Any, *args: Any, **kwargs: Any) -> Any:
            name = tool_name or getattr(self, "name", cls.__name__)
            result = client.check(command=name)
            if not result.allowed:
                raise BlockedError(
                    reason=result.reason,
                    decision=result.decision,
                    command=name,
                    policy_id=result.policy_id,
                    approval_key=result.approval_key,
                )
            return original_run(self, *args, **kwargs)

        cls._run = guarded_run
        return cls

    return decorator
