"""Decorator-based enforcement for Python functions."""

from __future__ import annotations

import functools
from typing import Any, Callable, List, Optional, TypeVar, cast

from .client import ChainwatchClient
from .types import BlockedError

F = TypeVar("F", bound=Callable[..., Any])

_default_client: Optional[ChainwatchClient] = None


def configure(
    binary: str = "chainwatch",
    profile: str = "",
    purpose: str = "",
    policy: str = "",
    denylist: str = "",
    timeout: float = 30.0,
) -> None:
    """Configure the default ChainwatchClient used by @guard decorators.

    Must be called before any @guard-decorated function executes.
    """
    global _default_client
    _default_client = ChainwatchClient(
        binary=binary,
        profile=profile,
        purpose=purpose,
        policy=policy,
        denylist=denylist,
        timeout=timeout,
    )


def guard(
    tool_name: str,
    client: Optional[ChainwatchClient] = None,
    args_builder: Optional[Callable[..., List[str]]] = None,
) -> Callable[[F], F]:
    """Decorator that enforces chainwatch policy before function execution.

    Uses ``chainwatch exec --dry-run`` to check the tool_name as a command.
    If denied, raises BlockedError without calling the wrapped function.

    Args:
        tool_name: Command/tool name to check (e.g., "file_write")
        client: Optional explicit client (defaults to module-level client)
        args_builder: Optional callable that converts function args to CLI args
                      for more specific policy matching. Signature: (*args, **kwargs) -> List[str]
    """

    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            c = client or _default_client
            if c is None:
                raise RuntimeError(
                    "No ChainwatchClient configured. "
                    "Call chainwatch_sdk.configure() or pass client= to @guard()"
                )

            check_args: Optional[List[str]] = None
            if args_builder is not None:
                check_args = args_builder(*args, **kwargs)

            result = c.check(command=tool_name, args=check_args)

            if not result.allowed:
                raise BlockedError(
                    reason=result.reason,
                    decision=result.decision,
                    command=tool_name,
                    policy_id=result.policy_id,
                    approval_key=result.approval_key,
                )

            return fn(*args, **kwargs)

        return cast(F, wrapper)

    return decorator
