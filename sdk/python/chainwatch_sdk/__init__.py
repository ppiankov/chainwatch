"""chainwatch-sdk: Python client for the chainwatch runtime control plane."""

from .client import ChainwatchClient
from .decorators import configure, guard
from .types import BinaryNotFoundError, BlockedError, CheckResult, ExecResult

__version__ = "0.1.0"
__all__ = [
    "ChainwatchClient",
    "configure",
    "guard",
    "BlockedError",
    "BinaryNotFoundError",
    "CheckResult",
    "ExecResult",
]
