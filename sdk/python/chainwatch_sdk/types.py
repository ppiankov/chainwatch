"""Core types for the chainwatch SDK."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


@dataclass(frozen=True)
class CheckResult:
    """Result of a dry-run policy check."""

    decision: str
    reason: str
    policy_id: str = ""
    approval_key: str = ""

    @property
    def allowed(self) -> bool:
        return self.decision in ("allow", "allow_with_redaction")

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> CheckResult:
        return cls(
            decision=data.get("decision", "deny"),
            reason=data.get("reason", ""),
            policy_id=data.get("policy_id", ""),
            approval_key=data.get("approval_key", ""),
        )


@dataclass(frozen=True)
class ExecResult:
    """Result of command execution through chainwatch."""

    stdout: str
    stderr: str
    exit_code: int


class BlockedError(Exception):
    """Raised when chainwatch denies an action."""

    def __init__(
        self,
        reason: str,
        decision: str = "deny",
        command: str = "",
        policy_id: str = "",
        approval_key: str = "",
    ):
        self.reason = reason
        self.decision = decision
        self.command = command
        self.policy_id = policy_id
        self.approval_key = approval_key
        super().__init__(f"chainwatch blocked ({decision}): {reason}")

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> BlockedError:
        return cls(
            reason=data.get("reason", "unknown"),
            decision=data.get("decision", "deny"),
            command=data.get("command", ""),
            policy_id=data.get("policy_id", ""),
            approval_key=data.get("approval_key", ""),
        )


class BinaryNotFoundError(Exception):
    """Raised when the chainwatch binary is not found on PATH."""

    pass
