"""ChainwatchClient: thin subprocess client for the Go chainwatch binary."""

from __future__ import annotations

from typing import List, Optional

from . import _subprocess
from .types import BlockedError, CheckResult, ExecResult

_EXIT_BLOCKED = 77


class ChainwatchClient:
    """Client that delegates policy enforcement to the chainwatch Go binary.

    Args:
        binary: Path or name of the chainwatch binary (default: "chainwatch")
        profile: Safety profile name (e.g., "clawbot")
        purpose: Purpose identifier for policy evaluation
        policy: Path to policy YAML
        denylist: Path to denylist YAML
        timeout: Subprocess timeout in seconds (default: 30)
    """

    def __init__(
        self,
        binary: str = "chainwatch",
        profile: str = "",
        purpose: str = "",
        policy: str = "",
        denylist: str = "",
        timeout: float = 30.0,
    ):
        self._binary = _subprocess.find_binary(binary)
        self._profile = profile
        self._purpose = purpose
        self._policy = policy
        self._denylist = denylist
        self._timeout = timeout

    def _build_flags(self) -> List[str]:
        """Build common CLI flags from client config."""
        flags: List[str] = []
        if self._profile:
            flags.extend(["--profile", self._profile])
        if self._purpose:
            flags.extend(["--purpose", self._purpose])
        if self._policy:
            flags.extend(["--policy", self._policy])
        if self._denylist:
            flags.extend(["--denylist", self._denylist])
        return flags

    def check(self, command: str, args: Optional[List[str]] = None) -> CheckResult:
        """Dry-run policy check for a command.

        Uses ``chainwatch exec --dry-run -- <command> [args...]``.

        Args:
            command: The command name (e.g., "curl", "rm")
            args: Command arguments

        Returns:
            CheckResult with decision, reason, policy_id, approval_key
        """
        cmd_args = ["exec", "--dry-run"] + self._build_flags() + ["--", command]
        if args:
            cmd_args.extend(args)

        exit_code, stdout, stderr = _subprocess.run(
            cmd_args, binary=self._binary, timeout=self._timeout
        )

        # Dry-run outputs JSON to stdout for both allowed and blocked
        if exit_code in (0, _EXIT_BLOCKED):
            data = _subprocess.parse_json(stdout)
            return CheckResult.from_json(data)

        raise RuntimeError(f"chainwatch exited with code {exit_code}: {stderr.strip()}")

    def exec(
        self,
        command: str,
        args: Optional[List[str]] = None,
        stdin_data: Optional[str] = None,
    ) -> ExecResult:
        """Execute a command through chainwatch policy enforcement.

        Uses ``chainwatch exec -- <command> [args...]``.
        Raises BlockedError if the command is denied.

        Args:
            command: The command name
            args: Command arguments
            stdin_data: Optional stdin input

        Returns:
            ExecResult with stdout, stderr, exit_code
        """
        cmd_args = ["exec"] + self._build_flags() + ["--", command]
        if args:
            cmd_args.extend(args)

        exit_code, stdout, stderr = _subprocess.run(
            cmd_args,
            binary=self._binary,
            timeout=self._timeout,
            stdin_data=stdin_data,
        )

        if exit_code == _EXIT_BLOCKED:
            data = _subprocess.parse_json(stderr)
            raise BlockedError.from_json(data)

        return ExecResult(stdout=stdout, stderr=stderr, exit_code=exit_code)

    def approve(self, key: str, duration: str = "") -> None:
        """Grant approval for a require_approval action.

        Args:
            key: Approval key from a BlockedError or CheckResult
            duration: Optional duration string (e.g., "5m", "1h")
        """
        cmd_args = ["approve", key]
        if duration:
            cmd_args.extend(["--duration", duration])

        exit_code, _, stderr = _subprocess.run(cmd_args, binary=self._binary, timeout=self._timeout)

        if exit_code != 0:
            raise RuntimeError(f"chainwatch approve failed (code {exit_code}): {stderr.strip()}")

    def pending(self) -> str:
        """List pending approval requests. Returns raw text output."""
        exit_code, stdout, stderr = _subprocess.run(
            ["pending"], binary=self._binary, timeout=self._timeout
        )

        if exit_code != 0:
            raise RuntimeError(f"chainwatch pending failed (code {exit_code}): {stderr.strip()}")

        return stdout
