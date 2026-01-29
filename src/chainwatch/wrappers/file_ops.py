"""
File operations wrapper for runtime enforcement.

This module provides FileGuard, a context manager that intercepts file read
operations and enforces chain-aware policies before allowing access.
"""

import builtins
import os
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from ..types import Action, TraceState
from ..tracer import TraceAccumulator, new_trace_id, new_span_id
from ..policy import evaluate
from ..enforcement import enforce


class FileGuard:
    """
    Context manager that wraps file operations to intercept and enforce policy.

    Usage:
        with FileGuard(purpose="SOC_efficiency", actor={...}) as guard:
            with open("sensitive.csv", "r") as f:
                data = f.read()  # May raise EnforcementError

    This monkey-patches builtins.open() and pathlib.Path read methods to
    intercept file reads, evaluate policy, and enforce decisions.
    """

    def __init__(
        self,
        purpose: str,
        actor: Dict[str, Any],
        trace_id: Optional[str] = None,
    ):
        """
        Initialize FileGuard.

        Args:
            purpose: Purpose identifier (e.g., "SOC_efficiency")
            actor: Dictionary with actor metadata (user_id, agent_id, etc.)
            trace_id: Optional trace ID (generated if not provided)
        """
        self.purpose = purpose
        self.actor = actor
        self.trace_id = trace_id or new_trace_id()
        self.tracer = TraceAccumulator(state=TraceState(trace_id=self.trace_id))

        # Store original functions for restoration
        self._original_open = builtins.open
        self._original_path_read_text = Path.read_text
        self._original_path_read_bytes = Path.read_bytes

        self.active = False

    def __enter__(self):
        """Context manager entry: install interceptors."""
        self.activate()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit: restore original functions."""
        self.deactivate()
        return False

    def activate(self):
        """Install file operation interceptors."""
        builtins.open = self._guarded_open
        Path.read_text = self._guarded_read_text
        Path.read_bytes = self._guarded_read_bytes
        self.active = True

    def deactivate(self):
        """Remove interceptors and restore original functions."""
        builtins.open = self._original_open
        Path.read_text = self._original_path_read_text
        Path.read_bytes = self._original_path_read_bytes
        self.active = False

    def _guarded_open(self, file, mode="r", *args, **kwargs):
        """Intercept open() calls."""
        if "r" in mode and "b" not in mode:  # Only intercept text reads
            # Execute read through enforcement
            def read_fn():
                return self._original_open(file, mode, *args, **kwargs)

            return self._enforce_read(str(file), read_fn)
        # Pass through writes and binary reads
        return self._original_open(file, mode, *args, **kwargs)

    def _guarded_read_text(self, *args, **kwargs):
        """Intercept Path.read_text() calls."""
        # Path.read_text is an instance method, so 'self' is the Path object
        # We need to extract it from args
        path_self = args[0] if args else self
        filepath = str(path_self)

        def read_fn():
            return self._original_path_read_text(path_self, *args[1:], **kwargs)

        return self._enforce_read(filepath, read_fn)

    def _guarded_read_bytes(self, *args, **kwargs):
        """Intercept Path.read_bytes() calls."""
        path_self = args[0] if args else self
        filepath = str(path_self)

        def read_fn():
            return self._original_path_read_bytes(path_self, *args[1:], **kwargs)

        return self._enforce_read(filepath, read_fn)

    def _enforce_read(self, filepath: str, read_fn: Callable) -> Any:
        """
        Core enforcement logic.

        Args:
            filepath: Path being accessed
            read_fn: Function to execute the actual read

        Returns:
            File content (possibly redacted) if allowed

        Raises:
            EnforcementError: If access is denied or approval required
        """
        # Build Action from file path
        action = self._build_action_from_path(filepath)

        # Evaluate policy against current trace state
        policy_result = evaluate(
            action=action,
            state=self.tracer.state,
            purpose=self.purpose,
        )

        # Record event (before enforcement for audit trail)
        self.tracer.record_action(
            actor=self.actor,
            purpose=self.purpose,
            action=action,
            decision={
                "result": policy_result.decision.value,
                "reason": policy_result.reason,
                "policy_id": policy_result.policy_id,
                "approval_key": policy_result.approval_key,
            },
            span_id=new_span_id(),
            parent_span_id=None,
        )

        # Execute read (before enforcement so we have data to redact if needed)
        data = read_fn()

        # Enforce decision (may raise or redact)
        return enforce(policy_result, data)

    def _build_action_from_path(self, filepath: str) -> Action:
        """
        Convert file path to Action with classified ResultMeta.

        Args:
            filepath: File path to classify

        Returns:
            Action with sensitivity, tags, and metadata
        """
        # Classify sensitivity based on path patterns
        sensitivity = "low"
        tags = []

        lower_path = filepath.lower()

        # High sensitivity patterns
        if any(
            pattern in lower_path
            for pattern in ["hr", "employee", "salary", "payroll", "pii", "ssn", "passport"]
        ):
            sensitivity = "high"
            if "hr" in lower_path or "employee" in lower_path:
                tags.append("HR")
            if any(p in lower_path for p in ["pii", "ssn", "passport"]):
                tags.append("PII")

        # Medium sensitivity patterns
        elif any(pattern in lower_path for pattern in ["siem", "incident", "security"]):
            sensitivity = "medium"
            tags.append("security")

        # Best-effort file size
        try:
            file_bytes = os.path.getsize(filepath) if os.path.exists(filepath) else 0
        except Exception:
            file_bytes = 0

        action = Action(
            tool="file_read",
            resource=filepath,
            operation="read",
            params={"path": filepath},
            result_meta={
                "sensitivity": sensitivity,
                "tags": tags,
                "bytes": file_bytes,
                "rows": 0,  # Unknown for files without parsing
                "egress": "internal",
                "destination": "localhost",
            },
        )

        # Normalize metadata before policy evaluation
        action.normalize_meta()

        return action

    def get_trace_summary(self) -> Dict[str, Any]:
        """
        Export trace for debugging/audit.

        Returns:
            Dictionary with trace_id, events, and state
        """
        return self.tracer.to_jsonable()
