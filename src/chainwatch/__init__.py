"""
Chainwatch: Runtime control plane for AI agents.

Chainwatch enforces chain-aware policies on AI agent operations,
providing deterministic control over data access and egress.
"""

from .enforcement import EnforcementError, enforce
from .policy import evaluate
from .redaction import redact_auto, redact_dict, redact_records
from .tracer import Event, TraceAccumulator, new_span_id, new_trace_id
from .types import Action, Decision, PolicyResult, ResultMeta, TraceState

__version__ = "0.1.0"
__all__ = [
    "Action",
    "Decision",
    "PolicyResult",
    "ResultMeta",
    "TraceState",
    "evaluate",
    "enforce",
    "EnforcementError",
    "TraceAccumulator",
    "Event",
    "new_trace_id",
    "new_span_id",
    "redact_auto",
    "redact_dict",
    "redact_records",
]
