"""
Chainwatch: Runtime control plane for AI agents.

Chainwatch enforces chain-aware policies on AI agent operations,
providing deterministic control over data access and egress.
"""

from .types import Action, Decision, PolicyResult, ResultMeta, TraceState
from .policy import evaluate
from .enforcement import enforce, EnforcementError
from .tracer import TraceAccumulator, Event, new_trace_id, new_span_id
from .redaction import redact_auto, redact_dict, redact_records

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
