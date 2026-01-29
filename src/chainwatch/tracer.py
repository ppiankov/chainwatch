# src/chainwatch/tracer.py
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .types import Action, TraceState, ResultMeta


SENS_RANK = {"low": 0, "medium": 1, "high": 2}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def new_trace_id(prefix: str = "t") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def new_span_id(prefix: str = "s") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@dataclass
class Event:
    """
    JSON-serializable event representing one intercepted agent action.
    Mirrors docs/mvp-event.md (v0).
    """
    ts: str
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]

    actor: Dict[str, Any]
    purpose: str

    action: Dict[str, Any]
    data: Dict[str, Any]
    egress: Dict[str, Any]

    decision: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TraceAccumulator:
    """
    Maintains evolving trace state and the ordered list of events.

    v0: in-memory only.
    v1+: persist events/state to Postgres; stream to OTel/Jaeger if desired.
    """
    state: TraceState
    events: List[Event] = field(default_factory=list)

    def _source_for(self, action: Action) -> str:
        # Prefer tool name; fallback to resource prefix.
        if action.tool:
            return action.tool
        if action.resource and "/" in action.resource:
            return action.resource.split("/", 1)[0]
        return action.resource or "unknown"

    def update_state_from_action(self, action: Action) -> ResultMeta:
        """
        Normalize metadata and update evolving trace state.
        Returns normalized ResultMeta for reuse by callers (avoid re-parsing).
        """
        # Normalize in-place so downstream components see stable keys.
        action.normalize_meta()
        meta = action.normalized_meta()

        source = self._source_for(action)
        if source not in self.state.seen_sources:
            self.state.seen_sources.append(source)

        if SENS_RANK.get(meta.sensitivity, 0) > SENS_RANK.get(self.state.max_sensitivity, 0):
            self.state.max_sensitivity = meta.sensitivity

        self.state.volume_rows += int(meta.rows)
        self.state.volume_bytes += int(meta.bytes)

        # keep "worst" egress (external beats internal)
        if self.state.egress != "external" and meta.egress == "external":
            self.state.egress = "external"

        for t in meta.tags:
            if t not in self.state.tags:
                self.state.tags.append(t)

        return meta

    def build_event(
        self,
        *,
        span_id: str,
        parent_span_id: Optional[str],
        actor: Dict[str, Any],
        purpose: str,
        action: Action,
        decision: Dict[str, Any],
        meta: Optional[ResultMeta] = None,
    ) -> Event:
        """
        Build an Event from an Action + decision.
        If meta is provided, it must correspond to action.normalized_meta().
        """
        if meta is None:
            action.normalize_meta()
            meta = action.normalized_meta()

        # NOTE: we intentionally store params as-is in v0.
        # If params may include secrets, hash or redact in your interceptor before calling this.
        return Event(
            ts=utc_now_iso(),
            trace_id=self.state.trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            actor=actor,
            purpose=purpose,
            action={
                "type": "tool_call",
                "tool": action.tool,
                "resource": action.resource,
                "operation": action.operation,
                "params": action.params,
            },
            data={
                "classification": meta.sensitivity,
                "tags": list(meta.tags),
                "volume": {"rows": int(meta.rows), "bytes": int(meta.bytes)},
            },
            egress={
                "direction": meta.egress,
                "destination": meta.destination,
            },
            decision=decision,
        )

    def record(self, event: Event) -> None:
        self.events.append(event)

    def record_action(
        self,
        *,
        actor: Dict[str, Any],
        purpose: str,
        action: Action,
        decision: Dict[str, Any],
        parent_span_id: Optional[str] = None,
        span_id: Optional[str] = None,
        update_state: bool = True,
    ) -> Event:
        """
        Convenience helper:
        - optionally updates state from action meta
        - builds and records an event
        """
        sid = span_id or new_span_id()
        meta = None
        if update_state:
            meta = self.update_state_from_action(action)

        ev = self.build_event(
            span_id=sid,
            parent_span_id=parent_span_id,
            actor=actor,
            purpose=purpose,
            action=action,
            decision=decision,
            meta=meta,
        )
        self.record(ev)
        return ev

    def to_jsonable(self) -> Dict[str, Any]:
        """
        Snapshot for debugging / export.
        """
        return {
            "trace_state": asdict(self.state),
            "events": [e.to_dict() for e in self.events],
        }
