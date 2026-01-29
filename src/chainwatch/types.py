from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Literal, Optional

Sensitivity = Literal["low", "medium", "high"]
EgressDirection = Literal["internal", "external"]


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ALLOW_WITH_REDACTION = "allow_with_redaction"
    REQUIRE_APPROVAL = "require_approval"
    REWRITE_OUTPUT = "rewrite_output"


@dataclass
class ResultMeta:
    """
    Standardized metadata describing what a tool call returned or is expected to return.

    Keep this *boring and deterministic*:
    - sensitivity: low|medium|high
    - tags: list of strings, e.g. ["PII", "HR"]
    - rows/bytes: approximate volume
    - egress: internal|external (where the data is going)
    - destination: host/service identifier (optional, best-effort)
    """

    sensitivity: Sensitivity = "low"
    tags: List[str] = field(default_factory=list)
    rows: int = 0
    bytes: int = 0
    egress: EgressDirection = "internal"
    destination: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any] | None) -> "ResultMeta":
        d = d or {}
        sens = d.get("sensitivity", "low")
        if sens not in ("low", "medium", "high"):
            sens = "low"

        egr = d.get("egress", "internal")
        if egr not in ("internal", "external"):
            egr = "internal"

        tags = d.get("tags", [])
        if tags is None:
            tags = []
        if not isinstance(tags, list):
            tags = [str(tags)]
        tags = [str(t) for t in tags]

        def _to_int(x: Any) -> int:
            try:
                return int(x)
            except Exception:
                return 0

        return cls(
            sensitivity=sens,
            tags=tags,
            rows=_to_int(d.get("rows", 0)),
            bytes=_to_int(d.get("bytes", 0)),
            egress=egr,
            destination=str(d.get("destination", "")) if d.get("destination") is not None else "",
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sensitivity": self.sensitivity,
            "tags": list(self.tags),
            "rows": self.rows,
            "bytes": self.bytes,
            "egress": self.egress,
            "destination": self.destination,
        }


@dataclass
class Action:
    """
    One intercepted operation in the agent chain.
    Examples: tool call, DB query, HTTP call, file write, etc.
    """

    tool: str
    resource: str
    operation: str  # "read" | "write" | "query" ... keep flexible
    params: Dict[str, Any] = field(default_factory=dict)

    # Allow connectors to send arbitrary dictionaries, but we normalize them immediately.
    result_meta: Dict[str, Any] = field(default_factory=dict)

    def normalized_meta(self) -> ResultMeta:
        return ResultMeta.from_dict(self.result_meta)

    def normalize_meta(self) -> None:
        """
        In-place normalization so downstream components can rely on stable keys.
        """
        self.result_meta = self.normalized_meta().to_dict()


@dataclass
class TraceState:
    """
    Evolving trace-level context. This is what policies reason about.
    """

    trace_id: str
    seen_sources: List[str] = field(default_factory=list)
    max_sensitivity: Sensitivity = "low"
    volume_rows: int = 0
    volume_bytes: int = 0
    egress: EgressDirection = "internal"
    tags: List[str] = field(default_factory=list)


@dataclass
class PolicyResult:
    decision: Decision
    reason: str
    redactions: Optional[Dict[str, Any]] = None
    approval_key: Optional[str] = None
    output_rewrite: Optional[str] = None
    policy_id: Optional[str] = None
