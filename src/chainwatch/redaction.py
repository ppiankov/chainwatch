from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional, Union
import copy
import re

MASK = "***"

DEFAULT_PII_KEYS = {
    "name",
    "first_name",
    "last_name",
    "full_name",
    "email",
    "phone",
    "address",
    "ssn",
    "passport",
    "dob",
}


def mask_value(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, (int, float, bool)):
        return v
    if isinstance(v, str):
        # preserve a hint of length without leaking content
        return MASK
    return MASK


def redact_dict(d: Mapping[str, Any], keys: Iterable[str]) -> Dict[str, Any]:
    out = dict(d)
    for k in keys:
        if k in out:
            out[k] = mask_value(out[k])
    return out


def redact_records(records: List[Dict[str, Any]], keys: Iterable[str]) -> List[Dict[str, Any]]:
    return [redact_dict(r, keys) for r in records]


def redact_auto(obj: Any, extra_keys: Optional[Iterable[str]] = None) -> Any:
    """
    Best-effort redaction for dict/list structures using a key allowlist.
    """
    keys = set(DEFAULT_PII_KEYS)
    if extra_keys:
        keys |= set(extra_keys)

    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in keys:
                out[k] = mask_value(v)
            else:
                out[k] = redact_auto(v, keys)
        return out
    if isinstance(obj, list):
        return [redact_auto(x, keys) for x in obj]
    return obj


def rewrite_output_text(text: str, patterns: Optional[List[str]] = None) -> str:
    """
    Primitive output rewriting: remove obvious sensitive patterns.
    MVP only. Replace later with structured output control.
    """
    out = text
    # email-like
    out = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", MASK, out)
    # phone-ish (very rough)
    out = re.sub(r"\+?\d[\d\-\s]{7,}\d", MASK, out)
    # user-provided patterns
    if patterns:
        for p in patterns:
            out = re.sub(p, MASK, out)
    return out
