"""Low-level subprocess runner for the chainwatch binary."""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from .types import BinaryNotFoundError


def find_binary(binary_name: str = "chainwatch") -> str:
    """Locate the chainwatch binary on PATH."""
    path = shutil.which(binary_name)
    if path is None:
        raise BinaryNotFoundError(
            f"{binary_name!r} not found on PATH. "
            f"Install from https://github.com/ppiankov/chainwatch"
        )
    return path


def run(
    args: List[str],
    binary: str = "chainwatch",
    timeout: Optional[float] = None,
    stdin_data: Optional[str] = None,
) -> Tuple[int, str, str]:
    """Run chainwatch binary with args. Returns (exit_code, stdout, stderr)."""
    proc = subprocess.run(
        [binary] + args,
        capture_output=True,
        text=True,
        timeout=timeout,
        input=stdin_data,
    )
    return proc.returncode, proc.stdout, proc.stderr


def parse_json(text: str) -> Dict[str, Any]:
    """Parse JSON from chainwatch output, returning empty dict on failure."""
    text = text.strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}
