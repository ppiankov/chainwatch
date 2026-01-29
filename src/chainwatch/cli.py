"""
Minimal CLI entrypoint for Chainwatch.

For MVP: just version and demo commands.
Complex reporting will be added in v0.2.0.
"""

import json
import sys
from datetime import datetime, timezone


def utc_now_iso() -> str:
    """Get current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def cmd_version():
    """Output version info as JSON."""
    from . import __version__

    output = {
        "tool": "chainwatch",
        "version": __version__,
        "timestamp": utc_now_iso(),
    }
    print(json.dumps(output, indent=2))
    sys.exit(0)


def cmd_demo_soc():
    """Run SOC efficiency demo."""
    import subprocess

    result = subprocess.run(
        ["python", "examples/soc_efficiency_demo.py"],
        capture_output=False,
    )
    sys.exit(result.returncode)


def main():
    """CLI entrypoint."""
    if len(sys.argv) < 2:
        cmd_version()

    command = sys.argv[1]

    if command == "version":
        cmd_version()
    elif command == "demo" and len(sys.argv) > 2 and sys.argv[2] == "soc":
        cmd_demo_soc()
    else:
        print(f"Unknown command: {command}", file=sys.stderr)
        print("Usage: chainwatch [version | demo soc]", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
