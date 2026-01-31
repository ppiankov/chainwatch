"""
Denylist enforcement for Chainwatch v0.1.1.

Simple, deterministic resource/action blocking.
No approval workflow - just hard deny for dangerous patterns.
"""

import re
from pathlib import Path
from typing import Dict, List, Optional

import yaml

DEFAULT_DENYLIST = {
    "urls": [
        # E-commerce checkout
        "/checkout",
        "/payment",
        "/billing",
        "/subscribe",
        "/cart/confirm",
        "/order/place",
        "/upgrade",
        # Payment providers
        "stripe.com/checkout",
        "paddle.com/checkout",
        "paypal.com/checkoutnow",
        # Subscription platforms
        "buy.stripe.com",
        "checkout.stripe.com",
    ],
    "files": [
        # SSH keys
        "~/.ssh/id_rsa",
        "~/.ssh/id_ed25519",
        "**/id_rsa",
        "**/id_ed25519",
        # Cloud credentials
        "~/.aws/credentials",
        "~/.aws/config",
        "~/.config/gcloud/credentials",
        "~/.azure/credentials",
        # API keys
        "**/secrets.json",
        "**/.env",
        "**/credentials.json",
        # Password managers
        "~/.password-store",
        "**/KeePass*.kdbx",
    ],
    "commands": [
        # Destructive
        "rm -rf /",
        "dd if=/dev/zero",
        "mkfs",
        "fdisk",
        # Privilege escalation
        "sudo su",
        "sudo -i",
        # Data exfiltration
        "curl.*|.*sh",
        "wget.*|.*sh",
    ],
}


class Denylist:
    """
    Simple pattern-based denylist for resources and actions.

    Usage:
        denylist = Denylist.load()
        if denylist.is_blocked(action):
            raise EnforcementError("Access denied: resource is denylisted")
    """

    def __init__(self, patterns: Dict[str, List[str]]):
        self.url_patterns = [re.compile(p, re.IGNORECASE) for p in patterns.get("urls", [])]
        self.file_patterns = patterns.get("files", [])
        self.command_patterns = [re.compile(p, re.IGNORECASE) for p in patterns.get("commands", [])]

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Denylist":
        """
        Load denylist from file, or use defaults if file doesn't exist.

        Args:
            path: Path to denylist.yaml. Defaults to ~/.chainwatch/denylist.yaml
        """
        if path is None:
            path = Path.home() / ".chainwatch" / "denylist.yaml"

        if path.exists():
            with open(path) as f:
                patterns = yaml.safe_load(f) or {}
        else:
            patterns = DEFAULT_DENYLIST

        return cls(patterns)

    @classmethod
    def create_default(cls, path: Optional[Path] = None) -> Path:
        """
        Create default denylist file at path.

        Args:
            path: Path to write denylist.yaml. Defaults to ~/.chainwatch/denylist.yaml

        Returns:
            Path where file was created
        """
        if path is None:
            path = Path.home() / ".chainwatch" / "denylist.yaml"

        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w") as f:
            yaml.dump(DEFAULT_DENYLIST, f, default_flow_style=False, sort_keys=False)

        return path

    def is_blocked(self, resource: str, tool: str) -> tuple[bool, Optional[str]]:
        """
        Check if resource/action is denylisted.

        Args:
            resource: The resource being accessed (URL, file path, command)
            tool: The tool type ("browser", "file_read", "shell_exec", etc.)

        Returns:
            (is_blocked: bool, reason: Optional[str])
        """
        # Check URL patterns
        if tool in ["browser_navigate", "browser", "http_get", "http_post"]:
            for pattern in self.url_patterns:
                if pattern.search(resource):
                    return True, f"URL matches denylist pattern: {pattern.pattern}"

        # Check file patterns
        if tool in ["file_read", "file_write", "file_delete"]:
            expanded = Path(resource).expanduser()
            for pattern in self.file_patterns:
                pattern_path = Path(pattern).expanduser()
                # Glob matching for wildcards
                if "*" in pattern:
                    if expanded.match(pattern):
                        return True, f"File matches denylist pattern: {pattern}"
                # Exact path matching
                elif expanded == pattern_path or str(expanded) == pattern:
                    return True, f"File is denylisted: {pattern}"

        # Check command patterns
        if tool in ["shell_exec", "exec", "command"]:
            for pattern in self.command_patterns:
                if pattern.search(resource):
                    return True, f"Command matches denylist pattern: {pattern.pattern}"

        return False, None

    def add_pattern(self, category: str, pattern: str) -> None:
        """
        Add a pattern to the denylist at runtime.

        Args:
            category: One of "urls", "files", "commands"
            pattern: The pattern to add
        """
        if category == "urls":
            self.url_patterns.append(re.compile(pattern, re.IGNORECASE))
        elif category == "files":
            self.file_patterns.append(pattern)
        elif category == "commands":
            self.command_patterns.append(re.compile(pattern, re.IGNORECASE))
        else:
            raise ValueError(f"Unknown category: {category}")

    def to_dict(self) -> Dict[str, List[str]]:
        """Export denylist as dictionary for serialization."""
        return {
            "urls": [p.pattern for p in self.url_patterns],
            "files": self.file_patterns,
            "commands": [p.pattern for p in self.command_patterns],
        }
