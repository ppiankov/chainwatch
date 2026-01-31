"""Unit tests for denylist enforcement."""

import tempfile
from pathlib import Path

from chainwatch.denylist import DEFAULT_DENYLIST, Denylist


def test_default_denylist_patterns():
    """Default denylist should contain common dangerous patterns."""
    assert "/checkout" in DEFAULT_DENYLIST["urls"]
    assert "/payment" in DEFAULT_DENYLIST["urls"]
    assert "~/.ssh/id_rsa" in DEFAULT_DENYLIST["files"]
    assert "~/.aws/credentials" in DEFAULT_DENYLIST["files"]
    assert any("rm -rf" in cmd for cmd in DEFAULT_DENYLIST["commands"])


def test_url_blocking():
    """URLs matching denylist patterns should be blocked."""
    denylist = Denylist({"urls": ["/checkout", "/payment", "stripe.com"]})

    blocked, reason = denylist.is_blocked("https://example.com/checkout", "browser_navigate")
    assert blocked
    assert "checkout" in reason.lower()

    blocked, reason = denylist.is_blocked("https://stripe.com/checkout/session", "http_post")
    assert blocked

    blocked, reason = denylist.is_blocked("https://example.com/products", "browser_navigate")
    assert not blocked


def test_file_blocking():
    """Files matching denylist patterns should be blocked."""
    denylist = Denylist({"files": ["~/.ssh/id_rsa", "**/secrets.json"]})

    home = Path.home()
    ssh_key = str(home / ".ssh" / "id_rsa")

    blocked, reason = denylist.is_blocked(ssh_key, "file_read")
    assert blocked
    assert "id_rsa" in reason

    blocked, reason = denylist.is_blocked("/tmp/secrets.json", "file_read")
    assert blocked
    assert "secrets.json" in reason

    blocked, reason = denylist.is_blocked("/tmp/safe_file.txt", "file_read")
    assert not blocked


def test_command_blocking():
    """Commands matching denylist patterns should be blocked."""
    denylist = Denylist({"commands": ["rm -rf", "sudo su"]})

    blocked, reason = denylist.is_blocked("rm -rf /data", "shell_exec")
    assert blocked
    assert "rm -rf" in reason.lower()

    blocked, reason = denylist.is_blocked("sudo su", "exec")
    assert blocked

    blocked, reason = denylist.is_blocked("ls -la", "shell_exec")
    assert not blocked


def test_case_insensitive_matching():
    """Pattern matching should be case-insensitive."""
    denylist = Denylist({"urls": ["/CHECKOUT"]})

    blocked, _ = denylist.is_blocked("https://example.com/checkout", "browser")
    assert blocked

    blocked, _ = denylist.is_blocked("https://example.com/Checkout", "browser")
    assert blocked


def test_load_from_file():
    """Denylist should load from YAML file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("""
urls:
  - /test-checkout
files:
  - /test/secret.key
commands:
  - test-rm
""")
        path = Path(f.name)

    try:
        denylist = Denylist.load(path)

        blocked, _ = denylist.is_blocked("https://example.com/test-checkout", "browser")
        assert blocked

        blocked, _ = denylist.is_blocked("/test/secret.key", "file_read")
        assert blocked

        blocked, _ = denylist.is_blocked("test-rm something", "exec")
        assert blocked
    finally:
        path.unlink()


def test_load_uses_defaults_if_file_missing():
    """If denylist file doesn't exist, should use defaults."""
    nonexistent = Path("/nonexistent/denylist.yaml")

    denylist = Denylist.load(nonexistent)

    # Should have default patterns
    blocked, _ = denylist.is_blocked("https://example.com/checkout", "browser")
    assert blocked


def test_create_default_file():
    """create_default should write denylist file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "denylist.yaml"

        created_path = Denylist.create_default(path)

        assert created_path == path
        assert path.exists()

        # Should be loadable
        denylist = Denylist.load(path)
        blocked, _ = denylist.is_blocked("https://example.com/checkout", "browser")
        assert blocked


def test_add_pattern_at_runtime():
    """Patterns can be added at runtime."""
    denylist = Denylist({"urls": []})

    blocked, _ = denylist.is_blocked("https://dangerous.com", "browser")
    assert not blocked

    denylist.add_pattern("urls", "dangerous.com")

    blocked, _ = denylist.is_blocked("https://dangerous.com", "browser")
    assert blocked


def test_to_dict_exports_patterns():
    """to_dict should export patterns for serialization."""
    denylist = Denylist({"urls": ["/checkout"], "files": ["~/.ssh/id_rsa"], "commands": ["rm -rf"]})

    exported = denylist.to_dict()

    assert "/checkout" in exported["urls"]
    assert "~/.ssh/id_rsa" in exported["files"]
    assert any("rm -rf" in cmd.lower() for cmd in exported["commands"])


def test_tool_type_specificity():
    """Blocking should only apply to relevant tool types."""
    denylist = Denylist({"urls": ["/checkout"]})

    # Should block browser/HTTP tools
    blocked, _ = denylist.is_blocked("https://example.com/checkout", "browser_navigate")
    assert blocked

    # Should NOT block file tools (different boundary)
    blocked, _ = denylist.is_blocked("/checkout", "file_read")
    assert not blocked
