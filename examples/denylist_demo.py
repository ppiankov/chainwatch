"""
Demonstration of Chainwatch v0.1.1 Denylist Enforcement.

Shows how the denylist blocks dangerous resources before they can be accessed.
"""

import os

from chainwatch.denylist import Denylist
from chainwatch.policy import evaluate
from chainwatch.types import Action, TraceState

print("=" * 70)
print("Chainwatch v0.1.1: Denylist Demonstration")
print("=" * 70)
print()

# Load denylist (uses defaults if ~/.chainwatch/denylist.yaml doesn't exist)
denylist = Denylist.load()

print("Loaded denylist with default patterns:")
print("  ✓ Checkout/payment URLs")
print("  ✓ Credential files (SSH keys, AWS credentials, etc.)")
print("  ✓ Dangerous shell commands")
print()
print("-" * 70)
print()

# Scenario 1: Agent tries to navigate to checkout page
print("[Scenario 1] Agent attempts to navigate to checkout URL...")
print()

action1 = Action(
    tool="browser_navigate",
    resource="https://coursera.org/checkout/confirm",
    operation="navigate",
    params={"url": "https://coursera.org/checkout/confirm"},
)

state = TraceState(trace_id="demo-123")

policy_result = evaluate(action=action1, state=state, purpose="research", denylist=denylist)

print(f"Decision: {policy_result.decision}")
print(f"Reason: {policy_result.reason}")
print()

if policy_result.decision == "deny":
    print("✓ BLOCKED: Agent cannot proceed to checkout")
else:
    print("✗ UNEXPECTED: Should have been blocked")

print()
print("-" * 70)
print()

# Scenario 2: Agent tries to read SSH private key
print("[Scenario 2] Agent attempts to read SSH private key...")
print()

action2 = Action(
    tool="file_read",
    resource=os.path.expanduser("~/.ssh/id_rsa"),
    operation="read",
    params={"path": "~/.ssh/id_rsa"},
)

policy_result2 = evaluate(action=action2, state=state, purpose="research", denylist=denylist)

print(f"Decision: {policy_result2.decision}")
print(f"Reason: {policy_result2.reason}")
print()

if policy_result2.decision == "deny":
    print("✓ BLOCKED: Agent cannot access SSH private key")
else:
    print("✗ UNEXPECTED: Should have been blocked")

print()
print("-" * 70)
print()

# Scenario 3: Agent tries normal browsing (should be allowed)
print("[Scenario 3] Agent browses normal content...")
print()

action3 = Action(
    tool="browser_navigate",
    resource="https://coursera.org/courses/python",
    operation="navigate",
    params={"url": "https://coursera.org/courses/python"},
)

policy_result3 = evaluate(action=action3, state=state, purpose="research", denylist=denylist)

print(f"Decision: {policy_result3.decision}")
print(f"Reason: {policy_result3.reason}")
print()

if policy_result3.decision != "deny":
    print("✓ ALLOWED: Normal browsing proceeds")
else:
    print("✗ UNEXPECTED: Should have been allowed")

print()
print("=" * 70)
print("Summary")
print("=" * 70)
print()
print("Chainwatch denylist successfully:")
print("  ✓ Blocked checkout URL (prevents $3000 purchase)")
print("  ✓ Blocked SSH private key access (prevents credential leak)")
print("  ✓ Allowed normal browsing (doesn't break legitimate use)")
print()
print("This protection is active for ALL Chainwatch-enforced operations.")
print("No ML. No guessing. Just deterministic blocking.")
print()
print("To customize the denylist:")
print("  1. Run: chainwatch init-denylist")
print("  2. Edit: ~/.chainwatch/denylist.yaml")
print("  3. Add your own patterns")
print()
print("=" * 70)
