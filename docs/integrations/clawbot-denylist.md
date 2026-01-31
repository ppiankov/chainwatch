# Using Chainwatch with Clawbot (v0.1.1)

**Status:** Manual integration required (automatic wrapper coming in v0.2.0)

---

## What It Blocks

When integrated, Chainwatch blocks:
- **SPEND:** Checkout URLs (`/checkout`, `/payment`, `stripe.com/checkout`)
- **CREDENTIALS:** SSH keys (`~/.ssh/id_rsa`), AWS credentials, `.env` files
- **DESTRUCTIVE:** Commands like `rm -rf`, `sudo su`

**No approval workflow yet** - just hard blocks. v0.1.1 says "no", not "ask me first".

---

## Quick Setup (2 Minutes)

### 1. Install Chainwatch

```bash
pip install chainwatch
```

### 2. Create Denylist

```bash
chainwatch init-denylist
```

This creates `~/.chainwatch/denylist.yaml` with defaults.

### 3. Integrate with Your Clawbot Tools

If you're using Python-based tools/wrappers for Clawbot:

```python
from chainwatch.denylist import Denylist
from chainwatch.policy import evaluate
from chainwatch.types import Action, TraceState
from chainwatch.enforcement import EnforcementError

# Load once at startup
denylist = Denylist.load()

# In your browser navigation wrapper
def navigate(url):
    action = Action(
        tool="browser_navigate",
        resource=url,
        operation="navigate"
    )

    policy_result = evaluate(
        action=action,
        state=TraceState(trace_id="session-123"),
        purpose="research",
        denylist=denylist
    )

    if policy_result.decision == "deny":
        raise EnforcementError(f"Blocked: {policy_result.reason}")

    # Proceed with navigation
    # ... your existing code
```

### 4. Test It

Try navigating to a checkout URL:

```python
navigate("https://coursera.org/checkout")
# EnforcementError: Blocked: Denylisted: URL matches denylist pattern: /checkout
```

---

## What the User Sees

When Clawbot tries something on the denylist:

```
EnforcementError: Blocked: Denylisted: URL matches denylist pattern: /checkout
```

**That's it. Hard stop. No proceeding.**

---

## What's NOT Covered Yet (v0.1.1)

- ❌ Automatic Clawbot wrapping (you must integrate manually)
- ❌ Approval workflow ("require human approval" decision)
- ❌ Network-level blocking (HTTP proxy mode)
- ❌ Non-Python agents (Go, Rust, etc.)

**v0.1.1 provides the policy logic.** You hook it into your tools yourself.

**v0.2.0 (coming soon)** will provide:
- `chainwatch wrap clawbot` - Automatic interception
- Browser checkout gate - Blocks purchases without manual integration
- Approval workflow - `chainwatch approve <id>` for gated actions

---

## Customize the Denylist

```bash
vim ~/.chainwatch/denylist.yaml
```

Add your patterns:

```yaml
urls:
  - /checkout
  - /payment
  - internal-billing.company.com  # Your specific domain

files:
  - ~/.ssh/id_rsa
  - **/production.env

commands:
  - rm -rf
  - kubectl delete
```

---

## Real Use Case

**Problem:** Clawbot purchased a $3000 online course using saved card.

**Solution with v0.1.1:**
1. Add `/checkout` to denylist (already in defaults)
2. Integrate denylist check in browser tool
3. Agent tries to navigate to checkout → **blocked**
4. Money stays in account

---

## Limitations

### FileGuard Works Out of the Box

If you're using `FileGuard` for file operations:

```python
from chainwatch.wrappers.file_ops import FileGuard

with FileGuard(purpose="research", actor={...}) as guard:
    with open("~/.ssh/id_rsa", "r") as f:  # BLOCKED automatically
        data = f.read()
```

Denylist is loaded automatically.

### Browser/Network Requires Manual Integration

For browser navigation, HTTP requests, or shell commands:
- You must call `evaluate()` explicitly
- Pass `denylist=Denylist.load()`
- Check `policy_result.decision`

**v0.2.0 will do this automatically.**

---

## Example: Full Browser Wrapper

```python
from chainwatch.denylist import Denylist
from chainwatch.policy import evaluate
from chainwatch.types import Action, TraceState
from chainwatch.enforcement import EnforcementError

class SafeBrowser:
    def __init__(self):
        self.denylist = Denylist.load()
        self.state = TraceState(trace_id="browser-session")

    def navigate(self, url):
        # Build action
        action = Action(
            tool="browser_navigate",
            resource=url,
            operation="navigate"
        )

        # Evaluate policy
        result = evaluate(
            action=action,
            state=self.state,
            purpose="research",
            denylist=self.denylist
        )

        # Enforce
        if result.decision == "deny":
            raise EnforcementError(f"Navigation blocked: {result.reason}")

        # Proceed (your existing browser code)
        print(f"Navigating to {url}")

# Usage
browser = SafeBrowser()
browser.navigate("https://example.com/products")  # OK
browser.navigate("https://example.com/checkout")  # BLOCKED
```

---

## Next Steps

1. Integrate denylist into your Clawbot tool wrappers
2. Test with: `python examples/denylist_demo.py`
3. Customize patterns for your environment
4. Wait for v0.2.0 for automatic wrapping

---

**v0.1.1 prevents the $3000 purchase IF you integrate it.**

**v0.2.0 will prevent it automatically.**
