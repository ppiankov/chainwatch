# Browser Checkout Gate

**Status:** v0.2.0 (planned)
**Priority:** HIGHEST
**Goal:** Prevent unauthorized spending via browser automation.

---

## Problem

Agents with browser access can:
- Navigate to e-commerce sites
- Add items to cart
- Complete checkout with saved payment methods
- Spend user's money without consent

**Real incident:** Clawbot purchased a $3000 online course using saved card.

**Root cause:** No enforcement between "browse" and "commit purchase".

---

## Solution

Intercept browser actions that indicate purchase intent and block them before money leaves the account.

### Detection Strategy

Identify checkout/payment through **multiple signals** (not just one):

#### 1. URL Pattern Matching

Detect URLs containing purchase-related paths:

```python
CHECKOUT_URL_PATTERNS = [
    r"/checkout",
    r"/payment",
    r"/billing",
    r"/subscribe",
    r"/cart/confirm",
    r"/order/place",
    r"/upgrade",
    r"/trial-to-paid",
    r"/purchase/complete",
]

# Third-party payment providers
PAYMENT_DOMAIN_PATTERNS = [
    r"stripe\.com/checkout",
    r"paddle\.com",
    r"paypal\.com/checkoutnow",
    r"braintree",
    r"square\.link/pay",
]
```

#### 2. Page Content Detection

Detect DOM elements and text indicating purchase:

```python
PURCHASE_BUTTON_TEXT = [
    "Buy Now",
    "Pay Now",
    "Complete Purchase",
    "Place Order",
    "Confirm Purchase",
    "Subscribe",
    "Upgrade Now",
    "Start Paid Plan",
    "Complete Payment",
]

PURCHASE_PAGE_INDICATORS = [
    # Payment form fields
    "input[name*='card']",
    "input[name*='cvv']",
    "input[autocomplete='cc-number']",

    # Order summary
    ".order-summary",
    ".checkout-summary",
    ".payment-total",

    # Price display near button
    r"\$\d+\.\d{2}.*(?:Buy|Pay|Subscribe)",
]
```

#### 3. Page Title/Meta Detection

```python
CHECKOUT_PAGE_TITLES = [
    "Checkout",
    "Payment",
    "Complete Order",
    "Confirm Purchase",
    "Billing Information",
]
```

---

## Architecture

### Component: `BrowserGuard`

Similar to `FileGuard`, but for browser operations.

```python
class BrowserGuard:
    """
    Context manager that wraps browser automation to enforce
    consent boundaries on purchase-related actions.
    """

    def __init__(
        self,
        purpose: str,
        actor: Dict[str, Any],
        consent_profile: Optional[ConsentProfile] = None,
        trace_id: Optional[str] = None
    ):
        self.purpose = purpose
        self.actor = actor
        self.consent_profile = consent_profile or load_default_consent()
        self.trace_id = trace_id or new_trace_id()
        self.tracer = TraceAccumulator(state=TraceState(trace_id=self.trace_id))

    def intercept_navigation(self, url: str) -> None:
        """
        Intercept browser navigation before it happens.
        Block if URL indicates checkout/payment.
        """
        action = self._build_action_from_url(url)
        policy_result = evaluate(
            action=action,
            state=self.tracer.state,
            purpose=self.purpose,
            consent=self.consent_profile
        )

        self.tracer.record_action(
            actor=self.actor,
            purpose=self.purpose,
            action=action,
            decision=asdict(policy_result),
            span_id=new_span_id()
        )

        # Enforce decision
        if policy_result.decision in [Decision.DENY, Decision.REQUIRE_APPROVAL]:
            raise EnforcementError(
                f"Navigation blocked: {policy_result.reason}\n"
                f"Approval required: chainwatch approve {policy_result.approval_key}"
            )

    def intercept_click(self, element: Dict[str, Any]) -> None:
        """
        Intercept button/link clicks.
        Block if element text indicates purchase.
        """
        text = element.get("text", "").lower()
        href = element.get("href", "")

        if self._is_purchase_button(text, href):
            action = self._build_action_from_click(element)
            # ... same enforcement flow

    def _build_action_from_url(self, url: str) -> Action:
        """Build Action from URL navigation."""
        classification = "low"
        tags = []

        # Check URL patterns
        for pattern in CHECKOUT_URL_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                classification = "critical"
                tags.append("CHECKOUT")
                break

        for pattern in PAYMENT_DOMAIN_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                classification = "critical"
                tags.append("PAYMENT_PROVIDER")
                break

        return Action(
            tool="browser_navigate",
            resource=url,
            operation="navigate",
            params={"url": url},
            result_meta={
                "classification": classification,
                "tags": tags,
            }
        )

    def _is_purchase_button(self, text: str, href: str) -> bool:
        """Check if button/link text indicates purchase."""
        for phrase in PURCHASE_BUTTON_TEXT:
            if phrase.lower() in text:
                return True

        # Check href for checkout patterns
        for pattern in CHECKOUT_URL_PATTERNS:
            if re.search(pattern, href, re.IGNORECASE):
                return True

        return False
```

---

## Integration with Playwright/Selenium

### Playwright Example

```python
from playwright.sync_api import sync_playwright
from chainwatch.wrappers.browser_ops import BrowserGuard

actor = {"user_id": "analyst1", "agent_id": "clawbot"}

with BrowserGuard(purpose="research", actor=actor) as guard:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()

        # Wrap navigation
        def guarded_goto(url):
            guard.intercept_navigation(url)  # Enforces before navigation
            return page.goto(url)

        # Wrap clicks
        def guarded_click(selector):
            element = page.locator(selector)
            element_info = {
                "text": element.inner_text(),
                "href": element.get_attribute("href") or "",
            }
            guard.intercept_click(element_info)  # Enforces before click
            return element.click()

        # Now use guarded versions
        guarded_goto("https://coursera.org/courses/python")  # Allowed
        guarded_goto("https://coursera.org/checkout")  # BLOCKED
```

### Selenium Example

```python
from selenium import webdriver
from chainwatch.wrappers.browser_ops import BrowserGuard

actor = {"user_id": "analyst1", "agent_id": "clawbot"}

with BrowserGuard(purpose="research", actor=actor) as guard:
    driver = webdriver.Chrome()

    original_get = driver.get

    def guarded_get(url):
        guard.intercept_navigation(url)
        return original_get(url)

    driver.get = guarded_get  # Monkey-patch

    driver.get("https://amazon.com/dp/B08N5WRWNW")  # Allowed
    driver.get("https://amazon.com/checkout/cart")  # BLOCKED
```

---

## Policy Rules

### Hardcoded Rule (MVP)

In `policy.py`, add:

```python
def evaluate(
    action: Action,
    state: TraceState,
    purpose: str,
    consent: Optional[ConsentProfile] = None
) -> PolicyResult:
    # ... existing logic

    # SPEND category enforcement
    if "CHECKOUT" in action.result_meta.get("tags", []):
        return PolicyResult(
            decision=Decision.REQUIRE_APPROVAL,
            reason="Purchase/checkout detected. Spending requires approval.",
            approval_key=f"spend_{action.resource[:20]}",
            policy_id="consent.SPEND",
        )

    if "PAYMENT_PROVIDER" in action.result_meta.get("tags", []):
        return PolicyResult(
            decision=Decision.REQUIRE_APPROVAL,
            reason="Payment provider detected. Transaction requires approval.",
            approval_key=f"payment_{urlparse(action.resource).netloc}",
            policy_id="consent.SPEND.payment_provider",
        )
```

### ConsentProfile Rule (v0.2.0+)

When `consent.yaml` exists:

```yaml
consent:
  spend:
    default: require_approval
    max_unattended: 0
```

The policy evaluates:

```python
if consent and consent.spend.default == "require_approval":
    if action matches SPEND category:
        return REQUIRE_APPROVAL
```

---

## Approval Flow

When browser action is blocked:

### Terminal Output

```
⚠️  Approval required

Category: SPEND
Action: Navigate to checkout
URL: https://coursera.org/checkout/confirm
Detected: URL pattern "/checkout"

Approve with:
  chainwatch approve spend_coursera

Or deny with:
  chainwatch deny spend_coursera

Expires in: 60 seconds
```

### User Approves

```bash
$ chainwatch approve spend_coursera
✓ Action approved: SPEND (coursera.org/checkout)
Approval token: spend_coursera_a9f2c1
Valid for: 1 use
```

Action proceeds. Token is consumed immediately.

### User Denies or Ignores

```bash
$ chainwatch deny spend_coursera
✓ Action denied: SPEND (coursera.org/checkout)
```

Or timeout:

```
✗ Approval expired: spend_coursera (60s timeout)
```

Agent receives:

```python
EnforcementError: Purchase requires approval (denied/expired)
```

---

## Testing Strategy

### Unit Tests

```python
def test_checkout_url_detection():
    """Checkout URLs should be classified as critical."""
    guard = BrowserGuard(purpose="test", actor={"user": "test"})

    action = guard._build_action_from_url("https://example.com/checkout")

    assert action.result_meta["classification"] == "critical"
    assert "CHECKOUT" in action.result_meta["tags"]


def test_purchase_button_detection():
    """Purchase buttons should be flagged."""
    guard = BrowserGuard(purpose="test", actor={"user": "test"})

    assert guard._is_purchase_button("Buy Now", "")
    assert guard._is_purchase_button("Pay $99", "")
    assert not guard._is_purchase_button("Learn More", "")
```

### Integration Tests

```python
def test_blocks_checkout_navigation():
    """Navigation to checkout should raise EnforcementError."""
    actor = {"user": "test"}

    with BrowserGuard(purpose="research", actor=actor) as guard:
        with pytest.raises(EnforcementError) as exc_info:
            guard.intercept_navigation("https://coursera.org/checkout/confirm")

        assert "approval" in str(exc_info.value).lower()


def test_allows_normal_browsing():
    """Normal navigation should proceed."""
    actor = {"user": "test"}

    with BrowserGuard(purpose="research", actor=actor) as guard:
        # Should not raise
        guard.intercept_navigation("https://coursera.org/courses/python")
```

### End-to-End Demo

```python
# examples/browser_checkout_demo.py

from chainwatch.wrappers.browser_ops import BrowserGuard
from chainwatch.enforcement import EnforcementError

actor = {"user_id": "demo_user", "agent_id": "clawbot"}

print("Demo: Agent attempts to purchase course")
print("=" * 60)

with BrowserGuard(purpose="research", actor=actor) as guard:
    try:
        print("[Agent] Browsing course catalog...")
        guard.intercept_navigation("https://coursera.org/courses/python")
        print("✓ Allowed: Course browsing")

        print("\n[Agent] Viewing pricing...")
        guard.intercept_navigation("https://coursera.org/courses/python/pricing")
        print("✓ Allowed: Pricing page")

        print("\n[Agent] Proceeding to checkout...")
        guard.intercept_navigation("https://coursera.org/checkout/confirm")
        print("✗ Should not reach here")

    except EnforcementError as e:
        print(f"✓ Blocked (expected): {e}")
        print("\n✓ Demo successful: Purchase blocked by Chainwatch")

    # Show trace
    trace = guard.get_trace_summary()
    print(f"\nEvents recorded: {len(trace['events'])}")
    print(f"Blocked actions: {sum(1 for e in trace['events'] if e['decision']['result'] == 'require_approval')}")
```

---

## Known Limitations

### False Positives

URLs that might trigger false blocks:
- `/checkout` in non-purchase contexts (e.g., library checkout)
- Payment-related documentation pages

**Mitigation:** Allow users to override per-domain or approve once for session.

### False Negatives

Purchase flows that might bypass detection:
- JavaScript-heavy SPAs with obfuscated URLs (e.g., `app.com/page?id=abc123`)
- Custom button text not in our patterns
- Payment via API calls (not browser navigation)

**Mitigation:**
- Add network-level interception (Phase 3: MCP gateway)
- User-reported patterns added to blocklist
- Layered defense: browser + network + tool-level gates

### Performance

URL/DOM pattern matching adds ~5-10ms per navigation.

**Mitigation:** Accept latency (human safety > speed).

---

## Deployment

### Install

```bash
pip install chainwatch[browser]  # Includes browser wrapper
```

### Configure

```bash
chainwatch init
# Answer questions about consent
```

Generates `~/.chainwatch/consent.yaml`:

```yaml
consent:
  spend:
    default: require_approval
```

### Run with Agent

```bash
chainwatch wrap clawbot --browser-guard
```

Or integrate directly:

```python
from chainwatch.wrappers.browser_ops import BrowserGuard

with BrowserGuard(purpose="research", actor={...}) as guard:
    # Your browser automation code
```

---

## Roadmap

### v0.2.0 (MVP)
- ✅ URL pattern detection
- ✅ Button text detection
- ✅ Approval workflow
- ✅ Playwright/Selenium integration examples

### v0.3.0
- Page content analysis (DOM inspection)
- Price extraction (show amount in approval prompt)
- Session-based approval (approve domain for session)

### v1.0.0
- Visual ML for checkout detection (fallback for obfuscated sites)
- Network-level payment API detection (Stripe, PayPal API calls)
- Per-merchant spending limits

---

## Success Metrics

**v0.2.0 ships when:**
- Agent navigates to checkout URL → blocked
- Agent clicks "Buy Now" → blocked
- User must approve out-of-band → action proceeds
- Trace shows the block + approval

**Prevents 95%+ of e-commerce checkout attempts.**

---

## Related Documents

- `docs/roadmap-clawbot.md` - Overall Clawbot integration strategy
- `docs/consent-profile-schema.md` - ConsentProfile specification
- `docs/threat-model-clawbot.md` - Browser-specific threats

---

**Last Updated:** 2026-01-29
**Status:** Planned (v0.2.0)
**Owner:** Chainwatch Core Team
