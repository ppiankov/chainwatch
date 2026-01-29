"""
SOC Efficiency Agent Demo

Demonstrates Chainwatch enforcement for a realistic agent scenario:
- Agent task: "Improve SOC analyst effectiveness"
- Attempts to read: org chart, SIEM data, HR records, salary data
- Expected enforcement: allow org chart, allow SIEM, potentially redact HR, block salary

CRITICAL: This demo exits 1 if salary access is NOT blocked.
This proves Chainwatch is a control plane, not just an observability tool.
"""

import json
import sys
import tempfile
from pathlib import Path

from chainwatch.wrappers.file_ops import FileGuard
from chainwatch.enforcement import EnforcementError


def setup_demo_files(base_dir: Path) -> dict:
    """Create mock data files for demo."""
    files = {}

    # 1. Org chart (low risk - should allow)
    org_chart = base_dir / "org_chart.txt"
    org_chart.write_text(
        """SOC Team Structure:
- Alice Chen (Manager)
- Bob Smith (Senior Analyst)
- Carol Johnson (Analyst)
- David Lee (Junior Analyst)
"""
    )
    files["org_chart"] = str(org_chart)

    # 2. SIEM incidents (medium risk - should allow)
    siem_data = base_dir / "siem_incidents.json"
    siem_data.write_text(
        json.dumps(
            {
                "incidents": [
                    {
                        "id": 1,
                        "severity": "high",
                        "assigned_to": "Bob Smith",
                        "status": "open",
                        "description": "Multiple failed login attempts detected",
                    },
                    {
                        "id": 2,
                        "severity": "medium",
                        "assigned_to": "Carol Johnson",
                        "status": "closed",
                        "description": "Unusual outbound traffic pattern",
                    },
                    {
                        "id": 3,
                        "severity": "low",
                        "assigned_to": "David Lee",
                        "status": "open",
                        "description": "Certificate expiring soon",
                    },
                ],
            },
            indent=2,
        )
    )
    files["siem"] = str(siem_data)

    # 3. HR employee list (high risk PII - may redact)
    hr_data = base_dir / "hr_employees.csv"
    hr_data.write_text(
        """name,email,phone,team
Alice Chen,alice.chen@corp.com,555-0101,SOC
Bob Smith,bob.smith@corp.com,555-0102,SOC
Carol Johnson,carol.j@corp.com,555-0103,SOC
David Lee,david.lee@corp.com,555-0104,SOC
"""
    )
    files["hr"] = str(hr_data)

    # 4. Salary data (high risk - MUST block)
    salary_data = base_dir / "hr_salary_bands.csv"
    salary_data.write_text(
        """name,salary,bonus_eligible
Alice Chen,165000,yes
Bob Smith,145000,yes
Carol Johnson,105000,yes
David Lee,85000,no
"""
    )
    files["salary"] = str(salary_data)

    return files


def simulate_agent_workflow(guard: FileGuard, files: dict):
    """Simulate agent attempting to read various files."""
    results = []

    # Action 1: Read org chart (should succeed)
    print("\n[Agent] Attempting to read org chart...")
    try:
        with open(files["org_chart"], "r") as f:
            content = f.read()
        results.append(
            {
                "action": "read_org_chart",
                "status": "allowed",
                "content_sample": content[:100],
            }
        )
        print("✓ Allowed: Org chart read successfully")
    except EnforcementError as e:
        results.append(
            {
                "action": "read_org_chart",
                "status": "blocked",
                "reason": str(e),
            }
        )
        print(f"✗ Blocked: {e}")

    # Action 2: Read SIEM data (should succeed)
    print("\n[Agent] Attempting to read SIEM incidents...")
    try:
        with open(files["siem"], "r") as f:
            content = f.read()
        results.append(
            {
                "action": "read_siem",
                "status": "allowed",
                "content_sample": content[:100],
            }
        )
        print("✓ Allowed: SIEM data read successfully")
    except EnforcementError as e:
        results.append(
            {
                "action": "read_siem",
                "status": "blocked",
                "reason": str(e),
            }
        )
        print(f"✗ Blocked: {e}")

    # Action 3: Read HR employee list (may succeed with redaction)
    print("\n[Agent] Attempting to read HR employee list...")
    try:
        with open(files["hr"], "r") as f:
            content = f.read()
        results.append(
            {
                "action": "read_hr_data",
                "status": "allowed",
                "content_sample": content[:100] if isinstance(content, str) else str(content)[:100],
            }
        )
        print("⚠ Allowed: HR data (may contain redacted PII)")
    except EnforcementError as e:
        results.append(
            {
                "action": "read_hr_data",
                "status": "blocked",
                "reason": str(e),
            }
        )
        print(f"✗ Blocked: {e}")

    # Action 4: Read salary data (MUST BLOCK)
    print("\n[Agent] Attempting to read salary data...")
    try:
        with open(files["salary"], "r") as f:
            content = f.read()
        results.append(
            {
                "action": "read_salary",
                "status": "allowed",  # Should not reach here
                "content_sample": content[:100],
            }
        )
        print("⚠ WARNING: Salary data was allowed (POLICY VIOLATION!)")
    except EnforcementError as e:
        results.append(
            {
                "action": "read_salary",
                "status": "blocked",
                "reason": str(e),
            }
        )
        print(f"✓ Blocked (expected): {e}")

    return results


def main():
    print("=" * 70)
    print("Chainwatch Demo: SOC Efficiency Agent")
    print("=" * 70)
    print("\nScenario: Agent task is 'Improve SOC analyst effectiveness'")
    print("Expected behavior:")
    print("  - Allow: org chart, SIEM data")
    print("  - Allow (may redact): HR employee list (PII)")
    print("  - Block: salary data (requires approval)")
    print()

    # Setup
    with tempfile.TemporaryDirectory() as tmpdir:
        base_dir = Path(tmpdir)
        files = setup_demo_files(base_dir)

        # Configure guard
        actor = {
            "user_id": "analyst_bob",
            "user_role": "soc_analyst",
            "agent_id": "soc_efficiency_agent",
            "agent_version": "0.1.0",
        }

        # Run with protection
        with FileGuard(purpose="SOC_efficiency", actor=actor) as guard:
            results = simulate_agent_workflow(guard, files)

        # Output trace summary
        print("\n" + "=" * 70)
        print("Trace Summary")
        print("=" * 70)
        trace = guard.get_trace_summary()
        print(json.dumps(trace, indent=2))

        # Check if salary was blocked (CRITICAL)
        salary_blocked = any(
            r["action"] == "read_salary" and r["status"] == "blocked" for r in results
        )

        print("\n" + "=" * 70)
        if salary_blocked:
            print("✓ Demo successful: Salary access was blocked as expected")
            print("=" * 70)
            return 0
        else:
            print("✗ Demo FAILED: Salary access was not properly blocked")
            print("=" * 70)
            print("\nThis is a CRITICAL failure - Chainwatch did not enforce control.")
            print("No 'warn-only' mode - it blocks or it's not an MVP.")
            return 1


if __name__ == "__main__":
    sys.exit(main())
