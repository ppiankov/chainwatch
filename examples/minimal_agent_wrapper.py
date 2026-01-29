from chainwatch.types import Action, TraceState
from chainwatch.policy import evaluate
from chainwatch.enforcement import enforce, EnforcementError


def call_tool(action: Action, state: TraceState, purpose: str):
    # pretend tool returns something + meta
    tool_result = {"rows": action.result_meta.get("rows", 0), "payload": "..."}

    result = evaluate(action, state, purpose)
    return enforce(result, tool_result)


if __name__ == "__main__":
    state = TraceState(trace_id="t-demo")
    purpose = "SOC_efficiency"

    actions = [
        Action(
            tool="org",
            resource="orgchart",
            operation="read",
            result_meta={"sensitivity": "low", "rows": 50},
        ),
        Action(
            tool="siem",
            resource="siem/incidents",
            operation="read",
            result_meta={"sensitivity": "medium", "rows": 5000},
        ),
        Action(
            tool="hr",
            resource="hr/salary",
            operation="read",
            result_meta={"sensitivity": "high", "rows": 1200},
        ),
    ]

    for a in actions:
        try:
            out = call_tool(a, state, purpose)
            print("OK:", a.resource, out if isinstance(out, dict) else "...")
        except EnforcementError as e:
            print("BLOCKED:", a.resource, str(e))
