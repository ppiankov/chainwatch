"""Unit tests for trace accumulation logic."""

from chainwatch.tracer import TraceAccumulator, new_span_id, new_trace_id
from chainwatch.types import Action, TraceState


def test_new_trace_id_format():
    """new_trace_id should return valid trace ID."""
    trace_id = new_trace_id()
    assert isinstance(trace_id, str)
    assert len(trace_id) > 0
    assert trace_id.startswith("t-")


def test_new_span_id_format():
    """new_span_id should return valid span ID."""
    span_id = new_span_id()
    assert isinstance(span_id, str)
    assert len(span_id) > 0
    assert span_id.startswith("s-")


def test_trace_accumulator_initialization():
    """TraceAccumulator should initialize with empty state."""
    state = TraceState(trace_id="test-123")
    tracer = TraceAccumulator(state=state)

    assert tracer.state.trace_id == "test-123"
    assert len(tracer.events) == 0
    assert len(tracer.state.seen_sources) == 0


def test_record_action_updates_state():
    """record_action should update trace state."""
    state = TraceState(trace_id="test")
    tracer = TraceAccumulator(state=state)

    action = Action(
        tool="api",
        resource="source1",
        operation="read",
        result_meta={"sensitivity": "medium", "rows": 10, "bytes": 1000},
    )

    tracer.record_action(
        actor={"user_id": "test"},
        purpose="test",
        action=action,
        decision={"result": "ALLOW", "reason": "Low risk"},
        span_id="s-1",
    )

    # State should be updated
    assert "api" in tracer.state.seen_sources  # Tracks tool name, not resource
    assert tracer.state.max_sensitivity == "medium"
    assert tracer.state.volume_rows == 10
    assert tracer.state.volume_bytes == 1000

    # Event should be recorded
    assert len(tracer.events) == 1
    event = tracer.events[0]
    assert event.action["tool"] == "api"  # action is a dict, not Action object
    assert event.decision["result"] == "ALLOW"


def test_state_tracks_max_sensitivity():
    """State should track highest sensitivity seen."""
    state = TraceState(trace_id="test")
    tracer = TraceAccumulator(state=state)

    # Low sensitivity action
    action1 = Action(
        tool="api1",
        resource="src1",
        operation="read",
        result_meta={"sensitivity": "low", "rows": 5},
    )
    tracer.record_action(
        actor={"user": "test"},
        purpose="test",
        action=action1,
        decision={"result": "ALLOW"},
        span_id="s-1",
    )
    assert tracer.state.max_sensitivity == "low"

    # High sensitivity action should update max
    action2 = Action(
        tool="api2",
        resource="src2",
        operation="read",
        result_meta={"sensitivity": "high", "rows": 5},
    )
    tracer.record_action(
        actor={"user": "test"},
        purpose="test",
        action=action2,
        decision={"result": "ALLOW"},
        span_id="s-2",
    )
    assert tracer.state.max_sensitivity == "high"

    # Medium sensitivity action should not lower max
    action3 = Action(
        tool="api3",
        resource="src3",
        operation="read",
        result_meta={"sensitivity": "medium", "rows": 5},
    )
    tracer.record_action(
        actor={"user": "test"},
        purpose="test",
        action=action3,
        decision={"result": "ALLOW"},
        span_id="s-3",
    )
    assert tracer.state.max_sensitivity == "high"


def test_state_accumulates_volume():
    """State should accumulate rows and bytes."""
    state = TraceState(trace_id="test")
    tracer = TraceAccumulator(state=state)

    action1 = Action(
        tool="api1",
        resource="src1",
        operation="read",
        result_meta={"rows": 100, "bytes": 5000},
    )
    tracer.record_action(
        actor={"user": "test"},
        purpose="test",
        action=action1,
        decision={"result": "ALLOW"},
        span_id="s-1",
    )

    assert tracer.state.volume_rows == 100
    assert tracer.state.volume_bytes == 5000

    action2 = Action(
        tool="api2",
        resource="src2",
        operation="read",
        result_meta={"rows": 50, "bytes": 2000},
    )
    tracer.record_action(
        actor={"user": "test"},
        purpose="test",
        action=action2,
        decision={"result": "ALLOW"},
        span_id="s-2",
    )

    assert tracer.state.volume_rows == 150
    assert tracer.state.volume_bytes == 7000


def test_to_jsonable_export():
    """to_jsonable should export serializable trace."""
    state = TraceState(trace_id="test-123")
    tracer = TraceAccumulator(state=state)

    action = Action(
        tool="api",
        resource="source1",
        operation="read",
        result_meta={"sensitivity": "low", "rows": 10},
    )
    tracer.record_action(
        actor={"user_id": "test"},
        purpose="test",
        action=action,
        decision={"result": "ALLOW", "reason": "Low risk"},
        span_id="s-1",
    )

    result = tracer.to_jsonable()

    assert isinstance(result, dict)
    assert "trace_state" in result  # Key is trace_state, not state
    assert "events" in result
    assert result["trace_state"]["trace_id"] == "test-123"  # trace_id is inside trace_state
    assert len(result["events"]) == 1
