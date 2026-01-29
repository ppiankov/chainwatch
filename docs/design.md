# Design (v0)

## Execution model
- One user request = one trace
- Each tool/data action = a span
- Spans carry security attributes (resource, operation, sensitivity, volume, egress)

## Components (prototype)
- Interceptor/wrapper: captures tool calls and output writes
- Tracer: builds trace state (seen sources, max sensitivity, volume, egress)
- Policy engine: rules evaluate (current action + trace state) -> decision
- Enforcer: applies decision (deny/redact/approval/output rewrite)

## Decisions
- ALLOW
- DENY
- ALLOW_WITH_REDACTION
- REQUIRE_APPROVAL
- REWRITE_OUTPUT
