# Scenario Library

`tests/scenarios/` holds YAML scenarios for the execution-stage scenario runner
defined in `internal/scenario/types.go`.

## Format

Each file defines one scenario:

```yaml
name: Example Scenario
profile: coding-agent # optional built-in profile
cases:
  - action:
      tool: command
      resource: "git push origin main"
      operation: execute
    expect: allow
    purpose: push_known_remote
    agent: "" # optional
```

Field meanings:

- `name`: human-readable scenario name.
- `profile`: optional built-in profile from `internal/profile/profiles/`.
- `cases`: list of actions to evaluate.
- `action.tool`: intercepted tool class, such as `command`, `file_read`, `http`, `curl`.
- `action.resource`: primary resource string, command text, path, or URL.
- `action.operation`: optional verb such as `read`, `write`, `post`, `execute`.
- `expect`: expected decision. Use `allow`, `deny`, or `require_approval`.
- `purpose`: optional policy context string.
- `agent`: optional agent identity string.

## Adding Scenarios

1. Add a new `*.yaml` file in `tests/scenarios/`.
2. Keep the file focused on one attack family or policy surface.
3. Use a built-in profile when the scenario needs extra execution boundaries beyond the default denylist.
4. Prefer actions the current runner can evaluate directly: tool, resource, operation, purpose, and agent.
5. Verify with:

```bash
go test -race ./internal/scenario/... -v
```

You can also run the checker directly:

```bash
go run ./cmd/chainwatch check --scenario 'tests/scenarios/*.yaml'
```

## Current Limitation

The scenario runner evaluates execution-stage actions only. Profile
`authority_boundaries` are not part of the scenario YAML schema yet, so prompt
injection cases must be modeled as concrete tool calls that also hit existing
execution or self-protection boundaries.
