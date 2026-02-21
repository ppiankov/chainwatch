# Operator Workflow

How a human operator uses nullbot and runforge on a production host.

## Overview

```
operator submits job
    ↓
nullbot daemon investigates (autonomous)
    ↓
nullbot proposes work order (pending_approval)
    ↓
operator reviews and approves ← YOU ARE HERE (human gate)
    ↓
sentinel executes via runner cascade (autonomous)
    ↓
operator checks results
```

The human makes exactly one decision: approve or reject. Everything before and after is automated but constrained by chainwatch policy.

## Directory layout

```
/home/nullbot/
  inbox/              ← operator drops jobs here
  outbox/             ← daemon writes results with proposed WOs
  state/
    processing/       ← daemon internal (jobs being investigated)
    approved/         ← approved WO results (moved from outbox)
    rejected/         ← rejected WO results
    ingested/         ← IngestPayloads for runforge (created on approve)
    sentinel/
      processing/     ← WOs being executed by sentinel
      completed/      ← successful execution results
      failed/         ← failed execution results
  config/
    nullbot.env       ← API keys, profile settings
  .chainwatch/
    policy.yaml       ← enforcement rules
    denylist.yaml     ← hard block patterns
    profiles/         ← agent profiles (clawbot, ephemeral WO profiles)
```

## Step 1: Submit a job

Drop a JSON file into the inbox. The daemon watches this directory.

```bash
cat > /home/nullbot/inbox/job-001.json <<'JSON'
{
  "id": "job-001",
  "type": "investigate",
  "target": {
    "host": "localhost",
    "scope": "/var/log"
  },
  "brief": "check for failed SSH logins in the last 24 hours",
  "source": "manual",
  "created_at": "2026-02-21T10:00:00Z"
}
JSON
```

**What happens next (autonomous):**

1. The nullbot daemon picks up the file within seconds (fsnotify)
2. It moves the job to `state/processing/` (prevents double-processing)
3. It runs the investigation runbook against the target scope
4. It collects evidence (log entries, file contents, system state)
5. If an LLM API key is configured, it classifies the evidence into typed observations
6. If observations exist, it generates a proposed work order with remediation goals
7. It writes a result to `outbox/` with status `pending_approval`

## Step 2: Review proposed work orders

```bash
nullbot list --outbox /home/nullbot/outbox --state /home/nullbot/state
```

Output shows each pending WO with:

- **Observations**: what nullbot found (type, severity, detail)
- **Proposed goals**: what the remediation should accomplish
- **Constraints**: allowed paths, denied paths, network access, sudo access, max steps
- **Expiration**: WOs expire after 24 hours if not approved

Read the full WO details:

```bash
cat /home/nullbot/outbox/<wo-id>.json | python3 -m json.tool
```

## Step 3: Approve or reject

This is the human gate. Nothing executes without explicit approval.

**Approve:**

```bash
nullbot approve <wo-id> --outbox /home/nullbot/outbox --state /home/nullbot/state
```

What approval does:

1. Moves the WO result from `outbox/` to `state/approved/`
2. Builds an `IngestPayload` from the proposed WO
3. Writes the payload to `state/ingested/<wo-id>.json`

The IngestPayload contains only typed observations and constraints. It does not carry raw evidence data. The constraints (allowed paths, network, sudo) map directly to a chainwatch enforcement profile.

**Approval does not bypass chainwatch.** The remediation agent runs all commands through `chainwatch exec` with an ephemeral profile derived from the WO constraints. If the agent tries to exceed its allowed scope, chainwatch blocks the command.

**Reject:**

```bash
nullbot reject <wo-id> --outbox /home/nullbot/outbox --state /home/nullbot/state --reason "false positive"
```

Rejected WOs are moved to `state/rejected/` with the rejection reason. No execution occurs.

## Step 4: Execution

### Automatic (sentinel)

If the `runforge-sentinel` service is running, it watches `state/ingested/` and automatically picks up approved WOs.

```bash
# Check sentinel status
systemctl status runforge-sentinel

# Watch sentinel logs
journalctl -u runforge-sentinel -f
```

The sentinel:

1. Detects new payload in `state/ingested/` (fsnotify or polling)
2. Validates the payload
3. Moves it to `state/sentinel/processing/`
4. Builds an ephemeral chainwatch profile from the WO constraints
5. Executes via the runner cascade (claude, codex, gemini)
6. Scans output for leaked secrets and redacts in place
7. Writes result to `state/sentinel/completed/` or `state/sentinel/failed/`
8. Cleans up the ephemeral profile

### Manual

If sentinel is not running or you want explicit control:

```bash
runforge ingest --payload /home/nullbot/state/ingested/<wo-id>.json
```

Flags:

```
--runner         Primary runner (default: claude)
--fallbacks      Fallback runners, comma-separated
--repo-dir       Target directory (default: .)
--max-runtime    Per-task timeout (default: 30m)
--dry-run        Show prompt and profile without executing
```

## Step 5: Check results

```bash
# Completed WOs
ls /home/nullbot/state/sentinel/completed/
cat /home/nullbot/state/sentinel/completed/<wo-id>.json

# Failed WOs
ls /home/nullbot/state/sentinel/failed/
cat /home/nullbot/state/sentinel/failed/<wo-id>.json
```

Each result contains:

- `wo_id`: the work order ID
- `state`: completed or failed
- `runner_used`: which runner executed the WO
- `duration`: execution time
- `error`: error message (if failed)
- `output_dir`: path to execution output files

## Safety invariants

These hold at every stage of the workflow:

1. **Human approval required** — nothing executes until `nullbot approve` is called
2. **Chainwatch enforcement** — all remediation commands go through `chainwatch exec` with WO-scoped constraints
3. **Environment sanitization** — API keys and tokens are stripped from subprocess environments before runner execution
4. **Output scanning** — execution output is scanned for leaked secrets and redacted in place
5. **Dedicated user** — everything runs as the `nullbot` system user (no login shell, minimal filesystem access)
6. **Systemd hardening** — `ProtectSystem=strict`, `NoNewPrivileges=true`, `MemoryDenyWriteExecute=true`, resource limits
7. **No automatic retry** — failed WOs stay in `failed/` for operator review. Re-execution requires manual re-queuing
8. **PID lock** — prevents duplicate sentinel instances

## Common operations

```bash
# Restart services after config change
systemctl restart nullbot-daemon
systemctl restart runforge-sentinel

# View daemon logs
journalctl -u nullbot-daemon --since "1 hour ago"

# View sentinel logs
journalctl -u runforge-sentinel --since "1 hour ago"

# Check service health
systemctl status nullbot-daemon runforge-sentinel

# List all pending WOs
nullbot list --outbox /home/nullbot/outbox --state /home/nullbot/state

# Re-queue a failed WO (copy back to ingested)
cp /home/nullbot/state/sentinel/failed/<wo-id>.json /home/nullbot/state/ingested/<wo-id>.json
```
