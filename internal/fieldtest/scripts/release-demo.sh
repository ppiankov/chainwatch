#!/bin/bash
# release-demo.sh — Orchestrates the split-screen fieldtest demo using GNU screen.
# Creates a screen session with two vertical regions:
#   Left:  real clawbot agent binary processing a mission
#   Right: real chainwatch audit log (tail -f on JSONL with jq formatting)
# Designed to run inside VHS for GIF recording.
set -eu

AUDIT_LOG="/tmp/release-fieldtest.jsonl"
DONE_MARKER="/tmp/release-demo-done"

# Clean up from previous runs
rm -f "$AUDIT_LOG" "$DONE_MARKER"
touch "$AUDIT_LOG"

# Kill any leftover screen session
screen -S fieldtest -X quit 2>/dev/null || true

# Create screen session running clawbot in the first window
screen -dmS fieldtest -t clawbot bash -c "./clawbot; exec bash"

# Create second window for the audit guard
screen -S fieldtest -X screen -t guard bash -c "printf '\\033[1;31m=== CHAINWATCH GUARD ===\\033[0m\\n\\033[2mReal-time enforcement decisions\\033[0m\\n\\n'; tail -f $AUDIT_LOG | jq -r '\"[\\(.decision | ascii_upcase)] \\(.action.tool):\\(.action.resource)\" + if .reason != \"\" then \"\\n         \" + .reason else \"\" end'; exec bash"

# Set up vertical split: left=clawbot, right=guard
screen -S fieldtest -X split -v
screen -S fieldtest -X focus
screen -S fieldtest -X select guard
screen -S fieldtest -X focus
screen -S fieldtest -X select clawbot

# Attach so VHS can see both panes
screen -r fieldtest &
SCREEN_PID=$!

# Wait for the clawbot agent to finish
while [ ! -f "$DONE_MARKER" ]; do
    sleep 1
done
sleep 3

# Clean up
screen -S fieldtest -X quit 2>/dev/null || true
rm -f "$DONE_MARKER"
