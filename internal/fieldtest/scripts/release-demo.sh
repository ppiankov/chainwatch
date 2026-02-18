#!/bin/bash
# release-demo.sh — Orchestrates the split-screen fieldtest demo.
# Creates a tmux session with two panes:
#   Left:  real clawbot agent binary processing a mission
#   Right: real chainwatch audit log (tail -f on JSONL with jq formatting)
# Designed to run inside VHS for GIF recording.
set -eu

AUDIT_LOG="/tmp/release-fieldtest.jsonl"
DONE_MARKER="/tmp/release-demo-done"

# Clean up from previous runs
rm -f "$AUDIT_LOG" "$DONE_MARKER"
touch "$AUDIT_LOG"

# Kill any leftover tmux session
tmux kill-session -t fieldtest 2>/dev/null || true

# Create detached tmux session
tmux new-session -d -s fieldtest -x 174 -y 44

# Split into left/right panes
tmux split-window -h -t fieldtest

# Right pane (pane 1): chainwatch guard — formatted audit log stream
tmux send-keys -t fieldtest:0.1 "printf '\\033[1;31m=== CHAINWATCH GUARD ===\\033[0m\\n\\033[2mReal-time enforcement decisions\\033[0m\\n\\n'" Enter
sleep 0.3
tmux send-keys -t fieldtest:0.1 "tail -f $AUDIT_LOG | jq -r '\"[\\(.decision | ascii_upcase)] \\(.action.tool):\\(.action.resource)\" + if .reason != \"\" then \"\\n         \" + .reason else \"\" end'" Enter

# Left pane (pane 0): real clawbot agent binary
tmux select-pane -t fieldtest:0.0
tmux send-keys -t fieldtest:0.0 "./clawbot" Enter

# Attach so VHS can see both panes
tmux attach -t fieldtest &
TMUX_PID=$!

# Wait for the clawbot agent to finish
while [ ! -f "$DONE_MARKER" ]; do
    sleep 1
done
sleep 3

# Clean up
tmux kill-session -t fieldtest 2>/dev/null || true
rm -f "$DONE_MARKER"
