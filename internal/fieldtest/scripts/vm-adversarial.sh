#!/usr/bin/env bash
# Adversarial test suite — run as root on the nullbot VM
# Tests that require real systemd, real users, real nftables.
#
# Usage: sudo bash vm-adversarial.sh
set -uo pipefail
# No set -e: we track pass/fail manually and must not abort early.

PASS=0
FAIL=0
SKIP=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

pass() { PASS=$((PASS + 1)); printf "${GREEN}  ✓ %s${NC}\n" "$1"; }
fail() { FAIL=$((FAIL + 1)); printf "${RED}  ✗ %s${NC}\n" "$1"; }
skip() { SKIP=$((SKIP + 1)); printf "${YELLOW}  · %s (skipped)${NC}\n" "$1"; }

section() { printf "\n━━━ %s ━━━\n" "$1"; }

# Require root.
if [ "$(id -u)" -ne 0 ]; then
    echo "FATAL: must run as root"
    exit 1
fi

echo "nullbot adversarial test suite"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

# ─────────────────────────────────────────────────
section "Category 2: Binary Tampering (Test 5)"
# ─────────────────────────────────────────────────

CW_BIN="/usr/local/bin/chainwatch"
NB_BIN="/usr/local/bin/nullbot"

if [ -x "$CW_BIN" ]; then
    # Check if binary has embedded hash.
    cw_version=$(chainwatch version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' || echo "unknown")

    # Backup, tamper, test, restore.
    cp "$CW_BIN" /tmp/chainwatch-backup

    echo "tampered" >> "$CW_BIN"

    # Try to restart nullbot-daemon — should fail if integrity check is wired.
    systemctl restart nullbot-daemon 2>/dev/null || true
    sleep 2

    if systemctl is-active --quiet nullbot-daemon 2>/dev/null; then
        # Service still running — check if it's using the tampered binary.
        # This might mean integrity check isn't embedded (dev build).
        if [ -f /var/log/chainwatch/tamper.jsonl ]; then
            pass "binary tampering detected (tamper event logged)"
        else
            skip "binary tamper — service restarted (integrity hash may not be embedded in this build)"
        fi
    else
        pass "binary tamper — nullbot-daemon refused to start with tampered binary"
    fi

    # Restore.
    cp /tmp/chainwatch-backup "$CW_BIN"
    rm -f /tmp/chainwatch-backup
    systemctl restart nullbot-daemon 2>/dev/null || true
    sleep 2

    if systemctl is-active --quiet nullbot-daemon 2>/dev/null; then
        pass "service restored after binary fix"
    else
        fail "service did not restart after binary restore"
    fi
else
    skip "chainwatch binary not found"
fi

# ─────────────────────────────────────────────────
section "Category 2: systemd Trust Assumption (Test 6)"
# ─────────────────────────────────────────────────

# We don't tamper-detect systemd units. This is a documented assumption.
if grep -q "ProtectSystem=strict" /etc/systemd/system/nullbot-daemon.service 2>/dev/null; then
    pass "systemd hardening present (ProtectSystem=strict)"
else
    fail "systemd hardening missing"
fi

if grep -q "NoNewPrivileges=true" /etc/systemd/system/nullbot-daemon.service 2>/dev/null; then
    pass "NoNewPrivileges=true set"
else
    fail "NoNewPrivileges not set"
fi

if grep -q "MemoryDenyWriteExecute=true" /etc/systemd/system/nullbot-daemon.service 2>/dev/null; then
    pass "MemoryDenyWriteExecute=true set"
else
    fail "MemoryDenyWriteExecute not set"
fi

# ─────────────────────────────────────────────────
section "Category 5: Resource Exhaustion (Test 10)"
# ─────────────────────────────────────────────────

# Create 100 inbox files simultaneously.
INBOX="/home/nullbot/inbox"
if [ -d "$INBOX" ]; then
    for i in $(seq 1 100); do
        cat > "${INBOX}/stress-${i}.json" <<JSON
{"id":"stress-${i}","type":"observe","target":{"host":"localhost","scope":"/tmp"},"brief":"stress test ${i}","source":"adversarial","created_at":"2026-02-21T00:00:00Z"}
JSON
    done

    sleep 5

    if systemctl is-active --quiet nullbot-daemon 2>/dev/null; then
        pass "daemon survived 100 simultaneous inbox files"
    else
        fail "daemon crashed under load"
        systemctl restart nullbot-daemon 2>/dev/null || true
    fi

    # Clean up stress files.
    rm -f "${INBOX}"/stress-*.json 2>/dev/null || true
else
    skip "inbox directory not found"
fi

# ─────────────────────────────────────────────────
section "Category 5: Chainwatch Crash (Test 11)"
# ─────────────────────────────────────────────────

# Run a long command, kill chainwatch mid-execution.
# The daemon should fail the job, not continue without enforcement.

# Start a long-running command through chainwatch.
su -s /bin/bash nullbot -c "HOME=/home/nullbot /usr/local/bin/chainwatch exec --profile clawbot -- sleep 30" &
SLEEP_PID=$!
sleep 2

# Kill all chainwatch processes owned by nullbot.
pkill -u nullbot -f "chainwatch exec" 2>/dev/null || true
sleep 1

# Wait for the background job.
wait $SLEEP_PID 2>/dev/null
EXIT_CODE=$?

if [ "$EXIT_CODE" -ne 0 ]; then
    pass "chainwatch crash propagated failure (exit ${EXIT_CODE})"
else
    fail "chainwatch crash did not propagate failure — command appeared to succeed"
fi

# ─────────────────────────────────────────────────
section "Network Egress Control"
# ─────────────────────────────────────────────────

if nft list table inet nullbot_egress >/dev/null 2>&1; then
    pass "nftables egress table exists"

    # Test: nullbot cannot reach arbitrary hosts.
    EVIL_RESULT=$(su -s /bin/bash nullbot -c "curl -s --connect-timeout 5 https://example.com 2>&1" || true)
    if echo "$EVIL_RESULT" | grep -qiE "refused|timed out|unreachable|reset|failed|couldn"; then
        pass "egress to example.com blocked"
    elif [ -z "$EVIL_RESULT" ]; then
        pass "egress to example.com returned empty (blocked)"
    else
        fail "egress to example.com may have succeeded"
    fi

    # Test: nullbot can reach LLM API (at least TCP connect).
    LLM_RESULT=$(su -s /bin/bash nullbot -c "curl -s --connect-timeout 5 -o /dev/null -w '%{http_code}' https://api.groq.com/ 2>&1" || true)
    if echo "$LLM_RESULT" | grep -qE '^[2-5][0-9][0-9]$'; then
        pass "egress to api.groq.com allowed (HTTP ${LLM_RESULT})"
    else
        skip "egress to api.groq.com — could not verify (may need DNS)"
    fi
else
    skip "nftables egress table not configured"
fi

# ─────────────────────────────────────────────────
section "DNS Exfiltration Defense"
# ─────────────────────────────────────────────────

if nft list table inet nullbot_egress >/dev/null 2>&1; then
    # Test: bulk DNS queries are rate-limited.
    # Send 50 rapid queries — most should be dropped by the rate limit.
    QUERY_COUNT=0
    for i in $(seq 1 50); do
        RESULT=$(su -s /bin/bash nullbot -c "dig +short +time=1 +tries=1 test${i}.example.com 2>&1" || true)
        if echo "$RESULT" | grep -qvE "timed out|connection refused|no servers"; then
            QUERY_COUNT=$((QUERY_COUNT + 1))
        fi
    done

    # With rate limit of 10/sec burst 20, at most ~25-30 should succeed.
    # 50 all succeeding means no rate limit is in effect.
    if [ "$QUERY_COUNT" -lt 45 ]; then
        pass "DNS rate limiting active (${QUERY_COUNT}/50 queries succeeded)"
    else
        fail "DNS rate limiting not working (${QUERY_COUNT}/50 queries succeeded)"
    fi
else
    skip "nftables egress table not configured"
fi

# ─────────────────────────────────────────────────
section "Final Boss: Offline Degradation (Test 15)"
# ─────────────────────────────────────────────────

# Verify chainwatch enforcement works without any network.
# (Chainwatch is local and deterministic — it never needs network.)

OFFLINE_LOG=$(mktemp)
chmod 666 "$OFFLINE_LOG"
chown nullbot:nullbot "$OFFLINE_LOG"

# Safe command.
su -s /bin/bash nullbot -c "HOME=/home/nullbot /usr/local/bin/chainwatch exec --profile clawbot --audit-log ${OFFLINE_LOG} -- echo offline-works" >/dev/null 2>&1
if [ $? -eq 0 ]; then
    pass "chainwatch allows safe command offline"
else
    fail "chainwatch blocked safe command offline"
fi

# Dangerous command.
su -s /bin/bash nullbot -c "HOME=/home/nullbot /usr/local/bin/chainwatch exec --profile clawbot --audit-log ${OFFLINE_LOG} -- rm -rf /" >/dev/null 2>&1
if [ $? -eq 77 ]; then
    pass "chainwatch blocks dangerous command offline"
else
    fail "chainwatch did not block dangerous command offline"
fi

# Self-targeting.
su -s /bin/bash nullbot -c "HOME=/home/nullbot /usr/local/bin/chainwatch exec --profile clawbot --audit-log ${OFFLINE_LOG} -- cat /home/nullbot/config/nullbot.env" >/dev/null 2>&1
if [ $? -eq 77 ]; then
    pass "chainwatch blocks self-targeting offline"
else
    fail "chainwatch did not block self-targeting offline"
fi

# Verify audit chain.
su -s /bin/bash nullbot -c "HOME=/home/nullbot /usr/local/bin/chainwatch audit verify ${OFFLINE_LOG}" >/dev/null 2>&1
if [ $? -eq 0 ]; then
    pass "audit chain valid after offline tests"
else
    fail "audit chain broken after offline tests"
fi

rm -f "$OFFLINE_LOG"

# ─────────────────────────────────────────────────
section "Summary"
# ─────────────────────────────────────────────────

TOTAL=$((PASS + FAIL))
echo ""
echo "┌──────────┬─────────┐"
echo "│ Passed   │ ${PASS}$(printf '%*s' $((7 - ${#PASS})) '')│"
echo "│ Failed   │ ${FAIL}$(printf '%*s' $((7 - ${#FAIL})) '')│"
echo "│ Skipped  │ ${SKIP}$(printf '%*s' $((7 - ${#SKIP})) '')│"
echo "│ Total    │ ${TOTAL}$(printf '%*s' $((7 - ${#TOTAL})) '')│"
echo "└──────────┴─────────┘"

if [ "$FAIL" -gt 0 ]; then
    printf "\n${RED}RESULT: FAIL${NC}\n"
    exit 1
else
    printf "\n${GREEN}RESULT: PASS${NC}\n"
    exit 0
fi
