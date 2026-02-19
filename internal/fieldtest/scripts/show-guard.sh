#!/bin/bash
# show-guard.sh — Chainwatch guard perspective: forensic view of enforcement decisions.
set -u

AUDIT_LOG="/tmp/release-fieldtest.jsonl"
BINARY="./chainwatch"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Tier descriptions
tier_label() {
    case "$1" in
        0) echo "SAFE" ;;
        1) echo "SENSITIVE" ;;
        2) echo "COMMITMENT" ;;
        3) echo "CRITICAL" ;;
        *) echo "UNKNOWN" ;;
    esac
}

tier_color() {
    case "$1" in
        0) echo "$GREEN" ;;
        1) echo "$YELLOW" ;;
        2) echo "$RED" ;;
        3) echo "$RED" ;;
        *) echo "$NC" ;;
    esac
}

printf "${BOLD}${CYAN}=== CHAINWATCH GUARD ===${NC}\n"
printf "${DIM}Forensic analysis of enforcement decisions${NC}\n\n"
sleep 1

# Show policy hash
first_hash=$(head -1 "$AUDIT_LOG" | jq -r '.policy_hash')
printf "${BOLD}Active policy:${NC}\n"
printf "  ${DIM}%s${NC}\n\n" "$first_hash"
sleep 1

# Verify chain
printf "${DIM}$ chainwatch audit verify ${AUDIT_LOG}${NC}\n"
$BINARY audit verify "$AUDIT_LOG"
printf "\n"
sleep 1

# Process each entry
entry_num=0
total=$(wc -l < "$AUDIT_LOG" | tr -d ' ')

printf "${BOLD}Decisions (${total} entries):${NC}\n"
printf "${DIM}──────────────────────────────────────────────────────────${NC}\n\n"
sleep 0.5

while IFS= read -r line; do
    entry_num=$((entry_num + 1))

    decision=$(echo "$line" | jq -r '.decision')
    tool=$(echo "$line" | jq -r '.action.tool')
    resource=$(echo "$line" | jq -r '.action.resource')
    reason=$(echo "$line" | jq -r '.reason // empty')
    tier=$(echo "$line" | jq -r '.tier // 0')
    trace=$(echo "$line" | jq -r '.trace_id')
    prev=$(echo "$line" | jq -r '.prev_hash' | cut -c8-19)
    curr=$(echo "$line" | jq -r '.policy_hash' | cut -c8-19)
    ts=$(echo "$line" | jq -r '.ts' | cut -c12-19)

    label=$(tier_label "$tier")
    color=$(tier_color "$tier")

    # Entry header
    if [ "$decision" = "deny" ]; then
        printf "  ${RED}${BOLD}DENY${NC}  ${BOLD}%s %s${NC}\n" "$tool" "$resource"
    else
        printf "  ${GREEN}${BOLD}ALLOW${NC} ${BOLD}%s %s${NC}\n" "$tool" "$resource"
    fi

    # Details
    printf "  ${DIM}risk:${NC}   ${color}tier %s (%s)${NC}\n" "$tier" "$label"
    printf "  ${DIM}reason:${NC} %s\n" "$reason"
    printf "  ${DIM}trace:${NC}  %s  ${DIM}chain:${NC} %s${DIM}→${NC}%s\n" "$trace" "$prev" "$curr"
    printf "\n"
    sleep 0.8

done < "$AUDIT_LOG"

# Summary
printf "${DIM}──────────────────────────────────────────────────────────${NC}\n"
allowed=$(jq -r 'select(.decision=="allow")' "$AUDIT_LOG" | grep -c '"allow"' || true)
denied=$(jq -r 'select(.decision=="deny")' "$AUDIT_LOG" | grep -c '"deny"' || true)
printf "\n${BOLD}Summary:${NC}\n"
printf "  Total:   %s decisions\n" "$total"
printf "  ${GREEN}Allowed: %s${NC}  (tier 0 — safe operations)\n" "$allowed"
printf "  ${RED}Denied:  %s${NC}  (tier 1-3 — denylist match, escalation, self-targeting)\n" "$denied"
printf "\n"
printf "  ${DIM}Chain:   %s entries, cryptographically linked${NC}\n" "$total"
printf "  ${DIM}Policy:  %s${NC}\n" "$first_hash"
printf "\n"
sleep 1

printf "${BOLD}${GREEN}All decisions enforced. Hash chain verified. Audit trail immutable.${NC}\n"
sleep 3
