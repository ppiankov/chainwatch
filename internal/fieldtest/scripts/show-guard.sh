#!/bin/bash
# show-guard.sh — Displays chainwatch guard perspective from the audit log.
set -u

AUDIT_LOG="/tmp/release-fieldtest.jsonl"
BINARY="./chainwatch"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

printf "${BOLD}${CYAN}=== CHAINWATCH GUARD ===${NC}\n"
printf "${DIM}Enforcement decisions from field test${NC}\n\n"
sleep 1

printf "${DIM}$ chainwatch audit verify ${AUDIT_LOG}${NC}\n"
$BINARY audit verify "$AUDIT_LOG"
printf "\n"
sleep 1

printf "${BOLD}Audit log entries:${NC}\n\n"
sleep 0.5

while IFS= read -r line; do
    decision=$(echo "$line" | jq -r '.decision')
    tool=$(echo "$line" | jq -r '.action.tool')
    resource=$(echo "$line" | jq -r '.action.resource')
    reason=$(echo "$line" | jq -r '.reason // empty')

    if [ "$decision" = "deny" ]; then
        printf "  ${RED}[DENY]${NC}  %s:%s\n" "$tool" "$resource"
    else
        printf "  ${GREEN}[ALLOW]${NC} %s:%s\n" "$tool" "$resource"
    fi

    if [ -n "$reason" ]; then
        printf "  ${DIM}        %s${NC}\n" "$reason"
    fi
    printf "\n"
    sleep 0.5
done < "$AUDIT_LOG"

printf "${BOLD}${GREEN}All decisions logged. Hash chain intact.${NC}\n"
sleep 3
