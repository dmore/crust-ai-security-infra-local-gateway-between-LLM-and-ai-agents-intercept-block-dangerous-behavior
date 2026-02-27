#!/bin/bash
# demo-acp.sh — Demonstrates ACP stdio proxy blocking malicious IDE agent requests
# Simulates an ACP-compatible IDE (VS Code, Cursor, etc.) connecting to a
# compromised agent through Crust.
#
# Prerequisites:
#   go build -o crust .
#   go build -o cmd/mock-acp-agent/mock-acp-agent ./cmd/mock-acp-agent

set -euo pipefail

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

CRUST="${CRUST:-./crust}"
MOCK="${MOCK:-./cmd/mock-acp-agent/mock-acp-agent}"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# show_results parses proxy log + IDE output and prints colored results.
show_results() {
    local log="$1" out="$2"

    # Blocked requests (from proxy WARN logs)
    while IFS= read -r line; do
        case "$line" in
            *"Blocked ACP"*)
                local method rule
                method="${line#*Blocked ACP }"
                method="${method%%:*}"
                rule="${line#*rule=}"
                rule="${rule%% *}"
                printf "${RED}    ✖ BLOCKED${RESET} ${DIM}%s — %s${RESET}\n" "$method" "$rule"
                sleep 0.25
                ;;
        esac
    done < "$log"

    # Allowed requests (forwarded to IDE stdout)
    while IFS= read -r line; do
        case "$line" in
            *'"method":"fs/'*|*'"method":"terminal/'*)
                local method
                method="${line#*\"method\":\"}"
                method="${method%%\"*}"
                printf "${GREEN}    ✔ Allowed${RESET} ${DIM}%s${RESET}\n" "$method"
                sleep 0.25
                ;;
        esac
    done < "$out"
}

echo ""
printf "${BOLD}${YELLOW}  ACP Stdio Proxy — VS Code + GLM-4-Plus${RESET}\n"
printf "${DIM}  VS Code → Crust acp-wrap → compromised agent (GLM-4-Plus backend)${RESET}\n"

# ── Phase 1: Session create triggers auto-reads ──
echo ""
printf "${CYAN}${BOLD}  Session Start${RESET}${DIM} — agent auto-reads .env + SSH key on init${RESET}\n\n"

{
    echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
    echo '{"jsonrpc":"2.0","method":"initialized","params":{}}'
    sleep 0.1
    echo '{"jsonrpc":"2.0","id":2,"method":"session/create","params":{"sessionId":"demo-1"}}'
    sleep 1
} | "$CRUST" acp-wrap --log-level warn -- "$MOCK" \
    >"$TMP/ide1.jsonl" 2>"$TMP/log1.txt" || true

show_results "$TMP/log1.txt" "$TMP/ide1.jsonl"
sleep 0.5

# ── Phase 2: Malicious prompt triggers full attack ──
echo ""
printf "${CYAN}${BOLD}  Attack Prompt${RESET}${DIM} — agent tries env, SSH, write, shell${RESET}\n\n"

{
    echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
    echo '{"jsonrpc":"2.0","method":"initialized","params":{}}'
    sleep 0.1
    echo '{"jsonrpc":"2.0","id":3,"method":"session/prompt","params":{"sessionId":"s1","text":"test attack vectors"}}'
    sleep 1.5
} | "$CRUST" acp-wrap --log-level warn -- "$MOCK" \
    >"$TMP/ide2.jsonl" 2>"$TMP/log2.txt" || true

show_results "$TMP/log2.txt" "$TMP/ide2.jsonl"

# ── Summary ──
blocked=$(cat "$TMP/log1.txt" "$TMP/log2.txt" | grep -c "Blocked ACP" || true)
allowed=$(cat "$TMP/ide1.jsonl" "$TMP/ide2.jsonl" | grep -cE '"method":"(fs/|terminal/)' || true)

echo ""
printf "${GREEN}${BOLD}  ✔ %s malicious ACP calls blocked, %s safe calls forwarded to IDE.${RESET}\n" "$blocked" "$allowed"
echo ""
