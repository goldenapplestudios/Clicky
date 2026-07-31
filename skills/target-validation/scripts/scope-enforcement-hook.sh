#!/bin/bash
#
# Scope Enforcement Hook - PreToolUse hook (Bash|WebFetch) that blocks or
# asks about tool calls against targets outside the active engagement's
# scope.json.
#
# Reuses scope-validator.sh's classification logic as-is (no duplication)
# and extract-targets.py to pull candidate targets out of the tool call.
# See skills/target-validation/SKILL.md for the scope.json schema.
#
# Controlled by the scope_enforcement userConfig option
# (CLAUDE_PLUGIN_OPTION_SCOPE_ENFORCEMENT): "enforce" (default) actually
# denies/asks, "warn" logs what it would have done but never blocks, "off"
# disables this hook entirely.
#
# Fails open on any internal error (missing jq/python3, malformed
# scope.json, unexpected script output) - a scope gate that can lock an
# operator out of a fully-authorized engagement due to a shell bug is
# worse for adoption than no gate. See docs on this trade-off in the
# plan's Risks section.
#

set -uo pipefail

MODE="${CLAUDE_PLUGIN_OPTION_SCOPE_ENFORCEMENT:-enforce}"
[ "$MODE" = "off" ] && exit 0

command -v jq >/dev/null 2>&1 || exit 0
command -v python3 >/dev/null 2>&1 || exit 0

input=$(cat)

tool_name=$(jq -r '.tool_name // ""' <<<"$input" 2>/dev/null) || exit 0
case "$tool_name" in
    Bash|WebFetch) ;;
    *) exit 0 ;;
esac

# Find the active Clicky session via the same pointer file
# session-manager.sh writes on create_session / clears on archive_session.
SESSION_BASE="${CLAUDE_PLUGIN_OPTION_DEFAULT_SESSION_DIRECTORY:-$HOME/.claude/sessions}"
CURRENT_SESSION_FILE="$SESSION_BASE/.current-session"

[ -f "$CURRENT_SESSION_FILE" ] || exit 0
SESSION_DIR=$(cat "$CURRENT_SESSION_FILE" 2>/dev/null || true)
[ -n "$SESSION_DIR" ] && [ -d "$SESSION_DIR" ] || exit 0

SCOPE_FILE="$SESSION_DIR/scope.json"
[ -f "$SCOPE_FILE" ] || exit 0

LOG_DIR="$SESSION_DIR/logs"
mkdir -p "$LOG_DIR" 2>/dev/null || true
HOOK_LOG="$LOG_DIR/scope-enforcement.log"

log_line() {
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [scope-enforcement-hook] $1" >> "$HOOK_LOG" 2>/dev/null || true
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

command_text="" url_text=""
if [ "$tool_name" = "Bash" ]; then
    command_text=$(jq -r '.tool_input.command // ""' <<<"$input" 2>/dev/null) || true
else
    url_text=$(jq -r '.tool_input.url // ""' <<<"$input" 2>/dev/null) || true
fi

[ -n "$command_text$url_text" ] || exit 0

extract_args=()
[ -n "$command_text" ] && extract_args+=(--command "$command_text")
[ -n "$url_text" ] && extract_args+=(--url "$url_text")

candidates=$(python3 "$SCRIPT_DIR/extract-targets.py" "${extract_args[@]}" 2>>"$HOOK_LOG")
if [ $? -ne 0 ]; then
    log_line "extract-targets.py failed for tool_name=$tool_name - failing open"
    exit 0
fi

[ -n "$candidates" ] || exit 0

deny_reason=""
ask_reason=""

while IFS= read -r candidate; do
    [ -n "$candidate" ] || continue

    result=$(bash "$SCRIPT_DIR/scope-validator.sh" --target "$candidate" --scope "$SCOPE_FILE" 2>>"$HOOK_LOG")
    status=$?

    if [ $status -eq 0 ]; then
        continue  # IN SCOPE - check next candidate
    fi

    case "$result" in
        "OUT OF SCOPE"*)
            deny_reason="Target '$candidate' is explicitly out of scope per $SCOPE_FILE: $result"
            break
            ;;
        "NOT LISTED"*)
            [ -n "$ask_reason" ] || ask_reason="Target '$candidate' is not explicitly listed in scope.json ($SCOPE_FILE). If this is an authorized pivot or newly-discovered in-scope host, approve to continue; otherwise deny."
            ;;
        *)
            log_line "unexpected scope-validator.sh output for candidate='$candidate': $result"
            ;;
    esac
done <<< "$candidates"

# Best-effort technique restriction check, only if scope.json defines
# authorized_techniques. Small, explicit tool-name -> technique table -
# deep flag-level inference (e.g. spotting a DoS-shaped nmap flag) is
# explicitly out of scope for this MVP, not silently promised.
if [ -z "$deny_reason" ] && [ "$tool_name" = "Bash" ]; then
    authorized_count=$(jq -r '(.authorized_techniques // []) | length' "$SCOPE_FILE" 2>/dev/null || echo 0)
    if [ "$authorized_count" != "0" ]; then
        technique=""
        case "$command_text" in
            hydra\ *|*/hydra\ *|medusa\ *|*/medusa\ *|ncrack\ *|*/ncrack\ *) technique="password attack" ;;
            sqlmap\ *|*/sqlmap\ *) technique="sql injection" ;;
            msfconsole*|msfvenom*|*exploit/*) technique="exploitation" ;;
            hashcat\ *|*/hashcat\ *|john\ *|*/john\ *) technique="password cracking" ;;
            nmap*-sS*|nmap*-sU*|masscan\ *|*/masscan\ *) technique="port scanning" ;;
        esac
        if [ -n "$technique" ]; then
            result=$(bash "$SCRIPT_DIR/scope-validator.sh" --technique "$technique" --scope "$SCOPE_FILE" 2>>"$HOOK_LOG")
            if [ $? -ne 0 ]; then
                deny_reason="Technique '$technique' (inferred from this command) is restricted or not in authorized_techniques per $SCOPE_FILE: $result"
            fi
        fi
    fi
fi

if [ "$MODE" = "warn" ]; then
    [ -n "$deny_reason" ] && log_line "WARN mode - would have denied: $deny_reason"
    [ -n "$ask_reason" ] && [ -z "$deny_reason" ] && log_line "WARN mode - would have asked: $ask_reason"
    exit 0
fi

if [ -n "$deny_reason" ]; then
    jq -n --arg reason "$deny_reason" \
        '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: $reason}}'
    exit 0
fi

if [ -n "$ask_reason" ]; then
    jq -n --arg reason "$ask_reason" \
        '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: $reason}}'
    exit 0
fi

exit 0
