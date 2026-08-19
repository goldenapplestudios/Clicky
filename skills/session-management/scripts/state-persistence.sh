#!/bin/bash
#
# Persistent State Management for Pentest Sessions
#
# record_attempt/check_failed_attempt/get_session_summary are session-scoped
# (write into $SESSION_DIR/logs/attempts.jsonl, same convention as the
# gateway's own logs/trace.jsonl - see skills/mcp-gateway/server.py's
# _trace() - and session-manager.sh's findings.json) - NOT a global
# cross-session store. This is a rewrite: the previous version
# wrote to a single global ~/.claude/pentest-state/attack-history.json
# keyed by session_id internally, inconsistent with every other piece of
# session state in this codebase, and it meant check_failed_attempt could
# suppress a retry based on an unrelated past target/engagement. Because
# attempts.jsonl lives inside $SESSION_DIR, archive_session() (see
# session-manager.sh) already sweeps it into archived/ along with
# everything else - no changes needed there.
#
# attempts.jsonl is the raw data skills/session-management/scripts/
# attempt-aggregator.sh reads across every session (active + archived) to
# compute real per-service/technique success rates for
# skills/htb-decision-tree - see that skill's SKILL.md. Log every attempt,
# not just successes: a rate needs both a numerator and a denominator.
#
# store_discovery/get_unused_discoveries/mark_discovery_used remain a
# separate, deliberately-global mechanism (shared credential/vuln/service
# discoveries an operator may want visible across engagements) - untouched
# by this rewrite.
#

set -euo pipefail

STATE_DIR="$HOME/.claude/pentest-state"
DISCOVERIES_FILE="$STATE_DIR/discoveries.json"
SESSION_BASE="${CLAUDE_PLUGIN_OPTION_DEFAULT_SESSION_DIRECTORY:-$HOME/.claude/sessions}"

# Initialize state directory
init_state() {
    mkdir -p "$STATE_DIR"

    if [ ! -f "$DISCOVERIES_FILE" ]; then
        echo '{"credentials": [], "vulnerabilities": [], "services": []}' | jq '.' > "$DISCOVERIES_FILE"
    fi
}

# Resolve a session_id to its directory, falling back to archived/ - same
# pattern as session-manager.sh's get_session_info().
_resolve_session_dir() {
    local session_id="$1"
    local dir="$SESSION_BASE/$session_id"
    if [ ! -d "$dir" ] && [ -d "$SESSION_BASE/archived/$session_id" ]; then
        dir="$SESSION_BASE/archived/$session_id"
    fi
    echo "$dir"
}

# Record an attack attempt - success or failure. Appends one JSON line to
# $SESSION_DIR/logs/attempts.jsonl (JSONL append, not a jq-read-modify-write
# cycle, so concurrent subagent writers within a session are safe).
#
# Usage: record_attempt <session_id> <service> <technique> <notes> <true|false>
#          [--agent NAME] [--port N] [--severity SEV] [--finding-id ID]
#
# <service> should use the canonical vocabulary
# skills/htb-decision-tree/data/baseline-priority-order.json uses
# (ftp|smb|http|ssh|mysql|redis|docker|mongodb|elasticsearch|rdp|other),
# or "-" for attempts that aren't port/service-specific (most privesc
# techniques).
record_attempt() {
    local session_id="$1" service="$2" technique="$3" notes="$4" success="$5"
    shift 5 || true

    local agent="" port="" severity="" finding_id=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --agent) agent="$2"; shift 2 ;;
            --port) port="$2"; shift 2 ;;
            --severity) severity="$2"; shift 2 ;;
            --finding-id) finding_id="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    case "$success" in
        true|false) ;;
        *) echo "ERROR: success must be 'true' or 'false', got: $success" >&2; return 1 ;;
    esac

    local session_dir; session_dir=$(_resolve_session_dir "$session_id")
    if [ ! -d "$session_dir" ]; then
        echo "ERROR: session not found: $session_id" >&2
        return 1
    fi
    mkdir -p "$session_dir/logs"

    local target=""
    [ -f "$session_dir/session.json" ] && target=$(jq -r '.target // ""' "$session_dir/session.json" 2>/dev/null || echo "")

    jq -nc \
        --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --arg sid "$session_id" \
        --arg target "$target" \
        --arg agent "$agent" \
        --arg service "$service" \
        --arg port "$port" \
        --arg technique "$technique" \
        --argjson success "$success" \
        --arg severity "$severity" \
        --arg finding_id "$finding_id" \
        --arg notes "$notes" \
        '{
            timestamp: $ts,
            session_id: $sid,
            target: $target,
            agent: (if $agent == "" then null else $agent end),
            service: $service,
            port: (if $port == "" then null else ($port | tonumber) end),
            technique: $technique,
            success: $success,
            severity: (if $severity == "" then null else $severity end),
            finding_id: (if $finding_id == "" then null else $finding_id end),
            notes: $notes
        }' >> "$session_dir/logs/attempts.jsonl"
}

# Check if a (service, technique) has already failed in THIS session -
# session-scoped now, not global (fixes a latent bug where the old global
# version could suppress a retry based on an unrelated past engagement).
#
# Usage: check_failed_attempt <session_id> <service> <technique>
check_failed_attempt() {
    local session_id="$1" service="$2" technique="$3"
    local session_dir; session_dir=$(_resolve_session_dir "$session_id")
    local attempts_file="$session_dir/logs/attempts.jsonl"

    [ -f "$attempts_file" ] || return 0

    local failed_count
    failed_count=$(jq -sc --arg svc "$service" --arg tech "$technique" \
        '[.[] | select(.service == $svc and .technique == $tech and .success == false)] | length' \
        "$attempts_file" 2>/dev/null || echo 0)

    if [ "$failed_count" -gt 0 ]; then
        echo "WARNING: $service/$technique has already failed $failed_count time(s) in this session"
        return 1
    fi
    return 0
}

# Store a discovery (credential, vulnerability, etc.) - unchanged, still
# global/cross-session by design.
store_discovery() {
    local type="$1"  # credentials, vulnerabilities, services
    local data="$2"  # JSON string with discovery data
    local session_id="${3:-unknown}"

    local timestamp=$(date +%s)

    jq --arg typ "$type" \
       --argjson data "$data" \
       --arg sid "$session_id" \
       --argjson ts "$timestamp" \
       'if (.[$typ] | map(select(.data == $data)) | length) == 0 then
           .[$typ] += [{
               "session_id": $sid,
               "timestamp": $ts,
               "data": $data,
               "used": false
           }]
       else . end' "$DISCOVERIES_FILE" > "$DISCOVERIES_FILE.tmp" && \
    mv "$DISCOVERIES_FILE.tmp" "$DISCOVERIES_FILE"
}

# Retrieve unused discoveries
get_unused_discoveries() {
    local type="$1"

    jq --arg typ "$type" \
        '.[$typ] | map(select(.used == false))' "$DISCOVERIES_FILE"
}

# Mark a discovery as used
mark_discovery_used() {
    local type="$1"
    local index="$2"

    jq --arg typ "$type" \
       --argjson idx "$index" \
       '.[$typ][$idx].used = true' "$DISCOVERIES_FILE" > "$DISCOVERIES_FILE.tmp" && \
    mv "$DISCOVERIES_FILE.tmp" "$DISCOVERIES_FILE"
}

# Get session summary
get_session_summary() {
    local session_id="$1"
    local session_dir; session_dir=$(_resolve_session_dir "$session_id")
    local attempts_file="$session_dir/logs/attempts.jsonl"

    echo "=== Session Summary for $session_id ==="

    if [ -f "$attempts_file" ]; then
        local total_attempts successful
        total_attempts=$(jq -sc 'length' "$attempts_file")
        successful=$(jq -sc '[.[] | select(.success == true)] | length' "$attempts_file")
        echo "Total Attempts: $total_attempts"
        echo "Successful: $successful"
        echo "Failed: $((total_attempts - successful))"
    else
        echo "Total Attempts: 0"
        echo "Successful: 0"
        echo "Failed: 0"
    fi

    echo ""
    echo "Discoveries:"
    echo "  Credentials: $(jq '.credentials | length' "$DISCOVERIES_FILE" 2>/dev/null || echo 0)"
    echo "  Vulnerabilities: $(jq '.vulnerabilities | length' "$DISCOVERIES_FILE" 2>/dev/null || echo 0)"
    echo "  Services: $(jq '.services | length' "$DISCOVERIES_FILE" 2>/dev/null || echo 0)"
}

# Main function
main() {
    local action="${1:-init}"
    shift || true

    init_state

    case "$action" in
        init)
            echo "State persistence initialized at $STATE_DIR"
            ;;
        record)
            record_attempt "$@"
            ;;
        check-failed)
            check_failed_attempt "$@"
            ;;
        store)
            store_discovery "$@"
            ;;
        get-unused)
            get_unused_discoveries "$@"
            ;;
        mark-used)
            mark_discovery_used "$@"
            ;;
        summary)
            get_session_summary "$@"
            ;;
        *)
            echo "Usage: $0 {init|record|check-failed|store|get-unused|mark-used|summary}" >&2
            echo "  record <session_id> <service> <technique> <notes> <true|false> [--agent NAME] [--port N] [--severity SEV] [--finding-id ID]" >&2
            echo "  check-failed <session_id> <service> <technique>" >&2
            exit 1
            ;;
    esac
}

# Run if executed directly
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi
