#!/bin/bash
#
# Persistent State Management for Pentest Sessions
# Uses JSON files for tracking attack history and discoveries
#

set -euo pipefail

STATE_DIR="$HOME/.claude/pentest-state"
STATE_FILE="$STATE_DIR/attack-history.json"
DISCOVERIES_FILE="$STATE_DIR/discoveries.json"
FAILED_ATTEMPTS_FILE="$STATE_DIR/failed-attempts.json"

# Initialize state directory
init_state() {
    mkdir -p "$STATE_DIR"

    # Create initial state files if they don't exist
    if [ ! -f "$STATE_FILE" ]; then
        echo '{"sessions": {}, "last_updated": null}' | jq '.' > "$STATE_FILE"
    fi

    if [ ! -f "$DISCOVERIES_FILE" ]; then
        echo '{"credentials": [], "vulnerabilities": [], "services": []}' | jq '.' > "$DISCOVERIES_FILE"
    fi

    if [ ! -f "$FAILED_ATTEMPTS_FILE" ]; then
        echo '{"attempts": []}' | jq '.' > "$FAILED_ATTEMPTS_FILE"
    fi
}

# Record an attack attempt
record_attempt() {
    local session_id="$1"
    local service="$2"
    local method="$3"
    local result="$4"
    local success="${5:-false}"

    local timestamp=$(date +%s)

    # Add to attack history
    jq --arg sid "$session_id" \
       --arg svc "$service" \
       --arg mth "$method" \
       --arg res "$result" \
       --argjson suc "$success" \
       --argjson ts "$timestamp" \
       '.sessions[$sid].attempts += [{
           "timestamp": $ts,
           "service": $svc,
           "method": $mth,
           "result": $res,
           "success": $suc
       }] | .last_updated = $ts' "$STATE_FILE" > "$STATE_FILE.tmp" && \
    mv "$STATE_FILE.tmp" "$STATE_FILE"

    # If failed, add to failed attempts for deduplication
    if [ "$success" = "false" ]; then
        jq --arg key "${service}_${method}" \
           --arg res "$result" \
           --argjson ts "$timestamp" \
           '.attempts += [{
               "key": $key,
               "timestamp": $ts,
               "reason": $res
           }]' "$FAILED_ATTEMPTS_FILE" > "$FAILED_ATTEMPTS_FILE.tmp" && \
        mv "$FAILED_ATTEMPTS_FILE.tmp" "$FAILED_ATTEMPTS_FILE"
    fi
}

# Check if an attack has already been tried and failed
check_failed_attempt() {
    local service="$1"
    local method="$2"
    local key="${service}_${method}"

    # Check if this combination has failed before
    local failed_count=$(jq --arg k "$key" \
        '[.attempts[] | select(.key == $k)] | length' "$FAILED_ATTEMPTS_FILE")

    if [ "$failed_count" -gt 0 ]; then
        echo "WARNING: This attack ($key) has failed $failed_count time(s) before"
        return 1
    fi

    return 0
}

# Store a discovery (credential, vulnerability, etc.)
store_discovery() {
    local type="$1"  # credentials, vulnerabilities, services
    local data="$2"  # JSON string with discovery data
    local session_id="${3:-unknown}"

    local timestamp=$(date +%s)

    # Add discovery with deduplication check
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

    echo "=== Session Summary for $session_id ==="

    # Attack attempts
    local total_attempts=$(jq --arg sid "$session_id" \
        '.sessions[$sid].attempts | length' "$STATE_FILE")
    local successful=$(jq --arg sid "$session_id" \
        '[.sessions[$sid].attempts[] | select(.success == true)] | length' "$STATE_FILE")

    echo "Total Attempts: $total_attempts"
    echo "Successful: $successful"
    echo "Failed: $((total_attempts - successful))"

    # Discoveries
    echo ""
    echo "Discoveries:"
    echo "  Credentials: $(jq '.credentials | length' "$DISCOVERIES_FILE")"
    echo "  Vulnerabilities: $(jq '.vulnerabilities | length' "$DISCOVERIES_FILE")"
    echo "  Services: $(jq '.services | length' "$DISCOVERIES_FILE")"
}

# Clean old failed attempts (older than 24 hours)
clean_old_failures() {
    local cutoff=$(date -d "24 hours ago" +%s)

    jq --argjson cutoff "$cutoff" \
        '.attempts = [.attempts[] | select(.timestamp > $cutoff)]' \
        "$FAILED_ATTEMPTS_FILE" > "$FAILED_ATTEMPTS_FILE.tmp" && \
    mv "$FAILED_ATTEMPTS_FILE.tmp" "$FAILED_ATTEMPTS_FILE"
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
        clean)
            clean_old_failures
            echo "Cleaned old failed attempts"
            ;;
        *)
            echo "Usage: $0 {init|record|check-failed|store|get-unused|mark-used|summary|clean}"
            exit 1
            ;;
    esac
}

# Run if executed directly
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi