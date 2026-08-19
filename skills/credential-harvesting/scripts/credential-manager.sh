#!/bin/bash
#
# Credential Manager - structured credential store for a pentest engagement
#
# Stores credentials as JSON (richer than session-manager.sh's flat
# username/password lists: tracks service, source, and tested/working state
# per entry). Operates on the current session directory if SESSION_DIR is
# set (see skills/session-management/scripts/session-manager.sh), otherwise
# falls back to a global store.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -n "${SESSION_DIR:-}" ] && [ -d "$SESSION_DIR" ]; then
    CRED_FILE="$SESSION_DIR/credentials/credential_store.json"
else
    CRED_DIR="$HOME/.claude/pentest-state"
    mkdir -p "$CRED_DIR"
    CRED_FILE="$CRED_DIR/credential_store.json"
fi

init_store() {
    mkdir -p "$(dirname "$CRED_FILE")"
    if [ ! -f "$CRED_FILE" ]; then
        echo '{"credentials": []}' | jq '.' > "$CRED_FILE"
    fi
}

# store "{username}" "{password}" "{hash}" "{service}" "{source}" [--target "{ip}"] [--hash-type "{type}"]
#
# --target and --hash-type are optional trailing flags (existing callers that
# only pass the 5 positional args keep working - target defaults to empty,
# and hash_type is auto-guessed from the hash via hash-identifier.py when a
# hash is given and --hash-type isn't).
store_credential() {
    local username="${1:-}"
    local password="${2:-}"
    local hash="${3:-}"
    local service="${4:-unknown}"
    local source="${5:-unknown}"
    local target=""
    local hash_type=""

    if [ $# -gt 5 ]; then
        shift 5
        while [ $# -gt 0 ]; do
            case "$1" in
                --target) target="${2:-}"; shift 2 ;;
                --hash-type) hash_type="${2:-}"; shift 2 ;;
                *) shift ;;
            esac
        done
    fi

    if [ -n "$hash" ] && [ -z "$hash_type" ]; then
        local identifier="$SCRIPT_DIR/hash-identifier.py"
        if [ -f "$identifier" ] && command -v python3 >/dev/null 2>&1; then
            hash_type=$(python3 "$identifier" "$hash" 2>/dev/null | awk '/^Likely type\(s\):/{getline; sub(/^  - /, ""); print; exit}')
        fi
    fi

    init_store
    local temp_file
    temp_file=$(mktemp)
    jq --arg id "$(date +%s%N)" \
       --arg user "$username" \
       --arg pass "${password:-null}" \
       --arg hash "${hash:-null}" \
       --arg htype "${hash_type:-null}" \
       --arg svc "$service" \
       --arg tgt "${target:-null}" \
       --arg src "$source" \
       --arg ts "$(date -Iseconds)" \
       '.credentials += [{
           "credential_id": $id,
           "username": $user,
           "password": (if $pass == "null" or $pass == "" then null else $pass end),
           "hash": (if $hash == "null" or $hash == "" then null else $hash end),
           "hash_type": (if $htype == "null" or $htype == "" then null else $htype end),
           "service": $svc,
           "target": (if $tgt == "null" or $tgt == "" then null else $tgt end),
           "source": $src,
           "tested": false,
           "working": false,
           "timestamp": $ts
       }]' "$CRED_FILE" > "$temp_file" && mv "$temp_file" "$CRED_FILE"

    echo "Stored credential for $username@$service (source: $source)"
}

# get --service ssh | get --username admin
get_credentials() {
    init_store
    local filter_type="${1:-}"
    local filter_value="${2:-}"

    case "$filter_type" in
        --service)
            jq --arg v "$filter_value" '.credentials[] | select(.service == $v)' "$CRED_FILE"
            ;;
        --username)
            jq --arg v "$filter_value" '.credentials[] | select(.username == $v)' "$CRED_FILE"
            ;;
        *)
            jq '.credentials' "$CRED_FILE"
            ;;
    esac
}

list_credentials() {
    init_store
    jq -r '.credentials[] | "\(.username // "?")@\(.service) (source: \(.source), tested: \(.tested), working: \(.working))"' "$CRED_FILE"
}

# export --format json
export_credentials() {
    init_store
    local format="json"
    if [ "${1:-}" = "--format" ]; then
        format="${2:-json}"
    fi

    case "$format" in
        json)
            jq '.' "$CRED_FILE"
            ;;
        csv)
            echo "username,password,hash,service,source,tested,working"
            jq -r '.credentials[] | [.username, (.password // ""), (.hash // ""), .service, .source, .tested, .working] | @csv' "$CRED_FILE"
            ;;
        *)
            echo "Unknown format: $format (use json or csv)" >&2
            return 1
            ;;
    esac
}

# test-all "{username}" "{password}" "{target}"
# Tests a single credential pair across common services on the target.
# This only prints the commands to run (does not execute attacks itself) -
# the calling agent decides which to actually run based on scope/context.
test_all() {
    local username="${1:?username required}"
    local password="${2:?password required}"
    local target="${3:?target required}"

    cat <<EOF
Credential reuse test plan for $username:$password @ $target
(review scope before running any of these)

SSH:  ssh -o BatchMode=no -o StrictHostKeyChecking=no $username@$target 'echo SUCCESS'
FTP:  curl -s "ftp://$username:$password@$target/" -o /dev/null -w "%{http_code}\n"
SMB:  smbclient -L "//$target" -U "$username%$password"
RDP:  xfreerdp /v:$target /u:$username /p:$password /cert:ignore /sec:nla
MySQL: mysql -h $target -u $username -p"$password" -e "SELECT 1"
Web:  (manual - submit $username/$password to any discovered login form)
EOF
}

# spray --target "{ip}" --services "ssh,ftp,smb"
# Sprays every stored credential against the listed services. Same
# print-the-plan-don't-auto-execute approach as test_all.
spray() {
    init_store
    local target="" services=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --target) target="$2"; shift 2 ;;
            --services) services="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    : "${target:?--target required}"
    : "${services:?--services required}"

    echo "Password spray plan: all stored credentials against [$services] @ $target"
    jq -r '.credentials[] | select(.password != null) | "\(.username):\(.password)"' "$CRED_FILE" | \
    while IFS=: read -r user pass; do
        echo "  - $user:$pass -> $services"
    done
}

# format-key "{raw_key_data}" > formatted_key
format_key() {
    local raw_key="${1:?raw key data or path required}"
    if [ -f "$raw_key" ]; then
        raw_key=$(cat "$raw_key")
    fi
    # Normalize line endings and ensure trailing newline, common issues with
    # keys copied out of file listings / web pages
    printf '%s\n' "$raw_key" | tr -d '\r'
}

# report --format markdown
report() {
    init_store
    local format="markdown"
    if [ "${1:-}" = "--format" ]; then
        format="${2:-markdown}"
    fi

    case "$format" in
        markdown)
            echo "## Discovered Credentials"
            echo
            echo "| Username | Password | Hash | Service | Source | Working |"
            echo "|----------|----------|------|---------|--------|---------|"
            jq -r '.credentials[] | "| \(.username // "-") | \(.password // "-") | \(.hash // "-") | \(.service) | \(.source) | \(if .working then "Yes" else "No" end) |"' "$CRED_FILE"
            ;;
        *)
            export_credentials --format "$format"
            ;;
    esac
}

main() {
    local command="${1:-help}"
    shift || true

    case "$command" in
        store) store_credential "$@" ;;
        get) get_credentials "$@" ;;
        list) list_credentials ;;
        export) export_credentials "$@" ;;
        test-all) test_all "$@" ;;
        spray) spray "$@" ;;
        format-key) format_key "$@" ;;
        report) report "$@" ;;
        help|*)
            echo "Credential Manager"
            echo "Usage: $0 <command> [arguments]"
            echo
            echo "Commands:"
            echo "  store <user> <pass> <hash> <service> <source> [--target <ip>] [--hash-type <type>]"
            echo "  get --service <svc> | get --username <user> | get"
            echo "  list"
            echo "  export [--format json|csv]"
            echo "  test-all <user> <pass> <target>"
            echo "  spray --target <ip> --services <svc,svc,...>"
            echo "  format-key <raw_key_or_path>"
            echo "  report [--format markdown|json|csv]"
            ;;
    esac
}

if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi
