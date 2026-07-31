#!/bin/bash
#
# Session Management for Penetration Testing
# Manages session directories and persistence
#

set -euo pipefail

# Base directory for sessions
SESSION_BASE="$HOME/.claude/sessions"

# Function to create a new session
create_session() {
    local target="${1:-unknown}"
    local session_id="pentest_$(date +%Y%m%d_%H%M%S)_$$"
    local session_dir="$SESSION_BASE/$session_id"

    # Create directory structure
    mkdir -p "$session_dir"/{recon,exploits,loot,reports,credentials,logs}

    # Create session metadata
    cat > "$session_dir/session.json" << EOF
{
  "session_id": "$session_id",
  "target": "$target",
  "start_time": "$(date -Iseconds)",
  "status": "active",
  "phase": "initialization"
}
EOF

    echo "$session_id"
    return 0
}

# Function to update session status
update_session() {
    local session_id="$1"
    local phase="$2"
    local session_dir="$SESSION_BASE/$session_id"

    if [ ! -d "$session_dir" ]; then
        echo "ERROR: Session not found: $session_id"
        return 1
    fi

    # Update session metadata
    local temp_file=$(mktemp)
    jq --arg phase "$phase" --arg time "$(date -Iseconds)" \
        '.phase = $phase | .last_update = $time' \
        "$session_dir/session.json" > "$temp_file" && \
        mv "$temp_file" "$session_dir/session.json"

    return 0
}

# Function to save credentials
save_credentials() {
    local session_id="$1"
    local cred_type="$2"
    local value="$3"
    local session_dir="$SESSION_BASE/$session_id"

    if [ ! -d "$session_dir" ]; then
        echo "ERROR: Session not found: $session_id"
        return 1
    fi

    # Append to appropriate file
    case "$cred_type" in
        username)
            echo "$value" >> "$session_dir/credentials/usernames.txt"
            ;;
        password)
            echo "$value" >> "$session_dir/credentials/passwords.txt"
            ;;
        hash)
            echo "$value" >> "$session_dir/credentials/hashes.txt"
            ;;
        credential)
            echo "$value" >> "$session_dir/credentials/valid_creds.txt"
            ;;
        *)
            echo "WARNING: Unknown credential type: $cred_type"
            return 1
            ;;
    esac

    # Sort and deduplicate
    sort -u "$session_dir/credentials/${cred_type}s.txt" -o "$session_dir/credentials/${cred_type}s.txt" 2>/dev/null || true

    return 0
}

# Function to log findings
log_finding() {
    local session_id="$1"
    local severity="$2"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    local finding="$3"
    local session_dir="$SESSION_BASE/$session_id"

    if [ ! -d "$session_dir" ]; then
        echo "ERROR: Session not found: $session_id"
        return 1
    fi

    # Create findings file if it doesn't exist
    local findings_file="$session_dir/reports/findings.json"
    if [ ! -f "$findings_file" ]; then
        echo '{"findings": []}' > "$findings_file"
    fi

    # Add finding
    local temp_file=$(mktemp)
    jq --arg severity "$severity" \
       --arg finding "$finding" \
       --arg time "$(date -Iseconds)" \
       '.findings += [{"severity": $severity, "description": $finding, "timestamp": $time}]' \
       "$findings_file" > "$temp_file" && \
       mv "$temp_file" "$findings_file"

    return 0
}

# Function to get session info
get_session_info() {
    local session_id="$1"
    local session_dir="$SESSION_BASE/$session_id"

    if [ ! -d "$session_dir" ]; then
        echo "ERROR: Session not found: $session_id"
        return 1
    fi

    cat "$session_dir/session.json"
    return 0
}

# Function to list all sessions
list_sessions() {
    if [ ! -d "$SESSION_BASE" ]; then
        echo "No sessions found"
        return 0
    fi

    echo "=== Active Sessions ===="
    for session_dir in "$SESSION_BASE"/*; do
        if [ -d "$session_dir" ] && [ -f "$session_dir/session.json" ]; then
            local session_id=$(basename "$session_dir")
            local target=$(jq -r '.target' "$session_dir/session.json")
            local phase=$(jq -r '.phase' "$session_dir/session.json")
            local start_time=$(jq -r '.start_time' "$session_dir/session.json")
            echo "[$session_id] Target: $target | Phase: $phase | Started: $start_time"
        fi
    done

    return 0
}

# Function to resume a session
resume_session() {
    local session_id="$1"
    local session_dir="$SESSION_BASE/$session_id"

    if [ ! -d "$session_dir" ]; then
        echo "ERROR: Session not found: $session_id"
        return 1
    fi

    # Export session variables for use in commands
    export SESSION_ID="$session_id"
    export SESSION_DIR="$session_dir"
    export TARGET=$(jq -r '.target' "$session_dir/session.json")

    echo "Session resumed: $session_id"
    echo "Target: $TARGET"
    echo "Session directory: $session_dir"

    return 0
}

# Function to archive completed session
archive_session() {
    local session_id="$1"
    local session_dir="$SESSION_BASE/$session_id"
    local archive_dir="$SESSION_BASE/archived"

    if [ ! -d "$session_dir" ]; then
        echo "ERROR: Session not found: $session_id"
        return 1
    fi

    # Create archive directory
    mkdir -p "$archive_dir"

    # Update status to completed
    local temp_file=$(mktemp)
    jq '.status = "completed" | .end_time = now | .phase = "archived"' \
       "$session_dir/session.json" > "$temp_file" && \
       mv "$temp_file" "$session_dir/session.json"

    # Move to archive
    mv "$session_dir" "$archive_dir/"

    echo "Session archived: $session_id"
    return 0
}

# Main function for CLI usage
main() {
    local command="${1:-help}"
    shift || true

    case "$command" in
        create)
            create_session "$@"
            ;;
        update)
            update_session "$@"
            ;;
        save-cred)
            save_credentials "$@"
            ;;
        log)
            log_finding "$@"
            ;;
        info)
            get_session_info "$@"
            ;;
        list)
            list_sessions
            ;;
        resume)
            resume_session "$@"
            ;;
        archive)
            archive_session "$@"
            ;;
        help|*)
            echo "Session Manager - Penetration Testing Session Management"
            echo ""
            echo "Usage: $0 <command> [arguments]"
            echo ""
            echo "Commands:"
            echo "  create <target>           Create a new session"
            echo "  update <id> <phase>       Update session phase"
            echo "  save-cred <id> <type> <value>  Save credentials"
            echo "  log <id> <severity> <finding>  Log a finding"
            echo "  info <id>                 Get session information"
            echo "  list                      List all sessions"
            echo "  resume <id>              Resume a session"
            echo "  archive <id>             Archive completed session"
            echo ""
            echo "Credential types: username, password, hash, credential"
            echo "Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO"
            echo "Phases: initialization, recon, enumeration, exploitation, post-exploitation, reporting"
            ;;
    esac
}

# Only run main if executed directly
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi