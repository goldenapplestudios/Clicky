#!/bin/bash
#
# Trace Logger - PostToolUse / PostToolUseFailure / SubagentStop hook
#
# Appends one JSONL line per tool attempt or subagent completion, so a
# pentest run can be walked back through afterward to see what was tried
# and where it failed. Reads the hook's JSON payload from stdin.
#
# Keyed on Claude Code's own session_id (always present in the hook
# payload, reliable). Clicky's own pentest_<timestamp>_<pid> session
# directory is a separate identifier that a plain Bash tool call has no
# reliable way to learn Claude's session_id from, so instead of forcing a
# join at write time, this script opportunistically tags each line with
# whichever Clicky session directory looks "current" (see
# session-manager.sh's CURRENT_SESSION_FILE), and simply omits that field
# if no session looks active. The trace file itself never depends on that
# pointer being correct.
#

set -euo pipefail

TRACE_DIR="$HOME/.claude/pentest-traces"
mkdir -p "$TRACE_DIR"

input=$(cat)

session_id=$(jq -r '.session_id // "unknown"' <<<"$input")
hook_event=$(jq -r '.hook_event_name // "unknown"' <<<"$input")
agent_type=$(jq -r '.agent_type // "main"' <<<"$input")
agent_id=$(jq -r '.agent_id // "none"' <<<"$input")
tool_name=$(jq -r '.tool_name // "N/A"' <<<"$input")
tool_use_id=$(jq -r '.tool_use_id // "N/A"' <<<"$input")
timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Opportunistic cross-reference to a Clicky session directory, if one looks
# active. CURRENT_SESSION_FILE is a pointer written by session-manager.sh's
# create_session; it's fine for this to be stale or absent (e.g. no /pentest
# is currently running), in which case clicky_session_dir stays null.
SESSION_BASE="${CLAUDE_PLUGIN_OPTION_DEFAULT_SESSION_DIRECTORY:-$HOME/.claude/sessions}"
CURRENT_SESSION_FILE="$SESSION_BASE/.current-session"
clicky_session_dir="null"
if [ -f "$CURRENT_SESSION_FILE" ]; then
    pointed_dir=$(cat "$CURRENT_SESSION_FILE" 2>/dev/null || true)
    if [ -n "$pointed_dir" ] && [ -d "$pointed_dir" ]; then
        clicky_session_dir="\"$pointed_dir\""
    fi
fi

trace_entry=$(jq -nc \
    --arg ts "$timestamp" \
    --arg session "$session_id" \
    --arg event "$hook_event" \
    --arg agent_type "$agent_type" \
    --arg agent_id "$agent_id" \
    --arg tool "$tool_name" \
    --arg tool_id "$tool_use_id" \
    --argjson clicky_session_dir "$clicky_session_dir" \
    --argjson input "$input" \
    '{
        timestamp: $ts,
        claude_session_id: $session,
        clicky_session_dir: $clicky_session_dir,
        event: $event,
        agent_type: $agent_type,
        agent_id: $agent_id,
        tool_name: $tool,
        tool_use_id: $tool_id,
        tool_input: $input.tool_input,
        tool_result: $input.tool_result,
        error: $input.error,
        last_assistant_message: $input.last_assistant_message,
        stop_reason: $input.stop_reason
    }')

echo "$trace_entry" >> "$TRACE_DIR/$session_id.jsonl"

exit 0
