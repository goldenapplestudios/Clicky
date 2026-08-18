#!/bin/bash
#
# Session Review - walk back through a trace log
#
# Reads a session's own JSONL trace log ($SESSION_DIR/logs/trace.jsonl,
# written directly by skills/mcp-gateway/server.py's _trace() helper on
# every gateway tool call and agent-dispatch boundary - see that file's
# "Phase 0 multi-CLI groundwork" docstring note) and prints a legible,
# chronological walk-through: what was attempted, by which agent, and
# what failed and why.
#
# This is an internal/operator-facing tool for improving Clicky itself
# (comparing real outcomes against the HTB baseline, spotting where an
# engagement went sideways) - it is NOT part of the client-facing report
# generated elsewhere in this skill.
#
# Usage:
#   session-review.sh [session_id | path/to/trace.jsonl]
#   session-review.sh                # uses the most recently modified session's trace log
#

set -euo pipefail

SESSION_BASE="${CLAUDE_PLUGIN_OPTION_DEFAULT_SESSION_DIRECTORY:-$HOME/.claude/sessions}"

resolve_trace_file() {
    local arg="${1:-}"

    if [ -n "$arg" ] && [ -f "$arg" ]; then
        echo "$arg"
        return 0
    fi

    if [ -n "$arg" ]; then
        # Try as a session_id, active first then archived - same fallback
        # pattern state-persistence.sh's _resolve_session_dir() uses.
        local session_dir="$SESSION_BASE/$arg"
        [ -d "$session_dir" ] || session_dir="$SESSION_BASE/archived/$arg"
        if [ -f "$session_dir/logs/trace.jsonl" ]; then
            echo "$session_dir/logs/trace.jsonl"
            return 0
        fi
    fi

    if [ -z "$arg" ]; then
        # Most recently modified session's trace log, active or archived.
        local latest
        latest=$(ls -t "$SESSION_BASE"/*/logs/trace.jsonl "$SESSION_BASE"/archived/*/logs/trace.jsonl 2>/dev/null | head -1 || true)
        if [ -n "$latest" ]; then
            echo "$latest"
            return 0
        fi
    fi

    return 1
}

main() {
    local trace_file
    if ! trace_file=$(resolve_trace_file "${1:-}"); then
        echo "No trace file found. Looked under: $SESSION_BASE" >&2
        echo "Usage: $0 [session_id | path/to/trace.jsonl]" >&2
        exit 1
    fi

    echo "=== Session Review: $trace_file ==="
    echo

    local total_calls failed_calls agent_boundaries
    total_calls=$(jq -s '[.[] | select(.event == "tool_call" or .event == "tool_error")] | length' "$trace_file")
    failed_calls=$(jq -s '[.[] | select(.event == "tool_error")] | length' "$trace_file")
    agent_boundaries=$(jq -s '[.[] | select(.event == "agent_start" or .event == "agent_end")] | length' "$trace_file")

    echo "Tool calls: $total_calls total, $failed_calls failed"
    echo "Agent boundaries logged: $agent_boundaries"
    echo

    echo "--- Chronological walk-through ---"
    jq -r '
      if .event == "agent_start" then
        "[\(.timestamp)] AGENT START   \(.caller)"
      elif .event == "agent_end" then
        "[\(.timestamp)] AGENT DONE    \(.caller)" + (if .tool_result then ": " + .tool_result else "" end)
      elif .event == "tool_error" then
        "[\(.timestamp)] FAILED  \(.caller)/\(.tool_name)  →  \(.error // "unknown error")\n           command: \(.tool_input.command // .tool_input | tostring)"
      else
        "[\(.timestamp)] ok      \(.caller)/\(.tool_name)"
      end
    ' "$trace_file"

    echo
    echo "--- Failures, grouped by agent ---"
    jq -s -r '
      [.[] | select(.event == "tool_error")]
      | group_by(.caller)
      | map({caller: .[0].caller, count: length, errors: [.[].error]})
      | .[]
      | "\(.caller): \(.count) failure(s)\n" + ([.errors[] | "  - " + .] | join("\n"))
    ' "$trace_file"

    if [ "$failed_calls" -eq 0 ]; then
        echo "(none)"
    fi
}

main "$@"
