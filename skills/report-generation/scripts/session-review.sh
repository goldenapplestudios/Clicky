#!/bin/bash
#
# Session Review - walk back through a trace log
#
# Reads the JSONL trace log written by
# skills/session-management/scripts/trace-logger.sh (one line per tool
# attempt or subagent completion) and prints a legible, chronological
# walk-through: what was attempted, by which agent, and what failed and why.
#
# This is an internal/operator-facing tool for improving Clicky itself
# (comparing real outcomes against the HTB baseline, spotting where an
# engagement went sideways) - it is NOT part of the client-facing report
# generated elsewhere in this skill.
#
# Usage:
#   session-review.sh [claude_session_id | path/to/trace.jsonl]
#   session-review.sh                # uses the most recently modified trace
#

set -euo pipefail

TRACE_DIR="$HOME/.claude/pentest-traces"

resolve_trace_file() {
    local arg="${1:-}"

    if [ -n "$arg" ] && [ -f "$arg" ]; then
        echo "$arg"
        return 0
    fi

    if [ -n "$arg" ] && [ -f "$TRACE_DIR/$arg.jsonl" ]; then
        echo "$TRACE_DIR/$arg.jsonl"
        return 0
    fi

    if [ -z "$arg" ]; then
        # Most recently modified trace file
        local latest
        latest=$(ls -t "$TRACE_DIR"/*.jsonl 2>/dev/null | head -1 || true)
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
        echo "No trace file found. Looked in: $TRACE_DIR" >&2
        echo "Usage: $0 [claude_session_id | path/to/trace.jsonl]" >&2
        exit 1
    fi

    echo "=== Session Review: $trace_file ==="
    echo

    local total_calls failed_calls subagent_stops
    total_calls=$(jq -s '[.[] | select(.event == "PostToolUse" or .event == "PostToolUseFailure")] | length' "$trace_file")
    failed_calls=$(jq -s '[.[] | select(.event == "PostToolUseFailure")] | length' "$trace_file")
    subagent_stops=$(jq -s '[.[] | select(.event == "SubagentStop")] | length' "$trace_file")

    echo "Tool calls: $total_calls total, $failed_calls failed"
    echo "Subagents completed: $subagent_stops"
    echo

    echo "--- Chronological walk-through ---"
    jq -r '
      if .event == "SubagentStop" then
        "[\(.timestamp)] SUBAGENT DONE  \(.agent_type) (\(.agent_id)) — \(.stop_reason // "unknown"): \(.last_assistant_message // "(no summary)")"
      elif .event == "PostToolUseFailure" then
        "[\(.timestamp)] FAILED  \(.agent_type)/\(.tool_name)  →  \(.error // "unknown error")\n           command: \(.tool_input.command // .tool_input | tostring)"
      else
        "[\(.timestamp)] ok      \(.agent_type)/\(.tool_name)"
      end
    ' "$trace_file"

    echo
    echo "--- Failures, grouped by agent ---"
    jq -s -r '
      [.[] | select(.event == "PostToolUseFailure")]
      | group_by(.agent_type)
      | map({agent: .[0].agent_type, count: length, errors: [.[].error]})
      | .[]
      | "\(.agent): \(.count) failure(s)\n" + ([.errors[] | "  - " + .] | join("\n"))
    ' "$trace_file"

    if [ "$failed_calls" -eq 0 ]; then
        echo "(none)"
    fi
}

main "$@"
