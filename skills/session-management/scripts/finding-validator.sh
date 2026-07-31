#!/bin/bash
#
# Finding Validator - Tier 1 (cheap, always-on) validation of findings.json
# entries. Cross-references each finding's evidence.command against the
# session's trace log (~/.claude/pentest-traces/*.jsonl, written by the
# trace-logger.sh PostToolUse/PostToolUseFailure/SubagentStop hook) and
# writes validation.tier1_trace_check / validation.tier1_notes back into
# findings.json in place.
#
# Usage: finding-validator.sh validate-all --session-id <session_id>
#
# This only confirms the claimed evidence command was actually executed
# during this session and didn't obviously error - it does NOT re-run
# anything or judge whether the finding's claim is actually true. That's
# what Tier 2 (agents/verification-agent.md) is for. See docs/workflow.md.
#
# Classifications:
#   pass        - a matching trace entry exists and doesn't look like it errored
#   fail        - a matching trace entry exists but looks like it errored
#   no_evidence - no evidence.command was recorded, or nothing in the trace
#                 log matches it. Never silently treated as a pass.
#

set -uo pipefail

SESSION_BASE="${CLAUDE_PLUGIN_OPTION_DEFAULT_SESSION_DIRECTORY:-$HOME/.claude/sessions}"
TRACE_DIR="$HOME/.claude/pentest-traces"

usage() {
    echo "Usage: $0 validate-all --session-id <session_id>" >&2
    exit 1
}

[ "${1:-}" = "validate-all" ] || usage
shift

SESSION_ID=""
while [ $# -gt 0 ]; do
    case "$1" in
        --session-id) SESSION_ID="$2"; shift 2 ;;
        *) shift ;;
    esac
done

: "${SESSION_ID:?--session-id required}"

SESSION_DIR="$SESSION_BASE/$SESSION_ID"
FINDINGS_FILE="$SESSION_DIR/reports/findings.json"

[ -d "$SESSION_DIR" ] || { echo "ERROR: session not found: $SESSION_ID" >&2; exit 1; }
if [ ! -f "$FINDINGS_FILE" ]; then
    echo '{"total_findings": 0, "tier1_pass": 0, "tier1_fail": 0, "tier1_no_evidence": 0, "critical_high_pending_tier2": []}'
    exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 required" >&2
    exit 1
fi

mkdir -p "$TRACE_DIR" 2>/dev/null || true

python3 - "$FINDINGS_FILE" "$SESSION_DIR" "$TRACE_DIR" << 'PYEOF'
import json
import sys
import glob
import os

findings_file, session_dir, trace_dir = sys.argv[1], sys.argv[2], sys.argv[3]
session_dir_abs = os.path.abspath(session_dir)

with open(findings_file) as f:
    data = json.load(f)

# Load every trace entry tagged with this session (a session can span
# multiple Claude Code sessions if resumed, hence scanning all trace files
# rather than assuming a 1:1 file).
trace_entries = []
for path in glob.glob(os.path.join(trace_dir, "*.jsonl")):
    try:
        with open(path) as tf:
            for line in tf:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                csd = entry.get("clicky_session_dir")
                if csd and os.path.abspath(csd) == session_dir_abs:
                    trace_entries.append(entry)
    except OSError:
        continue


def command_of(entry):
    ti = entry.get("tool_input") or {}
    return ti.get("command") or ti.get("url") or ""


def looks_errored(entry):
    if entry.get("event") == "PostToolUseFailure":
        return True
    if entry.get("error"):
        return True
    result = entry.get("tool_result")
    if isinstance(result, dict) and result.get("is_error"):
        return True
    return False


for finding in data.get("findings", []):
    evidence = finding.get("evidence") or {}
    evidence_command = (evidence.get("command") or "").strip()
    validation = finding.setdefault("validation", {})

    if not evidence_command:
        validation["tier1_trace_check"] = "no_evidence"
        validation["tier1_notes"] = (
            "No evidence.command was recorded for this finding - nothing to cross-check against the trace log."
        )
        continue

    matches = [
        e for e in trace_entries
        if evidence_command in command_of(e) or (command_of(e) and command_of(e) in evidence_command)
    ]

    if not matches:
        validation["tier1_trace_check"] = "no_evidence"
        validation["tier1_notes"] = f"No trace log entry in this session matched evidence.command: {evidence_command!r}"
    elif any(not looks_errored(e) for e in matches):
        validation["tier1_trace_check"] = "pass"
        validation["tier1_notes"] = f"Matched {len(matches)} trace entry/entries, at least one completed without an apparent error."
    else:
        validation["tier1_trace_check"] = "fail"
        validation["tier1_notes"] = f"Matched {len(matches)} trace entry/entries, all show an apparent error (PostToolUseFailure or error field set)."

with open(findings_file, "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")

all_findings = data.get("findings", [])
pending_tier2 = [
    f["id"] for f in all_findings
    if f.get("severity") in ("CRITICAL", "HIGH")
    and f.get("validation", {}).get("tier1_trace_check") != "fail"
    and f.get("validation", {}).get("tier2_review", "not_required") == "not_required"
]

print(json.dumps({
    "total_findings": len(all_findings),
    "tier1_pass": sum(1 for f in all_findings if f.get("validation", {}).get("tier1_trace_check") == "pass"),
    "tier1_fail": sum(1 for f in all_findings if f.get("validation", {}).get("tier1_trace_check") == "fail"),
    "tier1_no_evidence": sum(1 for f in all_findings if f.get("validation", {}).get("tier1_trace_check") == "no_evidence"),
    "critical_high_pending_tier2": pending_tier2,
}, indent=2))
PYEOF
