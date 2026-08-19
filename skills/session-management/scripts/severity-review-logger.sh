#!/bin/bash
#
# Severity Review Logger - writes agents/severity-analyst-agent.md's
# critique output into this session's own logs/severity_review.jsonl, one
# line per finding (JSONL append, same convention as state-persistence.sh's
# logs/attempts.jsonl - concurrent-safe, no read-modify-write cycle).
#
# This is the write side of the severity-calibration feedback loop;
# severity-calibration-aggregator.sh is the read/aggregate side, mirroring
# exactly how state-persistence.sh's record_attempt / attempt-aggregator.sh
# split write vs. aggregate for the (unrelated) HTB success-rate calibration.
#
# `category` is joined from findings.json's own `source_agent` field per
# finding_id - findings.json has no dedicated vulnerability-category field
# (see session-manager.sh's log_finding), and source_agent (exploit-agent /
# privesc-agent / loot-agent / cloud-recon-agent / ...) is a reasonable,
# always-available proxy: different source agents tend to produce
# structurally different finding classes.
#
# Usage: severity-review-logger.sh log --session-id <id> --critique-file <file>
#          --review-mode cross_family_codex|same_family_fallback
#
set -uo pipefail

SESSION_BASE="${CLAUDE_PLUGIN_OPTION_DEFAULT_SESSION_DIRECTORY:-$HOME/.claude/sessions}"

usage() {
    echo "Usage: $0 log --session-id <id> --critique-file <file> --review-mode cross_family_codex|same_family_fallback" >&2
    exit 1
}

[ "${1:-}" = "log" ] || usage
shift

SESSION_ID="" CRITIQUE_FILE="" REVIEW_MODE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --session-id) SESSION_ID="$2"; shift 2 ;;
        --critique-file) CRITIQUE_FILE="$2"; shift 2 ;;
        --review-mode) REVIEW_MODE="$2"; shift 2 ;;
        *) shift ;;
    esac
done

: "${SESSION_ID:?--session-id required}"
: "${CRITIQUE_FILE:?--critique-file required}"
case "$REVIEW_MODE" in
    cross_family_codex|same_family_fallback) ;;
    *) echo "ERROR: --review-mode must be cross_family_codex or same_family_fallback, got: ${REVIEW_MODE:-<empty>}" >&2; exit 1 ;;
esac

SESSION_DIR="$SESSION_BASE/$SESSION_ID"
[ -d "$SESSION_DIR" ] || { echo "ERROR: session not found: $SESSION_ID" >&2; exit 1; }
[ -f "$CRITIQUE_FILE" ] || { echo "ERROR: critique file not found: $CRITIQUE_FILE" >&2; exit 1; }

FINDINGS_FILE="$SESSION_DIR/reports/findings.json"
mkdir -p "$SESSION_DIR/logs"

command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 required" >&2; exit 1; }

python3 - "$CRITIQUE_FILE" "$FINDINGS_FILE" "$SESSION_DIR/logs/severity_review.jsonl" \
    "$SESSION_ID" "$REVIEW_MODE" << 'PYEOF'
import json
import sys
import datetime

critique_path, findings_path, out_path, session_id, review_mode = sys.argv[1:6]

with open(critique_path) as f:
    critique = json.load(f)

source_agent_by_id = {}
try:
    with open(findings_path) as f:
        findings_data = json.load(f)
    for finding in findings_data.get("findings", []):
        source_agent_by_id[finding.get("id", "")] = finding.get("source_agent") or "unknown"
except (OSError, json.JSONDecodeError):
    pass

now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

# Mechanically recompute slop_score from findings[]/flags rather than
# trusting severity-analyst-agent's self-reported number - same "don't
# trust a self-report, verify mechanically" posture finding-validator.sh
# already applies at Tier 1. Formula matches
# agents/severity-analyst-agent.md's "Step 3" section exactly; keep both
# in sync if either changes.
RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def recompute_slop_score(critique):
    findings = critique.get("findings", [])
    flags = critique.get("flags") or {}

    weighted_delta = 0
    for entry in findings:
        orig = RANK.get(entry.get("original_severity"))
        rec = RANK.get(entry.get("recommended_severity"))
        if orig is None or rec is None:
            continue
        weighted_delta += max(0, orig - rec) * orig

    n = len(findings)
    base_score = min(100, round(100 * weighted_delta / (4 * n))) if n else 0

    penalty = 5 * (
        int(flags.get("unsubstantiated_impact_language") or 0)
        + int(flags.get("ignored_compensating_controls") or 0)
        + int(flags.get("unresolved_could_chains") or 0)
    )
    return min(100, base_score + penalty)


recomputed_slop_score = recompute_slop_score(critique)
stated_slop_score = critique.get("slop_score")
slop_score_mismatch = stated_slop_score != recomputed_slop_score

# Correct severity_critique.json itself in place, not just this log - Step
# 11.2 (commands/pentest.md) reads this file back to compose the report's
# "Independent Severity Review" section, so it needs the trustworthy
# (mechanically-verified) number, not whatever severity-analyst-agent
# happened to state.
if slop_score_mismatch:
    critique["slop_score"] = recomputed_slop_score
    critique["slop_score_stated_by_agent"] = stated_slop_score
    critique["slop_score_mechanically_corrected"] = True
    try:
        with open(critique_path, "w") as f:
            json.dump(critique, f, indent=2)
    except OSError:
        pass

lines_written = 0
with open(out_path, "a") as out:
    for entry in critique.get("findings", []):
        finding_id = entry.get("finding_id", "")
        record = {
            "timestamp": now,
            "session_id": session_id,
            "review_mode": review_mode,
            # Redundant across every line in this session's file on purpose
            # (rather than a separate summary record) - keeps the aggregator
            # a single flat scan with no per-session join step. Mechanically
            # recomputed value, not severity-analyst-agent's self-report -
            # see recompute_slop_score() above.
            "report_slop_score": recomputed_slop_score,
            "report_slop_score_stated": stated_slop_score,
            "report_slop_score_mismatch": slop_score_mismatch,
            "finding_id": finding_id,
            "category": source_agent_by_id.get(finding_id, "unknown"),
            "original_severity": entry.get("original_severity"),
            "original_cvss": entry.get("original_cvss"),
            "recommended_severity": entry.get("recommended_severity"),
            "recommended_cvss": entry.get("recommended_cvss"),
            "direction": entry.get("direction", "unchanged"),
            "rationale": entry.get("rationale", ""),
        }
        out.write(json.dumps(record) + "\n")
        lines_written += 1

result = {
    "logged": lines_written,
    "slop_score": recomputed_slop_score,
    "review_mode": review_mode,
    "path": out_path,
}
if slop_score_mismatch:
    result["warning"] = (
        f"severity-analyst-agent stated slop_score={stated_slop_score}, "
        f"but the formula applied to its own findings[]/flags produces "
        f"{recomputed_slop_score}. Logged and reported the recomputed value."
    )
print(json.dumps(result))
PYEOF
