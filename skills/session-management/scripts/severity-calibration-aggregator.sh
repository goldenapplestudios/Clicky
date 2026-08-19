#!/bin/bash
#
# Severity Calibration Aggregator - scans every session's
# logs/severity_review.jsonl (active + archived/) and computes real
# per-category severity-inflation patterns. This is the read/aggregate
# side of the Tier 3 feedback loop; skills/session-management/scripts/
# severity-review-logger.sh is the write side - mirrors exactly how
# attempt-aggregator.sh / state-persistence.sh's record_attempt split
# aggregate vs. write for the (unrelated) HTB success-rate calibration.
#
# A category with fewer than --min-samples reviewed findings reports
# avg_delta: null, basis: "insufficient_data" - never a misleadingly
# precise average from a handful of points, same posture as
# attempt-aggregator.sh.
#
# review_mode is tracked separately per category (cross_family_codex vs.
# same_family_fallback) rather than blended into one number - the research
# behind this design (see agents/severity-analyst-agent.md) specifically
# found cross-family review catches correlated errors same-family review
# misses, so silently averaging the two together would dilute the
# stronger signal with the weaker one.
#
# Usage: severity-calibration-aggregator.sh compute [--min-samples N] [--session-base DIR]
#
set -uo pipefail

SESSION_BASE_DEFAULT="${CLAUDE_PLUGIN_OPTION_DEFAULT_SESSION_DIRECTORY:-$HOME/.claude/sessions}"

compute() {
    local min_samples="${CLAUDE_PLUGIN_OPTION_CALIBRATION_MIN_SAMPLE_SIZE:-5}"
    local session_base="$SESSION_BASE_DEFAULT"
    while [ $# -gt 0 ]; do
        case "$1" in
            --min-samples) min_samples="$2"; shift 2 ;;
            --session-base) session_base="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 required" >&2; exit 1; }

    python3 - "$session_base" "$min_samples" << 'PYEOF'
import json
import sys
import glob
import os
import datetime

session_base, min_samples = sys.argv[1], int(sys.argv[2])

RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

review_files = glob.glob(os.path.join(session_base, "*", "logs", "severity_review.jsonl")) + \
               glob.glob(os.path.join(session_base, "archived", "*", "logs", "severity_review.jsonl"))

# Per (category, review_mode) -> list of rank deltas (original - recommended;
# positive = downgrade/inflation found, negative = upgrade/under-scoring found)
by_category = {}
direction_counts = {}
sessions_seen = set()
slop_scores_by_session = {}
total_findings_reviewed = 0

for path in review_files:
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue

                total_findings_reviewed += 1
                sid = row.get("session_id")
                if sid:
                    sessions_seen.add(sid)
                    slop = row.get("report_slop_score")
                    if isinstance(slop, (int, float)):
                        # Same value repeated per line in a session - one
                        # write per session_id is enough, last one wins
                        # (they're all identical within a session anyway).
                        slop_scores_by_session[sid] = slop

                mode = row.get("review_mode") or "unknown"
                category = row.get("category") or "unknown"
                direction = row.get("direction") or "unchanged"

                dkey = (category, mode)
                direction_counts.setdefault(dkey, {"downgrade": 0, "upgrade": 0, "unchanged": 0})
                if direction in direction_counts[dkey]:
                    direction_counts[dkey][direction] += 1

                orig = row.get("original_severity")
                rec = row.get("recommended_severity")
                if orig in RANK and rec in RANK:
                    delta = RANK[orig] - RANK[rec]
                    by_category.setdefault(dkey, []).append(delta)
    except OSError:
        continue


def finalize_category_buckets():
    out = {}
    for (category, mode), deltas in by_category.items():
        n = len(deltas)
        measured = n >= min_samples
        entry = {
            "reviewed_findings": n,
            "avg_delta": round(sum(deltas) / n, 3) if measured else None,
            "basis": "measured" if measured else "insufficient_data",
            "directions": direction_counts.get((category, mode), {"downgrade": 0, "upgrade": 0, "unchanged": 0}),
        }
        out.setdefault(category, {})[mode] = entry
    return out


result = {
    "computed_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    "min_sample_threshold": min_samples,
    "sessions_scanned": len(sessions_seen),
    "total_findings_reviewed": total_findings_reviewed,
    "avg_report_slop_score": (
        round(sum(slop_scores_by_session.values()) / len(slop_scores_by_session), 1)
        if slop_scores_by_session else None
    ),
    "by_category": finalize_category_buckets(),
}

out_path = os.path.join(session_base, ".severity-calibration.json")
try:
    os.makedirs(session_base, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
except OSError:
    pass  # best-effort cache; stdout below is authoritative

print(json.dumps(result, indent=2))
PYEOF
}

main() {
    local cmd="${1:-}"
    case "$cmd" in
        compute) shift; compute "$@" ;;
        *) echo "Usage: $0 compute [--min-samples N] [--session-base DIR]" >&2; exit 1 ;;
    esac
}

main "$@"
