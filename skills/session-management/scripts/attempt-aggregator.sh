#!/bin/bash
#
# Attempt Aggregator - scans every session's logs/attempts.jsonl (active +
# archived/) and computes real success rates per service and per
# (agent, technique). This IS Clicky's self-calibration: no numbers here
# are fabricated, only successes/attempts actually recorded via
# state-persistence.sh's record_attempt (see agents/exploit-agent.md,
# privesc-agent.md, loot-agent.md Communication Protocol sections).
#
# A bucket with fewer than --min-samples attempts reports rate: null,
# basis: "insufficient_data" - never a misleadingly precise rate from a
# handful of points. See skills/htb-decision-tree/scripts/priority_data.py,
# which merges this with the static heuristic baseline for anything still
# under threshold.
#
# Also computes per-agent timing (median seconds from session start to
# first success) where session.json's start_time is available - backs the
# "Performance Metrics" timing claims in exploit-agent.md/privesc-agent.md/
# loot-agent.md instead of the invented numbers those used to have.
#
# Usage: attempt-aggregator.sh compute [--min-samples N] [--session-base DIR]
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
import statistics
import datetime

session_base, min_samples = sys.argv[1], int(sys.argv[2])

attempt_files = glob.glob(os.path.join(session_base, "*", "logs", "attempts.jsonl")) + \
                glob.glob(os.path.join(session_base, "archived", "*", "logs", "attempts.jsonl"))

by_service = {}
by_technique = {}
first_success_seconds_by_agent = {}
sessions_seen = set()
total = 0

def session_start_time(attempts_path):
    # attempts_path is .../<session_dir>/logs/attempts.jsonl
    session_dir = os.path.dirname(os.path.dirname(attempts_path))
    session_json = os.path.join(session_dir, "session.json")
    try:
        with open(session_json) as f:
            data = json.load(f)
        raw = data.get("start_time")
        if not raw:
            return None
        return datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def parse_ts(raw):
    try:
        return datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


for path in attempt_files:
    start = session_start_time(path)
    earliest_success_by_agent_this_session = {}
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

                total += 1
                sid = row.get("session_id")
                if sid:
                    sessions_seen.add(sid)

                success = bool(row.get("success"))
                svc = (row.get("service") or "").strip().lower()
                if svc and svc != "-":
                    bucket = by_service.setdefault(svc, {"attempts": 0, "successes": 0})
                    bucket["attempts"] += 1
                    if success:
                        bucket["successes"] += 1

                agent = row.get("agent") or "unknown"
                technique = row.get("technique") or "unknown"
                key = f"{agent}:{technique}"
                tbucket = by_technique.setdefault(key, {"attempts": 0, "successes": 0})
                tbucket["attempts"] += 1
                if success:
                    tbucket["successes"] += 1

                if success and start is not None:
                    ts = parse_ts(row.get("timestamp", ""))
                    if ts is not None:
                        prior = earliest_success_by_agent_this_session.get(agent)
                        if prior is None or ts < prior:
                            earliest_success_by_agent_this_session[agent] = ts
    except OSError:
        continue

    for agent, ts in earliest_success_by_agent_this_session.items():
        delta_seconds = (ts - start).total_seconds()
        if delta_seconds >= 0:
            first_success_seconds_by_agent.setdefault(agent, []).append(delta_seconds)


def finalize_rate_buckets(buckets):
    out = {}
    for key, bucket in buckets.items():
        attempts, successes = bucket["attempts"], bucket["successes"]
        measured = attempts >= min_samples
        out[key] = {
            "attempts": attempts,
            "successes": successes,
            "rate": round(successes / attempts, 3) if measured else None,
            "basis": "measured" if measured else "insufficient_data",
        }
    return out


def finalize_timing(samples_by_agent):
    out = {}
    for agent, samples in samples_by_agent.items():
        measured = len(samples) >= min_samples
        out[agent] = {
            "samples": len(samples),
            "median_seconds_to_first_success": round(statistics.median(samples), 1) if measured else None,
            "basis": "measured" if measured else "insufficient_data",
        }
    return out


result = {
    "computed_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    "min_sample_threshold": min_samples,
    "sessions_scanned": len(sessions_seen),
    "total_attempts": total,
    "by_service": finalize_rate_buckets(by_service),
    "by_technique": finalize_rate_buckets(by_technique),
    "timing_by_agent": finalize_timing(first_success_seconds_by_agent),
}

out_path = os.path.join(session_base, ".calibrated-rates.json")
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
