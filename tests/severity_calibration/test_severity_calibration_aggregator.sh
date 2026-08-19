#!/bin/bash
#
# Fixture test for
# skills/session-management/scripts/severity-calibration-aggregator.sh.
# Fixtures: fixtures/session_a (active) + fixtures/archived/session_b -
# hand-authored severity_review.jsonl with hand-computed expected
# aggregates below. Mirrors tests/calibration/test_calibrate_success_rates.sh's
# structure exactly (same fixture shape, same min-samples-threshold
# behavior), for the severity-inflation calibration data instead of the
# unrelated HTB technique-success-rate calibration.
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
AGGREGATOR="$REPO_ROOT/skills/session-management/scripts/severity-calibration-aggregator.sh"
FIXTURES="$(dirname "${BASH_SOURCE[0]}")/fixtures"

command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 not installed"; exit 0; }

FAILED=0

check() {
    local label="$1" actual="$2" expected="$3"
    if [ "$actual" != "$expected" ]; then
        echo "FAIL: $label expected '$expected', got '$actual'"
        FAILED=1
    else
        echo "PASS: $label == $expected"
    fi
}

echo "--- min-samples=1 (everything should be 'measured') ---"
out=$(bash "$AGGREGATOR" compute --min-samples 1 --session-base "$FIXTURES")
echo "$out"

# exploit-agent/cross_family_codex: 5 findings (3 in session_a, 2 in
# archived/session_b). Deltas (rank(original)-rank(recommended)):
#   HIGH->LOW=2, CRITICAL->MEDIUM=2, MEDIUM->MEDIUM=0 (session_a)
#   HIGH->MEDIUM=1, LOW->LOW=0 (session_b)
# sum=5, n=5, avg_delta=1.0. directions: downgrade=3, upgrade=0, unchanged=2.
check "exploit-agent.cross_family_codex.reviewed_findings" \
    "$(echo "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["by_category"]["exploit-agent"]["cross_family_codex"]["reviewed_findings"])')" "5"
check "exploit-agent.cross_family_codex.avg_delta" \
    "$(echo "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["by_category"]["exploit-agent"]["cross_family_codex"]["avg_delta"])')" "1.0"
check "exploit-agent.cross_family_codex.basis" \
    "$(echo "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["by_category"]["exploit-agent"]["cross_family_codex"]["basis"])')" "measured"
check "exploit-agent.cross_family_codex.directions.downgrade" \
    "$(echo "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["by_category"]["exploit-agent"]["cross_family_codex"]["directions"]["downgrade"])')" "3"
check "exploit-agent.cross_family_codex.directions.unchanged" \
    "$(echo "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["by_category"]["exploit-agent"]["cross_family_codex"]["directions"]["unchanged"])')" "2"

# loot-agent/cross_family_codex: 1 finding, HIGH->HIGH, delta=0.
check "loot-agent.cross_family_codex.avg_delta (min-samples=1)" \
    "$(echo "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["by_category"]["loot-agent"]["cross_family_codex"]["avg_delta"])')" "0.0"

check "sessions_scanned" "$(echo "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["sessions_scanned"])')" "2"
check "total_findings_reviewed" "$(echo "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["total_findings_reviewed"])')" "6"

# avg_report_slop_score: one score per session (last write wins, but every
# line in a session carries the same value here) - session_a=40,
# session_b=20 -> (40+20)/2 = 30.0.
check "avg_report_slop_score" "$(echo "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["avg_report_slop_score"])')" "30.0"

echo ""
echo "--- default min-samples=5 (loot-agent has only 1 finding -> insufficient_data) ---"
out_default=$(bash "$AGGREGATOR" compute --session-base "$FIXTURES")
check "loot-agent.basis (default threshold)" \
    "$(echo "$out_default" | python3 -c 'import json,sys;print(json.load(sys.stdin)["by_category"]["loot-agent"]["cross_family_codex"]["basis"])')" "insufficient_data"
check "loot-agent.avg_delta (default threshold)" \
    "$(echo "$out_default" | python3 -c 'import json,sys;print(json.load(sys.stdin)["by_category"]["loot-agent"]["cross_family_codex"]["avg_delta"])')" "None"
check "exploit-agent.basis (default threshold, exactly at 5)" \
    "$(echo "$out_default" | python3 -c 'import json,sys;print(json.load(sys.stdin)["by_category"]["exploit-agent"]["cross_family_codex"]["basis"])')" "measured"

# .severity-calibration.json cache file gets written too (best-effort,
# mirrors .calibrated-rates.json's own convention).
check ".severity-calibration.json cache written" \
    "$([ -f "$FIXTURES/.severity-calibration.json" ] && echo yes || echo no)" "yes"

rm -f "$FIXTURES/.severity-calibration.json"

exit $FAILED
