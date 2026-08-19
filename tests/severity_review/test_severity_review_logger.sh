#!/bin/bash
#
# Fixture test for skills/session-management/scripts/severity-review-logger.sh.
# Two fixture critiques (fixtures/critique_mismatched.json,
# fixtures/critique_matching.json) against one fixture findings.json,
# covering: category joined correctly from findings.json's source_agent,
# per-finding JSONL records written correctly, and - the load-bearing
# check - that a self-reported slop_score is mechanically recomputed
# from the critique's own findings[]/flags rather than trusted verbatim
# (same "don't trust a self-report, verify mechanically" posture
# finding-validator.sh already applies at Tier 1), including that
# severity_critique.json itself gets corrected in place on a mismatch.
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOGGER="$REPO_ROOT/skills/session-management/scripts/severity-review-logger.sh"
FIXTURES="$(dirname "${BASH_SOURCE[0]}")/fixtures"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }
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

# --- Case 1: mismatched self-reported slop_score gets corrected ---
# Hand-computed expected value: finding-1 CRITICAL(4)->MEDIUM(2), delta=2,
# weighted=2*4=8; finding-2 HIGH(3)->HIGH(3), delta=0; finding-3
# MEDIUM(2)->LOW(1), delta=1, weighted=1*2=2. weighted_delta=10, n=3,
# base_score=round(100*10/12)=83. flags sum=1+0+1=2, penalty=10.
# slop_score = min(100, 83+10) = 93. Fixture states 99 (deliberately wrong).
fake_home=$(mktemp -d)
session_id="test_session_mismatch"
session_dir="$fake_home/.claude/sessions/$session_id"
mkdir -p "$session_dir/reports" "$session_dir/logs"
cp "$FIXTURES/findings.json" "$session_dir/reports/findings.json"
critique_file="$session_dir/reports/severity_critique.json"
cp "$FIXTURES/critique_mismatched.json" "$critique_file"

echo "--- case: mismatched slop_score ---"
output=$(HOME="$fake_home" bash "$LOGGER" log \
    --session-id "$session_id" \
    --critique-file "$critique_file" \
    --review-mode cross_family_codex)
echo "$output"

check "logged.slop_score (recomputed)" "$(echo "$output" | jq -r '.slop_score')" "93"
check "logged.logged (line count)" "$(echo "$output" | jq -r '.logged')" "3"
check "stdout has a mismatch warning" "$(echo "$output" | jq -r 'has("warning")')" "true"

jsonl="$session_dir/logs/severity_review.jsonl"
[ -f "$jsonl" ] || { echo "FAIL: $jsonl was not created"; FAILED=1; }

check "line count in severity_review.jsonl" "$(wc -l < "$jsonl" | tr -d ' ')" "3"
check "finding-1 category (exploit-agent)" \
    "$(jq -sr '.[] | select(.finding_id=="finding-1") | .category' "$jsonl")" "exploit-agent"
check "finding-2 category (loot-agent)" \
    "$(jq -sr '.[] | select(.finding_id=="finding-2") | .category' "$jsonl")" "loot-agent"
check "finding-1 direction" \
    "$(jq -sr '.[] | select(.finding_id=="finding-1") | .direction' "$jsonl")" "downgrade"
check "every line's report_slop_score is the recomputed value (93), not the stated 99" \
    "$(jq -sr '[.[].report_slop_score] | unique | join(",")' "$jsonl")" "93"
check "every line flags the mismatch" \
    "$(jq -sr '[.[].report_slop_score_mismatch] | unique | join(",")' "$jsonl")" "true"
check "every line keeps the originally-stated score too" \
    "$(jq -sr '[.[].report_slop_score_stated] | unique | join(",")' "$jsonl")" "99"

# severity_critique.json itself must be corrected in place, since Step 11.2
# (commands/pentest.md) reads this file back to compose the report section.
check "severity_critique.json slop_score corrected in place" \
    "$(jq -r '.slop_score' "$critique_file")" "93"
check "severity_critique.json records the mechanical correction" \
    "$(jq -r '.slop_score_mechanically_corrected' "$critique_file")" "true"
check "severity_critique.json preserves what the agent originally stated" \
    "$(jq -r '.slop_score_stated_by_agent' "$critique_file")" "99"

rm -rf "$fake_home"

# --- Case 2: self-reported slop_score already matches - no correction, no mismatch flag ---
fake_home=$(mktemp -d)
session_id="test_session_matching"
session_dir="$fake_home/.claude/sessions/$session_id"
mkdir -p "$session_dir/reports" "$session_dir/logs"
cp "$FIXTURES/findings.json" "$session_dir/reports/findings.json"
critique_file="$session_dir/reports/severity_critique.json"
cp "$FIXTURES/critique_matching.json" "$critique_file"

echo "--- case: matching slop_score (all unchanged, flags 0) ---"
output=$(HOME="$fake_home" bash "$LOGGER" log \
    --session-id "$session_id" \
    --critique-file "$critique_file" \
    --review-mode same_family_fallback)
echo "$output"

check "logged.slop_score (all-unchanged case)" "$(echo "$output" | jq -r '.slop_score')" "0"
check "stdout has no mismatch warning" "$(echo "$output" | jq -r 'has("warning")')" "false"
check "severity_critique.json untouched (no mismatch field added)" \
    "$(jq -r 'has("slop_score_mechanically_corrected")' "$critique_file")" "false"

jsonl="$session_dir/logs/severity_review.jsonl"
check "all directions unchanged" \
    "$(jq -sr '[.[].direction] | unique | join(",")' "$jsonl")" "unchanged"
check "review_mode recorded correctly" \
    "$(jq -sr '[.[].review_mode] | unique | join(",")' "$jsonl")" "same_family_fallback"

rm -rf "$fake_home"

exit $FAILED
