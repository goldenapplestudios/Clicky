#!/bin/bash
#
# Fixture test for skills/session-management/scripts/finding-validator.sh's
# Tier 1 mechanical trace cross-check. Uses a fake $HOME (finding-
# validator.sh derives SESSION_BASE from $HOME/env, so overriding HOME is
# enough - zero changes needed to the script itself to make it testable)
# with three fixture findings covering the three possible
# tier1_trace_check outcomes: no_evidence, pass, fail. The trace log lives
# at $SESSION_DIR/logs/trace.jsonl (written directly by the gateway
# server's _trace() helper in real use - see skills/mcp-gateway/
# server.py) rather than a global directory, so this fixture writes
# straight into the session's own logs/ directory.
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VALIDATOR="$REPO_ROOT/skills/session-management/scripts/finding-validator.sh"
FIXTURES="$(dirname "${BASH_SOURCE[0]}")/fixtures"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 not installed"; exit 0; }

FAKE_HOME=$(mktemp -d)
trap 'rm -rf "$FAKE_HOME"' EXIT

SESSION_ID="test_session"
SESSION_DIR="$FAKE_HOME/.claude/sessions/$SESSION_ID"
mkdir -p "$SESSION_DIR/reports" "$SESSION_DIR/logs"

sed -e "s#__SESSION_TARGET__#10.10.10.5#g" \
    "$FIXTURES/findings.json.template" > "$SESSION_DIR/reports/findings.json"

sed -e "s#__SESSION_DIR__#$SESSION_DIR#g" -e "s#__SESSION_TARGET__#10.10.10.5#g" \
    "$FIXTURES/trace.jsonl.template" > "$SESSION_DIR/logs/trace.jsonl"

output=$(HOME="$FAKE_HOME" bash "$VALIDATOR" validate-all --session-id "$SESSION_ID")
echo "$output"

FAILED=0

no_evidence_result=$(jq -r '.findings[] | select(.id=="finding-no-evidence") | .validation.tier1_trace_check' "$SESSION_DIR/reports/findings.json")
pass_result=$(jq -r '.findings[] | select(.id=="finding-clean-pass") | .validation.tier1_trace_check' "$SESSION_DIR/reports/findings.json")
fail_result=$(jq -r '.findings[] | select(.id=="finding-errored-fail") | .validation.tier1_trace_check' "$SESSION_DIR/reports/findings.json")

check() {
    local label="$1" actual="$2" expected="$3"
    if [ "$actual" != "$expected" ]; then
        echo "FAIL: $label expected '$expected', got '$actual'"
        FAILED=1
    else
        echo "PASS: $label == $expected"
    fi
}

check "finding-no-evidence" "$no_evidence_result" "no_evidence"
check "finding-clean-pass" "$pass_result" "pass"
check "finding-errored-fail" "$fail_result" "fail"

# Only finding-clean-pass qualifies: finding-no-evidence is LOW severity
# (excluded), finding-errored-fail is HIGH but tier1_trace_check=="fail"
# excludes it too (a failed Tier 1 check doesn't need Tier 2 - it's
# already refuted).
summary_pending=$(echo "$output" | jq -r '.critical_high_pending_tier2 | length')
check "critical_high_pending_tier2 count" "$summary_pending" "1"

exit $FAILED
