#!/bin/bash
#
# Fixture test for skills/mcp-gateway/scope_gate.py's classify(), run
# against fixtures/scope.json. Exercises the real script (as a subprocess
# CLI call, the same invocation path server.py's register_target uses
# internally) rather than reimplementing scope-matching logic in the test.
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCOPE_GATE="$REPO_ROOT/skills/mcp-gateway/scope_gate.py"
SCOPE_FIXTURE="$(dirname "${BASH_SOURCE[0]}")/fixtures/scope.json"

command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 not installed"; exit 0; }

FAILED=0

check() {
    local label="$1" actual="$2" expected="$3"
    if [ "$actual" != "$expected" ]; then
        echo "FAIL: $label - expected '$expected', got '$actual'"
        FAILED=1
    else
        echo "PASS: $label == $expected"
    fi
}

check_exit() {
    local label="$1" actual="$2" expected="$3"
    check "$label" "$actual" "$expected"
}

# --- IN_SCOPE: matches the 10.10.10.0/24 CIDR entry ---
out=$(python3 "$SCOPE_GATE" --target "10.10.10.50" --scope "$SCOPE_FIXTURE")
code=$?
check "10.10.10.50 (in CIDR range) classification" "$out" "IN_SCOPE"
check_exit "10.10.10.50 exit code" "$code" "0"

# --- OUT_OF_SCOPE: explicit exclusion takes priority even though it also
# falls inside the in_scope CIDR range ---
out=$(python3 "$SCOPE_GATE" --target "10.10.10.5" --scope "$SCOPE_FIXTURE")
code=$?
check "10.10.10.5 (explicit exclusion inside in-scope CIDR) classification" "$out" "OUT_OF_SCOPE"
check_exit "10.10.10.5 exit code" "$code" "1"

# --- IN_SCOPE: wildcard domain match ---
out=$(python3 "$SCOPE_GATE" --target "app.example-corp.test" --scope "$SCOPE_FIXTURE")
code=$?
check "app.example-corp.test (wildcard domain match) classification" "$out" "IN_SCOPE"
check_exit "app.example-corp.test exit code" "$code" "0"

# --- NOT_LISTED: matches neither list ---
out=$(python3 "$SCOPE_GATE" --target "192.168.1.1" --scope "$SCOPE_FIXTURE")
code=$?
check "192.168.1.1 (not listed either way) classification" "$out" "NOT_LISTED"
check_exit "192.168.1.1 exit code" "$code" "1"

# --- NOT_LISTED: a missing scope file also degrades to NOT_LISTED, not a crash ---
out=$(python3 "$SCOPE_GATE" --target "10.10.10.50" --scope "$(dirname "${BASH_SOURCE[0]}")/fixtures/does-not-exist.json" 2>/dev/null)
check "missing scope.json degrades to NOT_LISTED rather than erroring" "$out" "NOT_LISTED"

# --- Library-level check: classify() importable and usable directly, not just via CLI ---
lib_result=$(python3 -c "
import sys
sys.path.insert(0, '$REPO_ROOT/skills/mcp-gateway')
import scope_gate
print(scope_gate.classify('10.10.10.50', '$SCOPE_FIXTURE'))
print(scope_gate.classify('10.10.10.5', '$SCOPE_FIXTURE'))
print(scope_gate.classify('192.168.1.1', '$SCOPE_FIXTURE'))
")
expected_lib=$'IN_SCOPE\nOUT_OF_SCOPE\nNOT_LISTED'
check "classify() called directly as a library gives the same 3 results" "$lib_result" "$expected_lib"

exit $FAILED
