#!/bin/bash
#
# Fixture test for skills/session-management/scripts/attempt-aggregator.sh.
# Fixtures: fixtures/session_a (active) + fixtures/archived/session_b -
# hand-authored attempts.jsonl with hand-computed expected rates below.
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
AGGREGATOR="$REPO_ROOT/skills/session-management/scripts/attempt-aggregator.sh"
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

# ftp: session_a has 1 success/1 fail, session_b has 2 success/1 fail = 3/5 = 0.6
check "ftp.attempts" "$(echo "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["by_service"]["ftp"]["attempts"])')" "5"
check "ftp.successes" "$(echo "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["by_service"]["ftp"]["successes"])')" "3"
check "ftp.rate" "$(echo "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["by_service"]["ftp"]["rate"])')" "0.6"
check "ftp.basis" "$(echo "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["by_service"]["ftp"]["basis"])')" "measured"

# smb: session_b has 1 success/1 attempt = 1.0
check "smb.rate" "$(echo "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["by_service"]["smb"]["rate"])')" "1.0"

# by_technique
check "exploit-agent:anonymous_login.rate" "$(echo "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["by_technique"]["exploit-agent:anonymous_login"]["rate"])')" "0.6"
check "privesc-agent:sudo_misconfiguration.rate" "$(echo "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["by_technique"]["privesc-agent:sudo_misconfiguration"]["rate"])')" "1.0"

echo ""
echo "--- default min-samples=5 (smb has only 1 attempt -> insufficient_data) ---"
out_default=$(bash "$AGGREGATOR" compute --session-base "$FIXTURES")
check "smb.basis (default threshold)" "$(echo "$out_default" | python3 -c 'import json,sys;print(json.load(sys.stdin)["by_service"]["smb"]["basis"])')" "insufficient_data"
check "smb.rate (default threshold)" "$(echo "$out_default" | python3 -c 'import json,sys;print(json.load(sys.stdin)["by_service"]["smb"]["rate"])')" "None"
check "ftp.basis (default threshold, exactly at 5)" "$(echo "$out_default" | python3 -c 'import json,sys;print(json.load(sys.stdin)["by_service"]["ftp"]["basis"])')" "measured"

exit $FAILED
