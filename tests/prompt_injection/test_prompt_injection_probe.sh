#!/bin/bash
#
# Backs skills/ai-llm-security-testing/SKILL.md's "Verified live against
# two mock endpoints" claim with an actual re-runnable test, against the
# real prompt-injection-probe.sh script (not a reimplementation of it).
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROBE="$REPO_ROOT/skills/ai-llm-security-testing/scripts/prompt-injection-probe.sh"
PAYLOAD_FILE="$REPO_ROOT/skills/ai-llm-security-testing/assets/payloads/prompt-injection.txt"
PORT=8998
WORK=$(mktemp -d)
SERVER_PID=""

cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 not installed"; exit 0; }

python3 "$(dirname "${BASH_SOURCE[0]}")/mock_server.py" "$PORT" &
SERVER_PID=$!

# Poll readiness instead of a blind sleep.
ready=0
for _ in $(seq 1 30); do
    if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$PORT/safe" -X POST -d '{}'; then
        ready=1
        break
    fi
    sleep 0.2
done
if [ "$ready" != "1" ]; then
    echo "FAIL: mock server never became ready on port $PORT"
    exit 1
fi

FAILED=0

echo "--- probing /reflect (should detect injection on every canary payload) ---"
"$PROBE" probe --url "http://127.0.0.1:$PORT/reflect" --payload-file "$PAYLOAD_FILE" --output "$WORK/reflect.json"
reflect_injections=$(jq '[.results[] | select(.verdict == "possible_injection")] | length' "$WORK/reflect.json")
reflect_total=$(jq '.results | length' "$WORK/reflect.json")
echo "possible_injection: $reflect_injections / $reflect_total payloads"
if [ "$reflect_injections" -lt 1 ] || [ "$reflect_injections" != "$reflect_total" ]; then
    echo "FAIL: expected every canary payload against /reflect to be flagged possible_injection"
    FAILED=1
fi

echo "--- probing /safe (should detect zero injections) ---"
"$PROBE" probe --url "http://127.0.0.1:$PORT/safe" --payload-file "$PAYLOAD_FILE" --output "$WORK/safe.json"
safe_injections=$(jq '[.results[] | select(.verdict == "possible_injection")] | length' "$WORK/safe.json")
echo "possible_injection: $safe_injections / $(jq '.results | length' "$WORK/safe.json") payloads"
if [ "$safe_injections" != "0" ]; then
    echo "FAIL: expected zero false positives against /safe, got $safe_injections"
    FAILED=1
fi

exit $FAILED
