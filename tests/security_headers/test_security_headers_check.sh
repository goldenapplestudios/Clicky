#!/bin/bash
#
# Backs skills/web-vulnerability-testing/scripts/security-headers-check.sh
# against real HTTP responses (real mock server, not just a syntax check) -
# same rationale as tests/prompt_injection's suite. Covers both the
# vulnerable case (no clickjacking headers, no CSRF token field, no
# SameSite) and the safe case (all present), against the real script.
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK="$REPO_ROOT/skills/web-vulnerability-testing/scripts/security-headers-check.sh"
PORT=8997
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

ready=0
for _ in $(seq 1 30); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "FAIL: mock server process (PID $SERVER_PID) died before becoming ready"
        exit 1
    fi
    if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$PORT/safe"; then
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

echo "--- checking /vulnerable (missing headers, no CSRF token field) ---"
"$CHECK" --url "http://127.0.0.1:$PORT/vulnerable" --output "$WORK/vulnerable.json"
cat "$WORK/vulnerable.json"

vuln_clickjacking=$(jq -r '.clickjacking.vulnerable' "$WORK/vulnerable.json")
[ "$vuln_clickjacking" = "true" ] || { echo "FAIL: expected clickjacking.vulnerable=true, got $vuln_clickjacking"; FAILED=1; }

vuln_xfo=$(jq -r '.clickjacking.x_frame_options' "$WORK/vulnerable.json")
[ "$vuln_xfo" = "null" ] || { echo "FAIL: expected x_frame_options=null, got $vuln_xfo"; FAILED=1; }

vuln_forms_without_token=$(jq -r '.csrf_signals.forms_without_token_field' "$WORK/vulnerable.json")
[ "$vuln_forms_without_token" = "1" ] || { echo "FAIL: expected csrf_signals.forms_without_token_field=1, got $vuln_forms_without_token"; FAILED=1; }

vuln_samesite=$(jq -r '.csrf_signals.cookies[0].samesite' "$WORK/vulnerable.json")
[ "$vuln_samesite" = "not_set" ] || { echo "FAIL: expected cookie samesite=not_set, got $vuln_samesite"; FAILED=1; }

vuln_hsts=$(jq -r '.other_headers.hsts' "$WORK/vulnerable.json")
[ "$vuln_hsts" = "false" ] || { echo "FAIL: expected other_headers.hsts=false, got $vuln_hsts"; FAILED=1; }

echo "--- checking /safe (headers present, CSRF token field present) ---"
"$CHECK" --url "http://127.0.0.1:$PORT/safe" --output "$WORK/safe.json"
cat "$WORK/safe.json"

safe_clickjacking=$(jq -r '.clickjacking.vulnerable' "$WORK/safe.json")
[ "$safe_clickjacking" = "false" ] || { echo "FAIL: expected clickjacking.vulnerable=false, got $safe_clickjacking"; FAILED=1; }

safe_xfo=$(jq -r '.clickjacking.x_frame_options' "$WORK/safe.json")
[ "$safe_xfo" = "DENY" ] || { echo "FAIL: expected x_frame_options=DENY, got $safe_xfo"; FAILED=1; }

safe_forms_without_token=$(jq -r '.csrf_signals.forms_without_token_field' "$WORK/safe.json")
[ "$safe_forms_without_token" = "0" ] || { echo "FAIL: expected csrf_signals.forms_without_token_field=0, got $safe_forms_without_token"; FAILED=1; }

safe_samesite=$(jq -r '.csrf_signals.cookies[0].samesite' "$WORK/safe.json")
[ "$safe_samesite" = "Strict" ] || { echo "FAIL: expected cookie samesite=Strict, got $safe_samesite"; FAILED=1; }

safe_hsts=$(jq -r '.other_headers.hsts' "$WORK/safe.json")
safe_xcto=$(jq -r '.other_headers.x_content_type_options' "$WORK/safe.json")
[ "$safe_hsts" = "true" ] && [ "$safe_xcto" = "true" ] || { echo "FAIL: expected hsts=true and x_content_type_options=true, got hsts=$safe_hsts xcto=$safe_xcto"; FAILED=1; }

echo "--- checking --output flag writes the file and --auth-file is accepted ---"
echo '{"cookies": {}, "headers": {"X-Test": "1"}}' > "$WORK/auth.json" 2>/dev/null || true
# auth-capture.sh's own auth-file schema is exercised by its own test
# suite - here we're only confirming security-headers-check.sh accepts
# --auth-file without erroring when a well-formed (if minimal) file is
# given, not re-testing auth-capture.sh's header-conversion logic.
AUTH_CAPTURE="$REPO_ROOT/skills/web-auth-capture/scripts/auth-capture.sh"
if [ -f "$AUTH_CAPTURE" ]; then
    "$CHECK" --url "http://127.0.0.1:$PORT/safe" --auth-file "$WORK/auth.json" --output "$WORK/authed.json" 2>"$WORK/authed.err"
    if [ ! -s "$WORK/authed.json" ]; then
        echo "FAIL: --auth-file run produced no output"
        cat "$WORK/authed.err"
        FAILED=1
    fi
fi

exit $FAILED
