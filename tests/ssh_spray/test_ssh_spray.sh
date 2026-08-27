#!/bin/bash
#
# End-to-end tests for tools/ssh-spray.py against a REAL SSH server.
#
# ssh_test_server.py speaks the actual SSH-2 protocol - real key exchange, real
# host key, real password authentication - so these assertions exercise the
# sprayer the same way a live engagement would. Nothing about the SSH client
# library is stubbed.
#
# The behavior under test is the one that matters operationally: telling
# "tested and wrong" apart from "never tested". OpenSSH's MaxStartups drops
# connections under load, and a connection dropped before the banner never
# reaches authentication. Scoring those as failed logins reports a clean
# negative for credentials that were never tried - which is exactly how a real
# spray in this repo's own history produced 1,617 meaningless "misses".
#
# Exit contract under test:
#   0 = a valid credential was found
#   1 = every candidate was genuinely tested, none valid (a clean negative)
#   2 = something was left UNTESTED (NOT a clean negative)
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
SPRAY="$REPO_ROOT/tools/ssh-spray.py"
SERVER="$HERE/ssh_test_server.py"

PY="python3"
if ! $PY -c "import paramiko" 2>/dev/null; then
    for cand in "$HOME/.claude/plugins/data/clicky-clicky/venv/bin/python3" \
                "${TMPDIR:-/tmp}/clicky-mcp-gateway-test-venv-data/venv/bin/python3"; do
        [ -x "$cand" ] && "$cand" -c "import paramiko" 2>/dev/null && { PY="$cand"; break; }
    done
fi
$PY -c "import paramiko" 2>/dev/null || { echo "SKIP: paramiko not available"; exit 0; }

FAILED=0
check() { if [ "$2" -eq 0 ]; then echo "PASS: $1"; else echo "FAIL: $1 ${3:-}"; FAILED=1; fi; }

WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() { [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

USER_OK="reactor"
PASS_OK="Reactor123"

start_server() {  # start_server [extra args...]
    [ -n "$SERVER_PID" ] && { kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; }
    "$PY" "$SERVER" --user "$USER_OK" --password "$PASS_OK" --port 0 "$@" > "$WORK/server.out" 2>"$WORK/server.err" &
    SERVER_PID=$!
    PORT=""
    for _ in $(seq 1 60); do
        PORT="$(awk '/^READY/{print $2; exit}' "$WORK/server.out" 2>/dev/null)"
        [ -n "$PORT" ] && break
        kill -0 "$SERVER_PID" 2>/dev/null || break
        sleep 0.2
    done
    [ -n "$PORT" ]
}

printf '%s\n' "$USER_OK" admin root > "$WORK/users.txt"
printf '%s\n' wrong1 "$PASS_OK" wrong2 > "$WORK/pass.txt"
printf '%s\n' nope1 nope2 > "$WORK/nomatch.txt"

# ---------------------------------------------------------- 1. real success
start_server; check "real SSH server started" $?
"$PY" "$SPRAY" -t 127.0.0.1 -p "$PORT" -U "$WORK/users.txt" -W "$WORK/pass.txt" \
    --rate 50 --threads 4 --out "$WORK/r1.json" > "$WORK/r1.log" 2>&1
rc=$?
[ "$rc" -eq 0 ]; check "finds a valid credential against a real SSH daemon (exit 0)" $? "exit $rc"
grep -q "\"username\": \"$USER_OK\"" "$WORK/r1.json"
check "reports the correct username" $?
grep -q "\"password\": \"$PASS_OK\"" "$WORK/r1.json"
check "reports the correct password" $?
[ "$(jq -r '.untested | length' "$WORK/r1.json")" -eq 0 ]
check "no candidate left untested on a healthy server" $?

# ------------------------------------------------- 2. genuine clean negative
"$PY" "$SPRAY" -t 127.0.0.1 -p "$PORT" -U "$WORK/users.txt" -W "$WORK/nomatch.txt" \
    --rate 50 --threads 4 --out "$WORK/r2.json" > "$WORK/r2.log" 2>&1
rc=$?
[ "$rc" -eq 1 ]; check "clean negative exits 1 (all tested, none valid)" $? "exit $rc"
[ "$(jq -r '.tested' "$WORK/r2.json")" -eq 6 ]
check "all 6 candidates actually reached authentication" $? "tested=$(jq -r .tested "$WORK/r2.json")"
[ "$(jq -r '.untested | length' "$WORK/r2.json")" -eq 0 ]
check "clean negative reports zero untested" $?

# ------------------------------- 3. throttling is NOT reported as a negative
# Server drops every connection pre-banner; nothing can ever be tested.
start_server --throttle-every 1; check "throttling server started" $?
"$PY" "$SPRAY" -t 127.0.0.1 -p "$PORT" -u "$USER_OK" -P "$PASS_OK" \
    --rate 50 --max-retries 1 --threads 2 --out "$WORK/r3.json" > "$WORK/r3.log" 2>&1
rc=$?
[ "$rc" -eq 2 ]; check "fully throttled run exits 2, NOT 1" $? "exit $rc"
[ "$(jq -r '.tested' "$WORK/r3.json")" -eq 0 ]
check "throttled attempts are counted as tested=0" $? "tested=$(jq -r .tested "$WORK/r3.json")"
[ "$(jq -r '.untested | length' "$WORK/r3.json")" -ge 1 ]
check "throttled attempts are classified UNTESTED" $?
grep -q "NOT a clean negative" "$WORK/r3.log"
check "operator is warned the result is not a clean negative" $?
[ "$(jq -r '.valid | length' "$WORK/r3.json")" -eq 0 ]
check "no credential is claimed from a throttled run" $?

# ------------------ 4. a valid credential survives intermittent throttling
# This is the case the original throwaway script got wrong: the correct
# password was in the list, but its connection was dropped pre-banner and
# scored as a miss. With retries it must still be found.
start_server --throttle-first 6; check "intermittently-throttling server started" $?
"$PY" "$SPRAY" -t 127.0.0.1 -p "$PORT" -u "$USER_OK" -P "$PASS_OK" \
    --rate 20 --max-retries 6 --threads 1 --out "$WORK/r4.json" > "$WORK/r4.log" 2>&1
rc=$?
[ "$rc" -eq 0 ]; check "valid credential is STILL found through throttling (exit 0)" $? "exit $rc"
[ "$(jq -r '.throttle_events' "$WORK/r4.json")" -ge 1 ]
check "throttle events were actually observed and recorded" $?
[ "$(jq -r '.untested | length' "$WORK/r4.json")" -eq 0 ]
check "retries left nothing untested" $?

exit $FAILED
