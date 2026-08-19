#!/bin/bash
#
# Test for skills/mcp-gateway/scripts/launch.sh: confirms it actually
# provisions the venv (real, not mocked) when called standalone with a
# cold CLAUDE_PLUGIN_DATA, that the provisioning it triggers is the exact
# same provision-venv.sh a SessionStart hook would run (so a second call
# after that hook already ran is a fast no-op, per
# test_provision_venv.sh's own second-run timing check), that
# provision-venv.sh's own stdout never reaches true fd 1 under the exact
# redirection launch.sh applies (it must stay clean for the MCP stdio
# JSON-RPC channel once server.py is exec'd), and that two concurrent
# provisioning calls against the same data dir (the SessionStart hook and
# launch.sh racing each other, or two launch.sh invocations) don't
# corrupt the venv.
#
# launch.sh ends in `exec ... server.py`, so a full standalone run would
# hang waiting on stdin for an MCP client that never connects. This test
# exercises the provisioning half directly (the same call launch.sh
# itself makes, with the same redirection) and confirms launch.sh's own
# script logic (path resolution, stdout redirection) is correct without
# needing a real MCP handshake - tests/mcp_gateway/test_server_tools.sh
# already covers server.py's real MCP behavior once launched directly.
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAUNCH="$REPO_ROOT/skills/mcp-gateway/scripts/launch.sh"
PROVISION="$REPO_ROOT/skills/mcp-gateway/scripts/provision-venv.sh"

command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 not installed"; exit 0; }

FAILED=0
check_true() {
    local label="$1" condition="$2" detail="${3:-}"
    if [ "$condition" = "1" ]; then
        echo "PASS: $label"
    else
        echo "FAIL: $label${detail:+ - $detail}"
        FAILED=1
    fi
}

TEST_DATA_DIR=$(mktemp -d)
STDERR_CAPTURE=$(mktemp)
trap 'rm -rf "$TEST_DATA_DIR" "$STDERR_CAPTURE"' EXIT

echo "--- launch.sh syntax and shape ---"
bash -n "$LAUNCH"
check_true "launch.sh passes bash -n" "$([ $? -eq 0 ] && echo 1 || echo 0)"
check_true "launch.sh has the executable bit set" "$([ -x "$LAUNCH" ] && echo 1 || echo 0)"
grep -q 'provision-venv.sh" 1>&2' "$LAUNCH"
check_true "launch.sh's source invokes provision-venv.sh with stdout redirected to stderr" \
    "$([ $? -eq 0 ] && echo 1 || echo 0)"
grep -q 'exec ' "$LAUNCH"
check_true "launch.sh's source execs the interpreter (doesn't just run it as a subprocess)" \
    "$([ $? -eq 0 ] && echo 1 || echo 0)"

echo "--- cold provisioning, exactly as launch.sh triggers it (stdout redirected to stderr) ---"
start1=$(date +%s)
stdout1=$( { CLAUDE_PLUGIN_DATA="$TEST_DATA_DIR" bash "$PROVISION" 1>&2; } 2>"$STDERR_CAPTURE" )
status1=$?
end1=$(date +%s)
check_true "cold provisioning (as launch.sh would trigger it) exits 0" \
    "$([ "$status1" -eq 0 ] && echo 1 || echo 0)"
check_true "cold provisioning creates the venv launch.sh will exec into" \
    "$([ -x "$TEST_DATA_DIR/venv/bin/python" ] && echo 1 || echo 0)"
check_true "true fd 1 receives nothing under launch.sh's redirection (stdout landed on stderr instead)" \
    "$([ -z "$stdout1" ] && echo 1 || echo 0)" "got on fd1: $stdout1"
check_true "provisioning's progress output actually did land on stderr (not silently dropped)" \
    "$(grep -q 'Creating venv' "$STDERR_CAPTURE" && echo 1 || echo 0)" "$(cat "$STDERR_CAPTURE")"
echo "(cold provisioning took $((end1 - start1))s)"

echo "--- confirm the venv launch.sh would exec is actually runnable ---"
import_out=$("$TEST_DATA_DIR/venv/bin/python" -c "import mcp; print('OK')" 2>&1)
check_true "mcp imports successfully in the venv launch.sh would exec into" \
    "$([ "$import_out" = "OK" ] && echo 1 || echo 0)" "$import_out"

echo "--- second call (as if launch.sh ran again, or raced the SessionStart hook) is fast ---"
start2=$(date +%s)
out2=$(CLAUDE_PLUGIN_DATA="$TEST_DATA_DIR" bash "$PROVISION" 2>&1)
status2=$?
end2=$(date +%s)
elapsed2=$((end2 - start2))
check_true "second (redundant) provisioning call exits 0" "$([ "$status2" -eq 0 ] && echo 1 || echo 0)"
check_true "second (redundant) provisioning call skips reinstall" \
    "$(echo "$out2" | grep -q 'skipping reinstall' && echo 1 || echo 0)" "$out2"
check_true "second (redundant) provisioning call is fast (no reinstall work)" \
    "$([ "$elapsed2" -le 10 ] && echo 1 || echo 0)" "elapsed=${elapsed2}s"

echo "--- concurrent invocations don't corrupt the venv (lock serializes them) ---"
CONCURRENT_DIR=$(mktemp -d)
c1_out=$(mktemp)
c2_out=$(mktemp)
CLAUDE_PLUGIN_DATA="$CONCURRENT_DIR" bash "$PROVISION" >"$c1_out" 2>&1 &
pid1=$!
CLAUDE_PLUGIN_DATA="$CONCURRENT_DIR" bash "$PROVISION" >"$c2_out" 2>&1 &
pid2=$!
wait "$pid1"; status_c1=$?
wait "$pid2"; status_c2=$?
check_true "both concurrent provisioning calls exit 0" \
    "$([ "$status_c1" -eq 0 ] && [ "$status_c2" -eq 0 ] && echo 1 || echo 0)" \
    "c1=$status_c1 c2=$status_c2 / c1 out: $(cat "$c1_out") / c2 out: $(cat "$c2_out")"
check_true "concurrent provisioning still leaves a working venv" \
    "$([ -x "$CONCURRENT_DIR/venv/bin/python" ] && "$CONCURRENT_DIR/venv/bin/python" -c 'import mcp' 2>/dev/null && echo 1 || echo 0)"
rm -f "$c1_out" "$c2_out"
rm -rf "$CONCURRENT_DIR"

exit $FAILED
