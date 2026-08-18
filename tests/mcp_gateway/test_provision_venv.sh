#!/bin/bash
#
# Test for skills/mcp-gateway/scripts/provision-venv.sh: confirms it
# actually creates a venv, actually installs `mcp` into it (real network
# pip install, not mocked - this test is slow on first run, that's
# expected), and actually skips reinstalling on a second run when
# requirements.txt hasn't changed - verified both by the log it writes and
# by timing (the second run must be dramatically faster than the first,
# since it does no pip work at all).
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
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
trap 'rm -rf "$TEST_DATA_DIR"' EXIT

echo "--- first run (expect: create venv + install requirements) ---"
start1=$(date +%s)
out1=$(CLAUDE_PLUGIN_DATA="$TEST_DATA_DIR" bash "$PROVISION")
status1=$?
end1=$(date +%s)
elapsed1=$((end1 - start1))
echo "$out1"
echo "(first run took ${elapsed1}s)"

check_true "first run exits 0" "$([ "$status1" -eq 0 ] && echo 1 || echo 0)"
check_true "first run created the venv directory" "$([ -x "$TEST_DATA_DIR/venv/bin/python3" ] && echo 1 || echo 0)"
check_true "first run wrote the requirements lock cache" "$([ -f "$TEST_DATA_DIR/.requirements.lock" ] && echo 1 || echo 0)"
check_true "first run's log records venv creation" \
    "$(grep -q 'created venv' "$TEST_DATA_DIR/provision.log" 2>/dev/null && echo 1 || echo 0)"
check_true "first run's log records an install" \
    "$(grep -q 'installed requirements' "$TEST_DATA_DIR/provision.log" 2>/dev/null && echo 1 || echo 0)"

echo "--- confirm mcp actually imports in the provisioned venv ---"
import_out=$("$TEST_DATA_DIR/venv/bin/python3" -c "import mcp; print('OK')" 2>&1)
check_true "mcp imports successfully in the provisioned venv" \
    "$([ "$import_out" = "OK" ] && echo 1 || echo 0)" "$import_out"

echo "--- second run (expect: skip reinstall, requirements.txt unchanged) ---"
start2=$(date +%s)
out2=$(CLAUDE_PLUGIN_DATA="$TEST_DATA_DIR" bash "$PROVISION")
status2=$?
end2=$(date +%s)
elapsed2=$((end2 - start2))
echo "$out2"
echo "(second run took ${elapsed2}s)"

check_true "second run exits 0" "$([ "$status2" -eq 0 ] && echo 1 || echo 0)"
check_true "second run's stdout says it skipped reinstall" \
    "$(echo "$out2" | grep -q 'skipping reinstall' && echo 1 || echo 0)" "$out2"
check_true "second run's log records the skip" \
    "$(grep -q 'skipped reinstall' "$TEST_DATA_DIR/provision.log" 2>/dev/null && echo 1 || echo 0)"
# The real proof it didn't redo the pip install: the second run has to be
# drastically faster than the first (which does a real network install).
# 10s is a generous ceiling for "create a venv dir, cmp two small files,
# write a log line" with zero network/pip work.
check_true "second run is much faster than the first (no reinstall happened)" \
    "$([ "$elapsed2" -le 10 ] && echo 1 || echo 0)" "first=${elapsed1}s second=${elapsed2}s"

echo "--- third run after touching requirements.txt content (simulated) ---"
# Don't mutate the real requirements.txt - point CLAUDE_PLUGIN_DATA-relative
# REQUIREMENTS resolution can't be redirected without a second copy of the
# script tree, so instead directly falsify the cached copy to simulate
# "requirements.txt changed since last install" without touching the repo's
# actual requirements.txt.
echo "mcp==999.999.999  # deliberately falsified for this test" > "$TEST_DATA_DIR/.requirements.lock"
out3=$(CLAUDE_PLUGIN_DATA="$TEST_DATA_DIR" bash "$PROVISION")
status3=$?
echo "$out3"
check_true "third run exits 0" "$([ "$status3" -eq 0 ] && echo 1 || echo 0)"
check_true "third run reinstalls when the cached requirements differ from the real file" \
    "$(echo "$out3" | grep -q 'Installing requirements' && echo 1 || echo 0)" "$out3"
check_true "third run's log records another install" \
    "$(grep -c 'installed requirements' "$TEST_DATA_DIR/provision.log" | grep -q '^2$' && echo 1 || echo 0)"

exit $FAILED
