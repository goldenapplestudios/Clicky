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

echo "--- fourth run: self-heals a pip-less venv (the Kali python3.13-venv bug) ---"
# Regression test for a real, total outage. On Debian-family systems without
# the pythonX.Y-venv package, `python3 -m venv` lays down bin/python3,
# pyvenv.cfg, lib/ and include/ and only THEN fails at the ensurepip stage -
# leaving a directory that looks complete and has no pip in it.
#
# provision-venv.sh used to gate recreation on `[ ! -x venv/bin/python3 ]`,
# which classified that wreckage as healthy: it skipped creation, fell
# through to `venv/bin/pip install`, and died with exit 127. Nothing cleaned
# the poisoned directory up, so it recurred every session, permanently - and
# since all 8 Clicky agents are provisioned with the gateway's tools and
# nothing else, every agent dispatch got an agent with zero working tools.
#
# `--without-pip` reproduces that exact end state on ANY machine (including
# ones that do have ensurepip), so this test is portable.
rm -rf "$TEST_DATA_DIR/venv"
python3 -m venv --without-pip "$TEST_DATA_DIR/venv" >/dev/null 2>&1
check_true "poisoned venv fixture has bin/python3 but no pip (bug's precondition)" \
    "$([ -x "$TEST_DATA_DIR/venv/bin/python3" ] && ! "$TEST_DATA_DIR/venv/bin/python3" -m pip --version >/dev/null 2>&1 && echo 1 || echo 0)"

out4=$(CLAUDE_PLUGIN_DATA="$TEST_DATA_DIR" bash "$PROVISION" 2>&1)
status4=$?
echo "$out4"
check_true "fourth run exits 0 (self-healed rather than dying at 'bin/pip: No such file')" \
    "$([ "$status4" -eq 0 ] && echo 1 || echo 0)" "$out4"
check_true "fourth run reports rebuilding the unusable venv" \
    "$(echo "$out4" | grep -q 'unusable' && echo 1 || echo 0)" "$out4"
check_true "fourth run leaves a venv with a working pip" \
    "$("$TEST_DATA_DIR/venv/bin/python3" -m pip --version >/dev/null 2>&1 && echo 1 || echo 0)"
check_true "fourth run leaves mcp importable" \
    "$("$TEST_DATA_DIR/venv/bin/python3" -c 'import mcp' >/dev/null 2>&1 && echo 1 || echo 0)"
check_true "fourth run writes no PROVISION_FAILED.txt on a successful repair" \
    "$([ ! -f "$TEST_DATA_DIR/PROVISION_FAILED.txt" ] && echo 1 || echo 0)"
# The ensurepip advice the venv module prints goes to STDOUT, so a
# recovering run must not echo a multi-line "apt install pythonX.Y-venv"
# notice that reads like a crash.
check_true "fourth run does not leak ensurepip/apt-install noise on a successful repair" \
    "$(echo "$out4" | grep -q 'ensurepip is not available' && echo 0 || echo 1)" "$out4"

echo "--- fifth run: reinstalls when the lock is intact but deps are gone ---"
# An intact .requirements.lock records that an install once succeeded; it is
# not evidence the packages are still importable. Without a dependency check
# the "requirements unchanged" branch would happily skip the reinstall that
# would have fixed this and hand back a venv the gateway can't run in.
"$TEST_DATA_DIR/venv/bin/python3" -m pip uninstall -y mcp -q >/dev/null 2>&1
check_true "fixture: mcp really is uninstalled but the lock file survives" \
    "$(! "$TEST_DATA_DIR/venv/bin/python3" -c 'import mcp' >/dev/null 2>&1 && [ -f "$TEST_DATA_DIR/.requirements.lock" ] && echo 1 || echo 0)"

out5=$(CLAUDE_PLUGIN_DATA="$TEST_DATA_DIR" bash "$PROVISION" 2>&1)
status5=$?
echo "$out5"
check_true "fifth run exits 0" "$([ "$status5" -eq 0 ] && echo 1 || echo 0)" "$out5"
check_true "fifth run reinstalls rather than trusting the lock file" \
    "$(echo "$out5" | grep -q 'Installing requirements' && echo 1 || echo 0)" "$out5"
check_true "fifth run restores mcp" \
    "$("$TEST_DATA_DIR/venv/bin/python3" -c 'import mcp' >/dev/null 2>&1 && echo 1 || echo 0)"

echo "--- sixth run: unrecoverable failure is loud, not silent ---"
# provision-venv.sh's stderr is the MCP server's stderr, which no operator
# reads - Claude Code surfaces only "server failed to connect". So an
# unfixable failure must persist its remediation text somewhere findable.
FAIL_DATA_DIR=$(mktemp -d)
STUB_BIN=$(mktemp -d)
# Break the get-pip.py bootstrap. On a machine WITH ensurepip this stub is
# never reached and the run legitimately succeeds, so the assertions below
# are conditional on having actually provoked the failure.
printf '#!/bin/sh\nexit 1\n' > "$STUB_BIN/curl"
chmod +x "$STUB_BIN/curl"
out6=$(PATH="$STUB_BIN:$PATH" CLAUDE_PLUGIN_DATA="$FAIL_DATA_DIR" bash "$PROVISION" 2>&1)
status6=$?
if [ "$status6" -ne 0 ]; then
    check_true "unrecoverable run writes PROVISION_FAILED.txt where a human will find it" \
        "$([ -f "$FAIL_DATA_DIR/PROVISION_FAILED.txt" ] && echo 1 || echo 0)"
    check_true "the failure text names the actual remediation (pythonX.Y-venv)" \
        "$(grep -q 'venv' "$FAIL_DATA_DIR/PROVISION_FAILED.txt" 2>/dev/null && echo 1 || echo 0)"
    check_true "the failure text explains the restart requirement" \
        "$(grep -qi 'restart' "$FAIL_DATA_DIR/PROVISION_FAILED.txt" 2>/dev/null && echo 1 || echo 0)"
    check_true "the failure is also logged" \
        "$(grep -q 'FAILED' "$FAIL_DATA_DIR/provision.log" 2>/dev/null && echo 1 || echo 0)"
else
    echo "SKIP: this machine has a working ensurepip, so the bootstrap failure path wasn't reached"
fi
rm -rf "$FAIL_DATA_DIR" "$STUB_BIN"

# ---------------------------------------------------------------------------
# Lock behavior
#
# `release_lock` runs from a trap, and SIGKILL does not honour traps. A hard-
# killed session therefore used to leave `.provision.lock` behind, and because
# nothing checked the lock's age or owner, EVERY later run spun out the wait
# and then hard-exited 1. That bricked the gateway until a human deleted a
# directory - and since the gateway is what gives every Clicky agent its only
# tools, a bricked gateway is a bricked framework.
# ---------------------------------------------------------------------------
echo "--- lock: warm runs take no lock at all ---"
LOCK_DIR_T=$(mktemp -d)
CLAUDE_PLUGIN_DATA="$LOCK_DIR_T" bash "$PROVISION" >/dev/null 2>&1   # warm it
CLAUDE_PLUGIN_DATA="$LOCK_DIR_T" bash "$PROVISION" >/dev/null 2>&1   # the run under test
check_true "a fully-warm run logs the lock-free fast path" \
    "$(grep -q 'fast path' "$LOCK_DIR_T/provision.log" && echo 1 || echo 0)" \
    "log: $(tail -2 "$LOCK_DIR_T/provision.log" 2>/dev/null)"
check_true "the fast path leaves no lock directory behind" \
    "$([ ! -d "$LOCK_DIR_T/.provision.lock" ] && echo 1 || echo 0)"

echo "--- lock: a lock owned by a DEAD pid self-heals ---"
# Defeat the fast path so the run must actually contend for the lock.
rm -f "$LOCK_DIR_T/.requirements.lock"
mkdir -p "$LOCK_DIR_T/.provision.lock"
printf '999999\n%s\n' "$(hostname 2>/dev/null || uname -n)" > "$LOCK_DIR_T/.provision.lock/owner"
t0=$(date +%s)
CLAUDE_PLUGIN_DATA="$LOCK_DIR_T" timeout 120 bash "$PROVISION" >/dev/null 2>&1
dead_status=$?
dead_elapsed=$(( $(date +%s) - t0 ))
check_true "a dead-owner lock is reclaimed rather than waited out" \
    "$([ "$dead_status" -eq 0 ] && [ "$dead_elapsed" -lt 30 ] && echo 1 || echo 0)" \
    "exit=$dead_status elapsed=${dead_elapsed}s (pre-fix: ~90s then exit 1)"
check_true "the reclaim is recorded in the log" \
    "$(grep -q 'reclaimed stale provisioning lock' "$LOCK_DIR_T/provision.log" && echo 1 || echo 0)"

echo "--- lock: a lock with no owner file self-heals on age ---"
rm -f "$LOCK_DIR_T/.requirements.lock"
mkdir -p "$LOCK_DIR_T/.provision.lock"          # no owner file at all
touch -d '2 hours ago' "$LOCK_DIR_T/.provision.lock" 2>/dev/null \
    || touch -A -020000 "$LOCK_DIR_T/.provision.lock" 2>/dev/null || true
t0=$(date +%s)
CLAUDE_PLUGIN_DATA="$LOCK_DIR_T" timeout 120 bash "$PROVISION" >/dev/null 2>&1
age_status=$?
age_elapsed=$(( $(date +%s) - t0 ))
check_true "an old ownerless lock is reclaimed on age" \
    "$([ "$age_status" -eq 0 ] && [ "$age_elapsed" -lt 30 ] && echo 1 || echo 0)" \
    "exit=$age_status elapsed=${age_elapsed}s"

echo "--- lock: a LIVE lock is still respected (must not be stolen) ---"
# The inverse of the two above, and the one that matters most: self-healing
# must never let two processes build the same venv concurrently.
rm -f "$LOCK_DIR_T/.requirements.lock"
sleep 30 &
HOLDER_PID=$!
mkdir -p "$LOCK_DIR_T/.provision.lock"
printf '%s\n%s\n' "$HOLDER_PID" "$(hostname 2>/dev/null || uname -n)" > "$LOCK_DIR_T/.provision.lock/owner"
steals_before=$(grep -c 'reclaimed stale' "$LOCK_DIR_T/provision.log" 2>/dev/null || echo 0)
CLAUDE_PLUGIN_DATA="$LOCK_DIR_T" timeout 8 bash "$PROVISION" >/dev/null 2>&1
live_status=$?
steals_after=$(grep -c 'reclaimed stale' "$LOCK_DIR_T/provision.log" 2>/dev/null || echo 0)
check_true "a live-owner lock is waited on, not stolen" \
    "$([ "$live_status" -eq 124 ] && [ "$steals_before" -eq "$steals_after" ] && echo 1 || echo 0)" \
    "exit=$live_status (124=still waiting, correct) steals ${steals_before}->${steals_after}"
kill "$HOLDER_PID" 2>/dev/null || true
rm -rf "$LOCK_DIR_T"

exit $FAILED
