#!/bin/bash
#
# Test for skills/mcp-gateway/server.py: provisions a real venv (via the
# real scripts/provision-venv.sh - this doubles as further exercise of
# that script beyond test_provision_venv.sh), then runs live_server_check.py
# and test_scope_enforcement_modes.py through that venv's python, each of
# which launches server.py as an actual subprocess and drives it over real
# MCP stdio JSON-RPC (a real `initialize`, a real `tools/list`, and real
# `tools/call` for all 7 tools including a real `create_session` bootstrap
# call, explicit `session_dir` threading through every other tool with no
# SESSION_DIR env var or pointer file involved, a real elicitation round
# trip, and confirmation that every session-scoped tool fails loudly on a
# missing/invalid session_dir, plus a real per-mode check of the
# scope_enforcement enforce/warn/off switch, plus execute_command's timeout
# behavior: partial output preserved and the whole process group killed) -
# not a description of expected behavior, an actual client/server exchange.
#
# Uses a cache directory outside the repo (like a real CLAUDE_PLUGIN_DATA
# would be) so repeated test runs don't re-pay the pip install cost every
# time - the whole point of provision-venv.sh's diff-and-skip behavior,
# which test_provision_venv.sh verifies in isolation.
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROVISION="$REPO_ROOT/skills/mcp-gateway/scripts/provision-venv.sh"
SERVER="$REPO_ROOT/skills/mcp-gateway/server.py"
LIVE_CHECK="$(dirname "${BASH_SOURCE[0]}")/live_server_check.py"
SCOPE_MODES_CHECK="$(dirname "${BASH_SOURCE[0]}")/test_scope_enforcement_modes.py"
TIMEOUT_CHECK="$(dirname "${BASH_SOURCE[0]}")/test_command_timeout.py"
GATE_CHECK="$(dirname "${BASH_SOURCE[0]}")/test_technique_gate.py"
LAZY_CHECK="$(dirname "${BASH_SOURCE[0]}")/test_toolchain_lazy.py"

command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 not installed"; exit 0; }

TEST_DATA_DIR="${TMPDIR:-/tmp}/clicky-mcp-gateway-test-venv-data"

echo "--- provisioning venv for the live server check (cached at $TEST_DATA_DIR) ---"
VENV_DIR=$(CLAUDE_PLUGIN_DATA="$TEST_DATA_DIR" bash "$PROVISION" | tail -1)

if [ ! -x "$VENV_DIR/bin/python3" ]; then
    echo "FAIL: provision-venv.sh did not produce a usable venv at $VENV_DIR"
    exit 1
fi
echo "Using venv: $VENV_DIR"

echo "--- running live_server_check.py (real subprocess, real MCP stdio protocol) ---"
"$VENV_DIR/bin/python3" "$LIVE_CHECK" "$SERVER"
LIVE_CHECK_STATUS=$?

echo "--- running test_scope_enforcement_modes.py (real subprocess, enforce/warn/off) ---"
"$VENV_DIR/bin/python3" "$SCOPE_MODES_CHECK" "$SERVER"
SCOPE_MODES_STATUS=$?

echo "--- running test_command_timeout.py (partial-output preservation + process-group kill) ---"
"$VENV_DIR/bin/python3" "$TIMEOUT_CHECK" "$SERVER"
TIMEOUT_STATUS=$?

echo "--- running test_technique_gate.py (credential-attack preconditions enforced at execution) ---"
"$VENV_DIR/bin/python3" "$GATE_CHECK" "$SERVER"
GATE_STATUS=$?

echo "--- running test_toolchain_lazy.py (toolchain resolved lazily, never at startup) ---"
"$VENV_DIR/bin/python3" "$LAZY_CHECK" "$SERVER"
LAZY_STATUS=$?

[ $LIVE_CHECK_STATUS -eq 0 ] && [ $SCOPE_MODES_STATUS -eq 0 ] && [ $TIMEOUT_STATUS -eq 0 ] \
    && [ $GATE_STATUS -eq 0 ] && [ $LAZY_STATUS -eq 0 ]
exit $?
