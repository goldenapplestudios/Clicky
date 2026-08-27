#!/bin/bash
#
# Runs every test in this directory. Single entry point for
# skills/mcp-gateway's test suite, matching the style of tests/run_all.sh
# (see tests/README.md) without editing that file - Phase 1 keeps this
# suite self-contained under tests/mcp_gateway/; wiring it into
# tests/run_all.sh is left for whichever later phase actually wires the
# gateway into the rest of the plugin.
#
# Note: test_provision_venv.sh and test_server_tools.sh do a real `pip
# install` on a cold cache, so a first run of this script is slow
# (dominated by network install time); subsequent runs are fast (both
# scripts cache their provisioned venvs outside the repo).
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAILED=0

run() {
    local label="$1"
    shift
    echo "=== $label ==="
    if "$@"; then
        echo "PASS"
    else
        echo "FAIL"
        FAILED=1
    fi
    echo
}

run "token_store.py unit tests" python3 "$HERE/test_token_store.py"
run "scope_gate.py fixture tests" "$HERE/test_scope_gate.sh"
run "provision-venv.sh (real venv creation + reinstall-skip)" "$HERE/test_provision_venv.sh"
run "launch.sh (real provisioning via the launch wrapper, concurrent-call safety)" "$HERE/test_launch.sh"
run "toolchain-path.sh (stubbed nix: cache hit/miss, GC-invalidation, key singularity)" "$HERE/test_toolchain_path.sh"
run "server.py live MCP protocol check (real subprocess, real stdio)" "$HERE/test_server_tools.sh"

exit $FAILED
