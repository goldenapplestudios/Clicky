#!/bin/bash
#
# Two checks for the OpenCode target (tools/generate-cli-targets.py):
#
# 1. Drift check (always runs, no `opencode` binary required): confirms
#    the checked-in .opencode/ + opencode.json actually match what the
#    generator produces from the current agents/*.md + commands/*.md -
#    catches "edited an agent, forgot to regenerate" before it ships.
#
# 2. Live permission-resolution check (skipped with a clear message if
#    `opencode` isn't installed, doesn't fail the suite): runs the real
#    `opencode debug agent <name>` against the actual checked-in
#    generated agents and confirms every OpenCode built-in tool resolves
#    to denied and every intended gateway tool resolves to allowed. This
#    is a fast, free, deterministic regression check on the permission
#    logic - not a re-run of the full live-model adversarial dispatch
#    test (whoami-via-gateway-only, real nmap scan against
#    scanme.nmap.org) that was done manually once to validate the design
#    in the first place; that doesn't need to spend real model tokens on
#    every test invocation to keep being true, since this check would
#    catch a regression in the underlying permission resolution just as
#    reliably and for free.
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GENERATOR="$REPO_ROOT/tools/generate-cli-targets.py"

FAILED=0

echo "--- drift check: checked-in .opencode/ + opencode.json vs. a fresh generation ---"
if python3 "$GENERATOR" opencode --check; then
    echo "PASS: generated OpenCode artifacts are up to date"
else
    FAILED=1
fi

if ! command -v opencode >/dev/null 2>&1; then
    echo
    echo "SKIP: 'opencode' binary not found - live permission-resolution check skipped."
    echo "(Install via 'brew install opencode' or see opencode.ai to run this check.)"
    exit $FAILED
fi

echo
echo "--- live permission-resolution check (real opencode binary, real repo config) ---"

check_denied_and_allowed() {
    local agent="$1"
    local deny_check_list="$2"  # space-separated, e.g. "bash edit write task ..."
    shift 2
    local expected_allow=("$@")

    local resolved
    resolved=$(cd "$REPO_ROOT" && timeout 30 opencode debug agent "$agent" 2>&1)
    if [ -z "$resolved" ]; then
        echo "FAIL: $agent - 'opencode debug agent' produced no output"
        FAILED=1
        return
    fi

    # Every OpenCode built-in that's supposed to be denied must resolve
    # to `false` in the agent's "tools" map - the confirmed-necessary
    # explicit-deny requirement (see tools/generate-cli-targets.py's own
    # BUILTIN_DENY_LIST doc comment for how this was originally verified
    # live against opencode 1.1.59). Caller passes which builtins to
    # check here - the orchestrator deliberately allows task/todowrite
    # (checked separately below), so it isn't part of every call's list.
    local builtin all_denied
    all_denied=true
    for builtin in $deny_check_list; do
        local val
        val=$(echo "$resolved" | python3 -c "import json,sys; print(json.load(sys.stdin).get('tools',{}).get('$builtin'))" 2>/dev/null)
        if [ "$val" != "False" ]; then
            echo "FAIL: $agent - built-in tool '$builtin' resolved to $val, expected denied (False)"
            FAILED=1
            all_denied=false
        fi
    done
    $all_denied && echo "PASS: $agent - every OpenCode built-in tool resolves to denied"

    local tool ok
    ok=true
    for tool in "${expected_allow[@]}"; do
        if ! echo "$resolved" | python3 -c "
import json, sys
d = json.load(sys.stdin)
perm = d.get('permission', [])
found = any(p.get('permission') == '$tool' and p.get('action') == 'allow' for p in perm)
sys.exit(0 if found else 1)
" 2>/dev/null; then
            echo "FAIL: $agent - expected gateway tool '$tool' not resolved as allowed"
            FAILED=1
            ok=false
        fi
    done
    $ok && echo "PASS: $agent - expected gateway tool(s) resolve to allowed: ${expected_allow[*]}"
}

ALL_BUILTINS="bash edit write task webfetch todowrite websearch codesearch"
# Everything except task/todowrite - the orchestrator uniquely allows
# those two (checked explicitly below), every other builtin still must
# be denied for it same as every leaf agent.
ORCHESTRATOR_BUILTINS="bash edit write webfetch websearch codesearch"

check_denied_and_allowed "recon-agent" "$ALL_BUILTINS" \
    "clicky-gateway_register_target" "clicky-gateway_execute_command" \
    "clicky-gateway_fetch_url" "clicky-gateway_read_file" "clicky-gateway_search_files"

check_denied_and_allowed "verification-agent" "$ALL_BUILTINS" \
    "clicky-gateway_execute_command" "clicky-gateway_read_file" "clicky-gateway_search_files"

check_denied_and_allowed "pentest-orchestrator" "$ORCHESTRATOR_BUILTINS" \
    "clicky-gateway_create_session" "clicky-gateway_register_target" \
    "clicky-gateway_execute_command" "clicky-gateway_read_file" \
    "clicky-gateway_write_file" "clicky-gateway_search_files"

echo
echo "--- confirm the orchestrator, uniquely, has task+todowrite allowed (it dispatches the other 9) ---"
resolved=$(cd "$REPO_ROOT" && timeout 30 opencode debug agent pentest-orchestrator 2>&1)
task_val=$(echo "$resolved" | python3 -c "import json,sys; print(json.load(sys.stdin).get('tools',{}).get('task'))" 2>/dev/null)
todowrite_val=$(echo "$resolved" | python3 -c "import json,sys; print(json.load(sys.stdin).get('tools',{}).get('todowrite'))" 2>/dev/null)
if [ "$task_val" = "True" ] && [ "$todowrite_val" = "True" ]; then
    echo "PASS: pentest-orchestrator has task=True, todowrite=True (unlike every leaf agent)"
else
    echo "FAIL: pentest-orchestrator - expected task=True todowrite=True, got task=$task_val todowrite=$todowrite_val"
    FAILED=1
fi

echo
echo "--- confirm the real clicky-gateway MCP server actually connects from the repo root ---"
if cd "$REPO_ROOT" && timeout 30 opencode mcp list 2>&1 | grep -q "clicky-gateway.*connected"; then
    echo "PASS: clicky-gateway MCP server connects"
else
    echo "FAIL: clicky-gateway MCP server did not report as connected"
    FAILED=1
fi

exit $FAILED
