#!/bin/bash
#
# Fast, deterministic checks for the Codex CLI target
# (tools/generate-cli-targets.py's `codex` subcommand):
#
# 1. Drift check (no `codex` binary required): confirms the checked-in
#    .codex/ + tools/run-clicky-agent.sh actually match what the
#    generator produces from the current agents/*.md + commands/*.md.
#
# 2. TOML validity + structural assertions on every generated agent file
#    (model pin, inline mcp_servers struct shape, caller-convention
#    text present) - all via Python's stdlib `tomllib`, no live `codex`
#    calls, no API cost, no multi-minute waits.
#
# Deliberately does NOT re-run a live model dispatch here - unlike
# OpenCode's `opencode debug agent` (free, fast, no model call), Codex
# has no equivalent static-introspection command, and a real dispatch
# costs real API time/credits and can take minutes even when working
# correctly (confirmed during development: subagent spawns with a cold
# gateway venv took several minutes on first use). The full live
# verification - real model-pinning requirement discovery, real
# mcp_servers schema correction (array/boolean both rejected before the
# correct full-struct shape was found), a real adversarial shell-denial
# test through an actual spawned subagent, and a real end-to-end nmap
# scan against scanme.nmap.org with correct tokenized/redacted output -
# was done manually once against these exact generated artifacts and is
# recorded in tools/generate-cli-targets.py's Codex section doc comment
# and the multi-CLI portability plan. This test guards against
# regressions in the deterministic parts cheaply and often; it doesn't
# re-spend real model tokens re-proving the live behavior on every run.
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GENERATOR="$REPO_ROOT/tools/generate-cli-targets.py"

FAILED=0

echo "--- drift check: checked-in .codex/ + tools/run-clicky-agent.sh vs. a fresh generation ---"
if python3 "$GENERATOR" codex --check; then
    echo "PASS: generated Codex artifacts are up to date"
else
    FAILED=1
fi

echo
echo "--- TOML validity + structural checks on every generated agent ---"
python3 - "$REPO_ROOT" << 'PYEOF'
import sys
import tomllib
from pathlib import Path

repo_root = Path(sys.argv[1])
agents_dir = repo_root / ".codex" / "agents"
failed = False

toml_files = sorted(agents_dir.glob("*.toml"))
if not toml_files:
    print(f"FAIL: no .toml files found under {agents_dir}")
    sys.exit(1)

for path in toml_files:
    label = path.relative_to(repo_root)
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        print(f"FAIL: {label} is not valid TOML: {e}")
        failed = True
        continue
    print(f"PASS: {label} is valid TOML")

    required_keys = {"name", "description", "developer_instructions", "model", "mcp_servers"}
    missing = required_keys - set(data.keys())
    if missing:
        print(f"FAIL: {label} missing required key(s): {missing}")
        failed = True
    else:
        print(f"PASS: {label} has all required keys")

    # Confirmed live: the default model has an open upstream bug
    # (openai/codex#32101) that silently drops MCP tool exposure for
    # some models - every generated agent must stay pinned to the
    # confirmed-working one.
    if data.get("model") != "gpt-5.4":
        print(f"FAIL: {label} model is {data.get('model')!r}, expected 'gpt-5.4' (see generator's doc comment)")
        failed = True
    else:
        print(f"PASS: {label} model is pinned to the confirmed-working value")

    gw = data.get("mcp_servers", {}).get("clicky-gateway")
    if not isinstance(gw, dict):
        print(f"FAIL: {label} mcp_servers.clicky-gateway is not a struct (got {type(gw).__name__}) - confirmed live that Codex rejects array/boolean forms here")
        failed = True
    elif gw.get("command") != "clicky-gateway":
        # Must be the PATH-resolved launcher name, never a filesystem path.
        # Codex's own docs show `command = "npx"` and only suggest an
        # absolute path as a fallback "if Codex cannot find a command"; the
        # MCP spec's canonical example is the same. Naming it keeps this
        # checked-in file byte-identical on every machine - which is both a
        # privacy property (no contributor's home directory in git) and what
        # makes the drift check above able to pass off the generating
        # machine. See tests/cli_targets/test_no_leaked_paths.sh.
        print(f"FAIL: {label} mcp_servers.clicky-gateway.command is not the PATH-resolved 'clicky-gateway' name: {gw.get('command')!r}")
        failed = True
    elif "env" in gw:
        # CLAUDE_PLUGIN_ROOT used to be injected here as a literal absolute
        # path. launch.sh now derives it from its own resolved location, so
        # an env block reappearing means someone reintroduced a baked path.
        print(f"FAIL: {label} mcp_servers.clicky-gateway has an env block again ({gw['env']!r}) - launch.sh derives CLAUDE_PLUGIN_ROOT itself")
        failed = True
    else:
        print(f"PASS: {label} mcp_servers.clicky-gateway is a correctly-shaped inline struct with no baked path")

    agent_name = data.get("name", "")
    if f'caller="{agent_name}"' not in data.get("developer_instructions", ""):
        print(f"FAIL: {label} developer_instructions doesn't tell the agent to pass caller=\"{agent_name}\"")
        failed = True
    else:
        print(f"PASS: {label} developer_instructions includes the caller-attribution convention")

sys.exit(1 if failed else 0)
PYEOF
[ $? -eq 0 ] || FAILED=1

echo
echo "--- install.sh / run-clicky-agent.sh sanity ---"
if bash -n "$REPO_ROOT/.codex/install.sh"; then
    echo "PASS: .codex/install.sh passes bash -n"
else
    echo "FAIL: .codex/install.sh has a syntax error"
    FAILED=1
fi
if bash -n "$REPO_ROOT/tools/run-clicky-agent.sh"; then
    echo "PASS: tools/run-clicky-agent.sh passes bash -n"
else
    echo "FAIL: tools/run-clicky-agent.sh has a syntax error"
    FAILED=1
fi
if [ -x "$REPO_ROOT/.codex/install.sh" ] && [ -x "$REPO_ROOT/tools/run-clicky-agent.sh" ]; then
    echo "PASS: both generated scripts are executable"
else
    echo "FAIL: one or both generated scripts are missing the executable bit"
    FAILED=1
fi

if ! command -v codex >/dev/null 2>&1; then
    echo
    echo "SKIP: 'codex' binary not found - no live checks attempted."
    echo "(This suite only ever does static/structural checks against codex - see"
    echo "this file's header comment for why the live verification isn't re-run here.)"
fi

exit $FAILED
