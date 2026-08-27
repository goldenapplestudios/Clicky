#!/bin/bash
#
# Fast, deterministic checks for the Copilot CLI target
# (tools/generate-cli-targets.py's `copilot` subcommand):
#
# 1. Drift check (no `copilot` binary required): confirms the checked-in
#    .github/agents/ + tools/run-clicky-copilot-agent.sh + the
#    .claude/skills symlink actually match what the generator produces
#    from the current agents/*.md + commands/pentest.md.
#
# 2. Structural assertions on every generated agent's YAML frontmatter
#    (tools: allowlist present and scoped to clicky-gateway, the
#    embedded mcp-servers.clicky-gateway struct has the fields confirmed
#    required by a real schema-validation error - `args`, `tools` -
#    caller= convention present in the body) - via Python's stdlib
#    (no PyYAML dependency added just for this test; the frontmatter
#    shape this generator emits is simple enough for a line-based
#    check, matching this repo's existing no-extra-deps discipline).
#
# Deliberately does NOT re-run a live model dispatch here - same
# reasoning as test_codex_generation.sh: a real dispatch costs real API
# time and credits. The full live verification - the workspace
# .mcp.json bug (github/copilot-cli#3126) that motivated embedding
# mcp-servers per-agent instead, the real required `args`/`tools`
# schema fields (each caught by an actual Copilot CLI validation error),
# a real adversarial shell-denial test through the actual --agent flag,
# and a real orchestrator-to-leaf delegation via the `task` tool - was
# done manually once against these exact generated artifacts and is
# recorded in tools/generate-cli-targets.py's Copilot section doc
# comment and the multi-CLI portability plan's Phase 3 section.
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GENERATOR="$REPO_ROOT/tools/generate-cli-targets.py"

FAILED=0

echo "--- drift check: checked-in .github/agents/ + wrapper + .claude/skills symlink vs. a fresh generation ---"
if python3 "$GENERATOR" copilot --check; then
    echo "PASS: generated Copilot artifacts are up to date"
else
    FAILED=1
fi

echo
echo "--- structural checks on every generated agent ---"
python3 - "$REPO_ROOT" << 'PYEOF'
import re
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
agents_dir = repo_root / ".github" / "agents"
failed = False

md_files = sorted(agents_dir.glob("*.md"))
if not md_files:
    print(f"FAIL: no .md files found under {agents_dir}")
    sys.exit(1)

for path in md_files:
    label = path.relative_to(repo_root)
    text = path.read_text()

    m = re.search(r"\n---\n(.*?)\n---\n", "\n" + text, re.DOTALL)
    if not m:
        print(f"FAIL: {label} has no frontmatter block")
        failed = True
        continue
    fm = m.group(1)
    print(f"PASS: {label} has a frontmatter block")

    if "description:" not in fm:
        print(f"FAIL: {label} missing required 'description' field")
        failed = True
    else:
        print(f"PASS: {label} has a description")

    # Confirmed live: `tools:` defaults to ALL tools if omitted entirely
    # - every generated agent must set it explicitly.
    if "tools:" not in fm:
        print(f"FAIL: {label} has no explicit tools: allowlist (defaults to ALL tools if omitted - confirmed live)")
        failed = True
    elif "clicky-gateway" not in fm.split("tools:")[1].split("\n")[0]:
        print(f"FAIL: {label} tools: doesn't reference clicky-gateway")
        failed = True
    else:
        print(f"PASS: {label} tools: allowlist references clicky-gateway")

    # `args` and `tools` are required on the embedded
    # mcp-servers.clicky-gateway struct - each caught by a real Copilot CLI
    # schema-validation error (see this file's header).
    #
    # `env.CLAUDE_PLUGIN_ROOT` was previously asserted here too, but it was
    # never a Copilot schema requirement - it was a Clicky-internal one, and
    # the only reason the generator had to embed an absolute repo path in
    # every checked-in agent file. launch.sh now resolves its own symlink to
    # derive the repo root and exports CLAUDE_PLUGIN_ROOT itself, so no host
    # config supplies it, and these artifacts carry no machine-specific path
    # at all. See tests/cli_targets/test_no_leaked_paths.sh.
    if "mcp-servers:" not in fm:
        print(f"FAIL: {label} has no embedded mcp-servers block (workspace .mcp.json is confirmed broken - github/copilot-cli#3126 - this must be embedded per-agent)")
        failed = True
    else:
        mcp_block = fm.split("mcp-servers:")[1]
        missing = []
        if "args:" not in mcp_block:
            missing.append("args")
        if "tools:" not in mcp_block:
            missing.append("tools (server-level)")
        if "command:" not in mcp_block:
            missing.append("command")
        if missing:
            print(f"FAIL: {label} mcp-servers.clicky-gateway missing schema-required field(s): {missing}")
            failed = True
        else:
            print(f"PASS: {label} mcp-servers.clicky-gateway has all schema-required fields")

        # The command must be the PATH-resolved launcher name, never a
        # filesystem path - the convention every MCP client documents.
        if "clicky-gateway" not in mcp_block.split("command:")[1].split("\n")[0]:
            print(f"FAIL: {label} command is not the PATH-resolved 'clicky-gateway' name")
            failed = True
        elif "launch.sh" in mcp_block or "/Users/" in mcp_block or "/home/" in mcp_block:
            print(f"FAIL: {label} embeds a filesystem path in its mcp-servers block")
            failed = True
        else:
            print(f"PASS: {label} registers the gateway by PATH-resolved name, no filesystem path")

    agent_name_match = re.search(r"You are ([\w-]+)\.", text)
    if agent_name_match:
        agent_name = agent_name_match.group(1)
        if f'caller="{agent_name}"' not in text:
            print(f"FAIL: {label} body doesn't tell the agent to pass caller=\"{agent_name}\"")
            failed = True
        else:
            print(f"PASS: {label} body includes the caller-attribution convention")

sys.exit(1 if failed else 0)
PYEOF
[ $? -eq 0 ] || FAILED=1

echo
echo "--- .claude/skills symlink and wrapper script sanity ---"
if [ -L "$REPO_ROOT/.claude/skills" ] && [ "$(readlink "$REPO_ROOT/.claude/skills")" = "../skills" ]; then
    echo "PASS: .claude/skills -> ../skills symlink is correct (confirmed live: this is how Copilot CLI discovers all 27 real skills)"
else
    echo "FAIL: .claude/skills is missing or not the expected symlink"
    FAILED=1
fi
if bash -n "$REPO_ROOT/tools/run-clicky-copilot-agent.sh"; then
    echo "PASS: tools/run-clicky-copilot-agent.sh passes bash -n"
else
    echo "FAIL: tools/run-clicky-copilot-agent.sh has a syntax error"
    FAILED=1
fi
if [ -x "$REPO_ROOT/tools/run-clicky-copilot-agent.sh" ]; then
    echo "PASS: tools/run-clicky-copilot-agent.sh is executable"
else
    echo "FAIL: tools/run-clicky-copilot-agent.sh is missing the executable bit"
    FAILED=1
fi

if ! command -v copilot >/dev/null 2>&1; then
    echo
    echo "SKIP: 'copilot' binary not found - no live checks attempted."
    echo "(This suite only ever does static/structural checks - see this file's"
    echo "header comment for why the live verification isn't re-run here.)"
fi

exit $FAILED
