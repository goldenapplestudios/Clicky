#!/bin/bash
#
# Launch wrapper for skills/mcp-gateway/server.py - what
# .claude-plugin/plugin.json's mcpServers.clicky-gateway.command actually
# points at (instead of the venv's python directly).
#
# Why this exists: SessionStart hooks and mcpServers process launch are
# NOT ordered relative to each other in Claude Code. Confirmed empirically
# in a real Claude Code 2.1.233 session (2026-08-15, --plugin-dir load of
# this repo): the MCP server connection attempt for clicky-gateway fired
# and failed with ENOENT (posix_spawn on
# ${CLAUDE_PLUGIN_DATA}/venv/bin/python, which didn't exist yet) about 12
# seconds *before* the SessionStart hook's own call to provision-venv.sh
# finished creating that same venv - and Claude Code did not retry the
# connection afterwards, so the server stayed broken for the rest of the
# session. Pointing mcpServers.clicky-gateway.command at the venv python
# directly and hoping the SessionStart hook has already run is therefore
# not safe on a cold plugin-data directory (i.e. every first session, and
# any session after requirements.txt changes).
#
# This wrapper removes the ordering dependency entirely: it provisions
# synchronously (calling the exact same provision-venv.sh the SessionStart
# hook calls - idempotent and lock-protected, see that script's header, so
# a redundant call here after the hook already did the work is a fast
# no-op, and a call that races the hook's own call is serialized rather
# than racing) and only then execs the real interpreter. Whichever caller
# (this script or the SessionStart hook) gets there first does the actual
# work; the other just confirms it's done.
#
# Two more things this file does now, both new (see the Kalilix +
# multi-CLI-config-wizard plan):
#
# 1. Environment normalization across all 4 supported CLI hosts. Only
#    Claude Code populates CLAUDE_PLUGIN_OPTION_<KEY> env vars natively
#    (from its own userConfig prompt) - OpenCode/Codex CLI/Copilot CLI
#    have no equivalent mechanism at all (confirmed by reading
#    tools/generate-cli-targets.py's own env-injection code: only
#    CLAUDE_PLUGIN_ROOT is ever propagated into their generated configs).
#    tools/clicky-setup.sh writes every operator-configured value into
#    ~/.clicky/config.json, a single CLI-neutral source of truth - this
#    script is the one place that reads it and fills in whichever
#    CLAUDE_PLUGIN_OPTION_<KEY> vars the current host hasn't already set,
#    so every downstream script (session-manager.sh, attempt-aggregator.sh,
#    etc.) keeps reading CLAUDE_PLUGIN_OPTION_* exactly as it already does
#    today, unchanged, regardless of which of the 4 hosts is running it. A
#    host's own native value always wins over the file.
#
# 2. NOT Kalilix tool provisioning. This file used to resolve the Kalilix
#    toolchain PATH before exec'ing the server; it no longer touches Nix at
#    all. That work costs ~44s cold and sat inside the MCP client's server
#    startup budget, where missing the deadline means "failed to connect"
#    with no retry for the whole session. It is now resolved lazily by
#    server.py on first execute_command, via scripts/toolchain-path.sh -
#    see the "--- 2." section below for the full reasoning.
#
#    THE INVARIANT: this file does only what the server cannot speak MCP
#    without - provision its venv, normalize config into the environment,
#    exec. Everything else is lazy.
#
# Usage: launch.sh (no args; invoked by Claude Code itself via
# mcpServers.clicky-gateway.command - see .claude-plugin/plugin.json - or
# by the equivalent generated command/env block for OpenCode/Codex/Copilot)

set -euo pipefail

# --- Resolve this script's REAL location, through symlinks ----------------
#
# This file is the `clicky-gateway` launcher: installers symlink it onto
# PATH (~/.local/bin/clicky-gateway -> <repo>/skills/mcp-gateway/scripts/
# launch.sh) so every generated per-CLI config can say
# `command = "clicky-gateway"` instead of baking in an absolute path.
#
# That matters for more than tidiness. Every MCP client's documented
# convention is that `command` is a NAME RESOLVED ON PATH - the canonical
# example in the MCP docs is `"command": "npx"`, with absolute paths
# appearing only in `args`, and the same docs rule out relative paths
# outright ("absolute and not relative"). Following the convention makes
# the generated configs byte-identical on every machine, which in turn
# means:
#   - no contributor's home directory is committed to this repo (the
#     checked-in artifacts previously embedded the generating machine's
#     absolute path in 23 tracked files),
#   - tests/cli_targets/'s drift check compares like with like, so it can
#     actually pass anywhere other than the machine that last generated,
#   - moving or re-cloning the repo no longer requires regenerating.
#
# But `${BASH_SOURCE[0]}` is the SYMLINK path when invoked that way, so a
# plain `dirname` would resolve to ~/.local/bin and every
# "$SCRIPT_DIR/../.."-relative lookup below would miss. Walk the symlink
# chain to the real file first.
#
# Uses a readlink loop rather than `readlink -f`/`realpath`: neither is
# available on macOS's stock BSD userland, which this repo explicitly
# supports (see the bash 3.2 notes elsewhere in this file).
_resolve_self() {
    local src="${BASH_SOURCE[0]}" dir
    while [ -L "$src" ]; do
        dir="$(cd -P "$(dirname "$src")" && pwd)"
        src="$(readlink "$src")"
        # A relative symlink target resolves against the link's own
        # directory, not the current working directory.
        case "$src" in
            /*) ;;
            *) src="$dir/$src" ;;
        esac
    done
    cd -P "$(dirname "$src")" && pwd
}

SCRIPT_DIR="$(_resolve_self)"

# skills/mcp-gateway/scripts -> repo root. Derived, never hardcoded, so
# this launcher is correct from any clone location without regeneration.
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Claude Code sets CLAUDE_PLUGIN_ROOT natively. The other three hosts have
# no equivalent - which is exactly why the generator used to inject it as
# a literal absolute path into their configs. Deriving it here removes
# that need entirely: every host gets it, and none of them has to know a
# path. A host's own value always wins.
: "${CLAUDE_PLUGIN_ROOT:=$REPO_ROOT}"
export CLAUDE_PLUGIN_ROOT

BASE_DIR="${CLAUDE_PLUGIN_DATA:-/tmp/clicky-mcp-gateway-data}"
VENV_DIR="$BASE_DIR/venv"
CLICKY_CONFIG="${CLICKY_CONFIG_PATH:-$HOME/.clicky/config.json}"

# provision-venv.sh's stdout is progress/diagnostic text ("Creating venv
# at ...", etc.), never MCP protocol output - but once server.py is
# exec'd below, fd 1 becomes the MCP stdio JSON-RPC channel to Claude
# Code, so nothing that isn't protocol traffic may reach it from this
# point on. Redirect provision-venv.sh's stdout to stderr to keep fd 1
# clean even before the exec. Same applies to everything else in this
# file from here on - every diagnostic below is explicitly sent to
# stderr (>&2), never left on the default stdout.
"$SCRIPT_DIR/provision-venv.sh" 1>&2

# --- 1. Environment normalization from ~/.clicky/config.json ----------
#
# Mechanical key.upper() transform (default_session_directory ->
# CLAUDE_PLUGIN_OPTION_DEFAULT_SESSION_DIRECTORY) - matches every existing
# CLAUDE_PLUGIN_OPTION_* name already in use across this repo's scripts,
# so this automatically covers the current 7 keys (the 6 pre-existing
# userConfig options plus the new tool_provisioning) and any future one
# added to plugin.json's userConfig block without needing a matching
# per-key line here. Only fills a gap - never overrides a value the host
# (today, only Claude Code) already set natively.
#
# Written to a temp file rather than piped through process substitution
# (`< <(python3 ...)`) - confirmed live on this repo's real target
# platform (macOS ships bash 3.2.57, frozen pre-GPLv3, as /bin/bash):
# a heredoc nested inside `<(...)` process substitution fails there with
# "bad substitution: no closing ')'", even though `bash -n` reports the
# file as syntactically valid. Every existing python3-heredoc call
# elsewhere in this repo (finding-validator.sh, success-calculator.sh,
# etc.) avoids this exact combination for the same reason - a temp file
# plus a plain `while read` is the portable equivalent.
if [ -f "$CLICKY_CONFIG" ] && command -v python3 >/dev/null 2>&1; then
    ENV_NORMALIZE_TMP="$(mktemp)"
    python3 - "$CLICKY_CONFIG" > "$ENV_NORMALIZE_TMP" 2>/dev/null << 'PYEOF'
import json
import sys

path = sys.argv[1]
try:
    with open(path) as f:
        data = json.load(f)
except (OSError, json.JSONDecodeError):
    sys.exit(0)

if not isinstance(data, dict):
    sys.exit(0)

for key, value in data.items():
    if value is None:
        continue
    env_name = f"CLAUDE_PLUGIN_OPTION_{key.upper()}"
    if isinstance(value, bool):
        env_value = "true" if value else "false"
    else:
        env_value = str(value)
    # Values in this file are operator-supplied paths/flags, not
    # arbitrary untrusted input, but a literal newline would still break
    # the one-pair-per-line protocol this loop parses - strip defensively
    # rather than trust the file's own hygiene.
    env_value = env_value.replace("\n", " ").replace("\r", " ")
    print(f"{env_name}={env_value}")
PYEOF
    while IFS='=' read -r env_name env_value; do
        [ -n "$env_name" ] || continue
        if [ -z "${!env_name+x}" ]; then
            export "$env_name=$env_value"
        fi
    done < "$ENV_NORMALIZE_TMP"
    rm -f "$ENV_NORMALIZE_TMP"
fi

# --- 2. Kalilix tool provisioning is NOT resolved here --------------------
#
# It used to be. Resolving the Kalilix toolchain PATH costs ~44s on a cold
# cache, and doing it here put that cost inside the MCP client's server-STARTUP
# budget: Claude Code applies a startup timeout (MCP_TIMEOUT; the
# documentation's own example is 10000ms) to stdio MCP servers, reports one
# that misses it as "failed to connect", and does NOT retry it for the rest of
# the session. Because every Clicky agent holds only gateway tools, a single
# missed startup left a whole engagement running against agents with no tools,
# degrading silently rather than stopping. The cache key includes flake.nix, so
# this re-colded on every plugin update - a recurring failure, not a first-run
# one.
#
# Nothing here needs those tools. The only consumer is execute_command's
# subprocess inside server.py, and a tool call has an entirely different
# budget: MCP_TOOL_TIMEOUT defaults to ~28 hours when unset, and stdio servers
# have no per-request timer at all. So server.py resolves it lazily, on first
# use, via skills/mcp-gateway/scripts/toolchain-path.sh, and memoizes it.
#
# THE INVARIANT THIS FILE NOW HOLDS: the startup path contains only work
# without which the server cannot speak MCP - provisioning the venv it runs in,
# and normalizing config into the environment. Everything else is lazy.
# tests/mcp_gateway/test_launch.sh enforces this by stripping comments from
# this file and asserting that no remaining EXECUTABLE line mentions nix,
# print-dev-env or the toolchain. (The words appear above, in prose, on
# purpose - the reasoning has to live somewhere.)


exec "$VENV_DIR/bin/python" "$SCRIPT_DIR/../server.py" "$@"
