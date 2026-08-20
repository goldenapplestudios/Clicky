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
# 2. Optional Kalilix tool provisioning (tool_provisioning=kalilix).
#    Wraps the final exec in `nix develop kalilix#kali --command` so
#    every execute_command call for the rest of the session has real
#    pentest tools (nmap/sqlmap/hydra/etc.) on PATH - see
#    skills/tool-management/SKILL.md and tools/clicky-setup.sh. Always
#    probed first and never allowed to prevent the gateway server from
#    starting - a Kalilix problem degrades to "whatever's already on
#    PATH," the same graceful-degradation posture tool-fallback.sh
#    already has everywhere else in this repo.
#
# Usage: launch.sh (no args; invoked by Claude Code itself via
# mcpServers.clicky-gateway.command - see .claude-plugin/plugin.json - or
# by the equivalent generated command/env block for OpenCode/Codex/Copilot)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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

# --- 2. Optional Kalilix tool provisioning -----------------------------
#
# kalilix#kali is the registry shortcut (tools/clicky-setup.sh registers
# it via `nix registry add kalilix github:scopecreep-zip/kalilix`) -
# deliberately not a bare github:scopecreep-zip/kalilix#kali URL, per
# Kalilix's own documented "regular use" pattern, avoiding a fresh
# branch-ref resolution on every gateway launch.
if [ "${CLAUDE_PLUGIN_OPTION_TOOL_PROVISIONING:-none}" = "kalilix" ]; then
    if ! command -v nix >/dev/null 2>&1; then
        echo "WARNING: tool_provisioning=kalilix but 'nix' is not on PATH - agents will only see tools already on PATH. Run tools/clicky-setup.sh to set this up." >&2
    elif ! nix develop kalilix#kali --command true >/dev/null 2>&1; then
        echo "WARNING: tool_provisioning=kalilix but 'nix develop kalilix#kali' failed (registry shortcut not set up, network issue, or a broken flake). Run tools/clicky-setup.sh to fix this. Falling back to tools already on PATH." >&2
    else
        exec nix develop kalilix#kali --command "$VENV_DIR/bin/python" "$SCRIPT_DIR/../server.py" "$@"
    fi
fi

exec "$VENV_DIR/bin/python" "$SCRIPT_DIR/../server.py" "$@"
