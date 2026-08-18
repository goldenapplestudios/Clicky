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
# Usage: launch.sh (no args; invoked by Claude Code itself via
# mcpServers.clicky-gateway.command - see .claude-plugin/plugin.json)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${CLAUDE_PLUGIN_DATA:-/tmp/clicky-mcp-gateway-data}"
VENV_DIR="$BASE_DIR/venv"

# provision-venv.sh's stdout is progress/diagnostic text ("Creating venv
# at ...", etc.), never MCP protocol output - but once server.py is
# exec'd below, fd 1 becomes the MCP stdio JSON-RPC channel to Claude
# Code, so nothing that isn't protocol traffic may reach it from this
# point on. Redirect provision-venv.sh's stdout to stderr to keep fd 1
# clean even before the exec.
"$SCRIPT_DIR/provision-venv.sh" 1>&2

exec "$VENV_DIR/bin/python" "$SCRIPT_DIR/../server.py" "$@"
