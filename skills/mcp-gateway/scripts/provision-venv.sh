#!/bin/bash
#
# Provision Venv - create/reuse a Python venv for skills/mcp-gateway's MCP
# server, reinstalling requirements.txt only when its contents have
# changed since the last successful install.
#
# This is registered as the SessionStart hook for the gateway
# (hooks/hooks.json) AND called synchronously by scripts/launch.sh (the
# mcpServers.clicky-gateway.command wrapper) before it execs the venv's
# python. Both callers can legitimately run this script around the same
# moment - confirmed empirically in a real Claude Code 2.1.233 session
# (2026-08-15): the SessionStart hook and the MCP server's own launch
# attempt are NOT ordered relative to each other, so treat concurrent
# invocations as the normal case, not an edge case. mkdir_lock()/
# release_lock() below serialize the actual venv-creation/pip-install
# critical section so two concurrent runs can't corrupt the same venv
# (e.g. two `python3 -m venv` calls or two `pip install`s racing on the
# same site-packages). It doesn't assume a real Claude Code runtime, and
# falls back to a fixed local path when CLAUDE_PLUGIN_DATA isn't set
# (which it won't be outside a real plugin invocation).
#
# Usage: provision-venv.sh
# Prints the venv directory path as its last line of stdout on success.
#
# Base data directory: ${CLAUDE_PLUGIN_DATA:-/tmp/clicky-mcp-gateway-data}
#   venv/                 - the actual virtualenv
#   .requirements.lock    - a copy of requirements.txt as of the last
#                            successful install, diffed against the live
#                            requirements.txt on every run to decide
#                            whether reinstall is needed
#   provision.log          - one line per run, so a caller (or a test) can
#                            confirm what this script actually did without
#                            having to infer it from timing alone
#   .provision.lock/       - lock directory (mkdir-based, portable - no
#                            dependency on the `flock` binary, which isn't
#                            present on macOS by default) held only while
#                            actually creating the venv or installing
#                            requirements; see mkdir_lock() below
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REQUIREMENTS="$SCRIPT_DIR/../requirements.txt"

BASE_DIR="${CLAUDE_PLUGIN_DATA:-/tmp/clicky-mcp-gateway-data}"
VENV_DIR="$BASE_DIR/venv"
CACHED_REQUIREMENTS="$BASE_DIR/.requirements.lock"
LOG_FILE="$BASE_DIR/provision.log"

log() {
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") $1" >> "$LOG_FILE"
}

if [ ! -f "$REQUIREMENTS" ]; then
    echo "ERROR: requirements.txt not found at $REQUIREMENTS" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 not found on PATH" >&2
    exit 1
fi

mkdir -p "$BASE_DIR"

# --- Portable mkdir-based lock -------------------------------------------
# `mkdir` is atomic even across processes/filesystems, so it doubles as a
# lock primitive without depending on the `flock` binary (absent on macOS
# by default; this script also runs in this repo's dev/test environment,
# not just on the Kali targets Clicky is meant to run on). Held only
# around the actual venv-creation/pip-install critical section below, not
# the whole script.
LOCK_DIR="$BASE_DIR/.provision.lock"
LOCK_HELD=0

acquire_lock() {
    local waited=0
    local max_wait=180  # generous: a cold `pip install` can take a while
    while ! mkdir "$LOCK_DIR" 2>/dev/null; do
        if [ "$waited" -ge "$max_wait" ]; then
            echo "ERROR: timed out after ${max_wait}s waiting for provisioning lock at $LOCK_DIR (another provision-venv.sh run may be stuck)" >&2
            exit 1
        fi
        sleep 0.5
        waited=$((waited + 1))  # loop sleeps 0.5s, so this only approximates seconds - fine for a generous timeout
    done
    LOCK_HELD=1
}

release_lock() {
    if [ "$LOCK_HELD" -eq 1 ]; then
        rmdir "$LOCK_DIR" 2>/dev/null || true
        LOCK_HELD=0
    fi
}

trap release_lock EXIT

acquire_lock

created_venv=0
if [ ! -x "$VENV_DIR/bin/python3" ]; then
    echo "Creating venv at $VENV_DIR"
    python3 -m venv "$VENV_DIR"
    created_venv=1
    log "created venv at $VENV_DIR"
fi

if [ "$created_venv" -eq 1 ] || [ ! -f "$CACHED_REQUIREMENTS" ] || ! cmp -s "$REQUIREMENTS" "$CACHED_REQUIREMENTS"; then
    echo "Installing requirements from $REQUIREMENTS"
    "$VENV_DIR/bin/pip" install --upgrade pip -q
    "$VENV_DIR/bin/pip" install -r "$REQUIREMENTS" -q
    cp "$REQUIREMENTS" "$CACHED_REQUIREMENTS"
    log "installed requirements (requirements.txt changed or first install)"
    echo "Provisioned: $VENV_DIR"
else
    echo "Requirements unchanged - skipping reinstall ($VENV_DIR already up to date)"
    log "skipped reinstall - requirements.txt unchanged since last install"
fi

release_lock

echo "$VENV_DIR"
