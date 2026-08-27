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
#   PROVISION_FAILED.txt   - written only when provisioning cannot be
#                            completed, containing the operator-facing
#                            remediation text (also printed to stderr).
#                            Removed again on the next successful run.
#                            Exists because this script's stderr goes to
#                            the MCP server's stderr, which no operator
#                            ever reads - Claude Code surfaces only
#                            "server failed to connect". See
#                            fail_unprovisionable() below.
#
# --- Why the health check is not just "does bin/python3 exist" -----------
#
# A venv directory containing an executable bin/python3 is NOT proof of a
# usable venv. On Debian-family systems without the pythonX.Y-venv package
# (Kali included, where Clicky is most often run), `python3 -m venv` gets
# far enough to lay down bin/python3, pyvenv.cfg, lib/ and include/, and
# only THEN fails at the ensurepip stage - leaving behind a directory that
# looks complete and has no pip in it.
#
# This script used to gate recreation on `[ ! -x "$VENV_DIR/bin/python3" ]`,
# which classified that wreckage as healthy: it skipped creation, fell
# through to `"$VENV_DIR/bin/pip" install`, and died with exit 127 and the
# message "No such file or directory". Nothing ever cleaned the poisoned
# directory up, so this recurred on every single session, permanently.
#
# Observed in the wild on Kali (python3.13, no python3.13-venv installed):
# the clicky-gateway MCP server failed to start for every session. That is
# a total outage rather than a degradation, because all 8 Clicky agents are
# provisioned with the gateway's tools and nothing else - so every agent
# dispatch got an agent with zero working tools.
#
# The fix is threefold: (1) venv_is_healthy() actually probes pip, (2) an
# unhealthy venv is torn down and rebuilt instead of being trusted, and
# (3) when ensurepip is unavailable, bootstrap_pip() recovers without root
# rather than requiring `sudo apt install pythonX.Y-venv`.
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
LOCK_OWNER_FILE="$LOCK_DIR/owner"
LOCK_HELD=0

# How long to wait for a lock whose holder is demonstrably alive. Real
# seconds, unlike the previous iteration counter: `max_wait=180` with a 0.5s
# sleep was 90 actual seconds - shorter than the ~60s cold `pip install` it
# called itself generous for.
LOCK_WAIT_SECONDS=600

# How old a lock may be before it is presumed abandoned. Only reached when the
# owner cannot be probed (no owner file, or another host), so it is a backstop
# rather than the primary test.
LOCK_STALE_AFTER=600

LOCAL_HOST="$(hostname 2>/dev/null || uname -n 2>/dev/null || echo unknown)"

_mtime() {
    stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null
}

# A lock is stale when the process that took it is gone. This matters because
# `release_lock` runs from a trap and SIGKILL does not honour traps: before
# this check existed, one `kill -9` left `.provision.lock` behind and every
# later run spun out the wait and hard-exited, bricking the gateway until
# someone manually removed a directory.
_lock_is_stale() {
    local owner_pid="" owner_host="" mtime now
    if [ -f "$LOCK_OWNER_FILE" ]; then
        owner_pid="$(sed -n '1p' "$LOCK_OWNER_FILE" 2>/dev/null || true)"
        owner_host="$(sed -n '2p' "$LOCK_OWNER_FILE" 2>/dev/null || true)"
    fi

    # (a) Owner liveness - instant and authoritative. The hostname guard is
    #     what makes this safe when BASE_DIR is shared between machines or a
    #     PID has been recycled: we only trust `kill -0` for our own host.
    if [ -n "$owner_pid" ] && [ "$owner_host" = "$LOCAL_HOST" ]; then
        if kill -0 "$owner_pid" 2>/dev/null; then
            return 1
        fi
        return 0
    fi

    # (b) Age backstop - covers a lock killed between `mkdir` and the owner
    #     write, and locks belonging to a host we cannot probe.
    mtime="$(_mtime "$LOCK_DIR")" || return 1
    [ -n "$mtime" ] || return 1
    now="$(date +%s)"
    [ $((now - mtime)) -gt "$LOCK_STALE_AFTER" ]
}

# Reclaim by rename, never by `rmdir` in place: two waiters can both decide a
# lock is stale, and only one `mv` of a given source can succeed. The loser
# simply loops and contends for the fresh lock normally.
_steal_lock() {
    local stale_dir="$LOCK_DIR.stale.$$"
    if mv "$LOCK_DIR" "$stale_dir" 2>/dev/null; then
        rm -rf "$stale_dir"
        log "reclaimed stale provisioning lock at $LOCK_DIR"
        return 0
    fi
    return 1
}

acquire_lock() {
    local deadline
    deadline=$(( $(date +%s) + LOCK_WAIT_SECONDS ))
    while ! mkdir "$LOCK_DIR" 2>/dev/null; do
        if [ "$(date +%s)" -ge "$deadline" ]; then
            echo "ERROR: timed out after ${LOCK_WAIT_SECONDS}s waiting for the provisioning lock at $LOCK_DIR." >&2
            echo "  Its holder still looks alive, so this was not reclaimed automatically." >&2
            echo "  If it is wedged, remove $LOCK_DIR and retry." >&2
            exit 1
        fi
        if _lock_is_stale; then
            _steal_lock || true
            continue
        fi
        sleep 0.5
    done
    # Written after the atomic mkdir, so the directory is the lock and this is
    # only metadata. A lock killed before this lands is caught by the age
    # backstop in _lock_is_stale.
    printf '%s\n%s\n' "$$" "$LOCAL_HOST" > "$LOCK_OWNER_FILE" 2>/dev/null || true
    LOCK_HELD=1
}

release_lock() {
    if [ "$LOCK_HELD" -eq 1 ]; then
        # Only release a lock we still own. If ours was presumed stale and
        # reclaimed by a waiter, the directory now belongs to that process;
        # removing it would let a third process take a lock two others believe
        # they hold.
        local owner_pid=""
        if [ -f "$LOCK_OWNER_FILE" ]; then
            owner_pid="$(sed -n '1p' "$LOCK_OWNER_FILE" 2>/dev/null || true)"
        fi
        if [ -z "$owner_pid" ] || [ "$owner_pid" = "$$" ]; then
            rm -f "$LOCK_OWNER_FILE" 2>/dev/null || true
            rmdir "$LOCK_DIR" 2>/dev/null || log "could not remove lock dir $LOCK_DIR"
        else
            log "not releasing $LOCK_DIR - reclaimed by PID $owner_pid, not $$"
        fi
        LOCK_HELD=0
    fi
}

# INT/TERM as well as EXIT: a CLI host shutting down sends SIGTERM, and
# catching it turns what would be an abandoned lock into a clean release.
# Only SIGKILL now reaches the self-heal path above.
trap release_lock EXIT INT TERM

# --- Health / repair helpers ---------------------------------------------

# A venv is only usable if its interpreter can actually run pip. See the
# "Why the health check is not just..." note in the header.
venv_is_healthy() {
    [ -x "$VENV_DIR/bin/python3" ] || return 1
    "$VENV_DIR/bin/python3" -m pip --version >/dev/null 2>&1 || return 1
    return 0
}

# Does the provisioned venv satisfy what the gateway server actually needs?
# Checked after installing, and also on every "requirements unchanged" run -
# an intact .requirements.lock is a record that an install once succeeded,
# not evidence that the packages are still importable now.
venv_has_deps() {
    "$VENV_DIR/bin/python3" -c "import mcp" >/dev/null 2>&1
}

# Get pip into a venv whose creation couldn't. ensurepip first (offline,
# instant); get-pip.py second, which is the path that works on a
# Debian-family box missing pythonX.Y-venv, where ensurepip isn't
# importable at all. Neither needs root - the whole point is that an
# operator should not have to `sudo apt install` anything to run Clicky.
bootstrap_pip() {
    if "$VENV_DIR/bin/python3" -m ensurepip --upgrade >/dev/null 2>&1; then
        log "bootstrapped pip via ensurepip"
        return 0
    fi
    command -v curl >/dev/null 2>&1 || return 1
    local getpip
    getpip="$(mktemp)"
    if curl -sSL --max-time 60 -o "$getpip" https://bootstrap.pypa.io/get-pip.py 2>/dev/null &&
        "$VENV_DIR/bin/python3" "$getpip" -q >/dev/null 2>&1; then
        rm -f "$getpip"
        log "bootstrapped pip via get-pip.py (ensurepip unavailable)"
        return 0
    fi
    rm -f "$getpip"
    return 1
}

# Build a venv from scratch, tearing down whatever was there first so a
# half-built directory from a previous failed attempt can never be mistaken
# for a good one.
create_venv() {
    rm -rf "$VENV_DIR"

    # Decide which creation path to take up front rather than running the
    # default one, letting it fail, and swallowing the noise.
    #
    # This distinction matters. `python3 -m venv` prints its "ensurepip is
    # not available / apt install pythonX.Y-venv" advice on STDOUT, so the
    # failure-and-retry shape means every recovering run emits a multi-line
    # apt-install notice that has to be muffled to avoid looking like a
    # crash - i.e. suppressing output we deliberately provoked. Probing
    # ensurepip first means the normal case on such a system never produces
    # that message at all, and anything that DOES reach the log below is a
    # genuine surprise rather than a known condition being papered over.
    local venv_args=()
    local needs_bootstrap=0
    if ! python3 -c "import ensurepip" >/dev/null 2>&1; then
        # Known, handled condition (Debian/Kali/Ubuntu without
        # pythonX.Y-venv). Skip straight to the path that works.
        venv_args=(--without-pip)
        needs_bootstrap=1
        log "ensurepip unavailable - creating venv with --without-pip and bootstrapping pip"
    fi

    local create_out
    create_out="$(mktemp)"
    if ! python3 -m venv "${venv_args[@]}" "$VENV_DIR" >"$create_out" 2>&1; then
        # Not the ensurepip case (that was handled above) - so this is an
        # unanticipated failure: permissions, disk, a broken interpreter.
        # Surface it rather than retrying blindly into the same wall.
        local detail
        detail="$(tr '\n' ' ' < "$create_out" | cut -c1-300)"
        log "python3 -m venv ${venv_args[*]} failed: $detail"
        echo "python3 -m venv failed: $detail" >&2
        rm -f "$create_out"
        return 1
    fi
    rm -f "$create_out"

    if [ "$needs_bootstrap" -eq 1 ] || ! venv_is_healthy; then
        bootstrap_pip || return 1
    fi
    venv_is_healthy
}

# Provisioning is unrecoverable. Persist the remediation text where a human
# will actually find it, since this script's stderr is the MCP server's
# stderr and Claude Code shows the operator only "server failed to connect".
fail_unprovisionable() {
    local reason="$1"
    local py_ver
    py_ver="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "3")"
    local msg
    msg="Clicky MCP gateway could not be provisioned.

Reason: $reason
Venv:   $VENV_DIR

Every Clicky agent is provisioned with the gateway's tools and nothing
else, so until this is fixed each agent dispatch gets an agent with zero
working tools. Fix this before running /clicky:pentest.

Most likely cause: this Python has no working 'ensurepip', and the
automatic pip bootstrap (get-pip.py) could not reach the network.

Fixes, in order of preference:
  1. Install the venv module for your interpreter:
         sudo apt install python${py_ver}-venv      # Debian/Kali/Ubuntu
  2. Restore network access to https://bootstrap.pypa.io and re-run:
         $SCRIPT_DIR/provision-venv.sh
  3. Provision the venv by hand:
         python3 -m venv --without-pip '$VENV_DIR'
         curl -sSL -o /tmp/get-pip.py https://bootstrap.pypa.io/get-pip.py
         '$VENV_DIR/bin/python3' /tmp/get-pip.py
         '$VENV_DIR/bin/python3' -m pip install -r '$REQUIREMENTS'

Then restart your CLI host - Claude Code attempts the MCP connection once
at session start and does not retry, so a mid-session fix needs a restart
to take effect.

Full diagnostic log: $LOG_FILE"
    printf '%s\n' "$msg" > "$BASE_DIR/PROVISION_FAILED.txt"
    printf '%s\n' "$msg" >&2
    log "FAILED: $reason"
    exit 1
}

# --- Lock-free fast path --------------------------------------------------
#
# "Everything is already provisioned" is the overwhelmingly common case, and
# it is the one that matters for the MCP startup budget: this script runs
# synchronously before launch.sh execs the server, and a stdio MCP server that
# misses the client's startup timeout is reported as "failed to connect" and
# is never retried.
#
# Answering that case without taking the lock has a second benefit: it makes
# the common path immune to a stale lock entirely, rather than merely able to
# recover from one.
#
# The `[ ! -d "$LOCK_DIR" ]` guard is what keeps this from being a TOCTOU
# hazard. If anyone holds the lock they may be mid-`pip install`, so we fall
# through to the normal wait path rather than exec'ing into a venv that is
# still being built.
if [ ! -d "$LOCK_DIR" ] && venv_is_healthy && venv_has_deps \
   && [ -f "$CACHED_REQUIREMENTS" ] && cmp -s "$REQUIREMENTS" "$CACHED_REQUIREMENTS"; then
    log "skipped reinstall - requirements.txt unchanged since last install (fast path, lock not taken)"
    rm -f "$BASE_DIR/PROVISION_FAILED.txt"
    echo "Requirements unchanged - skipping reinstall ($VENV_DIR already up to date)"
    echo "$VENV_DIR"
    exit 0
fi

acquire_lock

created_venv=0
if ! venv_is_healthy; then
    if [ -e "$VENV_DIR" ]; then
        echo "Existing venv at $VENV_DIR is unusable (no working pip) - rebuilding"
        log "detected unhealthy venv at $VENV_DIR - rebuilding"
    else
        echo "Creating venv at $VENV_DIR"
    fi
    create_venv || fail_unprovisionable "could not create a venv with a working pip at $VENV_DIR"
    created_venv=1
    log "created venv at $VENV_DIR"
fi

if [ "$created_venv" -eq 1 ] || [ ! -f "$CACHED_REQUIREMENTS" ] || ! cmp -s "$REQUIREMENTS" "$CACHED_REQUIREMENTS" || ! venv_has_deps; then
    echo "Installing requirements from $REQUIREMENTS"
    # No separate `pip install --upgrade pip`: it is an extra network round
    # trip on the startup path, and requirements.txt pins a single wheel-only
    # dependency that the bundled pip installs fine. `--only-binary=:all:`
    # keeps a cold install from falling into a source build (minutes, and it
    # needs a compiler); `--disable-pip-version-check` removes one more
    # network call. Deliberately NOT `--no-compile`: that trades install time
    # for import time, and import is on the path we are protecting.
    "$VENV_DIR/bin/python3" -m pip install -r "$REQUIREMENTS" -q \
        --only-binary=:all: --disable-pip-version-check --no-input ||
        fail_unprovisionable "'pip install -r $REQUIREMENTS' failed in $VENV_DIR"
    # Only record the lock once the install is verified to have produced
    # something importable - otherwise a broken install gets cached as good
    # and every later run skips the reinstall that would have fixed it.
    venv_has_deps || fail_unprovisionable "requirements installed but 'import mcp' still fails in $VENV_DIR"
    cp "$REQUIREMENTS" "$CACHED_REQUIREMENTS"
    log "installed requirements (requirements.txt changed, first install, or deps missing)"
    echo "Provisioned: $VENV_DIR"
else
    echo "Requirements unchanged - skipping reinstall ($VENV_DIR already up to date)"
    log "skipped reinstall - requirements.txt unchanged since last install"
fi

# Got here means the venv is healthy and importable - clear any stale
# failure marker from an earlier broken run.
rm -f "$BASE_DIR/PROVISION_FAILED.txt"

release_lock

echo "$VENV_DIR"
