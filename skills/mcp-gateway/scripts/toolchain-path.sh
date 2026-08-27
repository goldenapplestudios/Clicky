#!/bin/bash
#
# toolchain-path.sh - resolve the Kalilix toolchain PATH, and nothing else.
#
# Why this is its own script, called lazily, instead of part of launch.sh:
#
# This resolution costs ~44s on a cold cache and ~1s warm. It used to run
# before launch.sh exec'd the MCP server, which put it inside the client's
# server-STARTUP budget - and Claude Code applies a startup timeout
# (MCP_TIMEOUT; the documentation's own example is 10000ms) to stdio MCP
# servers, reports a server that misses it as "failed to connect", and does
# NOT retry it for the rest of the session. Every Clicky agent holds only
# gateway tools, so one missed startup left an entire engagement running
# against agents with no tools, silently degrading instead of stopping.
#
# The cache key is sha256(flake.lock + flake.nix), so ANY edit to flake.nix
# re-colds it for every user: this was a recurring cost on plugin updates,
# not a one-time first-run cost.
#
# Nothing at gateway startup actually needs this PATH. The sole consumer is
# execute_command's subprocess in server.py - and a tool call has a wholly
# different budget: MCP_TOOL_TIMEOUT defaults to ~28 hours when unset, and
# stdio servers have no per-request timer at all. So server.py calls this
# script on first use and memoizes the result, and the same 44s that was
# fatal at startup is harmless there.
#
# Callers (there are no others - keep it that way):
#   - server.py             _toolchain_subprocess_env(), lazily, once per process
#   - tools/clicky-setup.sh --refresh, to make an operator's first command fast
#   - gateway-doctor.sh     --check, to report cache health without invoking nix
#
# Contract:
#   stdout  the resolved PATH prefix on success, and nothing else
#   stderr  every diagnostic
#   exit 0  resolved
#   exit 1  enabled, but unresolvable (no nix, or print-dev-env failed)
#   exit 2  not enabled (tool_provisioning != kalilix) - nix is never invoked
#
# Options:
#   --refresh  ignore any cached value and re-resolve
#   --check    report cache health only; never invokes nix (exit 0 = usable)
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
BASE_DIR="${CLAUDE_PLUGIN_DATA:-/tmp/clicky-mcp-gateway-data}"
VENV_DIR="$BASE_DIR/venv"

MODE="resolve"
case "${1:-}" in
    --refresh) MODE="refresh" ;;
    --check)   MODE="check" ;;
    "")        ;;
    *) echo "toolchain-path.sh: unknown option '$1'" >&2; exit 1 ;;
esac

log() { echo "toolchain-path: $*" >&2; }

# Not enabled is a normal outcome, not a failure: the default configuration
# uses whatever is already on PATH. Exit before touching nix at all.
if [ "${CLAUDE_PLUGIN_OPTION_TOOL_PROVISIONING:-none}" != "kalilix" ]; then
    exit 2
fi

# So: look in the canonical install locations before concluding Nix is
# absent. Same logic as tools/clicky-setup.sh's _find_nix() - keep the two
# in sync.
# Colon-separated candidate list, overridable. Tests need this: because
# this function deliberately looks OUTSIDE PATH, restricting PATH no
# longer isolates a "Nix is not installed" fixture, and without an
# override tests/setup_wizard/ would detect the developer's real Nix and
# go on to do real work (registering the flake, pre-warming the store) in
# a suite documented as never touching the real system. Set it to empty
# to simulate a machine with no Nix. Uses ${VAR-default}, not ${VAR:-...},
# so an explicitly-empty value is honored rather than replaced.
CLICKY_NIX_CANDIDATES="${CLICKY_NIX_CANDIDATES-/nix/var/nix/profiles/default/bin/nix:$HOME/.nix-profile/bin/nix:/run/current-system/sw/bin/nix:/usr/local/bin/nix}"

_find_nix() {
    if command -v nix >/dev/null 2>&1; then
        command -v nix
        return 0
    fi
    local candidate
    local IFS=':'
    for candidate in $CLICKY_NIX_CANDIDATES; do
        [ -n "$candidate" ] || continue
        if [ -x "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

# --- Extracting the toolchain PATH, rather than entering a devShell -----
#
# The gateway does NOT run inside `nix develop`. It needs the tools on
# PATH for its own execute_command subprocesses - that is all - and
# wrapping the server in a devShell actively breaks it:
#
#   The MCP stdio transport specification is normative on this point:
#   "The server MUST NOT write anything to its stdout that is not a valid
#   MCP message." Kalilix's shellHook prints a multi-line ASCII banner on
#   STDOUT (verified: `nix develop kalilix#kali --command echo x
#   2>/dev/null` still emits the whole banner). Wrapping the exec in
#   `nix develop` therefore injects that banner straight into the JSON-RPC
#   channel and no frame parses.
#
# `nix print-dev-env --json` is the documented way to capture a devShell's
# environment programmatically ("a JSON serialisation of the variables and
# functions defined by the build process... suitable for consumption by
# another program"). Critically, it serialises shellHook as *data* and
# never executes it - so stdout stays clean by construction, rather than
# by suppressing output after the fact. It also avoids re-evaluating the
# whole devShell on every single gateway launch.
#
# Result is cached and keyed on the flake inputs, so the expensive
# evaluation happens once per toolchain change rather than once per
# session.

# The one place the toolchain-path cache key is derived. Both the resolver and
# the validity check call this, so a change to the invalidation rule cannot
# leave the two disagreeing - an earlier revision had a second derivation that
# keyed on flake.lock alone and reported a cold cache as warm whenever only
# flake.nix had changed.
_cache_file() {
    local flake_ref="$1" key_src cache_key
    # Invalidate when the flake or its lock changes.
    key_src="$(cat "$REPO_ROOT/flake.lock" "$REPO_ROOT/flake.nix" 2>/dev/null || echo "$flake_ref")"
    if command -v sha256sum >/dev/null 2>&1; then
        cache_key="$(printf '%s' "$key_src" | sha256sum | cut -d' ' -f1)"
    elif command -v shasum >/dev/null 2>&1; then
        cache_key="$(printf '%s' "$key_src" | shasum -a 256 | cut -d' ' -f1)"
    else
        cache_key="nokey"
    fi
    printf '%s' "$BASE_DIR/.toolchain-path.$cache_key"
}

# A cached PATH is only worth trusting if it still points at anything. A
# `nix store gc` removes the store paths outright, leaving a cache entry that
# reads as a hit and hands agents a PATH of directories that do not exist -
# tools then vanish with no error anyone attributes to the cache. So verify
# rather than trust, the same discipline provision-venv.sh applies to the venv
# with venv_has_deps.
#
# The predicate is "every /nix/store entry still exists" rather than "some
# sentinel tool resolves": a GC removes whole paths, so existence is the exact
# signal, and it stays correct if the flake ever stops shipping a given tool.
# Entries outside /nix/store are host PATH tails that print-dev-env may append;
# those are not ours to judge. Pure bash - no interpreter spawn, because this
# now runs on the first-command path.
# Store prefix is overridable purely so tests can point it at a fixture tree -
# the same test-seam convention as CLICKY_NIX_CANDIDATES above. ${VAR-default},
# not ${VAR:-default}, so an explicitly-empty value is honored.
CLICKY_NIX_STORE_PREFIX="${CLICKY_NIX_STORE_PREFIX-/nix/store}"

_cache_is_usable() {
    local cached="$1" entry saw_store=0
    [ -n "$cached" ] || return 1
    local IFS=':'
    for entry in $cached; do
        case "$entry" in
            "$CLICKY_NIX_STORE_PREFIX"/*)
                saw_store=1
                [ -d "$entry" ] || return 1
                ;;
        esac
    done
    # A resolved PATH with no store entries at all is not something this can
    # vouch for, so it is not trusted: better one extra resolve than handing
    # agents a PATH that was never verified.
    [ "$saw_store" -eq 1 ]
}


_resolve() {
    local nix_bin="$1" flake_ref="$2" cache_file
    cache_file="$(_cache_file "$flake_ref")"

    local json extracted py
    json="$("$nix_bin" print-dev-env "$flake_ref" --json 2>/dev/null)" || return 1
    [ -n "$json" ] || return 1

    # The venv python is preferred, but this script is also called by the setup
    # wizard, which can run before the venv exists.
    py="$VENV_DIR/bin/python3"
    [ -x "$py" ] || py="python3"
    command -v "$py" >/dev/null 2>&1 || return 1

    extracted="$(printf '%s' "$json" | "$py" -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(1)
value = data.get("variables", {}).get("PATH", {}).get("value", "")
if not value:
    sys.exit(1)
print(value)
' 2>/dev/null)" || return 1
    [ -n "$extracted" ] || return 1

    # Atomic publish. Codex spawns one gateway process per subagent
    # (.codex/agents/*.toml), so concurrent writers are the normal case, and a
    # reader that cats a half-written file gets a truncated PATH - worse than a
    # cold cache, because it looks valid.
    local tmp="$cache_file.tmp.$$"
    printf '%s' "$extracted" > "$tmp" 2>/dev/null && mv -f "$tmp" "$cache_file" 2>/dev/null || rm -f "$tmp" 2>/dev/null

    printf '%s' "$extracted"
}

mkdir -p "$BASE_DIR" 2>/dev/null || true

NIX_BIN="$(_find_nix || true)"

# Clicky's own flake composes Kalilix's #kali shell plus the tools Clicky's
# scripts need that Kalilix does not ship. Falls back to Kalilix directly if
# this checkout has no usable flake, so the registry shortcut still works
# standalone. Both refs normally share one cache entry - the flake_ref only
# participates in the key when neither flake file can be read.
PRIMARY_REF="$REPO_ROOT#clicky"
FALLBACK_REF="kalilix#kali"
[ -f "$REPO_ROOT/flake.nix" ] || PRIMARY_REF=""

CACHE_FILE="$(_cache_file "${PRIMARY_REF:-$FALLBACK_REF}")"
CACHED=""
[ -s "$CACHE_FILE" ] && CACHED="$(cat "$CACHE_FILE" 2>/dev/null || true)"

if [ "$MODE" = "check" ]; then
    if [ -z "$CACHED" ]; then
        log "no cache entry at $CACHE_FILE"
        exit 1
    fi
    if _cache_is_usable "$CACHED"; then
        log "cache valid ($CACHE_FILE)"
        exit 0
    fi
    log "cache STALE - store paths missing (likely a nix store gc): $CACHE_FILE"
    exit 1
fi

if [ "$MODE" != "refresh" ] && [ -n "$CACHED" ]; then
    if _cache_is_usable "$CACHED"; then
        printf '%s' "$CACHED"
        [ -n "$NIX_BIN" ] && printf ':%s' "$(dirname "$NIX_BIN")"
        printf '\n'
        exit 0
    fi
    log "discarding stale cache (store paths gone): $CACHE_FILE"
    rm -f "$CACHE_FILE" 2>/dev/null || true
fi

if [ -z "$NIX_BIN" ]; then
    log "tool_provisioning=kalilix but no 'nix' binary was found (checked PATH and the standard install locations). Agents will see only what is already on PATH. Run tools/clicky-setup.sh to set this up."
    exit 1
fi

RESOLVED=""
[ -n "$PRIMARY_REF" ] && RESOLVED="$(_resolve "$NIX_BIN" "$PRIMARY_REF" || true)"
[ -n "$RESOLVED" ] || RESOLVED="$(_resolve "$NIX_BIN" "$FALLBACK_REF" || true)"

if [ -z "$RESOLVED" ]; then
    log "tool_provisioning=kalilix but the toolchain could not be resolved ('$NIX_BIN print-dev-env' failed for ${PRIMARY_REF:-<no local flake>} and $FALLBACK_REF - registry shortcut not set up, network issue, or a broken flake). Run tools/clicky-setup.sh to fix this."
    exit 1
fi

# Toolchain first, then the directory holding the resolved nix, so agents can
# invoke nix itself from execute_command.
printf '%s:%s\n' "$RESOLVED" "$(dirname "$NIX_BIN")"
