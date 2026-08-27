#!/bin/bash
#
# Tests for skills/mcp-gateway/scripts/toolchain-path.sh.
#
# This script exists because resolving the Kalilix toolchain used to happen in
# launch.sh BEFORE the MCP server was exec'd, which put a ~44s cold operation
# inside the client's server-startup timeout. A stdio MCP server that misses
# that timeout is reported "failed to connect" and never retried, and since
# every Clicky agent holds only gateway tools, that left whole engagements
# running against agents with no tools - degrading silently rather than
# stopping. Resolution is now lazy, and this is the piece that does it.
#
# `nix` is stubbed (the technique tests/setup_wizard/ and tests/tls_scan/ use),
# so these run anywhere and never touch a real Nix store.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
SCRIPT="$REPO_ROOT/skills/mcp-gateway/scripts/toolchain-path.sh"

FAILED=0
check() { if [ "$2" -eq 0 ]; then echo "PASS: $1"; else echo "FAIL: $1 ${3:-}"; FAILED=1; fi; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Fake store dirs the stub will advertise. Real directories, so the
# validate-on-read check has something true to verify.
STORE="$WORK/nix/store"
mkdir -p "$STORE/aaaa-tool-1.0/bin" "$STORE/bbbb-tool-2.0/bin"
FAKE_PATH="$STORE/aaaa-tool-1.0/bin:$STORE/bbbb-tool-2.0/bin"

# The stub. Counts invocations so cache hits are observable.
STUB_BIN="$WORK/stubbin"; mkdir -p "$STUB_BIN"
cat > "$STUB_BIN/nix" <<STUB
#!/bin/bash
echo x >> "$WORK/nix-invocations"
# Only print-dev-env is exercised; anything else is a test bug.
[ "\$1" = "print-dev-env" ] || { echo "unexpected nix subcommand: \$1" >&2; exit 1; }
printf '{"variables":{"PATH":{"type":"exported","value":"%s"}}}\n' "$FAKE_PATH"
STUB
chmod +x "$STUB_BIN/nix"
invocations() { [ -f "$WORK/nix-invocations" ] && wc -l < "$WORK/nix-invocations" | tr -d ' ' || echo 0; }

# The script keys its cache on the repo's flake files, so give it a fixture
# repo we can mutate without touching the real one.
FAKE_REPO="$WORK/repo/skills/mcp-gateway/scripts"
mkdir -p "$FAKE_REPO"
cp "$SCRIPT" "$FAKE_REPO/toolchain-path.sh"
echo '{"nodes":{}}' > "$WORK/repo/flake.lock"
echo '{ description = "fixture"; }' > "$WORK/repo/flake.nix"
FIXTURE="$FAKE_REPO/toolchain-path.sh"

DATA="$WORK/data"; mkdir -p "$DATA"
run() {  # run [args...] - kalilix enabled, stubbed nix, fixture data dir
    CLAUDE_PLUGIN_DATA="$DATA" \
    CLAUDE_PLUGIN_OPTION_TOOL_PROVISIONING=kalilix \
    CLICKY_NIX_CANDIDATES= \
    CLICKY_NIX_STORE_PREFIX="$STORE" \
    PATH="$STUB_BIN:/usr/bin:/bin" \
    bash "$FIXTURE" "$@"
}

# --- not enabled: exit 2, and nix must never be invoked --------------------
before="$(invocations)"
CLAUDE_PLUGIN_DATA="$DATA" CLAUDE_PLUGIN_OPTION_TOOL_PROVISIONING=none \
    CLICKY_NIX_STORE_PREFIX="$STORE" PATH="$STUB_BIN:/usr/bin:/bin" bash "$FIXTURE" >/dev/null 2>&1
[ $? -eq 2 ]; check "tool_provisioning unset/none exits 2" $?
[ "$(invocations)" = "$before" ]; check "not-enabled path never invokes nix" $?

# --- cold resolve ----------------------------------------------------------
out="$(run 2>/dev/null)"; rc=$?
[ $rc -eq 0 ]; check "cold resolve succeeds" $? "exit $rc"
grep -q "aaaa-tool-1.0/bin" <<<"$out"; check "stdout carries the resolved PATH" $?
[ "$(invocations)" = "1" ]; check "nix invoked exactly once" $? "got $(invocations)"

# stdout purity matters: server.py parses this, so diagnostics must be stderr.
noise="$(run 2>/dev/null | grep -c 'toolchain-path:' || true)"
[ "$noise" = "0" ]; check "diagnostics never leak onto stdout" $?

# --- warm cache ------------------------------------------------------------
out2="$(run 2>/dev/null)"
[ "$(invocations)" = "1" ]; check "second run is a cache hit (nix not re-invoked)" $? "got $(invocations)"
[ "$out" = "$out2" ]; check "cache hit returns an identical PATH" $?

# --- --check reports health without invoking nix ---------------------------
run --check >/dev/null 2>&1
[ $? -eq 0 ]; check "--check passes on a valid cache" $?
[ "$(invocations)" = "1" ]; check "--check never invokes nix" $? "got $(invocations)"

# --- DEFECT REGRESSION: a garbage-collected store must invalidate the cache -
# Before validate-on-read, a `nix store gc` left a cache entry that read as a
# hit and handed agents a PATH of directories that no longer existed - tools
# vanished with no error anyone attributed to the cache.
rm -rf "$STORE/aaaa-tool-1.0"
run --check >/dev/null 2>&1
[ $? -ne 0 ]; check "--check FAILS when a store path has been GC'd" $?
err="$(run 2>&1 >/dev/null)"
grep -qi "discarding stale cache" <<<"$err"; check "resolve discards the stale cache" $? "$err"
[ "$(invocations)" = "2" ]; check "resolve re-invokes nix after invalidation" $? "got $(invocations)"

# --- cache key singularity -------------------------------------------------
# One derivation only: an earlier revision had a second that keyed on
# flake.lock alone and called a cold cache warm when only flake.nix changed.
before="$(invocations)"
echo '{ description = "fixture CHANGED"; }' > "$WORK/repo/flake.nix"
run >/dev/null 2>&1
[ "$(invocations)" = "$((before + 1))" ]; check "changing flake.nix invalidates the cache" $? "got $(invocations)"
[ "$(ls "$DATA"/.toolchain-path.* 2>/dev/null | wc -l | tr -d ' ')" -ge 2 ]
check "a changed flake produces a distinct cache file" $?

# --- no nix at all ---------------------------------------------------------
rm -rf "$DATA"; mkdir -p "$DATA"
out="$(CLAUDE_PLUGIN_DATA="$DATA" CLAUDE_PLUGIN_OPTION_TOOL_PROVISIONING=kalilix \
       CLICKY_NIX_CANDIDATES= CLICKY_NIX_STORE_PREFIX="$STORE" PATH=/usr/bin:/bin bash "$FIXTURE" 2>/dev/null)"; rc=$?
[ $rc -eq 1 ]; check "no nix available exits 1" $? "exit $rc"
[ -z "$out" ]; check "no nix available leaves stdout empty" $? "got '$out'"

# --- atomic write ----------------------------------------------------------
# Codex spawns one gateway per subagent, so concurrent writers are normal and a
# reader that cats a half-written file gets a truncated PATH - worse than a
# cold cache, because it looks valid.
[ -z "$(ls "$DATA"/*.tmp.* 2>/dev/null)" ]; check "no .tmp.* files left behind" $?

exit $FAILED
