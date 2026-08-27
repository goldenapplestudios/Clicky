#!/bin/bash
#
# Guards against re-committing a contributor's absolute filesystem paths
# into this repo's checked-in, generated per-CLI artifacts.
#
# Why this exists: the generated artifacts used to embed the *generating
# machine's* absolute repo path - `command = "/Users/<name>/Clicky/skills/
# mcp-gateway/scripts/launch.sh"` and a matching CLAUDE_PLUGIN_ROOT - in 23
# tracked files across .codex/, .github/agents/ and opencode.json. Two
# separate harms, both real:
#
#   1. Privacy. It published a contributor's username and home-directory
#      layout to a public repo - in a project whose whole premise is a
#      privacy-preserving gateway that keeps raw values out of model
#      context.
#
#   2. A permanently red test suite. tests/cli_targets/'s drift checks
#      compare checked-in output byte-for-byte against a fresh generation,
#      so they could only ever pass on the single machine that last ran the
#      generator. Every other contributor saw three failures that had
#      nothing to do with their changes - and "fixing" it by regenerating
#      just moved the failure to the next person.
#
# The fix was architectural, not cosmetic: every MCP client documents that
# a server's `command` is a NAME RESOLVED ON PATH (the canonical example in
# the MCP spec's own local-server guide is `"command": "npx"`), so the
# artifacts now say `clicky-gateway` and carry no path at all. See
# GATEWAY_COMMAND in tools/generate-cli-targets.py.
#
# This test locks that in. It is deliberately about the *committed* files,
# not the generator's internals - the invariant that matters is "nothing
# machine-specific is in git," however the generator happens to be written.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

FAILED=0
check() {
    local label="$1" ok="$2" detail="${3:-}"
    if [ "$ok" = "1" ]; then
        echo "PASS: $label"
    else
        echo "FAIL: $label"
        [ -n "$detail" ] && printf '%s\n' "$detail" | sed 's/^/    /'
        FAILED=1
    fi
}

cd "$REPO_ROOT" || exit 1

# Home-directory-shaped absolute paths. Deliberately broad: this should
# catch /Users/<anyone>, /home/<anyone>, and Windows-style C:\Users\<anyone>
# regardless of who generated.
LEAK_RE='(/Users/[A-Za-z0-9._-]+|/home/[A-Za-z0-9._-]+|[A-Za-z]:\\\\Users\\\\[A-Za-z0-9._-]+)'

# Only files this repo generates and commits. Not tests/ (fixtures may
# legitimately contain synthetic paths) and not docs/ (prose may show an
# example path).
GENERATED_PATHS=(
    ".codex"
    ".github/agents"
    "opencode.json"
    ".opencode"
)

echo "--- checked-in generated artifacts must contain no home-directory paths ---"
for target in "${GENERATED_PATHS[@]}"; do
    [ -e "$target" ] || continue
    # git grep, so this only ever inspects TRACKED content - an untracked
    # local build artifact is not what this test is about.
    hits="$(git grep -nIE "$LEAK_RE" -- "$target" 2>/dev/null)"
    check "no leaked absolute paths in $target" \
        "$([ -z "$hits" ] && echo 1 || echo 0)" "$hits"
done

echo "--- the gateway is registered by PATH-resolved name, not a filesystem path ---"
# Positive assertion: it's not enough that paths are absent; the artifacts
# must actually reference the launcher by name, or they'd be silently
# broken rather than merely leak-free.
for f in opencode.json .codex/agents/recon-agent.toml .github/agents/recon-agent.md; do
    [ -f "$f" ] || { echo "SKIP: $f not present"; continue; }
    check "$f registers command 'clicky-gateway'" \
        "$(grep -q 'clicky-gateway' "$f" && echo 1 || echo 0)"
    check "$f has no launch.sh path in its MCP command" \
        "$(grep -qE '(command.*launch\.sh|launch\.sh.*command)' "$f" && echo 0 || echo 1)"
done

echo "--- generated installer/wrapper scripts derive their own repo root ---"
# These are scripts rather than data, so they can and must compute their
# location at runtime instead of having it baked in.
for f in .codex/install.sh tools/run-clicky-agent.sh tools/run-clicky-copilot-agent.sh; do
    [ -f "$f" ] || { echo "SKIP: $f not present"; continue; }
    assign="$(grep -nE '^[A-Z_]*(REPO_ROOT|ROOT)=' "$f" | head -3)"
    check "$f does not hardcode an absolute repo root" \
        "$(printf '%s' "$assign" | grep -qE '=(\"|'\'')?(/Users/|/home/)' && echo 0 || echo 1)" "$assign"
done

echo "--- drift checks pass on THIS machine (the regression that motivated all of the above) ---"
if command -v python3 >/dev/null 2>&1; then
    for t in opencode codex copilot; do
        out="$(python3 tools/generate-cli-targets.py "$t" --check 2>&1)"
        check "$t artifacts are in sync regardless of clone location" \
            "$(printf '%s' "$out" | grep -q 'out of date' && echo 0 || echo 1)" "$out"
    done
else
    echo "SKIP: python3 not installed - cannot run generator drift checks"
fi

exit $FAILED
