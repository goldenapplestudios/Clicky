#!/bin/bash
#
# Checks every JavaScript file in the plugin, alongside check_bash_syntax.sh
# and check_python_syntax.sh.
#
# Three things make this less obvious than the bash/python equivalents. All
# three were established empirically against Node v24 / ESLint 10, not assumed:
#
# 1. `node --check` gives a FALSE PASS on a .js file containing ES module
#    syntax. A file with a real error - `export const meta = { name: "x"`
#    followed by `const a = ;` - exits 0 when named `.js`, and correctly exits 1
#    when named `.mjs`. Node's module-detection retry path swallows the error in
#    the ambiguous `.js` case. Files are therefore always checked through a
#    temporary `.mjs` copy, never in place.
#
# 2. Workflow scripts under workflows/ are NOT standalone ES modules. They open
#    with `export const meta` (module syntax) AND use a top-level `return`
#    (function-body semantics), because the engine evaluates the body inside a
#    function - see the `runInContext` frame in any workflow stack trace. That
#    combination is not valid JavaScript in any standard parser mode: Acorn's
#    `allowReturnOutsideFunction` (exposed by ESLint as
#    `ecmaFeatures.globalReturn`) only applies with sourceType "script", which
#    in turn forbids `export`. So a transform is genuinely required rather than
#    a parser flag: the leading `export` is dropped and the body wrapped in an
#    async function, which is what the engine does anyway. The wrapper is
#    emitted without a trailing newline so reported line numbers still match the
#    real file exactly.
#
# 3. A syntax check alone is too weak here. `phase("Scan")` misspelled as
#    `pahse("Scan")` is perfectly valid syntax and fails only at runtime, in the
#    middle of an engagement. ESLint's `no-undef`, with the workflow engine's
#    injected globals declared in workflow-eslint.config.mjs, catches exactly
#    that class of bug. ESLint is preferred; `node --check` is the fallback when
#    ESLint is unavailable, and the output says which ran so a weaker check is
#    never mistaken for the stronger one.
#
# Neither Node nor ESLint is a Clicky runtime dependency - nothing the plugin
# ships executes JavaScript outside the host CLI. They are needed only to CHECK
# these files, so this falls back to Nix (already a dependency of this repo for
# tool provisioning; `nix develop .#dev` provides both) and otherwise skips
# loudly rather than silently passing.
#
set -uo pipefail

# CLICKY_JS_CHECK_ROOT lets tests/syntax/test_js_syntax_check.sh point this
# script at fixture trees, so the checker is proven to reject broken files
# rather than merely observed to pass on a clean repo.
REPO_ROOT="${CLICKY_JS_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
CONFIG_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/workflow-eslint.config.mjs"
FAILED=0
COUNT=0

# --- resolve tooling -------------------------------------------------------
ESLINT_BIN=""; NODE_BIN=""
command -v eslint >/dev/null 2>&1 && ESLINT_BIN="$(command -v eslint)"
command -v node   >/dev/null 2>&1 && NODE_BIN="$(command -v node)"

if [ -z "$ESLINT_BIN$NODE_BIN" ] && command -v nix >/dev/null 2>&1; then
    # Resolved once, not per file: `nix shell ... --command` re-evaluates the
    # flake on every invocation, which would dominate runtime.
    p="$(nix build --no-link --print-out-paths nixpkgs#eslint 2>/dev/null | tail -1)"
    [ -n "$p" ] && [ -x "$p/bin/eslint" ] && ESLINT_BIN="$p/bin/eslint"
    p="$(nix build --no-link --print-out-paths nixpkgs#nodejs 2>/dev/null | tail -1)"
    [ -n "$p" ] && [ -x "$p/bin/node" ] && NODE_BIN="$p/bin/node"
fi

if [ -z "$ESLINT_BIN" ] && [ -z "$NODE_BIN" ]; then
    echo "SKIP: no JavaScript tooling available to check with."
    echo "  Install ESLint or Node - or Nix, which this repo already uses"
    echo "  (\`nix develop .#dev\`) - so workflows/*.js are checked rather than trusted."
    exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
declare -A ORIGIN

prepare() {  # prepare <path> -> writes a checkable .mjs into $WORK
    local script="$1" rel target
    rel="${script#"$REPO_ROOT"/}"
    target="$WORK/$(echo "$rel" | tr '/' '_').mjs"
    ORIGIN["$(basename "$target")"]="$rel"

    # Identify a workflow script by its CONTENT, not its directory: the
    # documented contract is that every workflow script begins with
    # `export const meta = {...}`. Keying off the workflows/ path instead
    # missed tests/syntax/probe-workflow-globals.js, which is a real workflow
    # script that lives elsewhere, and reported its legal top-level `return`
    # as a parse error.
    if grep -qE '^export[[:space:]]+const[[:space:]]+meta\b' "$script"; then
        # Mirror the engine: body evaluated inside a function. The wrapper
        # carries no newline, so line N here is line N in the real file.
        {
            printf '%s' 'async function __clicky_workflow_body__() {'
            sed '0,/^export[[:space:]]\{1,\}const[[:space:]]\{1,\}meta\b/s//const meta/' "$script"
            printf '\n}\n'
        } > "$target"
    else
        cat "$script" > "$target"
    fi
}

while IFS= read -r -d '' script; do
    COUNT=$((COUNT + 1))
    prepare "$script"
done < <(find "$REPO_ROOT" \
    \( -path "*/.git" -o -path "*/node_modules" -o -path "*/.venv" \) -prune -o \
    -name "*.js" -type f -print0 2>/dev/null)

if [ "$COUNT" -eq 0 ]; then
    echo "Checked 0 javascript files."
    exit 0
fi

# Rewrite temp filenames back to real repo-relative paths so errors are
# actionable rather than pointing at /tmp.
demangle() {
    local sed_args=()
    for base in "${!ORIGIN[@]}"; do
        sed_args+=(-e "s|$WORK/$base|${ORIGIN[$base]}|g")
    done
    sed "${sed_args[@]}"
}

if [ -n "$ESLINT_BIN" ] && [ -f "$CONFIG_SRC" ]; then
    cp "$CONFIG_SRC" "$WORK/eslint.config.mjs"
    # ESLint flat config only lints files under the config's base path, so the
    # config is placed alongside the copies and eslint is run from there.
    if ! out="$(cd "$WORK" && "$ESLINT_BIN" --no-config-lookup --config eslint.config.mjs ./*.mjs 2>&1)"; then
        echo "$out" | demangle | sed "s|^\./||"
        FAILED=1
    fi
    echo "Checked $COUNT javascript files with eslint $("$ESLINT_BIN" --version 2>/dev/null) (syntax + no-undef)."
else
    for target in "$WORK"/*.mjs; do
        if ! out="$("$NODE_BIN" --check "$target" 2>&1)"; then
            echo "SYNTAX ERROR: ${ORIGIN[$(basename "$target")]}"
            echo "$out" | demangle | head -12
            FAILED=1
        fi
    done
    echo "Checked $COUNT javascript files with node $("$NODE_BIN" --version) (syntax only - install ESLint for no-undef checking)."
fi

exit $FAILED
