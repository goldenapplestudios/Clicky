#!/bin/bash
#
# Tests for check_js_syntax.sh - proves the checker has teeth.
#
# A syntax checker that only ever runs against a clean repo is indistinguishable
# from one that always exits 0. These fixtures assert both directions, and
# specifically cover the two Node behaviors that make naive JS checking wrong:
#
#   * `node --check` FALSE-PASSES a .js file containing ES module syntax with a
#     real error in it (verified against Node v24). The checker must catch what
#     a plain `node --check <file>.js` misses.
#   * Workflow scripts legally use top-level `return`, which is a SyntaxError in
#     a standalone module. The checker must NOT report those as broken.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECKER="$HERE/check_js_syntax.sh"

FAILED=0
check() { if [ "$2" -eq 0 ]; then echo "PASS: $1"; else echo "FAIL: $1 ${3:-}"; FAILED=1; fi; }

if ! command -v node >/dev/null 2>&1 && ! command -v nix >/dev/null 2>&1; then
    echo "SKIP: no JS runtime and no nix - checker cannot run here"
    exit 0
fi

ROOT="$(mktemp -d)"; trap 'rm -rf "$ROOT"' EXIT
mkdir -p "$ROOT/workflows" "$ROOT/skills"

run_on() { CLICKY_JS_CHECK_ROOT="$1" bash "$CHECKER" >"$ROOT/out.txt" 2>&1; }

# A workflow-shaped file: `export const meta`, top-level await, top-level return.
cat > "$ROOT/workflows/good.js" <<'JS'
export const meta = { name: "t", description: "d", phases: [{ title: "P" }] };
phase("P");
const r = await agent("do a thing", { label: "x" });
if (!r) { log("nothing"); }
return { r };
JS
run_on "$ROOT"; rc=$?
[ "$rc" -eq 0 ]; check "valid workflow (top-level return + await) is ACCEPTED" $? "$(cat "$ROOT/out.txt")"

# Same file, genuinely broken.
cat > "$ROOT/workflows/bad.js" <<'JS'
export const meta = { name: "t", description: "d" };
const schema = {{ type: "object" };
return { schema };
JS
run_on "$ROOT"; rc=$?
[ "$rc" -ne 0 ]; check "broken workflow is REJECTED" $? "checker exited 0"
# Output format differs between checkers (eslint prints the path as a header,
# node --check prints a "SYNTAX ERROR:" line); both must name the real file.
grep -qE "workflows/bad\.js" "$ROOT/out.txt"
check "failure names the offending file" $? "$(cat "$ROOT/out.txt")"
rm "$ROOT/workflows/bad.js"

# The Node false-pass case: ESM syntax + a real error, in a plain .js file.
# `node --check` on this file directly exits 0; the checker must not.
cat > "$ROOT/skills/esm_broken.js" <<'JS'
export const meta = { name: "x"
const a = ;
JS
run_on "$ROOT"; rc=$?
[ "$rc" -ne 0 ]; check "broken ESM in a .js file is REJECTED (node --check alone false-passes this)" $? "checker exited 0"
rm "$ROOT/skills/esm_broken.js"

# Plain CommonJS-style file with an error.
printf 'function f( {\n' > "$ROOT/skills/plain_broken.js"
run_on "$ROOT"; rc=$?
[ "$rc" -ne 0 ]; check "broken plain JS is REJECTED" $?
rm "$ROOT/skills/plain_broken.js"

# no-undef: a misspelled workflow global is valid SYNTAX but fails at runtime
# mid-engagement. This is the class of bug `node --check` structurally cannot
# see, and the reason ESLint is preferred over it.
cat > "$ROOT/workflows/typo.js" <<'JS'
export const meta = { name: "t", description: "d" };
phase("Scan");
pahse("Verify");
return {};
JS
run_on "$ROOT"; rc=$?
if grep -q "with eslint" "$ROOT/out.txt"; then
    [ "$rc" -ne 0 ]; check "misspelled workflow global (pahse) is REJECTED by no-undef" $? "checker exited 0"
    grep -q "pahse" "$ROOT/out.txt"; check "failure names the offending identifier" $?
    grep -qE "workflows/typo\.js" "$ROOT/out.txt"; check "failure names the offending file" $?
    # Line numbers must map to the REAL file, not the wrapped temp copy: the
    # wrapper is emitted without a trailing newline precisely so they align.
    grep -qE "^[[:space:]]*3:" "$ROOT/out.txt"
    check "reported line number matches the real file (pahse is on line 3)" $? "$(cat "$ROOT/out.txt")"
else
    echo "SKIP: eslint unavailable - no-undef assertions not run (node --check fallback in use)"
fi
rm "$ROOT/workflows/typo.js"

# A workflow using the engine's real globals must NOT trip no-undef.
cat > "$ROOT/workflows/globals.js" <<'JS'
export const meta = { name: "t", description: "d" };
phase("P");
log(`args: ${JSON.stringify(args)}`);
const rs = await pipeline([1, 2], (i) => agent(`x ${i}`, { label: "l" }));
const ps = await parallel([() => agent("y", { label: "m" })]);
if (budget.total) { log(String(budget.remaining())); }
return { rs, ps };
JS
run_on "$ROOT"; rc=$?
[ "$rc" -eq 0 ]
check "workflow using the engine's declared globals is ACCEPTED" $? "$(cat "$ROOT/out.txt")"
rm "$ROOT/workflows/globals.js"

# The measured-globals contract: a workflow using globals the engine really
# injects must be accepted. An earlier hand-written config listed 28 of the
# real 71, so setTimeout/TypeError/Symbol/typed arrays were falsely rejected.
cat > "$ROOT/workflows/real_globals.js" <<'JS'
export const meta = { name: "t", description: "d" };
const t = setTimeout(() => log("tick"), 1);
clearTimeout(t);
const sym = Symbol("s");
const buf = new Uint8Array(4);
const view = new DataView(new ArrayBuffer(8));
const keys = Reflect.ownKeys({ a: 1 });
const big = BigInt(9);
const enc = encodeURI("a b");
const dec = decodeURIComponent("%20");
if (!buf.length) { throw new TypeError("bad"); }
return { sym, buf, view, keys, big, enc, dec, g: typeof globalThis };
JS
run_on "$ROOT"; rc=$?
[ "$rc" -eq 0 ]
check "workflow using the engine's REAL globals (setTimeout/Symbol/TypedArray/Reflect) is ACCEPTED" $? "$(cat "$ROOT/out.txt")"
rm "$ROOT/workflows/real_globals.js"

# The inverse: globals the sandbox genuinely does NOT provide must be rejected.
# This is the class of bug that killed workflows/pentest-parallel.js at runtime.
if grep -q "with eslint" "$ROOT/out.txt" 2>/dev/null || true; then :; fi
cat > "$ROOT/workflows/absent_globals.js" <<'JS'
export const meta = { name: "t", description: "d" };
const n = process.env.HOME;
return { n };
JS
run_on "$ROOT"; rc=$?
if grep -q "with eslint" "$ROOT/out.txt"; then
    [ "$rc" -ne 0 ]
    check "workflow using 'process' (absent from the sandbox) is REJECTED" $? "checker exited 0"
    grep -q "process" "$ROOT/out.txt"; check "failure names 'process'" $?
else
    echo "SKIP: eslint unavailable - absent-global assertion not run"
fi
rm "$ROOT/workflows/absent_globals.js"

# A workflow script outside workflows/ must still be recognised by content.
cat > "$ROOT/skills/stray_workflow.js" <<'JS'
export const meta = { name: "t", description: "d" };
phase("P");
return { ok: true };
JS
run_on "$ROOT"; rc=$?
[ "$rc" -eq 0 ]
check "workflow script OUTSIDE workflows/ is detected by content, not path" $? "$(cat "$ROOT/out.txt")"
rm "$ROOT/skills/stray_workflow.js"

# Valid plain JS is fine.
printf 'const a = 1;\nfunction f(x) { return x + a; }\n' > "$ROOT/skills/plain_ok.js"
run_on "$ROOT"; rc=$?
[ "$rc" -eq 0 ]; check "valid plain JS is ACCEPTED" $? "$(cat "$ROOT/out.txt")"

# The checker must actually look at files, not report a vacuous success.
grep -qE "Checked [1-9][0-9]* javascript files" "$ROOT/out.txt"
check "reports a non-zero count of files checked" $? "$(cat "$ROOT/out.txt")"

# The real repo must pass.
REAL_ROOT="$(cd "$HERE/../.." && pwd)"
run_on "$REAL_ROOT"; rc=$?
[ "$rc" -eq 0 ]; check "the real repository's JavaScript passes" $? "$(cat "$ROOT/out.txt")"

exit $FAILED
