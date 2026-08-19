#!/bin/bash
#
# Headless /pentest invocation wrapper, for external orchestrators that
# need "one subprocess call in, one result path out" - built for
# Springtale's planned connector-clicky (see
# docs/integrations/springtale.md), but not Springtale-specific.
#
# Spawns a Clicky-capable CLI non-interactively to run a full pentest
# engagement, waits for it to exit, then locates the session directory
# the run created and prints a single JSON line describing where the
# results landed.
#
# Session-directory discovery is a before/after snapshot diff of
# $SESSION_BASE (the same base directory session-manager.sh uses:
# $CLAUDE_PLUGIN_OPTION_DEFAULT_SESSION_DIRECTORY or ~/.claude/sessions),
# not a read of $SESSION_BASE/.current-session - that pointer file is
# explicitly documented in session-manager.sh's create_session as
# best-effort/last-writer-wins ("A concurrent second /pentest run will
# overwrite this pointer"), so it isn't safe to trust from a wrapper a
# second process might also be driving concurrently. The diff approach
# has no such race as long as this script's own invocations don't
# overlap with each other for the same target CLI.
#
# Usage:
#   tools/run-headless.sh <target> ["context"]
#       [--cli claude|codex|copilot] [--plugin-root PATH]
#       [--max-budget-usd N] [--report-format markdown|html|pdf]
#       [--report-out FILE]
#
# CLI support (only what has a real, live-verified non-interactive
# invocation today - see tools/generate-cli-targets.py's per-CLI doc
# comments for the evidence trail behind each):
#   claude   - `claude -p "/pentest ..." --output-format json
#              --permission-mode bypassPermissions --plugin-dir ...`.
#              Default; the only one verified live end-to-end this
#              session (real dispatch against scanme.nmap.org).
#   codex    - delegates to the already-generated tools/run-clicky-agent.sh
#              (`codex exec -m gpt-5.4 --disable shell_tool`). Requires
#              `.codex/install.sh` to have been run once first (global
#              MCP + prompt registration - Codex has no project-relative
#              discovery).
#   copilot  - delegates to the already-generated
#              tools/run-clicky-copilot-agent.sh. Copilot CLI has no
#              /pentest-equivalent slash command (confirmed: no custom
#              slash-command system exists in this version) - the
#              orchestrator agent IS the entry point, so it's given the
#              target/context directly, not a "/pentest ..." string.
#   opencode - NOT wired here. No generated wrapper script exists for it
#              yet (only Codex and Copilot have one under tools/); add
#              one following the same pattern before adding "opencode"
#              here, rather than guessing its exact non-interactive
#              invocation shape.
#
# stdout on success (and only on success): one JSON line -
#   {"session_id":"...","session_dir":"...","findings_json":"..."|null,"report":"..."|null}
#
# Exit codes: 0 success, 1 usage error, 2 CLI invocation failed,
# 3 could not identify the resulting session directory.
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SESSION_BASE="${CLAUDE_PLUGIN_OPTION_DEFAULT_SESSION_DIRECTORY:-$HOME/.claude/sessions}"

usage() {
    echo "Usage: $0 <target> [\"context\"] [--cli claude|codex|copilot] [--plugin-root PATH] [--max-budget-usd N] [--report-format markdown|html|pdf] [--report-out FILE]" >&2
    exit 1
}

[ $# -ge 1 ] || usage
target="$1"; shift
context=""
if [ $# -gt 0 ] && [[ "$1" != --* ]]; then
    context="$1"; shift
fi

cli="claude"
plugin_root="$HERE"
max_budget_usd=""
report_format=""
report_out=""

while [ $# -gt 0 ]; do
    case "$1" in
        --cli) cli="$2"; shift 2 ;;
        --plugin-root) plugin_root="$2"; shift 2 ;;
        --max-budget-usd) max_budget_usd="$2"; shift 2 ;;
        --report-format) report_format="$2"; shift 2 ;;
        --report-out) report_out="$2"; shift 2 ;;
        *) usage ;;
    esac
done

mkdir -p "$SESSION_BASE"

before="$(mktemp)"
after="$(mktemp)"
trap 'rm -f "$before" "$after"' EXIT
find "$SESSION_BASE" -maxdepth 1 -type d -name 'pentest_*' 2>/dev/null | sort > "$before"

prompt="/pentest $target"
[ -n "$context" ] && prompt="$prompt \"$context\""

case "$cli" in
    claude)
        claude_args=(-p "$prompt" --output-format json --permission-mode bypassPermissions
                      --plugin-dir "$plugin_root" --no-session-persistence)
        [ -n "$max_budget_usd" ] && claude_args+=(--max-budget-usd "$max_budget_usd")
        claude "${claude_args[@]}" >/dev/null \
            || { echo "ERROR: claude invocation failed" >&2; exit 2; }
        ;;
    codex)
        "$plugin_root/tools/run-clicky-agent.sh" "$prompt" >/dev/null \
            || { echo "ERROR: codex invocation failed (has .codex/install.sh been run once?)" >&2; exit 2; }
        ;;
    copilot)
        copilot_prompt="$target"
        [ -n "$context" ] && copilot_prompt="$copilot_prompt $context"
        "$plugin_root/tools/run-clicky-copilot-agent.sh" "$copilot_prompt" >/dev/null \
            || { echo "ERROR: copilot invocation failed" >&2; exit 2; }
        ;;
    *)
        echo "ERROR: unsupported --cli '$cli' (claude|codex|copilot)" >&2
        exit 1
        ;;
esac

find "$SESSION_BASE" -maxdepth 1 -type d -name 'pentest_*' 2>/dev/null | sort > "$after"
new_dir="$(comm -13 "$before" "$after" | head -1)"

if [ -z "$new_dir" ]; then
    echo "ERROR: could not identify a new session directory under $SESSION_BASE after the run" >&2
    exit 3
fi

session_id="$(basename "$new_dir")"

findings_json="$new_dir/reports/findings.json"
findings_json_out="null"
[ -f "$findings_json" ] && findings_json_out="\"$findings_json\""

report_out_json="null"
if [ -n "$report_format" ]; then
    out="${report_out:-$new_dir/reports/report.$report_format}"
    if "$HERE/skills/report-generation/scripts/report-generator.sh" \
        --session-id "$session_id" --format "$report_format" --output "$out" >&2; then
        [ -f "$out" ] && report_out_json="\"$out\""
    else
        echo "WARNING: report-generator.sh failed - findings_json is still available" >&2
    fi
fi

printf '{"session_id":"%s","session_dir":"%s","findings_json":%s,"report":%s}\n' \
    "$session_id" "$new_dir" "$findings_json_out" "$report_out_json"
