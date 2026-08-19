#!/bin/bash
#
# Cross-model-family dispatch for severity-analyst-agent's Tier 3 review
# (see agents/severity-analyst-agent.md, docs/workflow.md's Phase 6 section).
#
# Why this exists rather than just Task-dispatching severity-analyst-agent
# like every other agent: research this design is based on found that
# same-model-family "adversarial" reviewers share correlated blind spots
# that get WORSE with capability, not better - in one documented case, 80+
# agents including dedicated adversarial reviewers unanimously endorsed a
# vulnerability that did not exist. Running the critique through a genuinely
# different model family is the stronger mitigation the research points to.
#
# This is deliberately NOT a full multi-CLI dispatch like tools/run-headless.sh
# - the critique task needs zero MCP/gateway tools (the draft report and
# findings.json are already redacted/tokenized by the time report-agent
# produces them, so it's safe to hand their text directly to an external
# model with no target/credential access at all). That means this script
# needs only a bare `codex` binary, authenticated - NOT the full Clicky
# Codex integration (.codex/install.sh's MCP+prompt registration is
# unnecessary here and deliberately skipped).
#
# Usage:
#   tools/run-severity-critique.sh --report FILE --findings FILE
#       [--calibration FILE] [--model MODEL] [--output FILE]
#
# Exit codes:
#   0  success - critique JSON written to --output (or stdout)
#   1  usage error
#   2  codex CLI not installed/available - caller should fall back to
#      Task-dispatching severity-analyst-agent as an ordinary same-family
#      Claude subagent instead (see commands/pentest.md Step 11). This is
#      an expected, handled outcome, not a hard failure of the pipeline -
#      same "never hard-fail, degrade and say so" posture as
#      skills/tool-management/scripts/tool-fallback.sh.
#   3  codex ran but didn't return parseable JSON
#
# On --model: unlike tools/run-clicky-agent.sh's Codex wrapper (which pins
# -m gpt-5.4 specifically to avoid a bug that silently drops MCP tool
# exposure, openai/codex#32101), this script makes NO MCP tool calls at
# all - it's a plain text-in/JSON-out task. Whether that pin still helps
# critique QUALITY (as opposed to tool exposure) here is an open,
# unverified question, not something to assume either way - see the
# implementation plan's Verification section. Defaults to Codex's own
# default model; pass --model to override once that's been checked.
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
    echo "Usage: $0 --report FILE --findings FILE [--calibration FILE] [--model MODEL] [--output FILE]" >&2
    exit 1
}

report_file=""
findings_file=""
calibration_file=""
model=""
output_file=""

while [ $# -gt 0 ]; do
    case "$1" in
        --report) report_file="$2"; shift 2 ;;
        --findings) findings_file="$2"; shift 2 ;;
        --calibration) calibration_file="$2"; shift 2 ;;
        --model) model="$2"; shift 2 ;;
        --output) output_file="$2"; shift 2 ;;
        *) usage ;;
    esac
done

[ -n "$report_file" ] || usage
[ -n "$findings_file" ] || usage
[ -f "$report_file" ] || { echo "ERROR: report file not found: $report_file" >&2; exit 1; }
[ -f "$findings_file" ] || { echo "ERROR: findings file not found: $findings_file" >&2; exit 1; }

if ! command -v codex >/dev/null 2>&1; then
    echo "ERROR: codex CLI not found on PATH - cross-family review unavailable." >&2
    echo "Caller should fall back to Task-dispatching severity-analyst-agent" >&2
    echo "as a same-family Claude subagent instead (weaker calibration signal," >&2
    echo "but still valuable per the framing/isolation mitigations alone)." >&2
    exit 2
fi

AGENT_FILE="$HERE/agents/severity-analyst-agent.md"
[ -f "$AGENT_FILE" ] || { echo "ERROR: $AGENT_FILE not found" >&2; exit 1; }

command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 required" >&2; exit 1; }

PROMPT_FILE="$(mktemp)"
RAW_OUT="$(mktemp)"
trap 'rm -f "$PROMPT_FILE" "$RAW_OUT"' EXIT

python3 - "$AGENT_FILE" "$report_file" "$findings_file" "${calibration_file:-}" > "$PROMPT_FILE" << 'PYEOF'
import sys

agent_path, report_path, findings_path, calibration_path = sys.argv[1:5]

with open(agent_path) as f:
    agent_text = f.read()

# Strip YAML frontmatter (between the first two '---' lines).
lines = agent_text.split("\n")
if lines and lines[0].strip() == "---":
    end = next((i for i in range(1, len(lines)) if lines[i].strip() == "---"), None)
    if end is not None:
        lines = lines[end + 1:]
agent_text = "\n".join(lines)

# Drop the "## Gateway Calling Convention" section - irrelevant here, this
# invocation has no gateway tools at all (see this script's own header).
out_lines = []
skipping = False
for line in agent_text.split("\n"):
    if line.strip() == "## Gateway Calling Convention":
        skipping = True
        continue
    if skipping and line.startswith("## "):
        skipping = False
    if not skipping:
        out_lines.append(line)
agent_text = "\n".join(out_lines).strip()

with open(report_path) as f:
    report_text = f.read()
with open(findings_path) as f:
    findings_text = f.read()

calibration_text = ""
if calibration_path:
    try:
        with open(calibration_path) as f:
            calibration_text = f.read()
    except OSError:
        pass

print(agent_text)
print()
print("---")
print()
print("You are being run as a standalone, self-contained task with no tools of")
print("your own - everything you need is inlined below. Respond with EXACTLY")
print("ONE JSON object matching the Output Format section above, and nothing")
print("else - no markdown fencing, no prose before or after it.")
print()
print("## Drafted report (final_report.md)")
print()
print(report_text)
print()
print("## findings.json")
print()
print(findings_text)
if calibration_text:
    print()
    print("## Historical severity-calibration data (.severity-calibration.json)")
    print()
    print(calibration_text)
PYEOF

codex_args=(exec)
[ -n "$model" ] && codex_args+=(-m "$model")

codex "${codex_args[@]}" "$(cat "$PROMPT_FILE")" > "$RAW_OUT" 2>&1 \
    || { echo "ERROR: codex exec failed" >&2; cat "$RAW_OUT" >&2; exit 2; }

# Best-effort JSON extraction: codex's own preamble/thinking text (if any)
# may surround the JSON object - find the first '{' through the matching
# last '}' rather than assuming the whole stdout is bare JSON.
critique_json="$(python3 - "$RAW_OUT" << 'PYEOF'
import sys, json

with open(sys.argv[1]) as f:
    text = f.read()

start = text.find("{")
end = text.rfind("}")
if start == -1 or end == -1 or end < start:
    sys.exit(1)

candidate = text[start:end + 1]
try:
    json.loads(candidate)
except json.JSONDecodeError:
    sys.exit(1)

print(candidate)
PYEOF
)" || { echo "ERROR: codex did not return parseable JSON - raw output:" >&2; cat "$RAW_OUT" >&2; exit 3; }

if [ -n "$output_file" ]; then
    printf '%s\n' "$critique_json" > "$output_file"
    echo "Severity critique written -> $output_file (review_mode: cross_family_codex)"
else
    printf '%s\n' "$critique_json"
fi
