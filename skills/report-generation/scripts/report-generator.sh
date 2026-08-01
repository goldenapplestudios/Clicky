#!/bin/bash
#
# Report Generator - aggregate session data into a penetration test report
#
# Usage:
#   report-generator.sh --session-id ID [--format markdown|html|pdf] [--output FILE]
#                        [--template pentest|vuln-assessment|red-team|webapp]
#                        [--include-evidence] [--include-appendices]
#   report-generator.sh metrics --session-id ID
#   report-generator.sh priorities --session-id ID
#   report-generator.sh validate [--input FILE] [--session-id ID]
#   report-generator.sh sanitize --input FILE --output FILE
#   report-generator.sh aggregate --session ID --output FILE
#   report-generator.sh auto --session ID [--detect-vulns] [--calculate-cvss] [--collect-evidence]
#

set -uo pipefail

SESSION_BASE="${CLAUDE_PLUGIN_OPTION_DEFAULT_SESSION_DIRECTORY:-$HOME/.claude/sessions}"

session_dir_for() {
    local dir="$SESSION_BASE/$1"
    # Fall back to the archived/ subdirectory - archive_session() (in
    # session-management/scripts/session-manager.sh) moves a session's
    # whole directory there, so a bare $SESSION_BASE/$1 lookup alone would
    # silently see "no findings.json" for any archived session.
    if [ ! -d "$dir" ] && [ -d "$SESSION_BASE/archived/$1" ]; then
        dir="$SESSION_BASE/archived/$1"
    fi
    echo "$dir"
}

findings_file_for() {
    local dir
    dir=$(session_dir_for "$1")
    echo "$dir/reports/findings.json"
}

# --- aggregate ---
aggregate() {
    local session_id="" output=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --session) session_id="$2"; shift 2 ;;
            --output) output="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    : "${session_id:?--session required}"

    local findings_file
    findings_file=$(findings_file_for "$session_id")
    if [ ! -f "$findings_file" ]; then
        echo '{"findings": []}' > "${output:-/dev/stdout}"
        echo "WARNING: no findings.json for session $session_id yet (nothing logged via session-manager.sh log)" >&2
        return 0
    fi

    if [ -n "$output" ]; then
        cp "$findings_file" "$output"
        echo "Aggregated findings -> $output"
    else
        cat "$findings_file"
    fi
}

# --- metrics ---
metrics() {
    local session_id=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --session-id) session_id="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    : "${session_id:?--session-id required}"

    local session_dir findings_file
    session_dir=$(session_dir_for "$session_id")
    findings_file=$(findings_file_for "$session_id")

    if [ ! -f "$findings_file" ]; then
        echo "No findings recorded for session $session_id yet."
        return 0
    fi

    local total avg_cvss creds
    total=$(jq '.findings | length' "$findings_file")
    avg_cvss=$(jq '[.findings[] | select(.cvss != null) | .cvss] | if length > 0 then (add / length) else 0 end' "$findings_file" 2>/dev/null || echo 0)
    creds=0
    if [ -f "$session_dir/credentials/credential_store.json" ]; then
        creds=$(jq '.credentials | length' "$session_dir/credentials/credential_store.json" 2>/dev/null || echo 0)
    fi

    echo "Total findings: $total"
    echo "Average CVSS (where scored): $avg_cvss"
    echo "Credentials compromised: $creds"
    for sev in CRITICAL HIGH MEDIUM LOW INFO; do
        local count
        count=$(jq --arg s "$sev" '[.findings[] | select(.severity == $s)] | length' "$findings_file")
        echo "  $sev: $count"
    done
}

# --- priorities ---
priorities() {
    local session_id=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --session-id) session_id="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    : "${session_id:?--session-id required}"

    local findings_file
    findings_file=$(findings_file_for "$session_id")
    if [ ! -f "$findings_file" ]; then
        echo "No findings recorded for session $session_id yet."
        return 0
    fi

    echo "Priority 1 (Immediate):"
    jq -r '.findings[] | select(.severity == "CRITICAL") | "  - [ ] " + .description' "$findings_file"
    echo
    echo "Priority 2 (30 days):"
    jq -r '.findings[] | select(.severity == "HIGH") | "  - [ ] " + .description' "$findings_file"
    echo
    echo "Priority 3 (90 days):"
    jq -r '.findings[] | select(.severity == "MEDIUM" or .severity == "LOW") | "  - [ ] " + .description' "$findings_file"
}

# --- validate ---
# --input checks a rendered report file (text-linting: CVSS mentioned,
# evidence present, no obvious cleartext creds left in). --session-id
# checks findings.json structurally: any CRITICAL/HIGH finding that Tier 1
# (finding-validator.sh) flagged as "fail", or Tier 2 (verification-agent)
# marked "refuted", is a hard FAIL - self-reported severity alone is never
# enough. Either or both flags may be given.
validate() {
    local input="" session_id=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --input) input="$2"; shift 2 ;;
            --session-id) session_id="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    if [ -z "$input" ] && [ -z "$session_id" ]; then
        echo "ERROR: provide --input <report file> and/or --session-id <id>" >&2
        exit 1
    fi

    local pass=1
    check() {
        if [ "$2" -eq 0 ]; then
            echo "  X $1"
            pass=0
        else
            echo "  OK $1"
        fi
    }

    if [ -n "$input" ]; then
        [ -f "$input" ] || { echo "ERROR: file not found: $input" >&2; exit 1; }
        echo "Validating report text: $input"
        grep -qi "CVSS" "$input"; check "Findings have CVSS scores" $([ $? -eq 0 ] && echo 1 || echo 0)
        grep -qiE "screenshot|evidence|proof of concept" "$input"; check "Evidence/PoC present" $([ $? -eq 0 ] && echo 1 || echo 0)
        grep -qi "remediation" "$input"; check "Remediation guidance included" $([ $? -eq 0 ] && echo 1 || echo 0)
        ! grep -qE '\b(password|passwd)\s*[:=]\s*[^ ]{4,}' "$input"; check "No obvious cleartext credentials left in report" $([ $? -eq 0 ] && echo 1 || echo 0)
    fi

    if [ -n "$session_id" ]; then
        local findings_file
        findings_file=$(findings_file_for "$session_id")
        if [ -f "$findings_file" ]; then
            echo "Validating findings.json structurally for session: $session_id"
            local failing
            failing=$(jq -r '
                [.findings[] |
                 select(.severity == "CRITICAL" or .severity == "HIGH") |
                 select(((.validation.tier1_trace_check // "not_run") == "fail") or ((.validation.tier2_review // "not_required") == "refuted")) |
                 .id] | join(", ")
            ' "$findings_file" 2>/dev/null)
            if [ -n "$failing" ]; then
                echo "  X No CRITICAL/HIGH finding failed Tier 1 trace validation or was refuted by Tier 2 review"
                echo "    Failing: $failing (see their validation.tier1_notes/tier2_notes in findings.json)"
                pass=0
            else
                echo "  OK No CRITICAL/HIGH finding failed Tier 1 trace validation or was refuted by Tier 2 review"
            fi
        else
            echo "  (no findings.json yet for session $session_id - skipping structural check)"
        fi
    fi

    echo
    if [ "$pass" -eq 1 ]; then
        echo "PASS - report looks ready for review"
    else
        echo "FAIL - address the items marked X above before delivery"
    fi
}

# --- sanitize ---
sanitize() {
    local input="" output=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --input) input="$2"; shift 2 ;;
            --output) output="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    : "${input:?--input required}"
    : "${output:?--output required}"
    [ -f "$input" ] || { echo "ERROR: file not found: $input" >&2; exit 1; }

    # Uses Python's re module rather than sed - BSD sed (macOS default)
    # doesn't support \b word boundaries at all, which silently no-ops
    # every pattern below and was caught in testing before this fix.
    python3 - "$input" "$output" << 'PYEOF'
import re
import sys

infile, outfile = sys.argv[1], sys.argv[2]
with open(infile) as f:
    text = f.read()

patterns = [
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", "[REDACTED PRIVATE KEY]", re.DOTALL),
    (r"(?i)\b(api[ _-]?key[^:=]*[:=][ \"']*)[A-Za-z0-9_-]{16,}", r"\1[REDACTED]", 0),
    (r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "[INTERNAL_IP_REDACTED]", 0),
    (r"\b192\.168\.\d{1,3}\.\d{1,3}\b", "[INTERNAL_IP_REDACTED]", 0),
    (r"\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b", "[INTERNAL_IP_REDACTED]", 0),
]

for pattern, repl, flags in patterns:
    text = re.sub(pattern, repl, text, flags=flags)

with open(outfile, "w") as f:
    f.write(text)
PYEOF

    echo "Sanitized -> $output"
    echo "NOTE: this catches common patterns (private keys, api_key=..., RFC1918 IPs) - always"
    echo "manually review before client delivery, this is a first pass, not a guarantee."
}

# --- markdown/html/pdf report generation ---
generate() {
    local session_id="" format="markdown" output="" template="pentest"
    while [ $# -gt 0 ]; do
        case "$1" in
            # --session accepted as an alias: main()'s `auto` action forwards
            # its own "$@" (which uses --session, matching aggregate()'s
            # flag) straight into generate() unmodified - without this alias
            # `auto --session ID` always crashed here with "--session-id
            # required" since generate() never saw the session id at all.
            --session-id|--session) session_id="$2"; shift 2 ;;
            --format) format="$2"; shift 2 ;;
            --output) output="$2"; shift 2 ;;
            --template) template="$2"; shift 2 ;;
            --include-evidence|--include-appendices|--include-sections) shift 2 ;;
            *) shift ;;
        esac
    done
    : "${session_id:?--session-id required}"

    local session_dir findings_file
    session_dir=$(session_dir_for "$session_id")
    findings_file=$(findings_file_for "$session_id")

    local md
    md=$(mktemp)
    {
        echo "# Penetration Test Report"
        echo
        echo "## Executive Summary"
        echo
        if [ -f "$session_dir/session.json" ]; then
            echo "**Target**: $(jq -r '.target' "$session_dir/session.json" 2>/dev/null)"
            echo "**Started**: $(jq -r '.start_time' "$session_dir/session.json" 2>/dev/null)"
        fi
        echo "**Template**: $template"
        echo
        echo "## Findings"
        echo
        if [ -f "$findings_file" ]; then
            # A finding only counts as confirmed once Tier 1 (trace cross-check)
            # passed AND Tier 2 (independent review, CRITICAL/HIGH only)
            # didn't refute or leave it inconclusive. Anything else -
            # including a finding with no validation info at all, e.g. from
            # before this pipeline existed - goes to the Unverified section
            # rather than being silently treated as confirmed.
            local confirmed_filter unverified_filter
            confirmed_filter='(.validation.tier1_trace_check // "not_run") == "pass" and ((.validation.tier2_review // "not_required") == "not_required" or (.validation.tier2_review // "not_required") == "confirmed")'
            unverified_filter='((.validation.tier1_trace_check // "not_run") != "pass") or ((.validation.tier2_review // "not_required") == "refuted") or ((.validation.tier2_review // "not_required") == "inconclusive")'

            local confirmed_count unverified_count
            confirmed_count=$(jq "[.findings[] | select($confirmed_filter)] | length" "$findings_file")
            unverified_count=$(jq "[.findings[] | select($unverified_filter)] | length" "$findings_file")

            echo "### Confirmed Findings ($confirmed_count)"
            echo
            if [ "$confirmed_count" -gt 0 ]; then
                jq -r '
                    .findings[]
                    | select((.validation.tier1_trace_check // "not_run") == "pass"
                             and ((.validation.tier2_review // "not_required") == "not_required"
                                  or (.validation.tier2_review // "not_required") == "confirmed"))
                    | "#### [\(.severity)] \(.description)\n\n- Evidence: `\(.evidence.command // "n/a")`\n- Source: \(.source_agent // "unknown")\n"
                ' "$findings_file"
            else
                echo "_None yet._"
                echo
            fi

            if [ "$unverified_count" -gt 0 ]; then
                echo "### Unverified / Needs Manual Review ($unverified_count)"
                echo
                echo "_These findings did not pass automatic validation - do not present them to a client as confirmed without manual review._"
                echo
                jq -r '
                    .findings[]
                    | select(((.validation.tier1_trace_check // "not_run") != "pass")
                             or ((.validation.tier2_review // "not_required") == "refuted")
                             or ((.validation.tier2_review // "not_required") == "inconclusive"))
                    | "#### [\(.severity)] \(.description)\n\n- Evidence: `\(.evidence.command // "n/a")`\n- Tier 1: \(.validation.tier1_trace_check // "not_run") - \(.validation.tier1_notes // "")\n- Tier 2: \(.validation.tier2_review // "not_required") - \(.validation.tier2_notes // "")\n"
                ' "$findings_file"
            fi
        else
            echo "_No findings recorded for this session yet._"
        fi
    } > "$md"

    case "$format" in
        markdown)
            if [ -n "$output" ]; then cp "$md" "$output"; echo "Report written -> $output"; else cat "$md"; fi
            ;;
        html|pdf)
            if command -v pandoc >/dev/null 2>&1; then
                local out="${output:-report.$format}"
                pandoc "$md" -o "$out"
                echo "Report written -> $out"
            else
                echo "pandoc not found - cannot convert to $format. Falling back to markdown." >&2
                if [ -n "$output" ]; then cp "$md" "${output%.${format}}.md"; else cat "$md"; fi
            fi
            ;;
        *)
            echo "Unknown format: $format" >&2
            rm -f "$md"
            exit 1
            ;;
    esac
    rm -f "$md"
}

main() {
    local cmd="${1:-generate}"
    case "$cmd" in
        metrics) shift; metrics "$@" ;;
        priorities) shift; priorities "$@" ;;
        validate) shift; validate "$@" ;;
        sanitize) shift; sanitize "$@" ;;
        aggregate) shift; aggregate "$@" ;;
        auto) shift; aggregate --session "$(echo "$@" | grep -oE '\-\-session [^ ]+' | awk '{print $2}')" ; generate "$@" ;;
        --session-id|--format|--output|--template) generate "$@" ;;
        *) generate "$@" ;;
    esac
}

main "$@"
