#!/bin/bash
#
# Interop Formats - export a session's source/dependency findings as
# standard CI/tooling-consumed formats (SARIF, CycloneDX), separate from
# report-generator.sh's human-facing markdown/html/pdf narrative report -
# different source files, different consumers.
#
# Usage:
#   interop-formats.sh sarif         --session-id ID [--output FILE]
#   interop-formats.sh sbom-partial  --session-id ID [--output FILE]
#   interop-formats.sh aibom-partial --session-id ID [--output FILE]
#
# "sbom-partial"/"aibom-partial" are named that deliberately, not
# "sbom"/"aibom" - see cyclonedx_convert.py's and aibom_convert.py's
# header comments. dependency-scanner.sh's upstream tools only ever
# report packages with a known vulnerability, and the AI/LLM probes only
# ever see how an endpoint responds over HTTP - neither is a true
# software/model inventory. Presenting either as an unqualified
# "SBOM"/"AIBOM" to a consumer expecting CycloneDX's normal completeness
# guarantee would mislead them.
#
# All three converters validate their own output shape only implicitly
# (by construction against the real schemas during development - see
# skills/report-generation/SKILL.md); this script does not re-validate
# against the SARIF/CycloneDX JSON Schemas at runtime, so a Clicky version
# upgrade that changes source_findings.json/dependency_findings.json/
# llm_probe_*.json's shape without also updating these converters could
# silently produce invalid output. Re-check after any change to those
# upstream shapes.
#

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION_BASE="${CLAUDE_PLUGIN_OPTION_DEFAULT_SESSION_DIRECTORY:-$HOME/.claude/sessions}"

usage() {
    echo "Usage:" >&2
    echo "  $0 sarif         --session-id ID [--output FILE]" >&2
    echo "  $0 sbom-partial  --session-id ID [--output FILE]" >&2
    echo "  $0 aibom-partial --session-id ID [--output FILE]" >&2
    exit 1
}

session_dir_for() {
    local dir="$SESSION_BASE/$1"
    if [ ! -d "$dir" ] && [ -d "$SESSION_BASE/archived/$1" ]; then
        dir="$SESSION_BASE/archived/$1"
    fi
    echo "$dir"
}

sarif() {
    local session_id="" output=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --session-id) session_id="$2"; shift 2 ;;
            --output) output="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    : "${session_id:?--session-id required}"
    command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 required" >&2; exit 1; }

    local session_dir; session_dir=$(session_dir_for "$session_id")
    local findings_file="$session_dir/recon/source_findings.json"
    [ -f "$findings_file" ] || { echo "ERROR: no source_findings.json for session $session_id - run source-analyzer-agent (white-box analysis) first" >&2; exit 1; }

    local result
    result=$(python3 "$SCRIPT_DIR/sarif_convert.py" "$findings_file") || exit 1

    if [ -n "$output" ]; then
        echo "$result" > "$output"
        echo "SARIF export -> $output" >&2
    else
        echo "$result"
    fi
}

sbom_partial() {
    local session_id="" output=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --session-id) session_id="$2"; shift 2 ;;
            --output) output="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    : "${session_id:?--session-id required}"
    command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 required" >&2; exit 1; }

    local session_dir; session_dir=$(session_dir_for "$session_id")
    local findings_file="$session_dir/recon/dependency_findings.json"
    [ -f "$findings_file" ] || { echo "ERROR: no dependency_findings.json for session $session_id - run source-analyzer-agent (white-box analysis) first" >&2; exit 1; }

    local result
    result=$(python3 "$SCRIPT_DIR/cyclonedx_convert.py" "$findings_file") || exit 1

    if [ -n "$output" ]; then
        echo "$result" > "$output"
        echo "Partial SBOM export (vulnerability-derived, not a full inventory - see SKILL.md) -> $output" >&2
    else
        echo "$result"
    fi
}

aibom_partial() {
    local session_id="" output=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --session-id) session_id="$2"; shift 2 ;;
            --output) output="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    : "${session_id:?--session-id required}"
    command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 required" >&2; exit 1; }

    local session_dir; session_dir=$(session_dir_for "$session_id")
    local recon_dir="$session_dir/recon"
    ls "$recon_dir"/llm_probe_*.json >/dev/null 2>&1 || { echo "ERROR: no llm_probe_*.json for session $session_id - run skills/ai-llm-security-testing's prompt-injection-probe.sh first" >&2; exit 1; }

    local result
    result=$(python3 "$SCRIPT_DIR/aibom_convert.py" "$recon_dir") || exit 1

    if [ -n "$output" ]; then
        echo "$result" > "$output"
        echo "Partial AIBOM export (black-box-probe-derived, not a full model inventory - see SKILL.md) -> $output" >&2
    else
        echo "$result"
    fi
}

main() {
    local cmd="${1:-}"
    case "$cmd" in
        sarif) shift; sarif "$@" ;;
        sbom-partial) shift; sbom_partial "$@" ;;
        aibom-partial) shift; aibom_partial "$@" ;;
        *) usage ;;
    esac
}

main "$@"
