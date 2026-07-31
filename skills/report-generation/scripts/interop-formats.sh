#!/bin/bash
#
# Interop Formats - export a session's source/dependency findings as
# standard CI/tooling-consumed formats (SARIF, CycloneDX), separate from
# report-generator.sh's human-facing markdown/html/pdf narrative report -
# different source files, different consumers.
#
# Usage:
#   interop-formats.sh sarif        --session-id ID [--output FILE]
#   interop-formats.sh sbom-partial --session-id ID [--output FILE]
#
# "sbom-partial" is named that deliberately, not "sbom" - see
# cyclonedx_convert.py's header comment. dependency-scanner.sh's upstream
# tools only ever report packages with a known vulnerability, so this is
# a vulnerability-derived partial component list, not a true software
# inventory. Presenting it as an unqualified "SBOM" to a consumer
# expecting CycloneDX's normal completeness guarantee would mislead them.
#
# Both converters validate their own output shape only implicitly (by
# construction against the real schemas during development - see
# skills/report-generation/SKILL.md); this script does not re-validate
# against the SARIF/CycloneDX JSON Schemas at runtime, so a Clicky version
# upgrade that changes source_findings.json/dependency_findings.json's
# shape without also updating these converters could silently produce
# invalid output. Re-check after any change to those upstream shapes.
#

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION_BASE="${CLAUDE_PLUGIN_OPTION_DEFAULT_SESSION_DIRECTORY:-$HOME/.claude/sessions}"

usage() {
    echo "Usage:" >&2
    echo "  $0 sarif        --session-id ID [--output FILE]" >&2
    echo "  $0 sbom-partial --session-id ID [--output FILE]" >&2
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

main() {
    local cmd="${1:-}"
    case "$cmd" in
        sarif) shift; sarif "$@" ;;
        sbom-partial) shift; sbom_partial "$@" ;;
        *) usage ;;
    esac
}

main "$@"
