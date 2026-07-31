#!/bin/bash
#
# Dependency Scanner - wraps whichever dependency-vulnerability tool is
# actually installed and normalizes its output into one common JSON shape.
# Prefers `trivy fs` (covers npm/pip/gem/go and more from one pass over
# whatever lockfiles it finds); falls back to per-ecosystem native tools
# (npm audit, pip-audit, bundler-audit, govulncheck) for whichever manifest
# files are present. This is the concrete implementation behind
# skills/web-vulnerability-testing/SKILL.md's OWASP A03:2025
# (supply-chain/vulnerable-components) checklist item.
#
# Usage: dependency-scanner.sh --dir <source_dir> [--output <json_file>]
#
# A manifest found with no matching tool installed is reported in
# "skipped", not silently dropped - the caller (source-analyzer-agent)
# should surface that as "could not check" rather than "no vulnerabilities".
#

set -uo pipefail

DIR="" OUTPUT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --dir) DIR="$2"; shift 2 ;;
        --output) OUTPUT="$2"; shift 2 ;;
        *) shift ;;
    esac
done
: "${DIR:?--dir required}"
[ -d "$DIR" ] || { echo "ERROR: directory not found: $DIR" >&2; exit 1; }

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 required" >&2
    exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

scanners_run=()
skipped=()

if command -v trivy >/dev/null 2>&1; then
    trivy fs --format json --scanners vuln --quiet "$DIR" > "$WORK/trivy.json" 2>"$WORK/trivy.err"
    if [ -s "$WORK/trivy.json" ]; then
        scanners_run+=("trivy")
    else
        echo "WARNING: trivy is installed but produced no output (see $WORK/trivy.err below) - falling back to per-ecosystem tools instead of reporting zero vulnerabilities" >&2
        cat "$WORK/trivy.err" >&2 2>/dev/null || true
    fi
fi

# Per-ecosystem fallbacks always run unless trivy actually succeeded above -
# not just when trivy is absent, so a broken/misbehaving trivy install
# doesn't silently look like "zero vulnerabilities" when npm/pip-audit etc.
# could still cover it.
if [[ ! " ${scanners_run[*]:-} " == *" trivy "* ]]; then
    if [ -f "$DIR/package.json" ]; then
        if command -v npm >/dev/null 2>&1; then
            (cd "$DIR" && npm audit --json) > "$WORK/npm-audit.json" 2>"$WORK/npm-audit.err" || true
            if [ -s "$WORK/npm-audit.json" ]; then
                scanners_run+=("npm-audit")
            fi
        else
            skipped+=("package.json found but npm is not installed")
        fi
    fi

    if [ -f "$DIR/requirements.txt" ] || [ -f "$DIR/Pipfile.lock" ] || [ -f "$DIR/pyproject.toml" ]; then
        if command -v pip-audit >/dev/null 2>&1; then
            local_req="$DIR/requirements.txt"
            if [ -f "$local_req" ]; then
                pip-audit -r "$local_req" --format json > "$WORK/pip-audit.json" 2>"$WORK/pip-audit.err" || true
            else
                (cd "$DIR" && pip-audit --format json) > "$WORK/pip-audit.json" 2>"$WORK/pip-audit.err" || true
            fi
            if [ -s "$WORK/pip-audit.json" ]; then
                scanners_run+=("pip-audit")
            fi
        else
            skipped+=("Python dependency manifest found (requirements.txt/Pipfile.lock/pyproject.toml) but pip-audit is not installed")
        fi
    fi

    if [ -f "$DIR/Gemfile.lock" ]; then
        if command -v bundler-audit >/dev/null 2>&1; then
            (cd "$DIR" && bundler-audit check --update) > "$WORK/bundler-audit.txt" 2>"$WORK/bundler-audit.err" || true
            if [ -s "$WORK/bundler-audit.txt" ]; then
                scanners_run+=("bundler-audit")
            fi
        else
            skipped+=("Gemfile.lock found but bundler-audit is not installed")
        fi
    fi

    if [ -f "$DIR/go.mod" ]; then
        if command -v govulncheck >/dev/null 2>&1; then
            (cd "$DIR" && govulncheck -json ./...) > "$WORK/govulncheck.json" 2>"$WORK/govulncheck.err" || true
            if [ -s "$WORK/govulncheck.json" ]; then
                scanners_run+=("govulncheck")
            fi
        else
            skipped+=("go.mod found but govulncheck is not installed")
        fi
    fi
fi

python3 "$(dirname "${BASH_SOURCE[0]}")/dependency_normalize.py" "$WORK" \
    --scanners "$(IFS=,; echo "${scanners_run[*]:-}")" \
    --skipped "$(IFS='|'; echo "${skipped[*]:-}")" \
    > "$WORK/normalized.json"

if [ -n "$OUTPUT" ]; then
    cp "$WORK/normalized.json" "$OUTPUT"
    echo "Dependency scan results written -> $OUTPUT" >&2
else
    cat "$WORK/normalized.json"
fi
