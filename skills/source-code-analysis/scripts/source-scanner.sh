#!/bin/bash
#
# Source Scanner - acquire application source (local path, git clone, or
# reconstruction from an exposed .git directory) and scan it for
# taint-style source-to-sink flows and hardcoded secrets.
#
# Usage:
#   source-scanner.sh acquire --source <path|git_url|exposed_git_url> --output-dir <dir>
#   source-scanner.sh scan --dir <dir> [--output <json_file>]
#
# `scan` prefers Semgrep (real AST-based static analysis, via the bundled
# offline ruleset at references/semgrep-ruleset.yml - not `--config auto`,
# which would hit the network) when installed, and falls back to this
# repo's own grep/regex-based heuristic scanner otherwise. The regex
# fallback flags a dangerous sink with an untrusted-input source nearby in
# the same file as a candidate, not a proven exploitable path. Either way,
# treat every finding as a strong hint worth manually confirming (and,
# once a live target exists, worth confirming against it - see
# agents/source-analyzer-agent.md and the plan's Track 3 risk notes), not
# as gospel. Check the output's "scanner" field ("semgrep" or
# "regex_taint_scan") to see which path actually ran.
#

set -uo pipefail

usage() {
    echo "Usage:" >&2
    echo "  $0 acquire --source <path|git_url|exposed_git_url> --output-dir <dir>" >&2
    echo "  $0 scan --dir <dir> [--output <json_file>]" >&2
    exit 1
}

# --- acquire ---
acquire() {
    local source="" output_dir=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --source) source="$2"; shift 2 ;;
            --output-dir) output_dir="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    : "${source:?--source required}"
    : "${output_dir:?--output-dir required}"

    if [ -d "$source" ]; then
        echo "Source is a local directory - using in place: $source"
        echo "$source"
        return 0
    fi

    if ! command -v git >/dev/null 2>&1; then
        echo "ERROR: git required to acquire a remote source" >&2
        exit 1
    fi

    mkdir -p "$output_dir"

    case "$source" in
        *.git|git@*|*github.com*|*gitlab.com*|*bitbucket.org*)
            echo "Cloning repository: $source" >&2
            if git clone --depth 1 "$source" "$output_dir" 2>&1; then
                echo "$output_dir"
                return 0
            fi
            echo "ERROR: git clone failed for $source" >&2
            exit 1
            ;;
        http://*|https://*)
            # Likely an exposed .git directory on a live web server rather
            # than a real git hosting URL. The standard first move is a
            # direct clone against the .git path - misconfigured servers
            # that serve the raw object/pack files over static HTTP often
            # answer this correctly even without smart-HTTP support.
            local git_url="$source"
            case "$git_url" in
                */.git|*/.git/) ;;
                *) git_url="${git_url%/}/.git" ;;
            esac
            echo "Attempting direct clone of exposed .git: $git_url" >&2
            if git clone "$git_url" "$output_dir" 2>&1; then
                echo "$output_dir"
                return 0
            fi

            echo "Direct clone failed - falling back to a dumper tool if one is installed." >&2
            if command -v git-dumper >/dev/null 2>&1; then
                echo "Using git-dumper" >&2
                git-dumper "$git_url" "$output_dir" && { echo "$output_dir"; return 0; }
            fi
            if command -v gitdumper.sh >/dev/null 2>&1; then
                echo "Using GitTools gitdumper.sh" >&2
                gitdumper.sh "$git_url" "$output_dir" && { echo "$output_dir"; return 0; }
            fi

            echo "ERROR: could not reconstruct source from $source." >&2
            echo "The direct 'git clone' against .../.git failed and neither git-dumper nor GitTools' gitdumper.sh is installed." >&2
            echo "Install one (pip install git-dumper, or https://github.com/internetwache/GitTools) and retry, or supply a git_url/local path instead." >&2
            exit 1
            ;;
        *)
            echo "ERROR: '$source' is not an existing local directory, a recognizable git URL, or an http(s) URL to probe for an exposed .git" >&2
            exit 1
            ;;
    esac
}

# --- scan ---
scan() {
    local dir="" output=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --dir) dir="$2"; shift 2 ;;
            --output) output="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    : "${dir:?--dir required}"
    [ -d "$dir" ] || { echo "ERROR: directory not found: $dir" >&2; exit 1; }

    if ! command -v python3 >/dev/null 2>&1; then
        echo "ERROR: python3 required" >&2
        exit 1
    fi

    local script_dir result=""
    script_dir="$(dirname "${BASH_SOURCE[0]}")"

    if command -v semgrep >/dev/null 2>&1; then
        local semgrep_out semgrep_err
        semgrep_out=$(mktemp)
        semgrep_err=$(mktemp)
        # --dataflow-traces asks semgrep to populate extra.dataflow_trace
        # (a separately-tracked intermediate-variable file:line) on
        # mode: taint findings. Defensive, not load-bearing: that field is
        # gated behind Semgrep Pro Engine and is absent from this
        # project's OSS-engine output regardless of this flag (confirmed
        # live against semgrep 1.159.0 during this ruleset's
        # verification) - semgrep_normalize.py's extract_dataflow_trace()
        # already handles its absence honestly. Harmless to pass either
        # way in case a future maintainer runs this against a Pro-enabled
        # engine.
        semgrep --config "$script_dir/../references/semgrep-ruleset.yml" \
            --json --quiet --dataflow-traces "$dir" > "$semgrep_out" 2>"$semgrep_err"
        if [ -s "$semgrep_out" ] && python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$semgrep_out" 2>/dev/null; then
            result=$(python3 "$script_dir/semgrep_normalize.py" "$semgrep_out" --source-dir "$dir")
        else
            echo "WARNING: semgrep is installed but produced no usable output (see below) - falling back to the regex/proximity scanner" >&2
            cat "$semgrep_err" >&2 2>/dev/null || true
        fi
        rm -f "$semgrep_out" "$semgrep_err"
    fi

    if [ -z "$result" ]; then
        result=$(python3 "$script_dir/source_taint_scan.py" "$dir")
    fi

    if [ -n "$output" ]; then
        echo "$result" > "$output"
        echo "Scan results written -> $output" >&2
    else
        echo "$result"
    fi
}

main() {
    local cmd="${1:-}"
    case "$cmd" in
        acquire) shift; acquire "$@" ;;
        scan) shift; scan "$@" ;;
        *) usage ;;
    esac
}

main "$@"
