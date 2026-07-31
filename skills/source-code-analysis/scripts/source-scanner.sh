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
# `scan` is grep/regex-based heuristics, not real dataflow/AST analysis -
# it flags a dangerous sink with an untrusted-input source nearby in the
# same file as a candidate, not a proven exploitable path. Treat every
# finding as a strong hint worth manually confirming (and, once a live
# target exists, worth confirming against it - see
# agents/source-analyzer-agent.md and the plan's Track 3 risk notes), not
# as gospel.
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

    local result
    result=$(python3 "$(dirname "${BASH_SOURCE[0]}")/source_taint_scan.py" "$dir")

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
