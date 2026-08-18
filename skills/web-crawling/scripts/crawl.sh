#!/bin/bash
#
# Crawl - JS-aware endpoint discovery for modern SPA targets, with a
# tool-preference cascade: katana (JS parsing, XHR/form detection) ->
# hakrawler (link/form extraction, no JS execution - a real but
# materially weaker fallback) -> a stdlib-only static HTML link-extractor
# (weakest tier, finds nothing JS-rendered at all). Recon-agent's old
# fixed-endpoint-probe approach misses anything a target only exposes via
# client-side routing/XHR calls - this is what closes that gap.
#
# Usage: crawl.sh crawl --url <url> [--auth-file <path>] [--depth N] [--output <json>]
#
# Output is normalized to one shape regardless of which tool ran - check
# "crawler_used" ("katana"/"hakrawler"/"static-fallback") before trusting
# the completeness of the result: only "katana" can see JS-rendered
# routes. static-fallback always runs (and always sets a value) whenever
# both katana and hakrawler are unavailable or fail, so crawler_used is
# never actually empty/"none" in practice. See skills/web-crawling/SKILL.md.
#

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUTH_CAPTURE="$SCRIPT_DIR/../../web-auth-capture/scripts/auth-capture.sh"

usage() {
    echo "Usage: $0 crawl --url <url> [--auth-file <path>] [--depth N] [--output <json>]" >&2
    exit 1
}

AUTH_ARGS=()
load_auth_args() {
    local auth_file="$1"
    AUTH_ARGS=()
    [ -n "$auth_file" ] || return 0
    [ -f "$auth_file" ] || { echo "ERROR: auth file not found: $auth_file" >&2; exit 1; }
    local line
    while IFS= read -r line; do
        [ -n "$line" ] && AUTH_ARGS+=(-H "$line")
    done < <(bash "$AUTH_CAPTURE" to-header-args --auth-file "$auth_file")
}

crawl() {
    local url="" auth_file="" depth="2" output=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --url) url="$2"; shift 2 ;;
            --auth-file) auth_file="$2"; shift 2 ;;
            --depth) depth="$2"; shift 2 ;;
            --output) output="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    : "${url:?--url required}"
    command -v jq >/dev/null 2>&1 || { echo "ERROR: jq required" >&2; exit 1; }

    load_auth_args "$auth_file"

    local work; work=$(mktemp -d)
    local crawler_used="" skipped_reason="" endpoints_json="[]"

    if command -v katana >/dev/null 2>&1; then
        local args=(-u "$url" -jsonl -o "$work/katana.jsonl" -d "$depth" -silent)
        katana "${args[@]}" "${AUTH_ARGS[@]+${AUTH_ARGS[@]}}" >"$work/katana.stdout" 2>"$work/katana.stderr" || true
        if [ -s "$work/katana.jsonl" ]; then
            crawler_used="katana"
            endpoints_json=$(python3 -c '
import json, sys
out = []
try:
    with open(sys.argv[1]) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            req = e.get("request", {})
            endpoint = req.get("endpoint") or req.get("url") or ""
            if not endpoint:
                continue
            tag = (req.get("tag") or "").lower()
            attribute = (req.get("attribute") or "").lower()
            if tag == "form":
                source = "form"
            elif attribute in ("xhr", "fetch") or req.get("source") == "xhr":
                source = "xhr"
            elif tag in ("script", "a") or req.get("source") == "body":
                source = "js_parse"
            else:
                source = "js_parse"
            out.append({"url": endpoint, "method": req.get("method", "GET"), "source": source})
except OSError:
    pass
print(json.dumps(out))
' "$work/katana.jsonl")
        else
            skipped_reason="katana installed but produced no output"
        fi
    else
        skipped_reason="katana not installed"
    fi

    if [ -z "$crawler_used" ] && command -v hakrawler >/dev/null 2>&1; then
        echo "$url" | hakrawler -d "$depth" "${AUTH_ARGS[@]+${AUTH_ARGS[@]}}" > "$work/hakrawler.txt" 2>"$work/hakrawler.stderr" || true
        if [ -s "$work/hakrawler.txt" ]; then
            crawler_used="hakrawler"
            skipped_reason=""
            endpoints_json=$(python3 -c '
import json, sys
out = []
try:
    with open(sys.argv[1]) as f:
        for line in f:
            line = line.strip()
            if line.startswith("http"):
                out.append({"url": line, "method": "GET", "source": "link"})
except OSError:
    pass
print(json.dumps(out))
' "$work/hakrawler.txt")
        else
            skipped_reason="hakrawler installed but produced no output"
        fi
    fi

    if [ -z "$crawler_used" ]; then
        crawler_used="static-fallback"
        # Written to a file rather than captured via $(... << 'EOF') command
        # substitution deliberately - bash 3.2 (macOS's default /bin/bash)
        # has a real bug where a heredoc nested inside $(...) mis-parses
        # quote characters in the heredoc body even with a quoted (literal)
        # delimiter. Writing to a file and reading it back afterward avoids
        # the combination entirely.
        python3 - "$url" "${AUTH_ARGS[@]+${AUTH_ARGS[@]}}" > "$work/static_fallback.json" << 'PYEOF'
import json
import re
import sys
import urllib.request
from urllib.parse import urljoin

url = sys.argv[1]
auth_args = sys.argv[2:]

headers = {}
i = 0
while i < len(auth_args):
    if auth_args[i] == "-H" and i + 1 < len(auth_args):
        h = auth_args[i + 1]
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
        i += 2
    else:
        i += 1

ATTR_RE = re.compile(r'''(href|src|action)\s*=\s*["']([^"']+)["']''', re.IGNORECASE)

out = []
try:
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "Clicky-crawl/1.0"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    seen = set()
    for m in ATTR_RE.finditer(body):
        link = m.group(2)
        if link.startswith(("javascript:", "mailto:", "#", "data:")):
            continue
        resolved = urljoin(url, link)
        if resolved not in seen:
            seen.add(resolved)
            out.append({"url": resolved, "method": "GET", "source": "static_href"})
except Exception as exc:
    print(f"ERROR: static fallback fetch failed: {exc}", file=sys.stderr)
print(json.dumps(out))
PYEOF
        endpoints_json=$(cat "$work/static_fallback.json" 2>/dev/null || echo "[]")
        skipped_reason="katana and hakrawler unavailable - static HTML extraction cannot see JS-rendered routes"
    fi

    local result_json
    result_json=$(jq -n --arg target "$url" --arg crawler "$crawler_used" --arg reason "$skipped_reason" --argjson endpoints "$endpoints_json" \
        '{target: $target, crawler_used: $crawler, skipped_reason: $reason, endpoints: $endpoints}')

    rm -rf "$work"
    if [ -n "$output" ]; then
        echo "$result_json" > "$output"
        echo "Crawl results (crawler: $crawler_used, $(echo "$endpoints_json" | jq 'length') endpoint(s)) -> $output" >&2
    else
        echo "$result_json"
    fi
}

main() {
    local cmd="${1:-}"
    case "$cmd" in
        crawl) shift; crawl "$@" ;;
        *) usage ;;
    esac
}

main "$@"
