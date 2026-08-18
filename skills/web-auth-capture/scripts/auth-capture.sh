#!/bin/bash
#
# Auth Capture - capture an authenticated web-app session (cookies/bearer
# token/CSRF token) via one of three paths, and expose it in a uniform
# shape that skills/fuzzing and skills/web-crawling's --auth-file flags
# consume directly via `to-header-args`.
#
# Deliberately NOT named anything "session" - $SESSION_ID/$SESSION_DIR
# already mean "pentest engagement session" throughout this codebase; this
# is a different, narrower concept (one captured web-app auth context).
#
# Usage:
#   auth-capture.sh manual     --target <url> --cookie "<raw Cookie value>" [--header "Name: Value"]... --output <auth_file>
#   auth-capture.sh curl-login --url <login_url> --data "<form data>" [--action-url <url>] [--content-type <ct>] --output <auth_file>
#   auth-capture.sh from-har   --har-file <path> [--login-url-hint <url>] --output <auth_file>
#   auth-capture.sh to-header-args --auth-file <auth_file>
#   auth-capture.sh status     --auth-file <auth_file>
#
# `curl-login` is best-effort and only reliable against classic
# server-rendered login forms - it cannot execute JavaScript, so a
# JS-rendered SPA login form's CSRF field (if dynamically named/injected)
# will simply not be found. Use `from-har` (a browser devtools "Save as
# HAR", or a manually-run mitmproxy's own HAR export) for those cases -
# this repo does not orchestrate a live intercepting proxy itself, since
# that doesn't fit Claude Code's one-shot foreground Bash tool model.
#
# Output schema (see SKILL.md):
#   {"target": "...", "captured_at": "...", "method": "manual|curl_login|har_import",
#    "cookies": {"PHPSESSID": "abc123"}, "headers": {"Authorization": "Bearer ..."},
#    "csrf_token": {"field": "...", "value": "..."}, "expires_hint": ""}
#

set -uo pipefail

usage() {
    echo "Usage:" >&2
    echo "  $0 manual     --target <url> --cookie \"<raw Cookie value>\" [--header \"Name: Value\"]... --output <auth_file>" >&2
    echo "  $0 curl-login --url <login_url> --data \"<form data>\" [--action-url <url>] [--content-type <ct>] --output <auth_file>" >&2
    echo "  $0 from-har   --har-file <path> [--login-url-hint <url>] --output <auth_file>" >&2
    echo "  $0 to-header-args --auth-file <auth_file>" >&2
    echo "  $0 status     --auth-file <auth_file>" >&2
    exit 1
}

require_jq() {
    command -v jq >/dev/null 2>&1 || { echo "ERROR: jq required" >&2; exit 1; }
}

now_iso() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

# Parses a raw "k1=v1; k2=v2" Cookie header value into a jq-ready JSON
# object string.
cookie_string_to_json() {
    local raw="$1"
    python3 -c '
import json, sys
raw = sys.argv[1]
out = {}
for part in raw.split(";"):
    part = part.strip()
    if not part or "=" not in part:
        continue
    k, v = part.split("=", 1)
    out[k.strip()] = v.strip()
print(json.dumps(out))
' "$raw"
}

# --- manual ---
manual() {
    local target="" cookie="" output=""
    local headers=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --target) target="$2"; shift 2 ;;
            --cookie) cookie="$2"; shift 2 ;;
            --header) headers+=("$2"); shift 2 ;;
            --output) output="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    : "${target:?--target required}"
    : "${output:?--output required}"
    require_jq

    local cookies_json="{}"
    [ -n "$cookie" ] && cookies_json=$(cookie_string_to_json "$cookie")

    local headers_json="{}"
    if [ "${#headers[@]}" -gt 0 ]; then
        headers_json=$(python3 -c '
import json, sys
out = {}
for h in sys.argv[1:]:
    if ":" not in h:
        continue
    k, v = h.split(":", 1)
    out[k.strip()] = v.strip()
print(json.dumps(out))
' "${headers[@]}")
    fi

    jq -n --arg target "$target" --arg captured_at "$(now_iso)" \
        --argjson cookies "$cookies_json" --argjson headers "$headers_json" \
        '{target: $target, captured_at: $captured_at, method: "manual",
          cookies: $cookies, headers: $headers, csrf_token: null, expires_hint: ""}' \
        > "$output"
    echo "Auth context captured (manual) -> $output" >&2
}

# --- curl-login ---
curl_login() {
    local url="" data="" action_url="" content_type="application/x-www-form-urlencoded" output=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --url) url="$2"; shift 2 ;;
            --data) data="$2"; shift 2 ;;
            --action-url) action_url="$2"; shift 2 ;;
            --content-type) content_type="$2"; shift 2 ;;
            --output) output="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    : "${url:?--url required}"
    : "${data:?--data required}"
    : "${output:?--output required}"
    require_jq
    command -v curl >/dev/null 2>&1 || { echo "ERROR: curl required" >&2; exit 1; }

    [ -n "$action_url" ] || action_url="$url"

    local work; work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT

    # Best-effort CSRF field discovery: GET the login page first, look for
    # a handful of common hidden-field naming conventions. This is
    # explicitly heuristic and only works against classic server-rendered
    # forms - see the header comment.
    curl -s -o "$work/login_get.html" "$url" 2>"$work/get.err" || true

    local csrf_field="" csrf_value=""
    if [ -s "$work/login_get.html" ]; then
        for field in csrf_token _token authenticity_token csrfmiddlewaretoken __RequestVerificationToken; do
            local match
            match=$(grep -oE "name=[\"']${field}[\"'][^>]*value=[\"'][^\"']*[\"']" "$work/login_get.html" 2>/dev/null | head -1)
            if [ -n "$match" ]; then
                csrf_field="$field"
                csrf_value=$(echo "$match" | grep -oE "value=[\"'][^\"']*[\"']" | sed -E "s/value=[\"']//;s/[\"']$//")
                break
            fi
        done
    fi

    local post_data="$data"
    if [ -n "$csrf_field" ] && [ -n "$csrf_value" ]; then
        case "&$data&" in
            *"&${csrf_field}="*) ;;  # already present in caller-supplied data
            *) post_data="${data}&${csrf_field}=$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$csrf_value")" ;;
        esac
    fi

    curl -s -D "$work/response_headers.txt" -o "$work/response_body.html" \
        -X POST "$action_url" -H "Content-Type: $content_type" \
        --cookie-jar "$work/cookiejar_out.txt" \
        -d "$post_data" 2>"$work/post.err" || true

    if [ ! -s "$work/response_headers.txt" ]; then
        echo "ERROR: curl-login POST to $action_url produced no response - target unreachable or curl failed" >&2
        cat "$work/post.err" >&2 2>/dev/null || true
        exit 1
    fi

    local cookies_json="{}"
    if [ -s "$work/cookiejar_out.txt" ]; then
        cookies_json=$(python3 -c '
import json, sys
out = {}
try:
    with open(sys.argv[1]) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 7:
                out[parts[5]] = parts[6]
except OSError:
    pass
print(json.dumps(out))
' "$work/cookiejar_out.txt")
    fi

    if [ "$cookies_json" = "{}" ]; then
        echo "WARNING: curl-login completed but no Set-Cookie values were captured - login may have failed, or the app uses a non-cookie auth mechanism" >&2
    fi

    local csrf_json="null"
    [ -n "$csrf_field" ] && csrf_json=$(jq -n --arg f "$csrf_field" --arg v "$csrf_value" '{field: $f, value: $v}')

    jq -n --arg target "$url" --arg captured_at "$(now_iso)" \
        --argjson cookies "$cookies_json" --argjson csrf_token "$csrf_json" \
        '{target: $target, captured_at: $captured_at, method: "curl_login",
          cookies: $cookies, headers: {}, csrf_token: $csrf_token, expires_hint: ""}' \
        > "$output"
    echo "Auth context captured (curl-login) -> $output" >&2

    # $work is a `local` var, so the EXIT trap above must not outlive this
    # function - clean up explicitly and clear it here on the normal-exit
    # path. It's still safe/correct for the early `exit 1` error path
    # above, since that fires while still inside this function's scope.
    rm -rf "$work"
    trap - EXIT
}

# --- from-har ---
from_har() {
    local har_file="" login_url_hint="" output=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --har-file) har_file="$2"; shift 2 ;;
            --login-url-hint) login_url_hint="$2"; shift 2 ;;
            --output) output="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    : "${har_file:?--har-file required}"
    : "${output:?--output required}"
    [ -f "$har_file" ] || { echo "ERROR: HAR file not found: $har_file" >&2; exit 1; }
    require_jq

    python3 - "$har_file" "$login_url_hint" "$output" << 'PYEOF'
import json
import sys

har_file, login_url_hint, output = sys.argv[1], sys.argv[2], sys.argv[3]

try:
    with open(har_file) as f:
        har = json.load(f)
except (OSError, json.JSONDecodeError) as exc:
    print(f"ERROR: could not parse HAR file: {exc}", file=sys.stderr)
    sys.exit(1)

entries = har.get("log", {}).get("entries", [])
if not entries:
    print("ERROR: HAR file has no entries", file=sys.stderr)
    sys.exit(1)

cookies = {}
auth_header = None
target = login_url_hint or None

for entry in entries:
    req = entry.get("request", {})
    resp = entry.get("response", {})
    url = req.get("url", "")

    if target is None:
        target = url

    for h in req.get("headers", []):
        if h.get("name", "").lower() == "authorization" and h.get("value"):
            auth_header = h["value"]

    for c in resp.get("cookies", []):
        name = c.get("name")
        if name:
            cookies[name] = c.get("value", "")

if not cookies and not auth_header:
    print("ERROR: no cookies or Authorization header found anywhere in the HAR - "
          "nothing to capture. Confirm the HAR actually includes the authenticated "
          "requests (some exports only capture a subset).", file=sys.stderr)
    sys.exit(1)

headers = {"Authorization": auth_header} if auth_header else {}

result = {
    "target": target or "unknown",
    "captured_at": __import__("datetime").datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    "method": "har_import",
    "cookies": cookies,
    "headers": headers,
    "csrf_token": None,
    "expires_hint": "",
}

with open(output, "w") as f:
    json.dump(result, f, indent=2)

print(f"Auth context captured (from-har) -> {output}", file=sys.stderr)
print(f"  {len(cookies)} cookie(s), Authorization header: {'yes' if auth_header else 'no'}", file=sys.stderr)
PYEOF
}

# --- to-header-args ---
# Prints one raw header string (e.g. "Cookie: a=b; c=d") per line - no -H
# prefix baked in, since embedding shell-quoted "-H \"...\"" tokens in
# plain stdout is fragile to consume safely (values can contain spaces).
# Recommended consumption:
#   mapfile -t auth_headers < <(auth-capture.sh to-header-args --auth-file "$AUTH_FILE")
#   args=(); for h in "${auth_headers[@]}"; do args+=(-H "$h"); done
#   ffuf ... "${args[@]}"
to_header_args() {
    local auth_file=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --auth-file) auth_file="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    : "${auth_file:?--auth-file required}"
    [ -f "$auth_file" ] || { echo "ERROR: auth file not found: $auth_file" >&2; exit 1; }
    require_jq

    local cookie_pairs
    cookie_pairs=$(jq -r '.cookies // {} | to_entries | map("\(.key)=\(.value)") | join("; ")' "$auth_file")
    [ -n "$cookie_pairs" ] && echo "Cookie: $cookie_pairs"

    jq -r '.headers // {} | to_entries[] | "\(.key): \(.value)"' "$auth_file"
}

# --- status ---
status() {
    local auth_file=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --auth-file) auth_file="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    : "${auth_file:?--auth-file required}"
    [ -f "$auth_file" ] || { echo "ERROR: auth file not found: $auth_file" >&2; exit 1; }
    require_jq

    jq -r '
        "Target:       " + .target,
        "Method:        " + .method,
        "Captured at:   " + .captured_at,
        "Cookies:       " + ((.cookies // {}) | length | tostring),
        "Auth header:   " + (if (.headers.Authorization // "") != "" then "yes" else "no" end),
        "CSRF token:    " + (if .csrf_token then (.csrf_token.field + " (captured)") else "none" end),
        "Expires hint:  " + (if (.expires_hint // "") != "" then .expires_hint else "(not set - no active expiry detection)" end)
    ' "$auth_file"
}

main() {
    local cmd="${1:-}"
    case "$cmd" in
        manual) shift; manual "$@" ;;
        curl-login) shift; curl_login "$@" ;;
        from-har) shift; from_har "$@" ;;
        to-header-args) shift; to_header_args "$@" ;;
        status) shift; status "$@" ;;
        *) usage ;;
    esac
}

main "$@"
