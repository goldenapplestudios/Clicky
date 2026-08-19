#!/bin/bash
#
# Fuzz - directory/vhost/parameter fuzzing with a tool-preference cascade,
# consolidating the ffuf/gobuster/dirb/wfuzz mentions that used to be
# scattered across agents/recon-agent.md, web-vulnerability-testing, and
# api-security-testing into one script both recon-agent (dir/vhost) and
# exploit-agent (authenticated param fuzzing) call into.
#
# Usage:
#   fuzz.sh dir   --url <url> [--wordlist <path>] [--recursive] [--filter-code <codes>] [--filter-size <sizes>] [--match-code <codes>] [--threads N] [--rate N] [--auth-file <path>] [--output <json>]
#   fuzz.sh vhost --url <url> --domain <base_domain> [--wordlist <path>] [--auth-file <path>] [--output <json>]
#   fuzz.sh param --url <url> [--wordlist <path>] [--auth-file <path>] [--output <json>]
#
# Tool cascade (same "prefer, track what ran, fall back on absence/failure"
# idiom as dependency-scanner.sh): ffuf -> feroxbuster -> gobuster -> dirb
# -> wfuzz -> a plain curl loop as the last resort that always works.
# Output is normalized to one shape regardless of which tool ran - check
# "tool_used" to see which one actually did.
#
# ffuf/feroxbuster output is parsed from their own native JSON modes.
# gobuster/dirb/wfuzz's structured-output support is inconsistent across
# versions, so those three are parsed from their default text output via
# regex - best-effort, confirm against your installed version if results
# look off. See skills/fuzzing/SKILL.md.
#
# Wordlist resolution when --wordlist isn't given, in order: the
# default_web_wordlist_dir userConfig option (CLAUDE_PLUGIN_OPTION_
# DEFAULT_WEB_WORDLIST_DIR) if set and it contains a matching file for
# this mode; the bundled small wordlist in assets/wordlists/; the legacy
# hardcoded /usr/share/wordlists/dirb/common.txt (dir mode only, for
# behavior parity with recon-agent's old inline cascade on an unmodified
# Kali box).
#

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUTH_CAPTURE="$SCRIPT_DIR/../../web-auth-capture/scripts/auth-capture.sh"

usage() {
    echo "Usage:" >&2
    echo "  $0 dir   --url <url> [--wordlist <path>] [--recursive] [--filter-code <codes>] [--filter-size <sizes>] [--match-code <codes>] [--threads N] [--rate N] [--auth-file <path>] [--output <json>]" >&2
    echo "  $0 vhost --url <url> --domain <base_domain> [--wordlist <path>] [--auth-file <path>] [--output <json>]" >&2
    echo "  $0 param --url <url> [--wordlist <path>] [--auth-file <path>] [--output <json>]" >&2
    exit 1
}

# --- wordlist resolution ---
resolve_wordlist() {
    local mode="$1" explicit="$2"
    if [ -n "$explicit" ]; then
        [ -f "$explicit" ] || { echo "ERROR: wordlist not found: $explicit" >&2; exit 1; }
        echo "$explicit"
        return 0
    fi

    local bundled_name legacy_name
    case "$mode" in
        dir) bundled_name="dir-common-small.txt"; legacy_name="dir-common.txt" ;;
        vhost) bundled_name="vhost-subdomains-small.txt"; legacy_name="vhost-subdomains.txt" ;;
        param) bundled_name="api-params-small.txt"; legacy_name="api-params.txt" ;;
    esac

    local user_dir="${CLAUDE_PLUGIN_OPTION_DEFAULT_WEB_WORDLIST_DIR:-}"
    if [ -n "$user_dir" ] && [ -f "$user_dir/$legacy_name" ]; then
        echo "$user_dir/$legacy_name"
        return 0
    fi

    local bundled="$SCRIPT_DIR/../assets/wordlists/$bundled_name"
    if [ -f "$bundled" ]; then
        echo "$bundled"
        return 0
    fi

    if [ "$mode" = "dir" ] && [ -f "/usr/share/wordlists/dirb/common.txt" ]; then
        echo "/usr/share/wordlists/dirb/common.txt"
        return 0
    fi

    echo "ERROR: no wordlist found for mode '$mode' - pass --wordlist explicitly" >&2
    exit 1
}

# --- auth header args ---
# Populates the global AUTH_ARGS array (bash functions can't return arrays
# cleanly) with -H flags, or leaves it empty if --auth-file wasn't given.
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

# --- dir mode ---
run_dir() {
    local url="" wordlist_arg="" recursive=0 filter_code="" filter_size="" match_code="" threads="" rate="" auth_file="" output=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --url) url="$2"; shift 2 ;;
            --wordlist) wordlist_arg="$2"; shift 2 ;;
            --recursive) recursive=1; shift ;;
            --filter-code) filter_code="$2"; shift 2 ;;
            --filter-size) filter_size="$2"; shift 2 ;;
            --match-code) match_code="$2"; shift 2 ;;
            --threads) threads="$2"; shift 2 ;;
            --rate) rate="$2"; shift 2 ;;
            --auth-file) auth_file="$2"; shift 2 ;;
            --output) output="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    : "${url:?--url required}"

    local wordlist; wordlist=$(resolve_wordlist "dir" "$wordlist_arg")
    load_auth_args "$auth_file"

    local work; work=$(mktemp -d)
    local tool_used="" hits_json="[]"

    if command -v ffuf >/dev/null 2>&1; then
        local args=(-w "$wordlist" -u "${url%/}/FUZZ" -of json -o "$work/ffuf.json" -ac -s)
        [ "$recursive" = "1" ] && args+=(-recursion)
        [ -n "$filter_code" ] && args+=(-fc "$filter_code")
        [ -n "$filter_size" ] && args+=(-fs "$filter_size")
        [ -n "$match_code" ] && args+=(-mc "$match_code")
        [ -n "$threads" ] && args+=(-t "$threads")
        [ -n "$rate" ] && args+=(-rate "$rate")
        ffuf "${args[@]}" "${AUTH_ARGS[@]+${AUTH_ARGS[@]}}" >"$work/ffuf.stdout" 2>"$work/ffuf.stderr"
        if [ -s "$work/ffuf.json" ]; then
            tool_used="ffuf"
            hits_json=$(python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("[]"); sys.exit(0)
out = [{"value": r.get("input", {}).get("FUZZ", r.get("url", "")),
        "status": r.get("status"), "size": r.get("length")}
       for r in d.get("results", [])]
print(json.dumps(out))
' "$work/ffuf.json")
        fi
    fi

    if [ -z "$tool_used" ] && command -v feroxbuster >/dev/null 2>&1; then
        local args=(-u "$url" -w "$wordlist" --json -o "$work/ferox.json" -q)
        [ "$recursive" = "1" ] || args+=(--no-recursion)
        [ -n "$threads" ] && args+=(-t "$threads")
        feroxbuster "${args[@]}" "${AUTH_ARGS[@]+${AUTH_ARGS[@]}}" >"$work/ferox.stdout" 2>"$work/ferox.stderr" || true
        if [ -s "$work/ferox.json" ]; then
            tool_used="feroxbuster"
            hits_json=$(python3 -c '
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
            if e.get("type") == "response":
                out.append({"value": e.get("url", ""), "status": e.get("status"), "size": e.get("content_length")})
except OSError:
    pass
print(json.dumps(out))
' "$work/ferox.json")
        fi
    fi

    if [ -z "$tool_used" ] && command -v gobuster >/dev/null 2>&1; then
        local args=(dir -u "$url" -w "$wordlist" -q -o "$work/gobuster.txt")
        local hi=0
        while [ $hi -lt "${#AUTH_ARGS[@]}" ]; do
            [ "${AUTH_ARGS[$hi]}" = "-H" ] && args+=(-H "${AUTH_ARGS[$((hi+1))]}")
            hi=$((hi+2))
        done
        gobuster "${args[@]}" >"$work/gobuster.stdout" 2>"$work/gobuster.stderr" || true
        if [ -s "$work/gobuster.txt" ]; then
            tool_used="gobuster"
            # Default text format: "/admin               (Status: 200) [Size: 1234]"
            hits_json=$(python3 -c '
import json, re, sys
out = []
pat = re.compile(r"^(\S+)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]")
try:
    with open(sys.argv[1]) as f:
        for line in f:
            m = pat.match(line.strip())
            if m:
                out.append({"value": m.group(1), "status": int(m.group(2)), "size": int(m.group(3))})
except OSError:
    pass
print(json.dumps(out))
' "$work/gobuster.txt")
        fi
    fi

    if [ -z "$tool_used" ] && command -v dirb >/dev/null 2>&1; then
        dirb "$url" "$wordlist" -o "$work/dirb.txt" -S >"$work/dirb.stdout" 2>"$work/dirb.stderr" || true
        if [ -s "$work/dirb.txt" ]; then
            tool_used="dirb"
            # dirb default format: "+ http://target/admin (CODE:200|SIZE:1234)"
            hits_json=$(python3 -c '
import json, re, sys
out = []
pat = re.compile(r"^\+\s+(\S+)\s+\(CODE:(\d+)\|SIZE:(\d+)\)")
try:
    with open(sys.argv[1]) as f:
        for line in f:
            m = pat.match(line.strip())
            if m:
                out.append({"value": m.group(1), "status": int(m.group(2)), "size": int(m.group(3))})
except OSError:
    pass
print(json.dumps(out))
' "$work/dirb.txt")
        fi
    fi

    if [ -z "$tool_used" ] && command -v wfuzz >/dev/null 2>&1; then
        wfuzz -c -z file,"$wordlist" --hc 404 "${AUTH_ARGS[@]+${AUTH_ARGS[@]}}" "${url%/}/FUZZ" >"$work/wfuzz.txt" 2>"$work/wfuzz.stderr" || true
        if [ -s "$work/wfuzz.txt" ]; then
            tool_used="wfuzz"
            # Default columnar format: "000000123:   200        12 L   45 W    1234 Ch   \"admin\""
            hits_json=$(python3 -c '
import json, re, sys
out = []
pat = re.compile(r"^\d+:\s+(\d+)\s+\d+\s+L\s+\d+\s+W\s+(\d+)\s+Ch\s+\"([^\"]*)\"")
try:
    with open(sys.argv[1]) as f:
        for line in f:
            m = pat.match(line.strip())
            if m:
                out.append({"value": m.group(3), "status": int(m.group(1)), "size": int(m.group(2))})
except OSError:
    pass
print(json.dumps(out))
' "$work/wfuzz.txt")
        fi
    fi

    if [ -z "$tool_used" ]; then
        tool_used="curl_loop"
        hits_json=$(python3 -c '
import json, subprocess, sys
url, wordlist = sys.argv[1], sys.argv[2]
auth_args = sys.argv[3:]
out = []
with open(wordlist) as f:
    words = [w.strip() for w in f if w.strip()]
for w in words:
    target = url.rstrip("/") + "/" + w
    cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{size_download}", "--max-time", "5"] + auth_args + [target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        parts = result.stdout.strip().split()
        if len(parts) == 2:
            status, size = int(parts[0]), int(parts[1])
            if status != 404 and status != 0:
                out.append({"value": "/" + w, "status": status, "size": size})
    except Exception:
        continue
print(json.dumps(out))
' "$url" "$wordlist" "${AUTH_ARGS[@]+${AUTH_ARGS[@]}}")
    fi

    local result_json
    result_json=$(jq -n --arg mode "dir" --arg target "$url" --arg tool "$tool_used" --arg wordlist "$wordlist" --argjson hits "$hits_json" \
        '{mode: $mode, target: $target, tool_used: $tool, wordlist_used: $wordlist, hits: $hits}')

    rm -rf "$work"
    if [ -n "$output" ]; then
        echo "$result_json" > "$output"
        echo "Directory fuzz results (tool: $tool_used) -> $output" >&2
    else
        echo "$result_json"
    fi
}

# --- vhost mode ---
run_vhost() {
    local url="" domain="" wordlist_arg="" auth_file="" output=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --url) url="$2"; shift 2 ;;
            --domain) domain="$2"; shift 2 ;;
            --wordlist) wordlist_arg="$2"; shift 2 ;;
            --auth-file) auth_file="$2"; shift 2 ;;
            --output) output="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    : "${url:?--url required}"
    : "${domain:?--domain required}"

    local wordlist; wordlist=$(resolve_wordlist "vhost" "$wordlist_arg")
    load_auth_args "$auth_file"

    local work; work=$(mktemp -d)
    local tool_used="" hits_json="[]"

    if command -v ffuf >/dev/null 2>&1; then
        ffuf -w "$wordlist" -u "$url" -H "Host: FUZZ.$domain" -of json -o "$work/ffuf.json" -ac -s "${AUTH_ARGS[@]+${AUTH_ARGS[@]}}" \
            >"$work/ffuf.stdout" 2>"$work/ffuf.stderr"
        if [ -s "$work/ffuf.json" ]; then
            tool_used="ffuf"
            hits_json=$(python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("[]"); sys.exit(0)
out = [{"value": r.get("input", {}).get("FUZZ", "") + "." + sys.argv[2],
        "status": r.get("status"), "size": r.get("length")}
       for r in d.get("results", [])]
print(json.dumps(out))
' "$work/ffuf.json" "$domain")
        fi
    fi

    if [ -z "$tool_used" ] && command -v gobuster >/dev/null 2>&1; then
        local args=(vhost -u "$url" -w "$wordlist" -q -o "$work/gobuster.txt")
        local hi=0
        while [ $hi -lt "${#AUTH_ARGS[@]}" ]; do
            [ "${AUTH_ARGS[$hi]}" = "-H" ] && args+=(-H "${AUTH_ARGS[$((hi+1))]}")
            hi=$((hi+2))
        done
        gobuster "${args[@]}" >"$work/gobuster.stdout" 2>"$work/gobuster.stderr" || true
        if [ -s "$work/gobuster.txt" ]; then
            tool_used="gobuster"
            hits_json=$(python3 -c '
import json, re, sys
out = []
pat = re.compile(r"Found:\s*(\S+)\s*\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]")
try:
    with open(sys.argv[1]) as f:
        for line in f:
            m = pat.search(line)
            if m:
                out.append({"value": m.group(1), "status": int(m.group(2)), "size": int(m.group(3))})
except OSError:
    pass
print(json.dumps(out))
' "$work/gobuster.txt")
        fi
    fi

    if [ -z "$tool_used" ]; then
        tool_used="curl_loop"
        hits_json=$(python3 -c '
import json, subprocess, sys
url, wordlist, domain = sys.argv[1], sys.argv[2], sys.argv[3]
auth_args = sys.argv[4:]
out = []
with open(wordlist) as f:
    words = [w.strip() for w in f if w.strip()]
for w in words:
    host = f"{w}.{domain}"
    cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{size_download}", "--max-time", "5",
           "-H", f"Host: {host}"] + auth_args + [url]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        parts = result.stdout.strip().split()
        if len(parts) == 2:
            status, size = int(parts[0]), int(parts[1])
            if status != 404 and status != 0:
                out.append({"value": host, "status": status, "size": size})
    except Exception:
        continue
print(json.dumps(out))
' "$url" "$wordlist" "$domain" "${AUTH_ARGS[@]+${AUTH_ARGS[@]}}")
    fi

    local result_json
    result_json=$(jq -n --arg mode "vhost" --arg target "$url" --arg tool "$tool_used" --arg wordlist "$wordlist" --argjson hits "$hits_json" \
        '{mode: $mode, target: $target, tool_used: $tool, wordlist_used: $wordlist, hits: $hits}')

    rm -rf "$work"
    if [ -n "$output" ]; then
        echo "$result_json" > "$output"
        echo "Vhost fuzz results (tool: $tool_used) -> $output" >&2
    else
        echo "$result_json"
    fi
}

# --- param mode ---
run_param() {
    local url="" wordlist_arg="" auth_file="" output=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --url) url="$2"; shift 2 ;;
            --wordlist) wordlist_arg="$2"; shift 2 ;;
            --auth-file) auth_file="$2"; shift 2 ;;
            --output) output="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    : "${url:?--url required}"

    local wordlist; wordlist=$(resolve_wordlist "param" "$wordlist_arg")
    load_auth_args "$auth_file"

    local work; work=$(mktemp -d)
    local tool_used="" hits_json="[]"
    local sep="?"
    case "$url" in *\?*) sep="&" ;; esac

    if command -v ffuf >/dev/null 2>&1; then
        ffuf -w "$wordlist" -u "${url}${sep}FUZZ=test" -of json -o "$work/ffuf.json" -ac -s "${AUTH_ARGS[@]+${AUTH_ARGS[@]}}" \
            >"$work/ffuf.stdout" 2>"$work/ffuf.stderr"
        if [ -s "$work/ffuf.json" ]; then
            tool_used="ffuf"
            hits_json=$(python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("[]"); sys.exit(0)
out = [{"value": r.get("input", {}).get("FUZZ", ""), "status": r.get("status"), "size": r.get("length")}
       for r in d.get("results", [])]
print(json.dumps(out))
' "$work/ffuf.json")
        fi
    fi

    if [ -z "$tool_used" ] && command -v wfuzz >/dev/null 2>&1; then
        wfuzz -c -z file,"$wordlist" --hc 404 "${AUTH_ARGS[@]+${AUTH_ARGS[@]}}" "${url}${sep}FUZZ=test" >"$work/wfuzz.txt" 2>"$work/wfuzz.stderr" || true
        if [ -s "$work/wfuzz.txt" ]; then
            tool_used="wfuzz"
            hits_json=$(python3 -c '
import json, re, sys
out = []
pat = re.compile(r"^\d+:\s+(\d+)\s+\d+\s+L\s+\d+\s+W\s+(\d+)\s+Ch\s+\"([^\"]*)\"")
try:
    with open(sys.argv[1]) as f:
        for line in f:
            m = pat.match(line.strip())
            if m:
                out.append({"value": m.group(3), "status": int(m.group(1)), "size": int(m.group(2))})
except OSError:
    pass
print(json.dumps(out))
' "$work/wfuzz.txt")
        fi
    fi

    if [ -z "$tool_used" ]; then
        tool_used="curl_loop"
        hits_json=$(python3 -c '
import json, subprocess, sys
url, wordlist, sep = sys.argv[1], sys.argv[2], sys.argv[3]
auth_args = sys.argv[4:]
out = []
with open(wordlist) as f:
    words = [w.strip() for w in f if w.strip()]
# Baseline: a nonsense param name, to compare each candidate response
# status AND size against - a genuinely recognized param usually differs
# from "param not recognized" in one or both (matches the differential
# detection described in skills/fuzzing/SKILL.md).
baseline_cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{size_download}", "--max-time", "5"] + auth_args + [f"{url}{sep}__clicky_baseline_nonexistent=1"]
try:
    r = subprocess.run(baseline_cmd, capture_output=True, text=True, timeout=10)
    base_parts = r.stdout.strip().split()
    baseline_status, baseline_size = int(base_parts[0]), int(base_parts[1])
except Exception:
    baseline_status, baseline_size = -1, -1
for w in words:
    target = f"{url}{sep}{w}=test"
    cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{size_download}", "--max-time", "5"] + auth_args + [target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        parts = result.stdout.strip().split()
        if len(parts) == 2:
            status, size = int(parts[0]), int(parts[1])
            if status != 0 and (status != baseline_status or size != baseline_size):
                out.append({"value": w, "status": status, "size": size})
    except Exception:
        continue
print(json.dumps(out))
' "$url" "$wordlist" "$sep" "${AUTH_ARGS[@]+${AUTH_ARGS[@]}}")
    fi

    local result_json
    result_json=$(jq -n --arg mode "param" --arg target "$url" --arg tool "$tool_used" --arg wordlist "$wordlist" --argjson hits "$hits_json" \
        '{mode: $mode, target: $target, tool_used: $tool, wordlist_used: $wordlist, hits: $hits}')

    rm -rf "$work"
    if [ -n "$output" ]; then
        echo "$result_json" > "$output"
        echo "Parameter fuzz results (tool: $tool_used) -> $output" >&2
    else
        echo "$result_json"
    fi
}

main() {
    local cmd="${1:-}"
    case "$cmd" in
        dir) shift; run_dir "$@" ;;
        vhost) shift; run_vhost "$@" ;;
        param) shift; run_param "$@" ;;
        *) usage ;;
    esac
}

main "$@"
