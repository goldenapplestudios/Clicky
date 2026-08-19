#!/bin/bash
#
# Subdomain Enumeration & DNS Attack-Surface Mapping
#
# Runs a source cascade over a domain to build a subdomain list, resolves
# each discovered candidate, and checks resolved CNAMEs against a curated
# subdomain-takeover fingerprint list. This is the foundational first step
# of Jason Haddix's Bug Hunter's Methodology recon flow - map the DNS
# attack surface before anything else.
#
# Source cascade (each degrades gracefully - a missing tool or an empty/
# failed response from a source is a normal result, not an error):
#   1. crt.sh Certificate Transparency search - always runs, free, no key.
#      https://crt.sh/?q=%.<domain>&output=json returns a JSON array of
#      cert log entries; `name_value` on each entry is a newline-separated
#      list of SANs on that cert. crt.sh itself is a small, sometimes
#      rate-limited/flaky free service (a 502 or a non-JSON body is a real,
#      observed condition, not hypothetical) - a bad response here means
#      zero names from this source, not a script failure.
#   2. subfinder, if installed (`command -v subfinder`) - passive-only
#      sources work out of the box with no API key.
#   3. amass, if installed (`command -v amass`) - passive by default;
#      --active adds amass's own active/brute-force techniques. Amass had
#      a significant CLI restructuring in a v5.0.0 release, so this script
#      does NOT hardcode flags from memory - it inspects the installed
#      binary's own `amass enum -h` output and only passes flags that
#      binary actually advertises.
#
# Discovered names are merged, deduped, and stripped of a leading "*."
# wildcard, then each is resolved (CNAME + A, via dig if present else
# host) and checked against a curated subset of the community-maintained
# EdOverflow/can-i-take-over-xyz fingerprint list
# (https://github.com/EdOverflow/can-i-take-over-xyz) bundled at
# takeover-fingerprints.json alongside this script - refresh that file
# from the live list periodically, it is a curated 15-25 entry subset, not
# a full mirror. A resolved CNAME whose suffix matches a known
# takeover-prone provider is fetched and grepped for that provider's
# fingerprint string; only a confirmed string match is reported as a
# possible takeover, not just a suffix match on its own.
#
# Usage: subdomain-enum.sh --domain <domain> [--active] [--output <path>]
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FINGERPRINTS_FILE="$SCRIPT_DIR/takeover-fingerprints.json"

usage() {
    echo "Usage: $0 --domain <domain> [--active] [--output <path>]" >&2
    exit 1
}

DOMAIN="" ACTIVE=false OUTPUT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --domain) DOMAIN="$2"; shift 2 ;;
        --active) ACTIVE=true; shift ;;
        --output) OUTPUT="$2"; shift 2 ;;
        *) shift ;;
    esac
done
[ -n "$DOMAIN" ] || usage

command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 required" >&2; exit 1; }
[ -f "$FINGERPRINTS_FILE" ] || { echo "ERROR: fingerprints file not found: $FINGERPRINTS_FILE" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# --- 1. crt.sh (always runs, no key needed) ---------------------------
CRTSH_URL="https://crt.sh/?q=%25.${DOMAIN}&output=json"
curl -s --max-time 30 "$CRTSH_URL" -o "$WORK/crtsh.json" 2>"$WORK/crtsh.err" || true
CRTSH_RAN=true

# --- 2. subfinder, if installed ----------------------------------------
SUBFINDER_RAN=false
if command -v subfinder >/dev/null 2>&1; then
    SUBFINDER_RAN=true
    subfinder -d "$DOMAIN" -silent -oJ > "$WORK/subfinder.jsonl" 2>"$WORK/subfinder.err" || true
fi

# --- 3. amass, if installed --------------------------------------------
# Passive by default; --active adds amass's own active/brute flags, but
# only ones the installed binary's help text actually lists - see header.
AMASS_RAN=false
if command -v amass >/dev/null 2>&1; then
    AMASS_RAN=true
    AMASS_HELP=$( (amass enum -h) 2>&1 || true)

    AMASS_ARGS=(-d "$DOMAIN")
    if [ "$ACTIVE" = true ]; then
        echo "$AMASS_HELP" | grep -qe '-active' && AMASS_ARGS+=(-active)
        echo "$AMASS_HELP" | grep -qe '-brute' && AMASS_ARGS+=(-brute)
    else
        echo "$AMASS_HELP" | grep -qe '-passive' && AMASS_ARGS+=(-passive)
    fi

    if echo "$AMASS_HELP" | grep -qe '-json'; then
        AMASS_ARGS+=(-json "$WORK/amass.json")
        amass enum "${AMASS_ARGS[@]}" > "$WORK/amass.out" 2>"$WORK/amass.err" || true
    else
        # This installed version doesn't advertise -json - fall back to
        # plain stdout, amass enum's long-standing default output format
        # of one discovered name per line.
        amass enum "${AMASS_ARGS[@]}" > "$WORK/amass.out" 2>"$WORK/amass.err" || true
    fi
fi
[ -f "$WORK/amass.json" ] || : > "$WORK/amass.json"
[ -f "$WORK/amass.out" ] || : > "$WORK/amass.out"
[ -f "$WORK/subfinder.jsonl" ] || : > "$WORK/subfinder.jsonl"

# --- Merge + dedupe every source into a single subdomain list ---------
# Written to files rather than captured via $(... << 'EOF') command
# substitution deliberately - see shadow-api-discovery.sh and
# security-headers-check.sh for the bash 3.2 heredoc-inside-$(...)
# quote-parsing bug this sidesteps. This call also writes
# subdomains.txt directly (plain one-per-line, for the resolution loop
# below) as a side effect - subdomains.json (stdout) is the deduped list
# in JSON form for the final assembly stage.
python3 - "$DOMAIN" "$WORK/crtsh.json" "$WORK/subfinder.jsonl" "$WORK/amass.json" "$WORK/amass.out" "$WORK/subdomains.txt" > "$WORK/subdomains.json" << 'PYEOF'
import json
import sys

domain, crtsh_path, subfinder_path, amass_json_path, amass_out_path, txt_out_path = sys.argv[1:7]
domain_lc = domain.strip().lower()

names = set()

def add(raw):
    if not raw:
        return
    n = raw.strip().lower().rstrip(".")
    if not n:
        return
    if n.startswith("*."):
        n = n[2:]
    if not n:
        return
    # Only keep names actually under the target domain - crt.sh's %.domain
    # wildcard search is scoped server-side, but be defensive since the
    # other two sources aren't.
    if n == domain_lc or n.endswith("." + domain_lc):
        names.add(n)

# crt.sh: JSON array of cert log entries; name_value is newline-separated
# SANs on that one cert. A 502/HTML error body or empty file is a normal
# "source unavailable right now" result, not a crash.
try:
    with open(crtsh_path) as f:
        raw = f.read().strip()
    if raw:
        rows = json.loads(raw)
        for row in rows:
            for line in str(row.get("name_value", "")).split("\n"):
                add(line)
except (OSError, json.JSONDecodeError, ValueError, AttributeError, TypeError):
    pass

# subfinder -oJ: JSON-lines, one {"host": "...", ...} object per line.
try:
    with open(subfinder_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            add(obj.get("host") or obj.get("Name") or obj.get("name"))
except OSError:
    pass

# amass -json: JSON-lines, one {"name": "...", ...} object per line (pre-
# v5 and current OWASP Amass shape alike).
try:
    with open(amass_json_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            add(obj.get("name") or obj.get("Name"))
except OSError:
    pass

# amass plain stdout fallback (no -json support on this installed
# version) - one discovered name per line, possibly with extra
# whitespace/annotations amass sometimes prints; keep only the first
# whitespace-separated token per line.
try:
    with open(amass_out_path) as f:
        for line in f:
            token = line.strip().split()[:1]
            if token:
                add(token[0])
except OSError:
    pass

sorted_names = sorted(names)

with open(txt_out_path, "w") as f:
    for n in sorted_names:
        f.write(n + "\n")

print(json.dumps(sorted_names))
PYEOF

# --- Resolve each candidate (CNAME + A records) ------------------------
RESOLVE_TOOL=""
if command -v dig >/dev/null 2>&1; then
    RESOLVE_TOOL="dig"
elif command -v host >/dev/null 2>&1; then
    RESOLVE_TOOL="host"
fi

RESOLVED_FILE="$WORK/resolved.tsv"
: > "$RESOLVED_FILE"

if [ -n "$RESOLVE_TOOL" ] && [ -s "$WORK/subdomains.txt" ]; then
    while IFS= read -r sub; do
        [ -n "$sub" ] || continue
        cnames="" arecs=""
        if [ "$RESOLVE_TOOL" = "dig" ]; then
            cnames=$(dig +short +time=2 +tries=1 CNAME "$sub" 2>/dev/null | sed 's/\.$//' | paste -sd',' - 2>/dev/null)
            arecs=$(dig +short +time=2 +tries=1 A "$sub" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | paste -sd',' - 2>/dev/null)
        else
            out=$(host -W 2 "$sub" 2>/dev/null || true)
            cnames=$(echo "$out" | grep 'is an alias for' | sed -E 's/.*is an alias for (.*)\.$/\1/' | paste -sd',' - 2>/dev/null)
            arecs=$(echo "$out" | grep 'has address' | sed -E 's/.*has address ([0-9.]+)$/\1/' | paste -sd',' - 2>/dev/null)
        fi
        # Only record candidates that actually resolved to something -
        # crt.sh/subfinder/amass names can include long-expired/never-
        # deployed subdomains that never had DNS records at all, which
        # aren't a useful "resolved" entry.
        if [ -n "$cnames" ] || [ -n "$arecs" ]; then
            printf '%s\t%s\t%s\n' "$sub" "$cnames" "$arecs" >> "$RESOLVED_FILE"
        fi
    done < "$WORK/subdomains.txt"
fi

# --- Identify takeover candidates from resolved CNAMEs ------------------
# Suffix-match only, here - not yet a confirmed takeover. Uses jq (already
# a hard dependency elsewhere in this codebase) to compare each resolved
# CNAME against the bundled fingerprint list's cname_suffix field.
CANDIDATES_FILE="$WORK/candidates.tsv"
: > "$CANDIDATES_FILE"
if [ -s "$RESOLVED_FILE" ]; then
    while IFS=$'\t' read -r sub cnames _arecs; do
        [ -n "$cnames" ] || continue
        IFS=',' read -ra CNAME_ARR <<< "$cnames"
        for cname in "${CNAME_ARR[@]}"; do
            [ -n "$cname" ] || continue
            cname_lc=$(echo "$cname" | tr '[:upper:]' '[:lower:]')
            # ".cname_suffix" is captured into a $fp variable before piping
            # $cname into endswith() - endswith()'s argument expression is
            # evaluated with "." rebound to $cname (a string) inside that
            # pipe, so a bare ".cname_suffix" there would try to index the
            # string $cname, not the fingerprint object (confirmed by
            # reproducing the "Cannot index string with string" error
            # before adding the $fp binding).
            match=$(jq -r --arg cname "$cname_lc" '
                [.[] | . as $fp | select(($cname == $fp.cname_suffix) or ($cname | endswith("." + $fp.cname_suffix)))] | .[0] |
                if . == null then empty else [.provider, .fingerprint] | @tsv end
            ' "$FINGERPRINTS_FILE" 2>/dev/null)
            if [ -n "$match" ]; then
                provider=$(printf '%s' "$match" | cut -f1)
                fingerprint=$(printf '%s' "$match" | cut -f2)
                printf '%s\t%s\t%s\t%s\n' "$sub" "$provider" "$cname" "$fingerprint" >> "$CANDIDATES_FILE"
            fi
        done
    done < "$RESOLVED_FILE"
fi

# --- Confirm candidates by fetching and grepping for the fingerprint ---
POSSIBLE_TAKEOVERS_FILE="$WORK/possible_takeovers.tsv"
: > "$POSSIBLE_TAKEOVERS_FILE"
if [ -s "$CANDIDATES_FILE" ]; then
    while IFS=$'\t' read -r sub provider cname fingerprint; do
        body=$(curl -sL -k --max-time 10 "https://$sub" 2>/dev/null)
        if [ -z "$body" ]; then
            body=$(curl -sL --max-time 10 "http://$sub" 2>/dev/null)
        fi
        if [ -n "$body" ] && printf '%s' "$body" | grep -qF "$fingerprint"; then
            printf '%s\t%s\t%s\t%s\n' "$sub" "$provider" "$cname" "$fingerprint" >> "$POSSIBLE_TAKEOVERS_FILE"
        fi
    done < "$CANDIDATES_FILE"
fi

# --- Final JSON assembly ------------------------------------------------
python3 - "$DOMAIN" "$CRTSH_RAN" "$SUBFINDER_RAN" "$AMASS_RAN" "$WORK/subdomains.json" "$RESOLVED_FILE" "$POSSIBLE_TAKEOVERS_FILE" > "$WORK/result.json" << 'PYEOF'
import json
import sys

domain, crtsh_ran, subfinder_ran, amass_ran, subdomains_json_path, resolved_path, takeovers_path = sys.argv[1:8]


def as_bool(s):
    return s.strip().lower() == "true"


try:
    with open(subdomains_json_path) as f:
        subdomains = json.load(f)
    if not isinstance(subdomains, list):
        subdomains = []
except (OSError, json.JSONDecodeError):
    subdomains = []

resolved = []
try:
    with open(resolved_path) as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 3:
                continue
            sub, cnames_csv, arecs_csv = parts
            resolved.append({
                "subdomain": sub,
                "cnames": [c for c in cnames_csv.split(",") if c],
                "a_records": [a for a in arecs_csv.split(",") if a],
            })
except OSError:
    pass

possible_takeovers = []
try:
    with open(takeovers_path) as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 4:
                continue
            sub, provider, cname, fingerprint = parts
            possible_takeovers.append({
                "subdomain": sub,
                "provider": provider,
                "cname": cname,
                "fingerprint_matched": True,
            })
except OSError:
    pass

result = {
    "domain": domain,
    "sources": {
        "crtsh": as_bool(crtsh_ran),
        "subfinder": as_bool(subfinder_ran),
        "amass": as_bool(amass_ran),
    },
    "subdomains": subdomains,
    "resolved": resolved,
    "possible_takeovers": possible_takeovers,
}
print(json.dumps(result, indent=2))
PYEOF

if [ -n "$OUTPUT" ]; then
    cp "$WORK/result.json" "$OUTPUT"
    echo "Subdomain enumeration -> $OUTPUT" >&2
else
    cat "$WORK/result.json"
fi
