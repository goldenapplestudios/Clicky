#!/bin/bash
#
# Shadow API Discovery - OWASP API9:2023 (Improper Inventory Management)
# coverage gap: everything else in this skill enumerates *currently live*
# endpoints. This instead asks the Wayback Machine's CDX API what
# /api/*-shaped paths under this domain were ever crawled and indexed
# historically, then (optionally) diffs that against a list of endpoints
# already known from live discovery (recon-agent's output, fuzz.sh/
# crawl.sh results, etc.) - anything present historically but absent from
# current discovery is a shadow/retired API worth checking manually: it
# may still be reachable and unmonitored even though nothing currently
# links to it.
#
# Free, no auth, single network call - see
# https://archive.org/help/wayback_api.php for the CDX API this uses.
# A domain the Wayback Machine has never crawled, or with zero /api/*
# snapshots, is a normal empty result, not an error.
#
# Usage: shadow-api-discovery.sh --domain <domain> [--known-endpoints-file <file>] [--output <json>]
#
# --known-endpoints-file expects a plain JSON array of path strings (e.g.
# ["/api/v1/users", "/graphql"]), not recon-agent's full report shape -
# extract paths from that first, e.g.:
#   jq '[.services[]?.api_endpoints[]?, .apis.rest_endpoints[]?, .apis.graphql_endpoints[]?] | unique' \
#     recon_report.json > known_endpoints.json
#
set -uo pipefail

DOMAIN="" KNOWN_FILE="" OUTPUT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --domain) DOMAIN="$2"; shift 2 ;;
        --known-endpoints-file) KNOWN_FILE="$2"; shift 2 ;;
        --output) OUTPUT="$2"; shift 2 ;;
        *) shift ;;
    esac
done
: "${DOMAIN:?--domain required}"

command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 required" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

KNOWN_ARG=""
if [ -n "$KNOWN_FILE" ]; then
    [ -f "$KNOWN_FILE" ] || { echo "ERROR: known-endpoints file not found: $KNOWN_FILE" >&2; exit 1; }
    KNOWN_ARG="$KNOWN_FILE"
fi

# Wayback's CDX API can take noticeably longer than this codebase's usual
# 10s default for domains with a long crawl history - the longer timeout
# here is deliberate, not an oversight.
CDX_URL="http://web.archive.org/cdx/search/cdx?url=${DOMAIN}/api/*&output=json&collapse=urlkey"
curl -s --max-time 30 "$CDX_URL" -o "$WORK/cdx.json" 2>"$WORK/curl.err" || true

# Written to a file rather than captured via $(... << 'EOF') command
# substitution - see security-headers-check.sh and web-crawling/crawl.sh
# for the bash 3.2 heredoc-inside-$(...) quote-parsing bug this sidesteps.
python3 - "$DOMAIN" "$CDX_URL" "$WORK/cdx.json" "$KNOWN_ARG" > "$WORK/result.json" << 'PYEOF'
import json
import sys
from urllib.parse import urlparse

domain, cdx_url, cdx_path, known_path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

historical_paths = set()
try:
    with open(cdx_path) as f:
        raw = f.read().strip()
    if raw:
        rows = json.loads(raw)
        if rows:
            header = rows[0]
            idx = header.index("original") if "original" in header else 2
            for row in rows[1:]:
                if len(row) <= idx:
                    continue
                path = urlparse(row[idx]).path
                if path:
                    historical_paths.add(path)
except (OSError, json.JSONDecodeError, ValueError):
    pass  # CDX returned nothing usable (no snapshots, or malformed/empty response) - report zero, don't crash

known_endpoints = []
known_provided = bool(known_path)
if known_provided:
    try:
        with open(known_path) as f:
            known_endpoints = json.load(f)
        if not isinstance(known_endpoints, list):
            known_endpoints = []
    except (OSError, json.JSONDecodeError):
        known_endpoints = []

known_set = set(known_endpoints)
shadow_endpoints = sorted(p for p in historical_paths if p not in known_set)

result = {
    "domain": domain,
    "cdx_query": cdx_url,
    "historical_api_paths": sorted(historical_paths),
    "known_endpoints_provided": known_provided,
    "known_endpoints": known_endpoints,
    "shadow_endpoints": shadow_endpoints,
}
print(json.dumps(result, indent=2))
PYEOF

if [ -n "$OUTPUT" ]; then
    cp "$WORK/result.json" "$OUTPUT"
    echo "Shadow API discovery -> $OUTPUT" >&2
else
    cat "$WORK/result.json"
fi
