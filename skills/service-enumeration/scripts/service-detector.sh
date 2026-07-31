#!/bin/bash
#
# Service Detector - quick service identification, or match already-known
# service versions against a small curated list of well-known vulnerable
# versions
#
# Usage:
#   service-detector.sh --target IP --ports "21,22,80,445"
#   service-detector.sh --match-vulns service_versions.json
#

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="" PORTS="" MATCH_FILE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --target) TARGET="$2"; shift 2 ;;
        --ports) PORTS="$2"; shift 2 ;;
        --match-vulns) MATCH_FILE="$2"; shift 2 ;;
        *) shift ;;
    esac
done

detect() {
    : "${TARGET:?--target required}"
    : "${PORTS:?--ports required}"

    echo "=== Quick service detection: $TARGET (ports: $PORTS) ==="
    if command -v nmap >/dev/null 2>&1; then
        nmap -sV -T4 -p "$PORTS" "$TARGET"
    else
        echo "nmap not found - falling back to per-port banner grabs" >&2
        IFS=',' read -ra PORT_LIST <<< "$PORTS"
        for p in "${PORT_LIST[@]}"; do
            python3 "$SCRIPT_DIR/banner-grabber.py" --target "$TARGET" --port "$p" 2>/dev/null || echo "$TARGET:$p - closed/filtered"
        done
    fi
}

match_vulns() {
    : "${MATCH_FILE:?--match-vulns requires a service_versions.json file}"
    [ -f "$MATCH_FILE" ] || { echo "ERROR: file not found: $MATCH_FILE" >&2; exit 1; }

    if ! command -v python3 >/dev/null 2>&1; then
        echo "ERROR: python3 required for --match-vulns" >&2
        exit 1
    fi

    python3 - "$MATCH_FILE" << 'PYEOF'
import json
import re
import sys

# Small curated list of well-known outdated-version patterns worth flagging
# immediately. Not a CVE database - always verify the exact version against
# searchsploit/NVD before relying on this.
KNOWN_VULNERABLE = [
    (r"vsftpd 2\.3\.4", "vsftpd 2.3.4 backdoor (CVE-2011-2523)"),
    (r"ProFTPD 1\.3\.3", "ProFTPD 1.3.3 backdoor"),
    (r"OpenSSH [1-6]\.", "OpenSSH < 7.0 - multiple known CVEs, check exact version"),
    (r"OpenSSH 7\.[0-7](?!\d)", "OpenSSH < 7.8 - username enumeration (CVE-2018-15473)"),
    (r"Apache.* 2\.4\.4[0-9]", "Apache 2.4.4x - check for path traversal CVE-2021-41773 if 2.4.49-2.4.50"),
    (r"Apache.* 2\.2\.", "Apache 2.2.x - end of life, multiple known CVEs"),
    (r"vsftpd", "vsftpd - verify exact version against known CVEs"),
    (r"Microsoft-IIS/6", "IIS 6.0 - end of life, check WebDAV (CVE-2017-7269)"),
    (r"Samba 3\.", "Samba 3.x - check for CVE-2017-7494 (SambaCry) if < 4.6.4/4.5.10/4.4.14"),
    (r"MySQL 5\.[0-5]\.", "MySQL < 5.6 - end of life, multiple known CVEs"),
]

with open(sys.argv[1]) as f:
    data = json.load(f)

services = data.get("services", [])
matches_found = False
for svc in services:
    version_str = svc.get("version", "") or svc.get("banner", "")
    if not version_str:
        continue
    for pattern, note in KNOWN_VULNERABLE:
        if re.search(pattern, version_str, re.IGNORECASE):
            print(f"port {svc.get('port')}: {version_str} -> {note}")
            matches_found = True

if not matches_found:
    print("No matches against the curated known-vulnerable-version list.")
    print("This is a fast triage only - run searchsploit against each exact version for real coverage:")
    print("  searchsploit <product> <version>")
PYEOF
}

if [ -n "$MATCH_FILE" ]; then
    match_vulns
else
    detect
fi
