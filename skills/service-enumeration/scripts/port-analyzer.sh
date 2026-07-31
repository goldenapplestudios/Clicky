#!/bin/bash
#
# Port Analyzer - deep nmap-based version/service analysis with JSON export
#
# Usage:
#   port-analyzer.sh --deep --target IP
#   port-analyzer.sh --export-versions --target IP > service_versions.json
#

set -uo pipefail

TARGET=""
MODE="deep"
while [ $# -gt 0 ]; do
    case "$1" in
        --deep) MODE="deep"; shift ;;
        --export-versions) MODE="export"; shift ;;
        --target) TARGET="$2"; shift 2 ;;
        *) shift ;;
    esac
done

: "${TARGET:?--target required}"

if ! command -v nmap >/dev/null 2>&1; then
    echo "ERROR: nmap not found on PATH" >&2
    exit 1
fi

case "$MODE" in
    deep)
        echo "=== Deep service analysis: $TARGET ==="
        nmap -sV -sC -A -T4 -oN /dev/stdout "$TARGET"
        ;;
    export)
        # Produce JSON matching this skill's documented Output Format schema
        XML_OUT=$(mktemp)
        nmap -sV -oX "$XML_OUT" "$TARGET" >/dev/null 2>&1

        if command -v python3 >/dev/null 2>&1; then
            python3 - "$XML_OUT" "$TARGET" << 'PYEOF'
import sys
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

xml_file, target = sys.argv[1], sys.argv[2]
tree = ET.parse(xml_file)
root = tree.getroot()

services = []
for host in root.findall("host"):
    for port_el in host.findall(".//port"):
        state = port_el.find("state")
        if state is None or state.get("state") != "open":
            continue
        service_el = port_el.find("service")
        service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
        product = service_el.get("product", "") if service_el is not None else ""
        version = service_el.get("version", "") if service_el is not None else ""
        version_str = f"{product} {version}".strip()

        services.append({
            "port": int(port_el.get("portid")),
            "service": service_name,
            "version": version_str,
            "banner": version_str,
            "authentication": [],
            "users": [],
            "vulnerabilities": [],
        })

output = {
    "target": target,
    "services": services,
    "enumeration_time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
print(json.dumps(output, indent=2))
PYEOF
        else
            echo "ERROR: python3 required for --export-versions JSON output" >&2
            rm -f "$XML_OUT"
            exit 1
        fi
        rm -f "$XML_OUT"
        ;;
esac
