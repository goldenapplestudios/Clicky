#!/bin/bash
#
# Success Calculator - combine per-service success rates (from the HTB
# Priority Matrix in this skill's SKILL.md) into an overall probability
# that at least one attack path succeeds.
#
# Usage:
#   success-calculator.sh analyze "{service_list}"
#   success-calculator.sh --services "{service_list}" --attempts "{tried_exploits}"
#
# {service_list} is a comma-separated list of ports, e.g. "21,22,80,445"
# {tried_exploits} is a comma-separated list of ports already attempted and
# failed - these are excluded from the combined probability, since a known
# failure shouldn't inflate "chance something works."
#

set -uo pipefail

MODE="" SERVICES="" ATTEMPTS=""

if [ "${1:-}" = "analyze" ]; then
    MODE="analyze"
    SERVICES="${2:-}"
    shift 2 || true
else
    while [ $# -gt 0 ]; do
        case "$1" in
            --services) SERVICES="$2"; shift 2 ;;
            --attempts) ATTEMPTS="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    MODE="analyze"
fi

: "${SERVICES:?service list required (ports, comma-separated)}"

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 required" >&2
    exit 1
fi

python3 - "$SERVICES" "$ATTEMPTS" << 'PYEOF'
import json
import sys

services_arg, attempts_arg = sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else ""

# Mirrors the HTB Service Priority Matrix in SKILL.md and
# service-prioritizer.py's PRIORITY_MATRIX - keep all three in sync.
PORT_RATES = {
    21: ("ftp", 0.73),          # matches "Anonymous FTP with credentials" easy-box baseline
    445: ("smb_null", 0.61),
    139: ("smb_null", 0.61),
    80: ("web_sqli", 0.42),
    443: ("web_sqli", 0.42),
    22: ("ssh", 0.45),
    3306: ("mysql", 0.41),
    6379: ("redis", 0.95),
    2375: ("docker", 0.90),
    2376: ("docker", 0.90),
    27017: ("mongodb", 0.85),
    9200: ("elasticsearch", 0.82),
    3389: ("rdp", 0.35),
}

attempted_ports = {int(p.strip()) for p in attempts_arg.split(",") if p.strip().isdigit()}

result = {}
probabilities = []
seen_keys = set()
for raw in services_arg.split(","):
    raw = raw.strip()
    if not raw.isdigit():
        continue
    port = int(raw)
    if port in attempted_ports:
        continue
    entry = PORT_RATES.get(port)
    if entry:
        key, rate = entry
        if key not in seen_keys:
            result[key] = rate
            probabilities.append(rate)
            seen_keys.add(key)

if probabilities:
    overall = 1.0
    for p in probabilities:
        overall *= (1 - p)
    overall = round(1 - overall, 2)
else:
    overall = 0.0

result["overall_success"] = overall
print(json.dumps(result, indent=2))
PYEOF
