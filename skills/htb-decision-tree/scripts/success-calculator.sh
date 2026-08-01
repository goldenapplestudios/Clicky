#!/bin/bash
#
# Success Calculator - combine per-service data from Clicky's self-
# calibrated priority_data.py (real measured rates from this operator's
# session history where enough exist, honest heuristic weight otherwise -
# see that module and skills/htb-decision-tree/SKILL.md) into an overall
# probability that at least one attack path succeeds.
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
# Output includes overall_basis ("measured"/"mixed"/"heuristic") so a
# caller can never present the combined number without knowing how much of
# it came from real data vs. the heuristic fallback.
#

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

python3 - "$SERVICES" "$ATTEMPTS" "$SCRIPT_DIR" << 'PYEOF'
import json
import sys

services_arg, attempts_arg, script_dir = sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "", sys.argv[3]
sys.path.insert(0, script_dir)
import priority_data  # noqa: E402

merged, threshold = priority_data.load_merged_services()
port_to_service = priority_data.port_to_service_map(merged)

attempted_ports = {int(p.strip()) for p in attempts_arg.split(",") if p.strip().isdigit()}

result = {}
probabilities = []
bases = []
seen_services = set()
for raw in services_arg.split(","):
    raw = raw.strip()
    if not raw.isdigit():
        continue
    port = int(raw)
    if port in attempted_ports:
        continue
    svc = port_to_service.get(port)
    if svc and svc not in seen_services:
        entry = merged[svc]
        result[svc] = {"value": entry["value"], "basis": entry["basis"], "samples": entry["samples"]}
        probabilities.append(entry["value"])
        bases.append(entry["basis"])
        seen_services.add(svc)

if probabilities:
    overall = 1.0
    for p in probabilities:
        overall *= (1 - p)
    overall = round(1 - overall, 2)
    if all(b == "measured" for b in bases):
        overall_basis = "measured"
    elif any(b == "measured" for b in bases):
        overall_basis = "mixed"
    else:
        overall_basis = "heuristic"
else:
    overall = 0.0
    overall_basis = "heuristic"

result["overall_success"] = overall
result["overall_basis"] = overall_basis
print(json.dumps(result, indent=2))
PYEOF
