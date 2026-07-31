#!/bin/bash
#
# CVSS 3.1 Base Score Calculator
#
# Usage: cvss-calculator.sh --vector "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
#
# Implements the official CVSS v3.1 base score formula (FIRST.org spec).
# Delegates the floating-point math to python3 for correctness/precision.
#

set -euo pipefail

VECTOR=""
while [ $# -gt 0 ]; do
    case "$1" in
        --vector) VECTOR="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [ -z "$VECTOR" ]; then
    echo "Usage: $0 --vector \"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\"" >&2
    exit 1
fi

python3 - "$VECTOR" << 'PYEOF'
import sys
import math

vector = sys.argv[1].replace("CVSS:3.1/", "")

metrics = {}
for part in vector.split("/"):
    if ":" not in part:
        continue
    k, v = part.split(":", 1)
    metrics[k] = v

required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
missing = [m for m in required if m not in metrics]
if missing:
    print(f"ERROR: vector is missing required metric(s): {', '.join(missing)}", file=sys.stderr)
    sys.exit(1)

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC = {"L": 0.77, "H": 0.44}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.00}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}

scope = metrics["S"]
if scope not in ("U", "C"):
    print(f"ERROR: Scope must be U or C, got: {scope}", file=sys.stderr)
    sys.exit(1)

try:
    av = AV[metrics["AV"]]
    ac = AC[metrics["AC"]]
    ui = UI[metrics["UI"]]
    pr = (PR_CHANGED if scope == "C" else PR_UNCHANGED)[metrics["PR"]]
    c = CIA[metrics["C"]]
    i = CIA[metrics["I"]]
    a = CIA[metrics["A"]]
except KeyError as e:
    print(f"ERROR: unrecognized value for metric {e}", file=sys.stderr)
    sys.exit(1)

iss = 1 - ((1 - c) * (1 - i) * (1 - a))

if scope == "U":
    impact = 6.42 * iss
else:
    impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

exploitability = 8.22 * av * ac * pr * ui


def roundup(x):
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


if impact <= 0:
    base_score = 0.0
elif scope == "U":
    base_score = roundup(min(impact + exploitability, 10))
else:
    base_score = roundup(min(1.08 * (impact + exploitability), 10))

if base_score == 0.0:
    severity = "None"
elif base_score < 4.0:
    severity = "Low"
elif base_score < 7.0:
    severity = "Medium"
elif base_score < 9.0:
    severity = "High"
else:
    severity = "Critical"

print(f"Vector: CVSS:3.1/{vector}")
print(f"Base Score: {base_score} ({severity})")
print(f"  Impact Sub-Score: {round(impact, 3)}")
print(f"  Exploitability Sub-Score: {round(exploitability, 3)}")
PYEOF
