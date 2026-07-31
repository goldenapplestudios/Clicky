#!/bin/bash
#
# Scope Validator - check a target/technique/time against an engagement's
# scope.json before testing
#
# Usage:
#   scope-validator.sh --target "{ip}" --scope scope.json
#   scope-validator.sh --technique "dos" --scope scope.json
#   scope-validator.sh --check-time --scope scope.json
#
# scope.json schema (see "Scope Definition" earlier in this skill):
#   {
#     "targets": {"in_scope": [...], "out_of_scope": [...]},
#     "restrictions": ["No DoS attacks", "Business hours only", ...],
#     "authorized_techniques": [...],
#     "time_window": {"start": "09:00", "end": "17:00", "days": ["Mon", ...]}  (optional)
#   }
#

set -uo pipefail

TARGET="" TECHNIQUE="" SCOPE_FILE="" CHECK_TIME=0

while [ $# -gt 0 ]; do
    case "$1" in
        --target) TARGET="$2"; shift 2 ;;
        --technique) TECHNIQUE="$2"; shift 2 ;;
        --scope) SCOPE_FILE="$2"; shift 2 ;;
        --check-time) CHECK_TIME=1; shift ;;
        *) shift ;;
    esac
done

: "${SCOPE_FILE:?--scope <scope.json> required}"
[ -f "$SCOPE_FILE" ] || { echo "ERROR: scope file not found: $SCOPE_FILE" >&2; exit 1; }

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 required" >&2
    exit 1
fi

python3 - "$SCOPE_FILE" "$TARGET" "$TECHNIQUE" "$CHECK_TIME" << 'PYEOF'
import ipaddress
import json
import sys
import fnmatch
from datetime import datetime

scope_file, target, technique, check_time = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] == "1"

with open(scope_file) as f:
    scope = json.load(f)

exit_code = 0


def target_matches(entry: str, value: str) -> bool:
    # CIDR
    try:
        if "/" in entry:
            return ipaddress.ip_address(value) in ipaddress.ip_network(entry, strict=False)
    except ValueError:
        pass
    # IP range "a.b.c.d-e" (last octet range)
    if "-" in entry and "." in entry:
        try:
            base, end = entry.rsplit(".", 1)[0], entry.rsplit(".", 1)[1]
            if "-" in end:
                lo, hi = end.split("-")
                candidate_prefix, candidate_last = value.rsplit(".", 1)
                if candidate_prefix == base and lo.isdigit() and hi.isdigit() and candidate_last.isdigit():
                    return int(lo) <= int(candidate_last) <= int(hi)
        except (ValueError, IndexError):
            pass
    # Wildcard domain
    if "*" in entry:
        return fnmatch.fnmatch(value, entry)
    # Exact match
    return entry == value


if target:
    targets = scope.get("targets", {})
    in_scope = targets.get("in_scope", [])
    out_of_scope = targets.get("out_of_scope", [])

    if any(target_matches(e, target) for e in out_of_scope):
        print(f"OUT OF SCOPE (explicit exclusion): {target}")
        exit_code = 1
    elif any(target_matches(e, target) for e in in_scope):
        print(f"IN SCOPE: {target}")
    else:
        print(f"NOT LISTED (not explicitly in-scope): {target}")
        exit_code = 1

if technique:
    authorized = [t.lower() for t in scope.get("authorized_techniques", [])]
    restrictions = scope.get("restrictions", [])
    technique_lower = technique.lower()

    restricted = [r for r in restrictions if technique_lower in r.lower()]
    if restricted:
        print(f"RESTRICTED: '{technique}' matches restriction(s): {restricted}")
        exit_code = 1
    elif authorized and not any(technique_lower in a or a in technique_lower for a in authorized):
        print(f"NOT AUTHORIZED: '{technique}' is not in authorized_techniques")
        exit_code = 1
    else:
        print(f"AUTHORIZED: {technique}")

if check_time:
    window = scope.get("time_window")
    if not window:
        text_restrictions = [r for r in scope.get("restrictions", []) if "hour" in r.lower() or "time" in r.lower()]
        if text_restrictions:
            print(f"WARNING: scope has a free-text time restriction that can't be programmatically checked: {text_restrictions}")
            print("Add a structured 'time_window' field to scope.json ({\"start\": \"HH:MM\", \"end\": \"HH:MM\", \"days\": [...]}) to enforce this automatically.")
        else:
            print("No time restrictions found in scope.")
    else:
        now = datetime.now()
        current_day = now.strftime("%a")
        current_time = now.strftime("%H:%M")
        days_ok = current_day in window.get("days", [current_day])
        time_ok = window.get("start", "00:00") <= current_time <= window.get("end", "23:59")
        if days_ok and time_ok:
            print(f"WITHIN TIME WINDOW: {current_day} {current_time}")
        else:
            print(f"OUTSIDE TIME WINDOW: {current_day} {current_time} (allowed: {window.get('days')} {window.get('start')}-{window.get('end')})")
            exit_code = 1

sys.exit(exit_code)
PYEOF
