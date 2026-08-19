#!/usr/bin/env python3
"""Scope Gate - classify a target against an engagement's scope.json.

Deliberately does not reimplement scope matching: it shells out to the
existing skills/target-validation/scripts/scope-validator.sh, so
scope-matching rules live in exactly one place. (Before Phase 2,
skills/target-validation/scripts/scope-enforcement-hook.sh - a PreToolUse
hook - also called scope-validator.sh for the same reason; that hook has
since been retired in favor of server.py's register_target, the only
caller of classify() below, doing this check itself.) See
scope-validator.sh and skills/target-validation/SKILL.md's "Scope
Validation" section for the scope.json schema and the exact matching
semantics (CIDR / IP-range / wildcard-domain / exact-match).

Usage as a library:
    from scope_gate import classify, IN_SCOPE, OUT_OF_SCOPE, NOT_LISTED
    result = classify("10.10.10.10", "/path/to/scope.json")

Usage as a CLI (for ad hoc checks / shell scripting):
    scope_gate.py --target 10.10.10.10 --scope scope.json
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
SCOPE_VALIDATOR = _HERE.parent / "target-validation" / "scripts" / "scope-validator.sh"

IN_SCOPE = "IN_SCOPE"
OUT_OF_SCOPE = "OUT_OF_SCOPE"
NOT_LISTED = "NOT_LISTED"


def classify(target: str, scope_path: str) -> str:
    """Classify `target` against `scope_path` (a scope.json file).

    Returns one of IN_SCOPE / OUT_OF_SCOPE / NOT_LISTED. Any failure to
    get a clean classification out of scope-validator.sh (missing scope
    file, missing python3/bash, unexpected output, a crash) is treated as
    NOT_LISTED rather than silently allowed - in "enforce" mode (the
    default) that still means the operator gets asked to confirm via
    elicitation, not that they're locked out, so this is not in tension
    with server.py's register_target failing open on genuinely unexpected
    errors (exceptions raised, not merely an ambiguous classification)
    around its call to this function. See register_target's own docstring
    for the full enforce/warn/off mode handling and its fail-open
    guarantee - that logic intentionally lives one level up from here,
    not inside classify() itself, so this function's contract (a clean
    3-way classification, never a silent allow) stays simple regardless
    of which mode the caller is in.
    """
    if not SCOPE_VALIDATOR.is_file():
        return NOT_LISTED

    try:
        result = subprocess.run(
            ["bash", str(SCOPE_VALIDATOR), "--target", target, "--scope", scope_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return NOT_LISTED

    output = (result.stdout or "") + (result.stderr or "")

    # Check OUT_OF_SCOPE/NOT_LISTED before IN_SCOPE: scope-validator.sh's
    # own exit code already disambiguates (0 only for a clean IN SCOPE),
    # but matching on the printed line first keeps this correct even if a
    # future scope-validator.sh version changes its exit-code contract
    # without changing its output strings.
    if "OUT OF SCOPE" in output:
        return OUT_OF_SCOPE
    if "NOT LISTED" in output:
        return NOT_LISTED
    if result.returncode == 0 and "IN SCOPE" in output:
        return IN_SCOPE
    return NOT_LISTED


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Target to classify")
    parser.add_argument("--scope", required=True, help="Path to scope.json")
    args = parser.parse_args()

    result = classify(args.target, args.scope)
    print(result)
    return 0 if result == IN_SCOPE else 1


if __name__ == "__main__":
    sys.exit(main())
