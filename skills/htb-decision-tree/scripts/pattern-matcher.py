#!/usr/bin/env python3
"""Pattern Matcher - compare a target's discovered services/findings
against the Easy/Medium/Hard Box Patterns in this skill's SKILL.md, to
estimate which difficulty tier the target most resembles.

Usage: pattern-matcher.py --profile '{"services_json}"' --difficulty "medium"

The profile JSON accepts service names as boolean flags, and known finding
flags (see the patterns loaded from data/pattern-frequencies.json) if you
already know some results, e.g.:
  '{"ftp": true, "http": true, "ftp_anonymous": true, "sqli_found": false}'
Services alone (without finding flags) are fine too - unset finding flags
are just treated as "unknown", not "false".

Frequencies are qualitative ("common"/"occasional"/"rare"), not measured
percentages, and deliberately don't graduate to measured data the way
skills/htb-decision-tree's service-priority matrix does (see
priority_data.py): Clicky never records a target's actual difficulty tier
anywhere, so there's no ground truth to calibrate this axis against.
"""
import argparse
import json
import pathlib

PATTERN_DATA_PATH = pathlib.Path(__file__).resolve().parent / ".." / "data" / "pattern-frequencies.json"


def load_patterns():
    with open(PATTERN_DATA_PATH) as f:
        data = json.load(f)
    return data["patterns"]


def main():
    parser = argparse.ArgumentParser(description="Match a target profile against HTB box patterns")
    parser.add_argument("--profile", required=True, help="JSON object of service/finding flags")
    parser.add_argument("--difficulty", default=None, choices=["easy", "medium", "hard"],
                         help="Only report this difficulty tier (default: report all three)")
    args = parser.parse_args()

    try:
        profile = json.loads(args.profile)
    except json.JSONDecodeError as e:
        print(f"ERROR: --profile is not valid JSON: {e}")
        return

    patterns = load_patterns()
    tiers = [args.difficulty] if args.difficulty else ["easy", "medium", "hard"]

    for tier in tiers:
        confirmed = []
        candidates = []
        for pattern in patterns[tier]:
            name, flag, frequency = pattern["name"], pattern["flag"], pattern["frequency"]
            if flag in profile:
                if profile[flag]:
                    confirmed.append((name, frequency))
            else:
                candidates.append((name, frequency))

        print(f"=== {tier.upper()} box patterns ===")
        if confirmed:
            print("Confirmed:")
            for name, frequency in confirmed:
                print(f"  - {name} ({frequency} on {tier} boxes)")
        if candidates:
            print("Untested candidates (worth checking):")
            for name, frequency in candidates:
                print(f"  - {name} ({frequency} on {tier} boxes)")
        if not confirmed and not candidates:
            print("  (no patterns applicable given the profile)")
        print()

    if not args.difficulty:
        scores = {}
        for tier in ["easy", "medium", "hard"]:
            confirmed_count = sum(1 for p in patterns[tier] if profile.get(p["flag"]) is True)
            scores[tier] = confirmed_count
        best = max(scores, key=scores.get)
        if scores[best] > 0:
            print(f"Best-matching difficulty tier so far: {best} ({scores[best]} confirmed pattern(s))")
        else:
            print("No patterns confirmed yet - re-run with finding flags set as testing progresses.")


if __name__ == "__main__":
    main()
