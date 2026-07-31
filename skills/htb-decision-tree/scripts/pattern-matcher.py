#!/usr/bin/env python3
"""Pattern Matcher - compare a target's discovered services/findings
against the Easy/Medium/Hard Box Patterns in this skill's SKILL.md, to
estimate which difficulty tier the target most resembles.

Usage: pattern-matcher.py --profile '{"services_json}"' --difficulty "medium"

The profile JSON accepts service names as boolean flags, and known finding
flags (see PATTERN_FLAGS below) if you already know some results, e.g.:
  '{"ftp": true, "http": true, "ftp_anonymous": true, "sqli_found": false}'
Services alone (without finding flags) are fine too - unset finding flags
are just treated as "unknown", not "false".
"""
import argparse
import json

# Mirrors "HTB Pattern Recognition" in SKILL.md - keep these in sync if the
# lists there change. Each pattern's flag is what --profile should set to
# confirm/deny it; if the flag is absent from the profile, the pattern is
# reported as an untested candidate rather than matched or ruled out.
PATTERNS = {
    "easy": [
        ("Anonymous FTP with credentials", "ftp_anonymous", 0.73),
        ("SMB null sessions with user lists", "smb_null", 0.61),
        ("Default CMS credentials", "default_creds", 0.58),
        ("SQL injection in login forms", "sqli_found", 0.42),
    ],
    "medium": [
        ("Credential reuse across services", "cred_reuse", 0.67),
        ("Web application vulnerabilities leading to RCE", "web_rce", 0.54),
        ("Service version exploits", "version_exploit", 0.49),
        ("Configuration file exposure", "config_exposure", 0.45),
    ],
    "hard": [
        ("Chained exploits required", "chained_exploit", 0.89),
        ("Custom exploitation needed", "custom_exploit", 0.76),
        ("Binary exploitation", "binary_exploit", 0.64),
        ("Advanced pivoting", "advanced_pivot", 0.58),
    ],
}


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

    tiers = [args.difficulty] if args.difficulty else ["easy", "medium", "hard"]

    for tier in tiers:
        confirmed = []
        candidates = []
        for name, flag, base_rate in PATTERNS[tier]:
            if flag in profile:
                if profile[flag]:
                    confirmed.append((name, base_rate))
            else:
                candidates.append((name, base_rate))

        print(f"=== {tier.upper()} box patterns ===")
        if confirmed:
            print("Confirmed:")
            for name, rate in confirmed:
                print(f"  - {name} (baseline {rate:.0%} of {tier} boxes)")
        if candidates:
            print("Untested candidates (worth checking):")
            for name, rate in candidates:
                print(f"  - {name} (baseline {rate:.0%} of {tier} boxes)")
        if not confirmed and not candidates:
            print("  (no patterns applicable given the profile)")
        print()

    if not args.difficulty:
        scores = {}
        for tier in ["easy", "medium", "hard"]:
            confirmed_count = sum(1 for _, flag, _ in PATTERNS[tier] if profile.get(flag) is True)
            scores[tier] = confirmed_count
        best = max(scores, key=scores.get)
        if scores[best] > 0:
            print(f"Best-matching difficulty tier so far: {best} ({scores[best]} confirmed pattern(s))")
        else:
            print("No patterns confirmed yet - re-run with finding flags set as testing progresses.")


if __name__ == "__main__":
    main()
