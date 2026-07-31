#!/usr/bin/env python3
"""SARIF Convert - convert skills/source-code-analysis's source_findings.json
(from either the Semgrep or regex_taint_scan path - see the "scanner" field)
into valid SARIF 2.1.0, for CI/code-scanning tooling that consumes that
format natively (e.g. GitHub code scanning).

Usage: sarif_convert.py <source_findings.json>

Field mapping (all lossy/best-effort where noted - SARIF's model doesn't
have a 1:1 equivalent for everything Clicky tracks):
  - finding.type -> ruleId (one SARIF rule per distinct type seen)
  - finding.file/line -> physicalLocation
  - finding.confidence "high"/"low" -> SARIF level "error"/"warning" -
    a deliberate lossy mapping, same posture as semgrep_normalize.py's
    own confidence collapse.
  - finding.mitre_attack -> a "mitre_attack" key in the result's
    properties bag (SARIF has no native ATT&CK field).
  - hardcoded_secret findings (no sink/source_of_taint) get a
    secret_type-based message instead.
"""
import json
import sys

RULE_DESCRIPTIONS = {
    "sql_injection": "Possible SQL injection - a SQL keyword appears alongside string concatenation/formatting rather than a parameterized query.",
    "command_injection": "Possible command injection - untrusted input reaches a shell-executing sink.",
    "code_injection": "Possible code injection - untrusted input reaches a dynamic code execution or unsafe deserialization sink.",
    "xss": "Possible cross-site scripting - untrusted input reaches an HTML-rendering sink without visible sanitization.",
    "path_traversal": "Possible path traversal - untrusted input reaches a filesystem path.",
    "ssrf": "Possible server-side request forgery - untrusted input reaches an outbound HTTP request.",
    "hardcoded_secret": "Hardcoded secret material found in source.",
    "unmapped": "A Semgrep rule matched that this converter doesn't have a specific mapping for - see the finding's raw_rule_id.",
}


def build_message(finding):
    if finding.get("type") == "hardcoded_secret":
        return f"Hardcoded secret ({finding.get('secret_type', 'unknown type')}) found in source."
    sink = finding.get("sink", "")
    source = finding.get("source_of_taint", "")
    msg = RULE_DESCRIPTIONS.get(finding.get("type"), "Potential vulnerability found in source.")
    if sink:
        msg += f" Sink: {sink}."
    if source:
        msg += f" Source of taint: {source}."
    return msg


def main():
    if len(sys.argv) != 2:
        print("Usage: sarif_convert.py <source_findings.json>", file=sys.stderr)
        sys.exit(1)

    try:
        with open(sys.argv[1]) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: could not parse source findings JSON: {exc}", file=sys.stderr)
        sys.exit(1)

    findings = data.get("findings", [])
    scanner = data.get("scanner", "unknown")

    rule_ids_seen = []
    results = []
    for finding in findings:
        rule_id = finding.get("type", "unmapped")
        if rule_id not in rule_ids_seen:
            rule_ids_seen.append(rule_id)

        confidence = finding.get("confidence", "low")
        level = "error" if confidence == "high" else "warning"

        properties = {"confidence": confidence}
        if finding.get("mitre_attack"):
            properties["mitre_attack"] = finding["mitre_attack"]
        if finding.get("raw_rule_id"):
            properties["raw_rule_id"] = finding["raw_rule_id"]

        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": build_message(finding)},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.get("file", "unknown")},
                    "region": {"startLine": max(1, finding.get("line", 1))},
                }
            }],
            "properties": properties,
        })

    rules = [
        {
            "id": rid,
            "shortDescription": {"text": RULE_DESCRIPTIONS.get(rid, f"Clicky source-code-analysis finding: {rid}")},
        }
        for rid in rule_ids_seen
    ]

    sarif = {
        "$schema": "https://www.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Clicky",
                        "informationUri": "https://github.com/goldenapplestudios/Clicky",
                        "version": "1.0.0",
                        "properties": {"scanner": scanner},
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

    print(json.dumps(sarif, indent=2))


if __name__ == "__main__":
    main()
