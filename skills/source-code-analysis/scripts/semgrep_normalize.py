#!/usr/bin/env python3
"""Semgrep Normalize - read a `semgrep --json` output file and normalize it
into the exact same findings shape source_taint_scan.py produces, so
agents/source-analyzer-agent.md and everything downstream (decision-agent,
Tier 1/Tier 2 validation, report-generation) needs zero changes regardless
of which scanner actually ran - check the top-level "scanner" field to see
which one did.

Usage: semgrep_normalize.py <semgrep_json_file> --source-dir <dir>

Mapping notes (all deliberate, documented lossy conversions - see
skills/source-code-analysis/SKILL.md):
  - `type` is recovered from the rule id via substring match against a
    fixed table (rule ids in the bundled ruleset are namespaced
    `clicky-<type>-...`, but semgrep prefixes the id with the config
    file's path when loaded locally rather than from the Registry, so
    substring match - not exact/prefix match - is required). No match ->
    `type: "unmapped"` with the raw id preserved in `raw_rule_id`, never a
    wrong guess.
  - `confidence` is derived from semgrep's `extra.severity` (ERROR/WARNING/
    INFO, which is what a locally-authored ruleset controls directly -
    the Registry's separate `metadata.confidence` HIGH/MEDIUM/LOW
    convention doesn't apply to rules that don't set it): ERROR -> "high",
    WARNING/INFO -> "low".
  - `sink` is read directly from the source file at the reported line
    (semgrep's own `extra.lines` field requires a logged-in/Pro session in
    this CLI version and returned the literal string "requires login"
    during testing - reading the line ourselves, the same way
    source_taint_scan.py already does, is more reliable and has no such
    dependency).
  - Most of this ruleset is simple pattern matching (`mode: search`, the
    default), which has no separately-tracked taint-source line the way
    source_taint_scan.py's backward-window search produces one -
    `source_of_taint` says so honestly rather than fabricating a location.
    A subset of rules (id ends in `-taint`) use `mode: taint`: real
    intraprocedural dataflow analysis - matched only when semgrep confirms
    a `pattern-sources` value actually reaches a `pattern-sinks` call, not
    mere proximity. Those findings get `confidence: "high"` unconditionally
    and an additive `taint_traced: true` field. Semgrep's granular
    `extra.dataflow_trace` (which would carry a separately-tracked
    intermediate-variable file:line) is gated behind Semgrep Pro and was
    confirmed absent from this project's OSS engine output during
    verification, with and without `--dataflow-traces` - see
    `extract_dataflow_trace()` below, which returns `None` rather than
    fabricating one when it's missing, and `is_taint_finding()`/the
    three-way branch in `main()` for how the honest message differs from
    the plain-pattern disclaimer in that (expected, common) case.
"""
import argparse
import json
import os
import sys

TYPE_TABLE = [
    ("hardcoded-secret", "hardcoded_secret"),
    ("sql-injection", "sql_injection"),
    ("command-injection", "command_injection"),
    ("code-injection", "code_injection"),
    ("xss", "xss"),
    ("path-traversal", "path_traversal"),
    ("ssrf", "ssrf"),
]

SECRET_TYPE_TABLE = [
    ("private-key", "private_key"),
    ("aws-key", "aws_access_key"),
    ("slack-token", "slack_token"),
    ("api-key", "api_key"),
    ("password", "hardcoded_password"),
    ("db-connection-string", "db_connection_string"),
]

# Matches source_taint_scan.py's MITRE_BY_TYPE exactly - kept as an
# independent copy since these scripts are invoked standalone, not
# imported as a shared module.
MITRE_BY_TYPE = {
    "command_injection": ["T1190"],
    "code_injection": ["T1190"],
    "sql_injection": ["T1190"],
    "xss": ["T1189"],
    "path_traversal": ["T1083"],
    "ssrf": ["T1190"],
}


def classify(check_id):
    for substr, type_ in TYPE_TABLE:
        if substr in check_id:
            return type_
    return "unmapped"


def classify_secret(check_id):
    for substr, secret_type in SECRET_TYPE_TABLE:
        if substr in check_id:
            return secret_type
    return "unknown"


def confidence_from_severity(severity):
    return "high" if (severity or "").upper() == "ERROR" else "low"


def is_taint_finding(check_id):
    # Substring match, not exact/suffix match on the raw id - semgrep
    # prefixes the id with the config file's path when loaded locally
    # (e.g. "skills.source-code-analysis.references.clicky-sql-injection-
    # python-taint"), the same reason `classify()` above uses substring
    # match rather than a stricter comparison. Confirmed live against the
    # bundled ruleset during verification.
    return "-taint" in (check_id or "")


def extract_dataflow_trace(extra):
    # Reads semgrep's `extra.dataflow_trace`, which would carry a
    # separately-tracked intermediate-variable source file:line for a
    # `mode: taint` finding. Returns None when absent rather than
    # fabricating a location - confirmed to be the expected case for the
    # OSS engine this project deliberately uses (Pro-only field; verified
    # absent from this project's semgrep 1.159.0 output both with and
    # without `--dataflow-traces` passed to the semgrep invocation).
    trace = (extra or {}).get("dataflow_trace")
    if not trace:
        return None
    return trace


def read_line(path, line_no):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        if 1 <= line_no <= len(lines):
            return lines[line_no - 1].strip()
    except OSError:
        pass
    return ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("semgrep_json_file")
    parser.add_argument("--source-dir", required=True)
    args = parser.parse_args()

    try:
        with open(args.semgrep_json_file) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: could not parse semgrep JSON output: {exc}", file=sys.stderr)
        sys.exit(1)

    source_dir_abs = os.path.abspath(args.source_dir)
    findings = []
    next_id = 1

    for result in data.get("results", []):
        check_id = result.get("check_id", "")
        abs_path = result.get("path", "")
        rel_path = os.path.relpath(abs_path, source_dir_abs) if abs_path else "unknown"
        line = (result.get("start") or {}).get("line", 0)
        extra = result.get("extra") or {}
        severity = extra.get("severity", "")
        confidence = confidence_from_severity(severity)

        type_ = classify(check_id)

        if type_ == "hardcoded_secret":
            findings.append({
                "id": f"src-{next_id}",
                "type": "hardcoded_secret",
                "file": rel_path,
                "line": line,
                "secret_type": classify_secret(check_id),
                "confidence": confidence,
            })
        elif type_ == "unmapped":
            findings.append({
                "id": f"src-{next_id}",
                "type": "unmapped",
                "file": rel_path,
                "line": line,
                "sink": read_line(abs_path, line),
                "confidence": confidence,
                "raw_rule_id": check_id,
            })
        else:
            finding = {
                "id": f"src-{next_id}",
                "type": type_,
                "file": rel_path,
                "line": line,
                "sink": read_line(abs_path, line),
                "confidence": confidence,
                "suggested_attack_vector": {"technique": type_},
                "mitre_attack": MITRE_BY_TYPE.get(type_, []),
            }

            if is_taint_finding(check_id):
                # A traced flow is stronger evidence than severity alone -
                # unconditional "high", regardless of the rule's static
                # `severity:`.
                finding["confidence"] = "high"
                finding["taint_traced"] = True
                trace = extract_dataflow_trace(extra)
                if trace is not None:
                    # Rare, Pro-only case: a real separately-tracked
                    # intermediate-variable source file:line.
                    finding["source_of_taint"] = (
                        f"traced via semgrep dataflow_trace: {trace}"
                    )
                else:
                    # Expected OSS-engine case (confirmed live during this
                    # ruleset's verification, both with and without
                    # `--dataflow-traces`): the flow itself is genuinely
                    # traced - `pattern-sources` was confirmed to reach
                    # `pattern-sinks` through the function's dataflow, not
                    # mere proximity - but the granular intermediate-
                    # variable trace requires Semgrep Pro and isn't
                    # available in this deployment.
                    finding["source_of_taint"] = (
                        "traced via semgrep `mode: taint` dataflow analysis - "
                        "source pattern confirmed to reach this sink through "
                        "the function's data flow; the granular intermediate-"
                        "variable trace requires Semgrep Pro and isn't "
                        "available in this deployment, but this is a real "
                        "traced flow, not proximity matching"
                    )
            else:
                finding["source_of_taint"] = (
                    "matched via semgrep pattern match, not a separately-tracked "
                    "line - this ruleset uses pattern matching, not taint-mode "
                    "dataflow rules, so source and sink are the same matched "
                    "expression (see 'sink')"
                )

            findings.append(finding)
        next_id += 1

    files_scanned = len((data.get("paths") or {}).get("scanned", []))

    print(json.dumps({
        "source_location": source_dir_abs,
        "files_scanned": files_scanned,
        "scanner": "semgrep",
        "findings": findings,
    }, indent=2))


if __name__ == "__main__":
    main()
