#!/usr/bin/env python3
"""Dependency Normalize - read whichever raw scanner output files
dependency-scanner.sh produced in a work directory and normalize them into
one common JSON shape.

Usage: dependency_normalize.py <work_dir> --scanners <comma,list> --skipped <pipe|list>

Uses python (not jq) deliberately: each tool's JSON shape varies in ways
(optional keys, nested unions) that are more robust to handle with
.get()-chains than with a strict jq path expression.
"""
import argparse
import json
import os
import re
import sys


def normalize_trivy(path):
    out = []
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return out
    for result in data.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            out.append({
                "package": vuln.get("PkgName", "unknown"),
                "installed_version": vuln.get("InstalledVersion", "unknown"),
                "fixed_version": vuln.get("FixedVersion", ""),
                "vulnerability_id": vuln.get("VulnerabilityID", "unknown"),
                "severity": (vuln.get("Severity") or "UNKNOWN").upper(),
                "description": (vuln.get("Title") or vuln.get("Description") or "")[:300],
                "source": "trivy",
            })
    return out


def normalize_npm_audit(path):
    out = []
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return out

    # npm v7+ shape: {"vulnerabilities": {"<pkg>": {"severity", "via": [...], "range", ...}}}
    vulns = data.get("vulnerabilities")
    if isinstance(vulns, dict):
        for pkg, info in vulns.items():
            severity = (info.get("severity") or "unknown").upper()
            via = info.get("via", [])
            ids = []
            descriptions = []
            for v in via:
                if isinstance(v, dict):
                    if v.get("url"):
                        m = re.search(r"(CVE-\d{4}-\d+|GHSA-[\w-]+)", v["url"])
                        ids.append(m.group(1) if m else v["url"])
                    if v.get("title"):
                        descriptions.append(v["title"])
                elif isinstance(v, str):
                    # via can just be a package name string for transitive deps
                    continue
            out.append({
                "package": pkg,
                "installed_version": info.get("range", "unknown"),
                "fixed_version": (info.get("fixAvailable") or {}).get("version", "")
                                 if isinstance(info.get("fixAvailable"), dict) else "",
                "vulnerability_id": ", ".join(ids) if ids else "unknown",
                "severity": severity,
                "description": "; ".join(descriptions)[:300],
                "source": "npm-audit",
            })
        return out

    # npm v6 shape: {"advisories": {"<id>": {"module_name", "severity", "findings": [{"version"}], "title"}}}
    advisories = data.get("advisories")
    if isinstance(advisories, dict):
        for adv_id, info in advisories.items():
            findings = info.get("findings", [])
            version = findings[0].get("version", "unknown") if findings else "unknown"
            out.append({
                "package": info.get("module_name", "unknown"),
                "installed_version": version,
                "fixed_version": info.get("patched_versions", ""),
                "vulnerability_id": str(info.get("cves") or adv_id),
                "severity": (info.get("severity") or "unknown").upper(),
                "description": (info.get("title") or "")[:300],
                "source": "npm-audit",
            })
    return out


def normalize_govulncheck(path):
    out = []
    try:
        with open(path) as f:
            lines = f.readlines()
    except OSError:
        return out
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        finding = entry.get("finding")
        if not finding:
            continue
        osv = finding.get("osv", "unknown")
        out.append({
            "package": (finding.get("trace") or [{}])[0].get("module", "unknown"),
            "installed_version": (finding.get("trace") or [{}])[0].get("version", "unknown"),
            "fixed_version": "",
            "vulnerability_id": osv,
            "severity": "UNKNOWN",
            "description": "Reachable known-vulnerable Go module (govulncheck)",
            "source": "govulncheck",
        })
    return out


def normalize_bundler_audit(path):
    # bundler-audit's plaintext output isn't structured JSON; extract what
    # we reasonably can rather than skip it entirely.
    out = []
    try:
        with open(path) as f:
            text = f.read()
    except OSError:
        return out
    for block in text.split("\n\n"):
        gem_m = re.search(r"^Name:\s*(\S+)", block, re.MULTILINE)
        version_m = re.search(r"^Version:\s*(\S+)", block, re.MULTILINE)
        advisory_m = re.search(r"^Advisory:\s*(\S+)", block, re.MULTILINE)
        title_m = re.search(r"^Title:\s*(.+)$", block, re.MULTILINE)
        criticality_m = re.search(r"^Criticality:\s*(\S+)", block, re.MULTILINE)
        if gem_m:
            out.append({
                "package": gem_m.group(1),
                "installed_version": version_m.group(1) if version_m else "unknown",
                "fixed_version": "",
                "vulnerability_id": advisory_m.group(1) if advisory_m else "unknown",
                "severity": (criticality_m.group(1).upper() if criticality_m else "UNKNOWN"),
                "description": (title_m.group(1) if title_m else "")[:300],
                "source": "bundler-audit",
            })
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("work_dir")
    parser.add_argument("--scanners", default="")
    parser.add_argument("--skipped", default="")
    args = parser.parse_args()

    scanners = [s for s in args.scanners.split(",") if s]
    skipped = [s for s in args.skipped.split("|") if s]

    vulnerabilities = []
    if "trivy" in scanners:
        vulnerabilities += normalize_trivy(os.path.join(args.work_dir, "trivy.json"))
    if "npm-audit" in scanners:
        vulnerabilities += normalize_npm_audit(os.path.join(args.work_dir, "npm-audit.json"))
    if "govulncheck" in scanners:
        vulnerabilities += normalize_govulncheck(os.path.join(args.work_dir, "govulncheck.json"))
    if "bundler-audit" in scanners:
        vulnerabilities += normalize_bundler_audit(os.path.join(args.work_dir, "bundler-audit.txt"))
    if "pip-audit" in scanners:
        # pip-audit's --format json is already close to flat; normalize keys.
        path = os.path.join(args.work_dir, "pip-audit.json")
        try:
            with open(path) as f:
                data = json.load(f)
            deps = data.get("dependencies", data if isinstance(data, list) else [])
            for dep in deps:
                for vuln in dep.get("vulns", []):
                    vulnerabilities.append({
                        "package": dep.get("name", "unknown"),
                        "installed_version": dep.get("version", "unknown"),
                        "fixed_version": ", ".join(vuln.get("fix_versions", [])),
                        "vulnerability_id": vuln.get("id", "unknown"),
                        "severity": "UNKNOWN",
                        "description": (vuln.get("description") or "")[:300],
                        "source": "pip-audit",
                    })
        except (OSError, json.JSONDecodeError):
            pass

    print(json.dumps({
        "scanners_run": scanners,
        "skipped": skipped,
        "vulnerabilities": vulnerabilities,
    }, indent=2))


if __name__ == "__main__":
    main()
