#!/usr/bin/env python3
"""Dependency Enrich - add CVE exploitability signal (EPSS score/percentile,
CISA KEV listed status) to dependency_normalize.py's output.

Usage: dependency_enrich.py <normalized_json_file>

Only CVE-shaped vulnerability_id values can be enriched - EPSS and CISA KEV
are both CVE-only feeds. GHSA-only (npm-audit) or OSV-only (govulncheck)
entries are left completely untouched, not fabricated with placeholder
values. This is the first network-dependent step in this skill (everything
upstream - trivy/npm-audit/pip-audit/bundler-audit/govulncheck plus
dependency_normalize.py - is fully offline), so failure here must never
fail the parent scan: any network error for either feed is caught,
recorded in a new top-level "enrichment_skipped" array with a human-
readable reason, and this script still exits 0 with the vulnerabilities
list otherwise intact (unenriched). See dependency-scanner.sh's existing
trivy-preferred/per-ecosystem-fallback block for the same "never silently
report success or silently swallow a real failure" idiom this follows.

EPSS: batched via api.first.org (https://www.first.org/epss/api), chunked
at 100 CVEs per request as a conservative default - unverified against the
API's actual limits in this implementation, confirm empirically if this
becomes a bottleneck on large dependency trees.

CISA KEV: fetched once per run from the static feed. Not cached to disk -
this repo's scripts are otherwise stateless, and this is a deliberate
choice to keep it that way rather than default to a TTL cache.
"""
import argparse
import json
import re
import sys
import urllib.error
import urllib.request

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REQUEST_TIMEOUT = 10
EPSS_CHUNK_SIZE = 100

CVE_RE = re.compile(r"CVE-\d{4}-\d+")


def extract_cve(vulnerability_id):
    m = CVE_RE.search(vulnerability_id or "")
    return m.group(0) if m else None


def fetch_json(url, timeout=REQUEST_TIMEOUT):
    req = urllib.request.Request(url, headers={"User-Agent": "Clicky-dependency-enrich/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status}")
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def fetch_epss(cve_ids):
    """Returns {cve: (score, percentile)} for whichever CVEs EPSS knows about."""
    result = {}
    cve_list = sorted(cve_ids)
    for i in range(0, len(cve_list), EPSS_CHUNK_SIZE):
        chunk = cve_list[i:i + EPSS_CHUNK_SIZE]
        url = f"{EPSS_URL}?cve={','.join(chunk)}"
        data = fetch_json(url)
        for entry in data.get("data", []):
            cve = entry.get("cve")
            if not cve:
                continue
            try:
                score = float(entry.get("epss"))
                percentile = float(entry.get("percentile"))
            except (TypeError, ValueError):
                continue
            result[cve] = (score, percentile)
    return result


def fetch_kev():
    """Returns the set of CVE IDs CISA lists as known-exploited."""
    data = fetch_json(KEV_URL)
    return {v.get("cveID") for v in data.get("vulnerabilities", []) if v.get("cveID")}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("normalized_json_file")
    args = parser.parse_args()

    try:
        with open(args.normalized_json_file) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: could not parse normalized dependency JSON: {exc}", file=sys.stderr)
        sys.exit(1)

    vulnerabilities = data.get("vulnerabilities", [])
    enrichment_skipped = list(data.get("enrichment_skipped", []))

    cve_by_vuln = {}
    for idx, vuln in enumerate(vulnerabilities):
        cve = extract_cve(vuln.get("vulnerability_id", ""))
        if cve:
            cve_by_vuln[idx] = cve

    cve_ids = set(cve_by_vuln.values())

    epss_scores = {}
    if cve_ids:
        try:
            epss_scores = fetch_epss(cve_ids)
        except (urllib.error.URLError, RuntimeError, TimeoutError, OSError, ValueError) as exc:
            enrichment_skipped.append(f"EPSS: {exc}")

    kev_set = None
    if cve_ids:
        try:
            kev_set = fetch_kev()
        except (urllib.error.URLError, RuntimeError, TimeoutError, OSError, ValueError) as exc:
            enrichment_skipped.append(f"CISA KEV: {exc}")

    for idx, cve in cve_by_vuln.items():
        vuln = vulnerabilities[idx]
        if cve in epss_scores:
            score, percentile = epss_scores[cve]
            vuln["epss_score"] = score
            vuln["epss_percentile"] = percentile
        if kev_set is not None:
            vuln["cisa_kev_listed"] = cve in kev_set

    data["vulnerabilities"] = vulnerabilities
    data["enrichment_skipped"] = enrichment_skipped

    print(json.dumps(data, indent=2))


if __name__ == "__main__":
    main()
