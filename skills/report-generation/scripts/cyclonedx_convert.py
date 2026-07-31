#!/usr/bin/env python3
"""CycloneDX Convert - convert skills/source-code-analysis's
dependency_findings.json into CycloneDX 1.5 JSON.

Usage: cyclonedx_convert.py <dependency_findings.json>

IMPORTANT LIMITATION, stated here and in the caller's command name
(interop-formats.sh's subcommand is deliberately "sbom-partial", not
"sbom"): this is a vulnerability-derived PARTIAL component list, not a
true software inventory. dependency-scanner.sh's upstream tools
(trivy/npm-audit/pip-audit/bundler-audit/govulncheck) only ever report
packages that have a known vulnerability - a package with zero known
CVEs never appears anywhere in dependency_findings.json, so it never
appears here either. Do not present this output as a complete SBOM to
anyone expecting CycloneDX's normal completeness guarantee.

Field mapping:
  - one components[] entry per distinct (package, installed_version) pair
    (deduped - a package with 5 CVEs shows up once in components,
    5 times in vulnerabilities)
  - bom-ref uses a best-effort purl, typed by which scanner found it
    (npm-audit -> pkg:npm/..., pip-audit -> pkg:pypi/..., bundler-audit
    -> pkg:gem/..., govulncheck -> pkg:golang/..., trivy -> pkg:generic/...
    since trivy itself spans ecosystems and the normalized shape doesn't
    carry which one a given trivy result came from)
  - Phase 1's epss_score/epss_percentile/cisa_kev_listed enrichment
    (when present) is carried into each vulnerability's properties bag -
    CycloneDX 1.5 has no native EPSS/KEV fields.
"""
import json
import sys
import uuid

PURL_TYPE_BY_SOURCE = {
    "npm-audit": "npm",
    "pip-audit": "pypi",
    "bundler-audit": "gem",
    "govulncheck": "golang",
}


def purl_for(vuln):
    purl_type = PURL_TYPE_BY_SOURCE.get(vuln.get("source", ""), "generic")
    package = vuln.get("package", "unknown")
    version = vuln.get("installed_version", "unknown")
    return f"pkg:{purl_type}/{package}@{version}"


def severity_for_cyclonedx(severity):
    s = (severity or "unknown").lower()
    valid = {"critical", "high", "medium", "low", "info", "none", "unknown"}
    return s if s in valid else "unknown"


def main():
    if len(sys.argv) != 2:
        print("Usage: cyclonedx_convert.py <dependency_findings.json>", file=sys.stderr)
        sys.exit(1)

    try:
        with open(sys.argv[1]) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: could not parse dependency findings JSON: {exc}", file=sys.stderr)
        sys.exit(1)

    vulnerabilities_in = data.get("vulnerabilities", [])

    components = {}
    cdx_vulnerabilities = []

    for vuln in vulnerabilities_in:
        ref = purl_for(vuln)

        if ref not in components:
            components[ref] = {
                "type": "library",
                "bom-ref": ref,
                "name": vuln.get("package", "unknown"),
                "version": vuln.get("installed_version", "unknown"),
                "purl": ref,
            }

        properties = []
        if "epss_score" in vuln:
            properties.append({"name": "epss_score", "value": str(vuln["epss_score"])})
        if "epss_percentile" in vuln:
            properties.append({"name": "epss_percentile", "value": str(vuln["epss_percentile"])})
        if "cisa_kev_listed" in vuln:
            properties.append({"name": "cisa_kev_listed", "value": str(vuln["cisa_kev_listed"]).lower()})

        cdx_vuln = {
            "id": vuln.get("vulnerability_id", "unknown"),
            "source": {"name": vuln.get("source", "unknown")},
            "ratings": [{"severity": severity_for_cyclonedx(vuln.get("severity"))}],
            "affects": [{"ref": ref}],
        }
        if vuln.get("description"):
            cdx_vuln["description"] = vuln["description"]
        if properties:
            cdx_vuln["properties"] = properties

        cdx_vulnerabilities.append(cdx_vuln)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": __import__("datetime").datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [{"vendor": "Clicky", "name": "dependency-scanner", "version": "1.0.0"}],
        },
        "components": list(components.values()),
        "vulnerabilities": cdx_vulnerabilities,
    }

    print(json.dumps(bom, indent=2))


if __name__ == "__main__":
    main()
