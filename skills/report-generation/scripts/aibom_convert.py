#!/usr/bin/env python3
"""AIBOM Convert - convert skills/ai-llm-security-testing's probe output
(llm_probe_*.json files, written by prompt-injection-probe.sh) into
CycloneDX 1.5 JSON, using the "machine-learning-model" component type.

Usage: aibom_convert.py <session_recon_dir>

Unlike sarif_convert.py/cyclonedx_convert.py (one findings file in, one
converter run), this one takes a *directory* and globs every
llm_probe_*.json inside it - a single target is typically probed by more
than one payload file (prompt-injection.txt, jailbreak-techniques.txt,
system-prompt-extraction.txt), and this converter groups all of them by
`target` into one machine-learning-model component per endpoint.

IMPORTANT LIMITATION, stated here and in the caller's command name
(interop-formats.sh's subcommand is deliberately "aibom-partial", not
"aibom", mirroring cyclonedx_convert.py's "sbom-partial" precedent): this
is a black-box-probe-derived PARTIAL AI component inventory, not a true
AIBOM/model card. Clicky's probes never see the model's architecture,
training data, weights, hash, or provenance - only how an endpoint
responds to injected text over HTTP. Do not present this output as a
complete AIBOM to anyone expecting CycloneDX ML-BOM's normal model-card
completeness (modelCard is intentionally omitted below rather than
populated with fabricated data).

Field mapping:
  - one components[] entry per distinct `target` URL seen across all
    input files, typed "machine-learning-model"
  - which OWASP LLM Top 10 (2025) category each input file represents is
    inferred from its `payload_file` name (authoritative - the field the
    probe script itself set - not from the operator-chosen --output
    filename):
      *jailbreak*                 -> LLM01 (Prompt Injection)
      *system-prompt-extraction*  -> LLM07 (System Prompt Leakage)
      anything else (default prompt-injection.txt) -> LLM01
  - each component's properties[] record, per category tested, a verdict
    breakdown (counts of possible_injection/no_injection_detected/
    manual_review_needed/no_response) - so a consumer can see coverage
    even for categories that produced zero findings
  - a `possible_injection` result becomes one vulnerabilities[] entry,
    severity fixed at "low" - matching this skill's own Communication
    Protocol rule (SKILL.md: "Never log this above `low` confidence" -
    a canary appearing in a response is a lead, not confirmed impact)
  - `manual_review_needed` results (system-prompt-extraction has no
    automated verdict) are counted in properties[] but deliberately never
    promoted to a vulnerabilities[] entry - SKILL.md is explicit that
    logging one of these as a finding on its own, without a human
    reading the actual response first, is not allowed. This converter
    holds the same line.
"""
import glob
import hashlib
import json
import os
import sys
import uuid

CATEGORY_BY_PAYLOAD_MARKER = [
    ("jailbreak", "LLM01", "Prompt Injection (jailbreak variant)"),
    ("system-prompt-extraction", "LLM07", "System Prompt Leakage"),
]
DEFAULT_CATEGORY = ("LLM01", "Prompt Injection")


def category_for(payload_file):
    basename = os.path.basename(payload_file or "")
    for marker, owasp_id, label in CATEGORY_BY_PAYLOAD_MARKER:
        if marker in basename:
            return owasp_id, label
    return DEFAULT_CATEGORY


def bom_ref_for(target):
    digest = hashlib.sha1(target.encode("utf-8")).hexdigest()[:16]
    return f"ai-component-{digest}"


def load_probe_files(recon_dir):
    paths = sorted(glob.glob(os.path.join(recon_dir, "llm_probe_*.json")))
    records = []
    for path in paths:
        try:
            with open(path) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"WARNING: skipping unparseable probe file {path}: {exc}", file=sys.stderr)
            continue
        target = data.get("target")
        if not target:
            print(f"WARNING: skipping probe file with no target: {path}", file=sys.stderr)
            continue
        records.append(data)
    return records


def main():
    if len(sys.argv) != 2:
        print("Usage: aibom_convert.py <session_recon_dir>", file=sys.stderr)
        sys.exit(1)

    recon_dir = sys.argv[1]
    probe_records = load_probe_files(recon_dir)
    if not probe_records:
        print(f"ERROR: no parseable llm_probe_*.json files found in {recon_dir}", file=sys.stderr)
        sys.exit(1)

    # verdict_counts_by_target[ref][owasp_id] -> {verdict: count}, accumulated
    # across every probe file for that target before rendering to a
    # properties[] string, so two files mapping to the same category (e.g.
    # two separate jailbreak runs) merge into one clean count instead of
    # two concatenated summary strings.
    targets = {}
    verdict_counts_by_target = {}
    vulnerabilities = []
    vuln_counter = 0

    for record in probe_records:
        target = record["target"]
        owasp_id, owasp_label = category_for(record.get("payload_file"))
        ref = bom_ref_for(target)
        targets[ref] = target
        verdict_counts_by_target.setdefault(ref, {}).setdefault(owasp_id, {"label": owasp_label, "counts": {}})
        counts = verdict_counts_by_target[ref][owasp_id]["counts"]

        for result in record.get("results", []):
            verdict = result.get("verdict", "unknown")
            counts[verdict] = counts.get(verdict, 0) + 1

            if verdict == "possible_injection":
                vuln_counter += 1
                excerpt = (result.get("payload_excerpt") or "")[:120]
                response_excerpt = (result.get("response_excerpt") or "")[:200]
                vulnerabilities.append({
                    "id": f"CLICKY-AIBOM-{vuln_counter:04d}",
                    "source": {"name": "Clicky ai-llm-security-testing (prompt-injection-probe.sh)"},
                    "ratings": [{"severity": "low"}],
                    "description": f"Canary token from an injected payload was reflected/acted on in the "
                                    f"model response - a lead, not confirmed exploitation. "
                                    f"Payload: \"{excerpt}\". Response excerpt: \"{response_excerpt}\".",
                    "affects": [{"ref": ref}],
                    "properties": [{"name": "owasp_llm", "value": owasp_id}],
                })

    components = []
    for ref, target in targets.items():
        properties = [
            {"name": "clicky:aibom_scope",
             "value": "black-box probe-derived only - not a vendor model card"},
        ]
        for owasp_id, entry in sorted(verdict_counts_by_target[ref].items()):
            summary = ", ".join(f"{k}={v}" for k, v in sorted(entry["counts"].items()))
            note = " (no automated verdict - manual review required per SKILL.md)" if owasp_id == "LLM07" else ""
            properties.append({
                "name": f"clicky:owasp_llm:{owasp_id}",
                "value": f"{entry['label']} - tested{note}: {summary}",
            })
        components.append({
            "type": "machine-learning-model",
            "bom-ref": ref,
            "name": target,
            "description": "LLM-integrated endpoint discovered and probed via black-box testing "
                            "(skills/ai-llm-security-testing). No model architecture, weights, or "
                            "training provenance available - see this file's header.",
            "properties": properties,
        })

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": __import__("datetime").datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [{"vendor": "Clicky", "name": "ai-llm-security-testing", "version": "1.0.0"}],
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }

    print(json.dumps(bom, indent=2))


if __name__ == "__main__":
    main()
