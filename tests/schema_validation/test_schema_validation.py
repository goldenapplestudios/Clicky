#!/usr/bin/env python3
"""Backs skills/report-generation/SKILL.md's claim that sarif_convert.py,
cyclonedx_convert.py, and aibom_convert.py were "validated ... against the
real, published SARIF 2.1.0 and CycloneDX 1.5 JSON Schemas" with an actual
re-runnable test, instead of prose pointing at header comments that (per
an earlier audit) don't actually contain any such statement.

Runs each converter as a real subprocess against a fixture, then validates
its actual stdout against the vendored schemas in tests/schema_validation/
schemas/ (fetched from their canonical published URLs - see schemas/README.md).
"""
import json
import pathlib
import subprocess
import sys
import warnings

try:
    import jsonschema
except ImportError:
    print("ERROR: the 'jsonschema' package is required to run this test (pip install jsonschema).")
    print("This is a dev-time test dependency only, not a runtime dependency of the plugin itself.")
    sys.exit(1)

HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
SCHEMAS = HERE / "schemas"
FIXTURES = HERE / "fixtures"
SCRIPTS = REPO_ROOT / "skills" / "report-generation" / "scripts"


def load_schema_with_resolver(schema_path):
    schema = json.loads(schema_path.read_text())
    # CycloneDX's schema $refs spdx.schema.json and jsf-0.82.schema.json by
    # relative filename - point the resolver at the local vendored copies
    # instead of hitting the network on every test run. RefResolver is
    # deprecated in favor of the `referencing` library as of jsonschema
    # 4.18 but still functional; not worth an extra dependency for a test
    # script - silence the deprecation warning rather than pull it in.
    base_uri = schema_path.resolve().as_uri()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        resolver = jsonschema.RefResolver(base_uri=base_uri, referrer=schema)
    return schema, resolver


def run_converter(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"{args} exited {result.returncode}: {result.stderr}")
    return json.loads(result.stdout)


def validate(name, instance, schema_path):
    schema, resolver = load_schema_with_resolver(schema_path)
    validator = jsonschema.Draft7Validator(schema, resolver=resolver)
    errors = list(validator.iter_errors(instance))
    if errors:
        print(f"FAIL: {name} - {len(errors)} schema violation(s):")
        for e in errors[:5]:
            print(f"  - {list(e.path)}: {e.message}")
        return False
    print(f"PASS: {name} is valid against {schema_path.name}")
    return True


def main():
    ok = True

    sarif_output = run_converter([
        "python3", str(SCRIPTS / "sarif_convert.py"),
        str(FIXTURES / "source_findings_sample.json"),
    ])
    ok &= validate("sarif_convert.py output", sarif_output, SCHEMAS / "sarif-2.1.0.json")

    cyclonedx_output = run_converter([
        "python3", str(SCRIPTS / "cyclonedx_convert.py"),
        str(FIXTURES / "dependency_findings_sample.json"),
    ])
    ok &= validate("cyclonedx_convert.py output", cyclonedx_output, SCHEMAS / "cyclonedx-1.5.json")

    aibom_output = run_converter([
        "python3", str(SCRIPTS / "aibom_convert.py"),
        str(FIXTURES / "llm_probe_sample_dir"),
    ])
    ok &= validate("aibom_convert.py output", aibom_output, SCHEMAS / "cyclonedx-1.5.json")

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
