# Clicky tests

Run everything with:
```bash
./tests/run_all.sh
```

Requires `python3`, `jq`, and the `jsonschema` pip package (`pip install jsonschema`) - the last one is a dev-time test dependency only, not something the plugin itself needs at runtime.

## Why this exists

An audit of this repo found several places asserting things were "verified live" or "validated during development... see their header comments," with zero test/CI/mock infrastructure anywhere to back those claims - the header comments in question didn't actually contain any such statement, and there was nothing anyone (including a future Claude session) could re-run to check. This directory makes those specific claims either true and reproducible, or removes them. It's deliberately scoped to what's actually claimed elsewhere in the repo, not an open-ended "test everything" effort:

- `syntax/` - `bash -n` / `python3 -m py_compile` over every script in `skills/`. The baseline sanity check.
- `prompt_injection/` - runs the real `skills/ai-llm-security-testing/scripts/prompt-injection-probe.sh` against a real local mock HTTP server (`mock_server.py`, stdlib only) and asserts its canary-detection logic actually works: every injected canary is detected against a naively-reflecting endpoint, zero false positives against a refusing one. Backs `skills/ai-llm-security-testing/SKILL.md`'s "Verified live against two mock endpoints" claim.
- `schema_validation/` - runs the real `sarif_convert.py`, `cyclonedx_convert.py`, and `aibom_convert.py` (all in `skills/report-generation/scripts/`) against fixtures, and validates their actual output against the real, published SARIF 2.1.0 and CycloneDX 1.5 JSON Schemas (vendored in `schemas/`, see `schemas/README.md` for provenance). Backs `skills/report-generation/SKILL.md`'s schema-validation claim.
- `finding_validator/` - fixture test for `skills/session-management/scripts/finding-validator.sh`'s Tier 1 mechanical trace cross-check, covering all three possible outcomes (`pass`/`fail`/`no_evidence`).
- `calibration/` - fixture test for `skills/session-management/scripts/attempt-aggregator.sh`, the mechanism behind `skills/htb-decision-tree`'s self-calibrated success rates. Hand-computed expected rates, plus a check that a service below the sample-size threshold correctly reports `insufficient_data` instead of a misleadingly precise number.

Nothing here is a general-purpose test framework - it's plain bash/python with manual assertions, matching the rest of this repo's style (no other dependency is added beyond `jsonschema`).
