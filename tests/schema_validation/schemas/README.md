Vendored copies of the real, published schemas these tests validate against - fetched 2026-07-31:

- `sarif-2.1.0.json` - https://www.schemastore.org/sarif-2.1.0.json
- `cyclonedx-1.5.json` - https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.5.schema.json
- `spdx.schema.json`, `jsf-0.82.schema.json` - `$ref` dependencies of the CycloneDX schema above, from the same repository

If Clicky ever bumps its target SARIF/CycloneDX version, re-fetch these from the same sources for the new version and update `tests/schema_validation/test_schema_validation.py`'s references accordingly.
