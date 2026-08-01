#!/bin/bash
#
# Runs every test in this directory. Single entry point, non-zero exit if
# anything fails. See tests/README.md for what each suite actually backs.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAILED=0

run() {
    local label="$1"
    shift
    echo "=== $label ==="
    if "$@"; then
        echo "PASS"
    else
        echo "FAIL"
        FAILED=1
    fi
    echo
}

if ! python3 -c "import jsonschema" 2>/dev/null; then
    echo "ERROR: the 'jsonschema' Python package is required for the schema-validation"
    echo "suite. Install it with: pip install jsonschema"
    echo "(This is a dev-time test dependency only - not required to run the plugin itself.)"
    exit 1
fi

run "bash syntax" "$HERE/syntax/check_bash_syntax.sh"
run "python syntax" "$HERE/syntax/check_python_syntax.sh"
run "prompt-injection-probe canary detection (real mock HTTP server)" "$HERE/prompt_injection/test_prompt_injection_probe.sh"
run "converter schema validation (real SARIF 2.1.0 / CycloneDX 1.5 schemas)" python3 "$HERE/schema_validation/test_schema_validation.py"
run "finding-validator Tier 1 trace cross-check (fixtures)" "$HERE/finding_validator/test_finding_validator.sh"
run "attempt-aggregator calibration (fixtures)" "$HERE/calibration/test_calibrate_success_rates.sh"

exit $FAILED
