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

run "bash syntax" "$HERE/syntax/check_bash_syntax.sh"
run "python syntax" "$HERE/syntax/check_python_syntax.sh"
run "prompt-injection-probe canary detection (real mock HTTP server)" "$HERE/prompt_injection/test_prompt_injection_probe.sh"

if python3 -c "import jsonschema" 2>/dev/null; then
    run "converter schema validation (real SARIF 2.1.0 / CycloneDX 1.5 schemas)" python3 "$HERE/schema_validation/test_schema_validation.py"
else
    echo "=== converter schema validation (real SARIF 2.1.0 / CycloneDX 1.5 schemas) ==="
    echo "ERROR: the 'jsonschema' Python package is required for this suite."
    echo "Install it with: pip install jsonschema"
    echo "(This is a dev-time test dependency only - not required to run the plugin itself.)"
    echo "FAIL"
    FAILED=1
    echo
fi

run "finding-validator Tier 1 trace cross-check (fixtures)" "$HERE/finding_validator/test_finding_validator.sh"
run "attempt-aggregator calibration (fixtures)" "$HERE/calibration/test_calibrate_success_rates.sh"
run "severity-review-logger mechanical slop_score recomputation (fixtures)" "$HERE/severity_review/test_severity_review_logger.sh"
run "severity-calibration-aggregator (fixtures)" "$HERE/severity_calibration/test_severity_calibration_aggregator.sh"
run "tls-scan.sh (real self-signed server + testssl/sslscan/nmap fixtures)" "$HERE/tls_scan/test_tls_scan.sh"
run "security-headers-check.sh (real mock HTTP server)" "$HERE/security_headers/test_security_headers_check.sh"
run "mcp-gateway suite (token_store/scope_gate/provision-venv/launch.sh + live MCP protocol check)" "$HERE/mcp_gateway/run_tests.sh"
run "OpenCode target generation (drift check + live permission-resolution check if opencode is installed)" "$HERE/cli_targets/test_opencode_generation.sh"
run "Codex CLI target generation (drift check + TOML/structural validation)" "$HERE/cli_targets/test_codex_generation.sh"
run "Copilot CLI target generation (drift check + frontmatter/structural validation)" "$HERE/cli_targets/test_copilot_generation.sh"

exit $FAILED
