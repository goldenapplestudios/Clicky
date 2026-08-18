#!/bin/bash
#
# API Security Testing Script
# Tests REST, GraphQL, and modern API vulnerabilities
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Findings accumulated by the test_* functions below, read by
# generate_report() so the written report reflects what was actually
# found on this run instead of a static, always-unchecked template (L2).
CRITICAL_FINDINGS=()
HIGH_FINDINGS=()
MEDIUM_FINDINGS=()

# Endpoints that responded 200 during test_rest_api, reused by
# test_mass_assignment() as candidate resources to probe - the "known-good
# endpoint from an earlier discovery step" this script has to work with.
DISCOVERED_ENDPOINTS=()

# Function to test JWT vulnerabilities
test_jwt() {
    local endpoint="$1"
    local token="${2:-}"

    echo -e "${YELLOW}[*] Testing JWT vulnerabilities...${NC}"

    if [ -z "$token" ]; then
        echo "  No JWT token provided, skipping JWT tests"
        return
    fi

    # Decode JWT (base64)
    local header=$(echo "$token" | cut -d. -f1 | base64 -d 2>/dev/null || echo "Invalid")
    local payload=$(echo "$token" | cut -d. -f2 | base64 -d 2>/dev/null || echo "Invalid")

    echo "  JWT Header: $header"
    echo "  JWT Payload: $payload"

    # Test for none algorithm
    local none_token="${header}.${payload}."
    response=$(curl -s --max-time 10 -H "Authorization: Bearer $none_token" "$endpoint" 2>/dev/null || true)
    if ! echo "$response" | grep -q "invalid\|unauthorized\|401\|403"; then
        echo -e "${RED}[!] VULNERABLE: JWT none algorithm accepted!${NC}"
        CRITICAL_FINDINGS+=("JWT 'none' algorithm accepted at $endpoint")
    fi

    # Test for weak secret (common secrets)
    for secret in "secret" "password" "123456" "admin"; do
        # This would need jwt_tool or similar for proper testing
        echo "  Testing weak secret: $secret"
    done
}

# Function to test GraphQL introspection
test_graphql() {
    local endpoint="$1"

    echo -e "${YELLOW}[*] Testing GraphQL endpoint...${NC}"

    # Test introspection query
    local introspection_query='{"query":"{ __schema { types { name fields { name } } } }"}'

    response=$(curl -s --max-time 10 -X POST \
        -H "Content-Type: application/json" \
        -d "$introspection_query" \
        "$endpoint" 2>/dev/null || true)

    if echo "$response" | grep -q "__schema"; then
        echo -e "${RED}[!] GraphQL introspection is ENABLED!${NC}"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
        CRITICAL_FINDINGS+=("GraphQL introspection is enabled at $endpoint")

        # Test for query depth attack
        local depth_query='{"query":"{ user { posts { comments { user { posts { comments { user { name } } } } } } } }"}'
        depth_response=$(curl -s --max-time 10 -X POST \
            -H "Content-Type: application/json" \
            -d "$depth_query" \
            "$endpoint" 2>/dev/null || true)

        if ! echo "$depth_response" | grep -q "depth\|limit\|too deep"; then
            echo -e "${RED}[!] No query depth limit detected!${NC}"
            MEDIUM_FINDINGS+=("No GraphQL query depth limit detected at $endpoint")
        fi
    else
        echo -e "${GREEN}[+] GraphQL introspection appears disabled${NC}"
    fi
}

# Function to test REST API vulnerabilities
#
# Optional 3rd arg: a skills/web-crawling crawl_results.json file. When
# given, its discovered endpoint paths are tested alongside the fixed list
# below rather than instead of it - omitting this arg reproduces the
# original fixed-list-only behavior exactly.
test_rest_api() {
    local base_url="$1"
    local crawled_endpoints_file="${2:-}"

    echo -e "${YELLOW}[*] Testing REST API...${NC}"

    # Test for common endpoints
    local endpoints=("/users" "/admin" "/api/v1/users" "/api/v2/users" "/debug" "/metrics" "/health" "/swagger" "/api-docs")

    if [ -n "$crawled_endpoints_file" ] && [ -f "$crawled_endpoints_file" ] && command -v jq >/dev/null 2>&1; then
        while IFS= read -r crawled_path; do
            [ -n "$crawled_path" ] && endpoints+=("$crawled_path")
        done < <(jq -r --arg base "$base_url" '.endpoints[]?.url | if startswith($base) then .[($base | length):] else empty end' "$crawled_endpoints_file" 2>/dev/null)
        echo "  Merged in $(jq '.endpoints | length' "$crawled_endpoints_file" 2>/dev/null || echo 0) crawled endpoint(s) from $crawled_endpoints_file"
    fi

    for endpoint in "${endpoints[@]}"; do
        response_code=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" "$base_url$endpoint" 2>/dev/null || true)
        if [ "$response_code" != "404" ] && [ "$response_code" != "000" ]; then
            echo -e "${GREEN}[+] Found endpoint: $endpoint (HTTP $response_code)${NC}"

            # Test for authentication bypass
            if [ "$response_code" == "200" ]; then
                echo -e "${YELLOW}  Testing authentication on $endpoint...${NC}"
                DISCOVERED_ENDPOINTS+=("$base_url$endpoint")
            fi
        fi
    done

    # Test HTTP methods
    echo -e "${YELLOW}[*] Testing HTTP methods...${NC}"
    for method in GET POST PUT DELETE PATCH OPTIONS HEAD TRACE; do
        response_code=$(curl -s --max-time 10 -X $method -o /dev/null -w "%{http_code}" "$base_url" 2>/dev/null || true)
        if [ "$response_code" != "405" ] && [ "$response_code" != "000" ]; then
            echo "  $method: $response_code"
        fi
    done
}

# Function to test for rate limiting
test_rate_limiting() {
    local endpoint="$1"

    echo -e "${YELLOW}[*] Testing rate limiting...${NC}"

    # Send 20 rapid requests
    local success_count=0
    for i in {1..20}; do
        response_code=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" "$endpoint" 2>/dev/null || true)
        if [ "$response_code" == "200" ]; then
            success_count=$((success_count+1))
        elif [ "$response_code" == "429" ]; then
            echo -e "${GREEN}[+] Rate limiting detected after $i requests${NC}"
            return
        fi
    done

    if [ "$success_count" -eq 20 ]; then
        echo -e "${RED}[!] No rate limiting detected (20 requests succeeded)${NC}"
        HIGH_FINDINGS+=("No rate limiting detected on $endpoint (20 rapid requests all succeeded)")
    fi
}

# Function to test CORS configuration
test_cors() {
    local endpoint="$1"

    echo -e "${YELLOW}[*] Testing CORS configuration...${NC}"

    # Test with evil origin
    response=$(curl -s --max-time 10 -I -H "Origin: https://evil.com" "$endpoint" 2>/dev/null || true)

    if echo "$response" | grep -qi "access-control-allow-origin: \*\|access-control-allow-origin: https://evil.com"; then
        echo -e "${RED}[!] CORS misconfiguration detected - wildcard or reflects origin${NC}"
        CRITICAL_FINDINGS+=("CORS misconfiguration on $endpoint: wildcard or reflected origin accepted")
    else
        echo -e "${GREEN}[+] CORS appears properly configured${NC}"
    fi

    # Check credentials
    if echo "$response" | grep -qi "access-control-allow-credentials: true"; then
        echo -e "${YELLOW}[!] Credentials allowed in CORS${NC}"
        MEDIUM_FINDINGS+=("CORS Access-Control-Allow-Credentials: true on $endpoint")
    fi
}

# Function to test API versioning vulnerabilities
test_api_versions() {
    local base_url="$1"

    echo -e "${YELLOW}[*] Testing API versions...${NC}"

    local versions=("v1" "v2" "v3" "1.0" "2.0" "beta" "dev" "test" "staging")

    for version in "${versions[@]}"; do
        # Try different version patterns
        for pattern in "/api/$version" "/$version/api" "/api.$version" ""; do
            if [ -n "$pattern" ]; then
                url="$base_url$pattern"
                response_code=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || true)
                if [ "$response_code" != "404" ] && [ "$response_code" != "000" ]; then
                    echo -e "${GREEN}[+] Found API version: $url (HTTP $response_code)${NC}"
                    HIGH_FINDINGS+=("Old/beta API version reachable: $url (HTTP $response_code)")
                fi
            fi
        done
    done
}

# Function to test for API key vulnerabilities
test_api_keys() {
    local endpoint="$1"

    echo -e "${YELLOW}[*] Testing API key security...${NC}"

    # Test without API key
    response_code=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" "$endpoint" 2>/dev/null || true)
    if [ "$response_code" == "200" ]; then
        echo -e "${RED}[!] API accessible without authentication!${NC}"
        CRITICAL_FINDINGS+=("API accessible without any authentication: $endpoint")
    fi

    # Test common API key headers
    local headers=("X-API-Key" "apikey" "api-key" "authorization" "x-auth-token")
    local common_keys=("test" "demo" "admin" "12345" "password")

    for header in "${headers[@]}"; do
        for key in "${common_keys[@]}"; do
            response_code=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" -H "$header: $key" "$endpoint" 2>/dev/null || true)
            if [ "$response_code" == "200" ]; then
                echo -e "${RED}[!] Weak API key accepted: $header: $key${NC}"
                HIGH_FINDINGS+=("Weak API key accepted on $endpoint: $header: $key")
            fi
        done
    done
}

# Function to test for Mass Assignment (OWASP API3:2023 / Broken Object
# Property Level Authorization). Best-effort and generic: this script has
# no endpoint-specific knowledge of real field names, so for each endpoint
# test_rest_api discovered as live (DISCOVERED_ENDPOINTS), it resends a
# minimal synthetic JSON body twice - once "clean", once with common
# privilege-escalation-flavored fields appended - and flags cases where
# the response looks like the server accepted/echoed those extra fields.
# Like the JWT weak-secret list, a hit here is a strong lead worth
# confirming by hand, not a confirmed vulnerability on its own.
#
# IDOR is deliberately NOT attempted here: confirming IDOR requires two
# distinct object IDs known to belong to two different users/owners, which
# is target-specific context this generic script has no way to obtain on
# its own (see SKILL.md's IDOR section for the manual technique instead).
test_mass_assignment() {
    if [ "${#DISCOVERED_ENDPOINTS[@]}" -eq 0 ]; then
        echo -e "${YELLOW}[*] Skipping mass assignment test - no live endpoints were discovered to probe${NC}"
        return
    fi

    echo -e "${YELLOW}[*] Testing for mass assignment (best-effort, generic body)...${NC}"

    local clean_body='{"name":"clickytest","email":"clickytest@example.com"}'
    local polluted_body='{"name":"clickytest","email":"clickytest@example.com","role":"admin","isAdmin":true,"admin":true,"permissions":["*"]}'

    local endpoint method clean_code polluted_raw polluted_code
    for endpoint in "${DISCOVERED_ENDPOINTS[@]}"; do
        for method in PUT PATCH POST; do
            clean_code=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" -X "$method" \
                -H "Content-Type: application/json" \
                -d "$clean_body" \
                "$endpoint" 2>/dev/null || true)

            polluted_raw=$(curl -s --max-time 10 -X "$method" \
                -H "Content-Type: application/json" \
                -d "$polluted_body" \
                -w "\n%{http_code}" \
                "$endpoint" 2>/dev/null || true)
            polluted_code="${polluted_raw##*$'\n'}"

            # Only a signal when the request was actually accepted - a
            # rejected/nonexistent-method response (404/405/etc.) tells us
            # nothing about mass assignment either way.
            if [ "$polluted_code" == "200" ] || [ "$polluted_code" == "201" ]; then
                if echo "$polluted_raw" | grep -qiE '"(role"[[:space:]]*:[[:space:]]*"admin|isAdmin"[[:space:]]*:[[:space:]]*true|admin"[[:space:]]*:[[:space:]]*true|permissions"[[:space:]]*:[[:space:]]*\[)'; then
                    echo -e "${RED}[!] POSSIBLE MASS ASSIGNMENT: $method $endpoint accepted and echoed back privileged fields (role/isAdmin/admin/permissions)${NC}"
                    HIGH_FINDINGS+=("Possible mass assignment: $method $endpoint echoed injected role/isAdmin/admin/permissions fields back in a $polluted_code response - confirm manually")
                elif [ "$clean_code" != "200" ] && [ "$clean_code" != "201" ]; then
                    echo -e "${RED}[!] POSSIBLE MASS ASSIGNMENT: $method $endpoint rejected the clean body ($clean_code) but accepted the body with extra privileged fields ($polluted_code)${NC}"
                    HIGH_FINDINGS+=("Possible mass assignment: $method $endpoint returned $clean_code for a clean body but $polluted_code once role/isAdmin/admin/permissions fields were added - confirm manually")
                fi
            fi
        done
    done
}

# Renders one findings section as GitHub-style checkboxes: "[x]" for each
# real finding passed in as an arg, or a single unchecked "None detected"
# line when called with none. Takes the findings as positional args rather
# than a nameref (bash 3.2 - macOS's default /bin/bash - has no `local -n`;
# same constraint noted in web-crawling/crawl.sh's heredoc comment) so
# callers pass "${ARRAY[@]}" directly. Used by generate_report() so the
# report reflects what test_* actually found on this run instead of a
# static, always-unchecked template (L2).
render_findings_section() {
    if [ "$#" -eq 0 ]; then
        echo "- [ ] None detected by automated tests"
    else
        local f
        for f in "$@"; do
            echo "- [x] $f"
        done
    fi
}

# Function to generate API security report
generate_report() {
    local output_dir="$1"
    local target="$2"

    {
        echo "# API Security Assessment Report"
        echo ""
        echo "**Target:** $target"
        echo "**Date:** $(date)"
        echo ""
        echo "## Findings Summary"
        echo ""
        echo "### Critical"
        render_findings_section "${CRITICAL_FINDINGS[@]+"${CRITICAL_FINDINGS[@]}"}"
        echo ""
        echo "### High"
        render_findings_section "${HIGH_FINDINGS[@]+"${HIGH_FINDINGS[@]}"}"
        echo ""
        echo "### Medium"
        render_findings_section "${MEDIUM_FINDINGS[@]+"${MEDIUM_FINDINGS[@]}"}"
        echo ""
        echo "### Not covered by this script's automated tests (manual review recommended)"
        echo "- [ ] Sensitive data exposure in responses"
        echo "- [ ] Missing security headers (X-Content-Type-Options, X-Frame-Options, CSP, HSTS)"
        echo "- [ ] Verbose error messages"
        echo "- [ ] IDOR / Broken Object Level Authorization (requires two known object IDs owned by different users - see SKILL.md's IDOR section for the manual technique)"
        echo ""
        echo "## Recommendations"
        echo ""
        echo "1. Implement proper authentication and authorization"
        echo "2. Enable rate limiting on all endpoints"
        echo "3. Disable GraphQL introspection in production"
        echo "4. Configure CORS properly with specific origins"
        echo "5. Implement API versioning strategy"
        echo "6. Use strong API keys and rotate regularly"
        echo ""
    } > "$output_dir/api_security_report.md"

    echo -e "${GREEN}[+] Report saved to $output_dir/api_security_report.md${NC}"
}

# Main function
main() {
    local target="${1:-}"
    local output_dir="${2:-.}"
    local crawled_endpoints_file="${3:-}"

    if [ -z "$target" ]; then
        echo "Usage: $0 <target> [output_dir] [crawled_endpoints.json]"
        echo ""
        echo "Example:"
        echo "  $0 https://api.example.com ./results/"
        exit 1
    fi

    mkdir -p "$output_dir"

    echo -e "${GREEN}=== API Security Testing ===${NC}"
    echo "Target: $target"
    echo ""

    # Determine API type
    if curl -s --max-time 10 "$target" 2>/dev/null | grep -q "graphql\|GraphQL"; then
        test_graphql "$target" || true
    fi

    # Test REST API
    test_rest_api "$target" "$crawled_endpoints_file" || true

    # Test common vulnerabilities
    test_cors "$target" || true
    test_rate_limiting "$target" || true
    test_api_versions "$target" || true
    test_api_keys "$target" || true
    test_mass_assignment || true

    # Generate report - always reached regardless of how many probes above
    # failed/timed out/errored (F1): every test_* call above is guarded
    # with `|| true` and every curl invocation inside them is individually
    # guarded too, so an unreachable/slow endpoint degrades that one probe
    # instead of aborting the run.
    generate_report "$output_dir" "$target"

    echo ""
    echo -e "${GREEN}[+] API testing complete${NC}"
}

# Run main if executed directly
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi