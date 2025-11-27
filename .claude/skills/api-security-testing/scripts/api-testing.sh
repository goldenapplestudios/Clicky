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
    response=$(curl -s -H "Authorization: Bearer $none_token" "$endpoint")
    if ! echo "$response" | grep -q "invalid\|unauthorized\|401\|403"; then
        echo -e "${RED}[!] VULNERABLE: JWT none algorithm accepted!${NC}"
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

    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "$introspection_query" \
        "$endpoint" 2>/dev/null)

    if echo "$response" | grep -q "__schema"; then
        echo -e "${RED}[!] GraphQL introspection is ENABLED!${NC}"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"

        # Test for query depth attack
        local depth_query='{"query":"{ user { posts { comments { user { posts { comments { user { name } } } } } } } }"}'
        depth_response=$(curl -s -X POST \
            -H "Content-Type: application/json" \
            -d "$depth_query" \
            "$endpoint" 2>/dev/null)

        if ! echo "$depth_response" | grep -q "depth\|limit\|too deep"; then
            echo -e "${RED}[!] No query depth limit detected!${NC}"
        fi
    else
        echo -e "${GREEN}[+] GraphQL introspection appears disabled${NC}"
    fi
}

# Function to test REST API vulnerabilities
test_rest_api() {
    local base_url="$1"

    echo -e "${YELLOW}[*] Testing REST API...${NC}"

    # Test for common endpoints
    local endpoints=("/users" "/admin" "/api/v1/users" "/api/v2/users" "/debug" "/metrics" "/health" "/swagger" "/api-docs")

    for endpoint in "${endpoints[@]}"; do
        response_code=$(curl -s -o /dev/null -w "%{http_code}" "$base_url$endpoint")
        if [ "$response_code" != "404" ] && [ "$response_code" != "000" ]; then
            echo -e "${GREEN}[+] Found endpoint: $endpoint (HTTP $response_code)${NC}"

            # Test for authentication bypass
            if [ "$response_code" == "200" ]; then
                echo -e "${YELLOW}  Testing authentication on $endpoint...${NC}"
            fi
        fi
    done

    # Test HTTP methods
    echo -e "${YELLOW}[*] Testing HTTP methods...${NC}"
    for method in GET POST PUT DELETE PATCH OPTIONS HEAD TRACE; do
        response_code=$(curl -s -X $method -o /dev/null -w "%{http_code}" "$base_url")
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
        response_code=$(curl -s -o /dev/null -w "%{http_code}" "$endpoint")
        if [ "$response_code" == "200" ]; then
            ((success_count++))
        elif [ "$response_code" == "429" ]; then
            echo -e "${GREEN}[+] Rate limiting detected after $i requests${NC}"
            return
        fi
    done

    if [ "$success_count" -eq 20 ]; then
        echo -e "${RED}[!] No rate limiting detected (20 requests succeeded)${NC}"
    fi
}

# Function to test CORS configuration
test_cors() {
    local endpoint="$1"

    echo -e "${YELLOW}[*] Testing CORS configuration...${NC}"

    # Test with evil origin
    response=$(curl -s -I -H "Origin: https://evil.com" "$endpoint")

    if echo "$response" | grep -i "access-control-allow-origin: \*\|access-control-allow-origin: https://evil.com"; then
        echo -e "${RED}[!] CORS misconfiguration detected - wildcard or reflects origin${NC}"
    else
        echo -e "${GREEN}[+] CORS appears properly configured${NC}"
    fi

    # Check credentials
    if echo "$response" | grep -i "access-control-allow-credentials: true"; then
        echo -e "${YELLOW}[!] Credentials allowed in CORS${NC}"
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
                response_code=$(curl -s -o /dev/null -w "%{http_code}" "$url")
                if [ "$response_code" != "404" ] && [ "$response_code" != "000" ]; then
                    echo -e "${GREEN}[+] Found API version: $url (HTTP $response_code)${NC}"
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
    response_code=$(curl -s -o /dev/null -w "%{http_code}" "$endpoint")
    if [ "$response_code" == "200" ]; then
        echo -e "${RED}[!] API accessible without authentication!${NC}"
    fi

    # Test common API key headers
    local headers=("X-API-Key" "apikey" "api-key" "authorization" "x-auth-token")
    local common_keys=("test" "demo" "admin" "12345" "password")

    for header in "${headers[@]}"; do
        for key in "${common_keys[@]}"; do
            response_code=$(curl -s -o /dev/null -w "%{http_code}" -H "$header: $key" "$endpoint")
            if [ "$response_code" == "200" ]; then
                echo -e "${RED}[!] Weak API key accepted: $header: $key${NC}"
            fi
        done
    done
}

# Function to generate API security report
generate_report() {
    local output_dir="$1"
    local target="$2"

    cat > "$output_dir/api_security_report.md" << EOF
# API Security Assessment Report

**Target:** $target
**Date:** $(date)

## Findings Summary

### Critical
- [ ] GraphQL introspection enabled
- [ ] No authentication required
- [ ] JWT none algorithm accepted
- [ ] CORS wildcard configuration

### High
- [ ] No rate limiting
- [ ] Weak API keys accepted
- [ ] Sensitive data in responses
- [ ] Old API versions exposed

### Medium
- [ ] Verbose error messages
- [ ] Missing security headers
- [ ] No query depth limiting

## Recommendations

1. Implement proper authentication and authorization
2. Enable rate limiting on all endpoints
3. Disable GraphQL introspection in production
4. Configure CORS properly with specific origins
5. Implement API versioning strategy
6. Use strong API keys and rotate regularly

EOF

    echo -e "${GREEN}[+] Report saved to $output_dir/api_security_report.md${NC}"
}

# Main function
main() {
    local target="${1:-}"
    local output_dir="${2:-.}"

    if [ -z "$target" ]; then
        echo "Usage: $0 <target> [output_dir]"
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
    if curl -s "$target" | grep -q "graphql\|GraphQL"; then
        test_graphql "$target"
    fi

    # Test REST API
    test_rest_api "$target"

    # Test common vulnerabilities
    test_cors "$target"
    test_rate_limiting "$target"
    test_api_versions "$target"
    test_api_keys "$target"

    # Generate report
    generate_report "$output_dir" "$target"

    echo ""
    echo -e "${GREEN}[+] API testing complete${NC}"
}

# Run main if executed directly
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi