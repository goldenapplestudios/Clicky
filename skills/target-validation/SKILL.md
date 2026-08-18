---
name: target-validation
description: Validates targets, detects environments, parses context, and ensures scope compliance for penetration testing engagements
allowed-tools: Bash, Read, Write
---

# Target Validation Skill

## Purpose
Ensures targets are valid, within scope, and properly identified before penetration testing begins. Includes environment detection, context parsing, and scope validation.

## Target Validation Process

### Input Validation
```bash
# Validate target FORMAT (IP, IP range, CIDR, or hostname) and reject a
# small set of obviously-dangerous targets (localhost, 0.0.0.0, link-local,
# cloud metadata addresses). Accepts a single target, or a comma-separated
# list of targets (each validated independently).
${CLAUDE_PLUGIN_ROOT}/skills/target-validation/scripts/validate-target.sh "{target}"

# Returns (this is the real, current contract - see note below):
# 0 - Valid target. Prints one of:
#       VALID_IP: {target}        VALID_RANGE: {target}
#       VALID_CIDR: {target}      VALID_HOSTNAME: {target}
#     A private-IP/private-range target also prints a WARNING line first;
#     that is informational, not a failure.
# 1 - Invalid: bad format (prints "ERROR: Invalid target format: ..." or
#     "ERROR: Invalid IP range format: ..."), OR a well-formed but
#     dangerous target rejected regardless of format (localhost, 0.0.0.0,
#     link-local, cloud metadata - prints "ERROR: Cannot scan ..."), OR -
#     for a comma-separated list - at least one target in the list failed
#     (the rest are still printed, but the overall exit code is 1).
#
# validate-target.sh only checks FORMAT and that small dangerous-IP
# denylist. It does no DNS resolution and has no engagement scope /
# exclusion-list logic - that is scope-validator.sh's job, a separate
# script with its own exit-code contract; see "Scope Validation" below.
# A hostname that resolves fine but is out of scope, or one that doesn't
# resolve at all, still returns 0 here. (An earlier draft of this doc
# described a single 6-code contract - 0/1/2/private-IP/3-DNS-failure/
# 4-exclusion-list/5-outside-range - spanning both scripts; that never
# matched either script's actual behavior and has been replaced by the
# two contracts documented in place, above and in "Scope Validation".)
```

### Target Format Support
```bash
# Single IP
10.10.10.10

# IP Range
10.10.10.0/24
10.10.10.1-254

# Hostname (dotted). A bare single-label hostname (e.g. "dc01", an ordinary
# internal AD host) is also a valid validate-target.sh format. The
# scope-enforcement extractor (scripts/extract-targets.py) recognizes bare
# hostnames too, but conservatively: only a token containing both a letter
# and a digit and not glued to a preceding "-"/"=" is treated as a
# candidate target, to avoid flagging ordinary flag values/usernames/tool
# names. A bare hostname with no digit in it (e.g. "attackbox") is a known
# blind spot there - use a dotted or otherwise-qualified name if you need
# the extractor to catch it reliably.
target.example.com
api.example.com
dc01

# Multiple targets (validate-target.sh splits on comma and validates each
# target independently; the whole call fails if any single one does)
10.10.10.10,10.10.10.11,10.10.10.12

# CIDR notation
192.168.1.0/24
172.16.0.0/12
10.0.0.0/8
```

## Environment Detection

### Platform Identification
```bash
# Detect target environment type
${CLAUDE_PLUGIN_ROOT}/skills/target-validation/scripts/environment-detector.sh "{target}"

# Detects:
# - Cloud providers (AWS, Azure, GCP)
# - Container platforms (Docker, Kubernetes)
# - Operating systems (Windows, Linux, BSD)
# - Virtual environments (VMware, VirtualBox, Hyper-V)
# - Network devices (routers, firewalls, switches)
```

### Cloud Provider Detection

#### AWS Detection
```bash
# Check for AWS indicators
- IP ranges: Check against AWS IP ranges JSON
- DNS: *.amazonaws.com, *.aws.amazon.com
- Headers: x-amz-* headers in HTTP responses
- SSL Certs: *.amazonaws.com in certificate
- Metadata: 169.254.169.254 endpoint accessible
```

#### Azure Detection
```bash
# Check for Azure indicators
- IP ranges: Azure public IP ranges
- DNS: *.azurewebsites.net, *.blob.core.windows.net
- Headers: x-ms-* headers
- SSL Certs: *.azure.com, *.microsoft.com
- Metadata: 169.254.169.254/metadata/instance
```

#### GCP Detection
```bash
# Check for Google Cloud indicators
- IP ranges: GCP IP ranges
- DNS: *.googleapis.com, *.googleusercontent.com
- Headers: x-goog-* headers
- SSL Certs: *.google.com, *.googleapis.com
- Metadata: metadata.google.internal
```

### Container Detection
```bash
# Docker indicators
- Ports: 2375, 2376 (Docker API)
- Files: /.dockerenv, /var/run/docker.sock
- Processes: dockerd, containerd
- Cgroups: /proc/1/cgroup contains "docker"

# Kubernetes indicators
- Ports: 6443, 8443 (API), 10250 (kubelet)
- DNS: kubernetes.default.svc.cluster.local
- Files: /var/run/secrets/kubernetes.io
- Environment: KUBERNETES_* variables
```

## Context Parsing

### Parse Additional Context
```bash
# Parse user-provided context
${CLAUDE_PLUGIN_ROOT}/skills/target-validation/scripts/parse-summary.sh "{context_string}" "{output_dir}"

# Extracts:
# - Credentials: username:password pairs
# - Services: service:port mappings
# - Technologies: frameworks, languages, databases
# - Notes: additional information
```

### Context Format Examples
```bash
# Credential context
"user: admin, password: Password123"

# Service context
"services: SSH:22, HTTP:80, MySQL:3306"

# Technology context
"tech: WordPress 5.8, PHP 7.4, MySQL 8.0"

# Mixed context
"cloud: AWS, region: us-east-1, service: kubernetes, auth: JWT"
```

## Scope Management

### Scope Definition
```json
{
  "engagement_id": "PT-2025-001",
  "client": "Example Corp",
  "targets": {
    "in_scope": [
      "10.10.10.0/24",
      "*.example.com",
      "192.168.1.100-200"
    ],
    "out_of_scope": [
      "10.10.10.5",
      "production.example.com",
      "192.168.1.1"
    ]
  },
  "restrictions": [
    "No DoS attacks",
    "Business hours only",
    "No social engineering"
  ],
  "authorized_techniques": [
    "Port scanning",
    "Vulnerability scanning",
    "Exploitation",
    "Password attacks"
  ]
}
```

### Scope Validation
```bash
# Check if target is in scope
${CLAUDE_PLUGIN_ROOT}/skills/target-validation/scripts/scope-validator.sh --target "{ip}" --scope scope.json

# Validate technique
${CLAUDE_PLUGIN_ROOT}/skills/target-validation/scripts/scope-validator.sh --technique "dos" --scope scope.json

# Check time restrictions
${CLAUDE_PLUGIN_ROOT}/skills/target-validation/scripts/scope-validator.sh --check-time --scope scope.json

# --target/--technique/--check-time can be combined in one call.

# Exit codes - a separate contract from validate-target.sh's above (this
# script does the actual scope/exclusion-list/technique/time checking;
# validate-target.sh only checks target format):
# 0 - every check that was requested passed:
#       --target:      matched an in_scope entry            -> "IN SCOPE: ..."
#       --technique:   not restricted, and (if
#                      authorized_techniques is set) matches it -> "AUTHORIZED: ..."
#       --check-time:  within time_window, or no time_window/
#                      free-text time restriction is defined at all
#                      -> "WITHIN TIME WINDOW: ..." / "No time restrictions found..."
# 1 - any requested check failed:
#       --target:      matched an out_of_scope entry ("OUT OF SCOPE ...")
#                      or matched neither list ("NOT LISTED ...")
#       --technique:   matches a free-text restriction ("RESTRICTED: ...")
#                      or authorized_techniques is non-empty and doesn't
#                      mention it ("NOT AUTHORIZED: ...")
#       --check-time:  outside the configured time_window ("OUTSIDE TIME WINDOW: ...")
#     Also returned for usage errors: missing/nonexistent --scope file,
#     or python3 not available.
#
# When multiple flags are passed in one call, the exit code is 1 if ANY of
# the requested checks failed, not just the last one evaluated - check the
# printed lines (one per flag passed) to see which check(s) failed.
```

### Automatic Scope Enforcement

`scope-validator.sh` and `scripts/extract-targets.py` are still the real, live scope-matching and target-extraction logic - nothing here has been removed. What changed is *where* they're invoked from: a `PreToolUse` hook (`skills/target-validation/scripts/scope-enforcement-hook.sh`) used to run both scripts before every Bash/WebFetch tool call, for every agent, automatically. That hook has since been **retired** and replaced by `skills/mcp-gateway`'s `register_target` MCP tool, which does the equivalent scope check server-side. `commands/pentest.md` Step 1 (and `workflows/pentest-parallel.js`'s init stage) still resolve a `scope.json` for the engagement the same way as before - first `./scope.json` in the operator's working directory, then a `scope: <path>` key in the `/pentest` context argument, then an auto-generated single-target scope if neither is provided - and write it to `$SESSION_DIR/scope.json`, since both the gateway and each agent's own explicit check (below) still read it from there.

**How the gateway's check works** (`skills/mcp-gateway/scope_gate.py` + `server.py`'s `register_target`):

1. `register_target(target)` classifies `target` against `$SESSION_DIR/scope.json` via `scope_gate.classify()`, which shells out to `scope-validator.sh` (same script and same matching semantics as above - CIDR / IP-range / wildcard-domain / exact-match - not duplicated logic).
2. The result maps to a decision the same way the old hook's did: an explicitly excluded target is **denied** outright (raises an error); a target that isn't listed either way triggers a real MCP **elicitation** prompt asking the operator to confirm (covers legitimate mid-engagement pivots to newly-discovered hosts); an explicitly in-scope target registers immediately.
3. This is on by default (`scope_enforcement` userConfig option, default `enforce`). Set it to `warn` to always register the target but log what would have happened to `$SESSION_DIR/logs/scope-enforcement.log`, or `off` to skip the scope check entirely. The gateway fails open (registers the target) on any *unexpected* internal error - as opposed to a clean out-of-scope/not-listed classification, which is a real decision, not an error - matching the old hook's fail-open design principle: a scope gate that can lock an authorized operator out of a fully-authorized engagement due to an internal bug is worse for adoption than no gate.
4. Unlike the old hook, there is currently no automatic `authorized_techniques` (tool-name → technique) check anywhere in the gateway - that was hook-specific logic that hasn't been ported. `execute_command` and the gateway's other 5 tools also do not re-run a scope check themselves; `register_target` is the sole chokepoint, on the theory that every other tool operates on tokens that were already resolved through it.

**Current state**: `register_target`'s check only runs when `register_target` itself is called - not on every subsequent `execute_command`/`fetch_url`/etc. call (see point 4 above and "Scope-check integration" in `skills/mcp-gateway/SKILL.md`). That's no longer a caveat about missing coverage, though: all 9 `agents/*.md` files (`recon`, `decision`, `exploit`, `privesc`, `loot`, `cloud-recon`, `source-analyzer`, `verification`, `report`) now have their `tools:` frontmatter rewritten to grant exclusively the gateway's 7 MCP tools, with zero direct `Bash`/`Read`/`Write`/`WebFetch` grants left anywhere in the plugin - so every raw target an agent acts on has to pass through `register_target` first, which makes it the real, automatic, tool-call-level scope gate for those agents (see `exploit-agent`'s "Safety Checks" section, which now says exactly that and no longer instructs a manual `scope-validator.sh` call). The one exception is `verification-agent`, which deliberately does not hold `register_target` (see its "Gateway Calling Convention" section) and so still runs `scope-validator.sh` directly via `execute_command` before any re-attempt - nothing else gates it, so that explicit check remains the real, currently-active gate for that one agent specifically, not a redundant belt-and-suspenders step. Regex-based command parsing (extraction) always had real blind spots (obfuscation, indirect variable references) even when the old hook ran automatically on every call, so per-target `register_target`/`scope-validator.sh` checks were never purely redundant with it anyway.

## Network Information Gathering

### DNS Resolution
```bash
# Forward DNS lookup
host {hostname}
nslookup {hostname}
dig {hostname} +short

# Reverse DNS lookup
host {ip}
nslookup {ip}
dig -x {ip} +short

# DNS server detection
dig @{target} version.bind txt chaos
```

### Network Path Analysis
```bash
# Traceroute to target
traceroute {target}
tracepath {target}

# MTU discovery
ping -M do -s 1472 {target}

# Network latency
ping -c 10 {target} | tail -1 | awk '{print $4}'
```

### ASN and Organization Info
```bash
# ASN lookup
whois -h whois.cymru.com " -v {ip}"

# Organization information
whois {ip} | grep -i "org\|netname\|descr"

# BGP information
curl -s https://api.bgpview.io/ip/{ip}
```

## Target Fingerprinting

### Operating System Detection
```bash
# TCP/IP stack fingerprinting
nmap -O {target}

# TTL analysis
ping -c 1 {target} | grep ttl
# Linux/Unix: TTL 64
# Windows: TTL 128
# Network devices: TTL 255

# Service banner analysis
nc -nv {target} 22  # SSH banner
nc -nv {target} 21  # FTP banner
```

### Service Detection Quick Check
```bash
# Top 20 ports quick scan
nmap -sV -sC -top-ports 20 {target}

# Common service detection
nc -zv {target} 21 22 23 25 80 443 445 3306 3389
```

## Validation Workflow

1. **Format Validation**
   ```bash
   # Check if input is valid IP/hostname
   ${CLAUDE_PLUGIN_ROOT}/skills/target-validation/scripts/validate-target.sh "{input}"
   ```

2. **DNS Resolution**
   ```bash
   # Resolve hostname to IP
   host {hostname} | grep "has address"
   ```

3. **Scope Check**
   ```bash
   # Verify target is in scope
   ${CLAUDE_PLUGIN_ROOT}/skills/target-validation/scripts/scope-validator.sh --target {ip} --scope {scope.json}
   ```

4. **Environment Detection**
   ```bash
   # Identify target environment
   ${CLAUDE_PLUGIN_ROOT}/skills/target-validation/scripts/environment-detector.sh {ip}
   ```

5. **Context Integration**
   ```bash
   # Parse any additional context
   ${CLAUDE_PLUGIN_ROOT}/skills/target-validation/scripts/parse-summary.sh "{context}"
   ```

6. **Connectivity Verification**
   ```bash
   # Verify target is reachable
   ping -c 1 {target} && echo "Target is alive"
   ```

## Integration with Session Management

`$SESSION_ID` is set earlier in the workflow (`commands/pentest.md` Step 1 exports it) — use the value already in the environment.

No separate persistence call needed here: validation status and environment type are already captured in `$SESSION_DIR/session.json`/`context/` from `commands/pentest.md` Step 1, and `state-persistence.sh record` is reserved for attack-attempt success/failure outcomes (the data `attempt-aggregator.sh` calibrates htb-decision-tree's rates from) - target validation isn't an attack attempt, so it doesn't belong in that stream.

## Error Handling

### Common Validation Errors
```bash
# Invalid IP format
Error: "300.300.300.300" is not a valid IP address

# Out of scope
Error: Target "10.10.10.5" is explicitly out of scope

# DNS resolution failure
Error: Cannot resolve "nonexistent.example.com"

# Network unreachable
Error: Target "10.10.10.10" is not reachable

# Time restriction
Error: Testing not allowed outside business hours (9 AM - 5 PM)
```

### Recovery Actions
```bash
# For DNS failure
- Try alternative DNS servers
- Check for typos in hostname
- Try IP address instead

# For unreachable target
- Check network connectivity
- Verify VPN connection
- Check firewall rules
- Try different source IP
```

## Monitoring and Logging

### Validation Logging
```bash
# Log all validation attempts
echo "[$(date)] Target: {target}, Status: {status}, Environment: {env}" >> validation.log

# Failed validation tracking
echo "[$(date)] FAILED: {target}, Reason: {reason}" >> validation_failures.log
```

### Metrics Collection
```bash
# Track validation statistics
- Total validations attempted
- Successful validations
- Failed validations by reason
- Environment type distribution
- Average validation time
```

## Best Practices

1. **Always validate before scanning** - Prevents scope violations
2. **Document validation results** - For audit trail
3. **Check time restrictions** - Respect testing windows
4. **Verify connectivity first** - Saves time on unreachable targets
5. **Parse context carefully** - Extract all useful information
6. **Update scope regularly** - Scope may change during engagement
7. **Handle errors gracefully** - Provide clear error messages

## Notes

- Validation is critical for legal compliance
- Some cloud providers detect and log validation attempts
- Environment detection helps select appropriate techniques
- Context parsing can reveal important testing constraints
- Always maintain an audit log of validation activities