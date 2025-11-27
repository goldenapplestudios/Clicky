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
# Validate target format and scope
scripts/validate-target.sh "{target}"

# Returns:
# 0 - Valid target
# 1 - Invalid IP format
# 2 - Private IP not in scope
# 3 - Hostname resolution failed
# 4 - Target in exclusion list
# 5 - Target outside IP range
```

### Target Format Support
```bash
# Single IP
10.10.10.10

# IP Range
10.10.10.0/24
10.10.10.1-254

# Hostname
target.example.com
api.example.com

# Multiple targets
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
scripts/environment-detector.sh "{target}"

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
scripts/parse-summary.sh "{context_string}" "{output_dir}"

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
scripts/scope-validator.sh --target "{ip}" --scope scope.json

# Validate technique
scripts/scope-validator.sh --technique "dos" --scope scope.json

# Check time restrictions
scripts/scope-validator.sh --check-time --scope scope.json
```

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
   scripts/validate-target.sh "{input}"
   ```

2. **DNS Resolution**
   ```bash
   # Resolve hostname to IP
   host {hostname} | grep "has address"
   ```

3. **Scope Check**
   ```bash
   # Verify target is in scope
   scripts/scope-validator.sh --target {ip}
   ```

4. **Environment Detection**
   ```bash
   # Identify target environment
   scripts/environment-detector.sh {ip}
   ```

5. **Context Integration**
   ```bash
   # Parse any additional context
   scripts/parse-summary.sh "{context}"
   ```

6. **Connectivity Verification**
   ```bash
   # Verify target is reachable
   ping -c 1 {target} && echo "Target is alive"
   ```

## Integration with Session Management

```bash
# Store validation results in session
SESSION_ID=$(scripts/session-manager.sh current)
scripts/state-persistence.sh record "$SESSION_ID" "target_validation" "status" "validated"
scripts/state-persistence.sh record "$SESSION_ID" "target_validation" "environment" "{env_type}"
scripts/state-persistence.sh record "$SESSION_ID" "target_validation" "scope" "in_scope"
```

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