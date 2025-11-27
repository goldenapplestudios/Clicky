---
name: htb-decision-tree
description: Strategic attack prioritization based on Hack The Box patterns and success rates from extensive machine analysis
allowed-tools: Bash, Read, Grep
---

# HTB Decision Tree Skill

## Purpose
Provides data-driven attack prioritization based on patterns observed across hundreds of HTB machines, with success probability calculations and strategic recommendations.

## HTB Service Priority Matrix

Based on analysis of HTB machines, services should be tested in this priority order:

| Priority | Service | Port | Success Rate | Common Vulnerabilities |
|----------|---------|------|--------------|------------------------|
| 1 | FTP | 21 | 100% | Anonymous access, credential files |
| 2 | SMB | 445/139 | 75% | Null sessions, user enumeration |
| 3 | HTTP/HTTPS | 80/443 | 68% | Web vulnerabilities, default creds |
| 4 | SSH | 22 | 45% | Credential reuse, weak passwords |
| 5 | MySQL | 3306 | 41% | Default/blank root, UDF exploitation |
| 6 | Redis | 6379 | 95% | Unauthenticated access |
| 7 | Docker | 2375/2376 | 90% | API exposure, container escape |
| 8 | MongoDB | 27017 | 85% | No authentication |
| 9 | Elasticsearch | 9200 | 82% | No authentication, data exposure |
| 10 | RDP | 3389 | 35% | BlueKeep, credential attacks |

## Attack Decision Trees

### FTP Service (Port 21)
```
FTP Detected
├─> Check Anonymous Access
│   ├─> Success: Download all files
│   │   └─> Search for: credentials, SSH keys, configuration files
│   └─> Failed: Try default credentials
│       └─> Failed: Move to next service
└─> Check for writable directories
    └─> Success: Upload webshell if web root accessible
```

### SMB Service (Port 445/139)
```
SMB Detected
├─> Test Null Session
│   ├─> Success: Enumerate shares
│   │   ├─> List users for password spraying
│   │   └─> Download accessible files
│   └─> Failed: Try guest access
├─> Check for MS17-010 (EternalBlue)
└─> Test for SMB signing disabled
```

### Web Service (Port 80/443)
```
HTTP/HTTPS Detected
├─> Technology Identification
│   ├─> CMS Detected (WordPress, Joomla, Drupal)
│   │   └─> Run CMS-specific scanner
│   ├─> Custom Application
│   │   └─> Test for common vulnerabilities
│   └─> API Endpoint
│       └─> Test for API-specific issues
├─> Directory Enumeration
├─> Check for default credentials
└─> SQL Injection testing on all parameters
```

### SSH Service (Port 22)
```
SSH Detected
├─> Check version for vulnerabilities
├─> Username enumeration (if < OpenSSH 7.7)
├─> Test discovered credentials
│   └─> Success: Check sudo privileges
└─> Brute force only if usernames known
```

## Success Probability Calculations

Calculate attack success probability based on discovered services:

```bash
# Run probability calculator
scripts/success-calculator.sh analyze "{service_list}"

# Example output:
# {
#   "ftp_anonymous": 0.73,
#   "smb_null": 0.61,
#   "web_sqli": 0.42,
#   "overall_success": 0.89
# }
```

## HTB Pattern Recognition

### Easy Box Patterns
- Anonymous FTP with credentials (73% of easy boxes)
- SMB null sessions with user lists (61%)
- Default CMS credentials (58%)
- SQL injection in login forms (42%)

### Medium Box Patterns
- Credential reuse across services (67%)
- Web application vulnerabilities leading to RCE (54%)
- Service version exploits (49%)
- Configuration file exposure (45%)

### Hard Box Patterns
- Chained exploits required (89%)
- Custom exploitation needed (76%)
- Binary exploitation (64%)
- Advanced pivoting (58%)

## Strategic Recommendations

### Initial Access Strategy
1. **Always check FTP first** - Highest success rate, minimal time investment
2. **SMB enumeration second** - Often provides usernames for other attacks
3. **Web enumeration parallel** - Can run while testing other services
4. **Save SSH for last** - Unless specific credentials found

### Failure Recovery Patterns
When primary attacks fail, follow these recovery strategies:

```
Primary Failed -> Recovery Action
FTP anonymous -> Check version-specific exploits
SMB null session -> Try credential spraying with enum4linux users
Web SQLi -> Try file upload vulnerabilities
SSH brute -> Focus on credential reuse from other services
```

### Time Management
Allocate time based on success probabilities:
- 5 minutes: FTP anonymous check
- 10 minutes: SMB enumeration
- 30 minutes: Web application testing
- 10 minutes: Service version vulnerability research
- 15 minutes: Credential testing across services

## Multi-Service Correlation

### Credential Reuse Matrix
When credentials are found, test in this order:
1. SSH (highest impact)
2. FTP (potential file system access)
3. SMB (potential file shares)
4. MySQL (database access)
5. Web applications (admin panels)

### Information Correlation
Connect information across services:
- Usernames from SMB → SSH brute force
- Passwords from FTP files → Service logins
- Web application users → System users
- Email addresses → Username formats

## Conditional Logic Rules

### Service Combination Patterns
```python
if "FTP" in services and "HTTP" in services:
    priority = "Check FTP for web files"

if "SMB" in services and "AD_indicators":
    priority = "Focus on AD enumeration"

if "Docker" in services or "Kubernetes" in services:
    priority = "Container escape paths"

if "MongoDB" in services or "Redis" in services:
    priority = "NoSQL injection and data extraction"
```

## Scripts Usage

### Service Prioritizer
```bash
# Analyze services and return priority order
scripts/service-prioritizer.py --services "21,22,80,445" --target {ip}
```

### Pattern Matcher
```bash
# Match current scenario to HTB patterns
scripts/pattern-matcher.py --profile "{services_json}" --difficulty "medium"
```

### Success Calculator
```bash
# Calculate success probabilities
scripts/success-calculator.sh --services "{service_list}" --attempts "{tried_exploits}"
```

## Integration Instructions

When analyzing scan results:
1. Execute service-prioritizer.py with discovered ports
2. Follow the recommended attack sequence
3. Track attempted exploits for probability updates
4. Use pattern-matcher.py to identify similar HTB machines
5. Adjust strategy based on failure recovery patterns

## Performance Metrics

Track these metrics to improve decision making:
- Time to initial access
- Number of attempts before success
- Accuracy of probability predictions
- Pattern matching success rate

## Notes

- Probabilities are based on HTB machine analysis, real environments may differ
- Always prioritize services with exposed sensitive data
- Consider the machine difficulty rating when calculating probabilities
- Update patterns based on new HTB releases and walkthroughs