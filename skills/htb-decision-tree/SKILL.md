---
name: htb-decision-tree
description: Strategic attack prioritization, self-calibrated from this operator's own accumulated session history (real measured success rates once enough data exists), with an honestly-labeled heuristic fallback until then
allowed-tools: Bash, Read, Grep
---

# HTB Decision Tree Skill

## Purpose
Provides data-driven attack prioritization: real per-service/technique success rates computed from Clicky's own session history (`skills/session-management/scripts/attempt-aggregator.sh`, fed by every exploit-agent/privesc-agent/loot-agent attempt via `state-persistence.sh`), falling back to a clearly-labeled heuristic ordering until a service has enough recorded attempts to trust a measured number. No external dataset is claimed - the previous version of this skill asserted specific percentages "based on analysis of hundreds of HTB machines," which turned out to have no backing dataset anywhere in the repo and disagreed with itself across the three files that restated it. This mechanism replaces that with numbers that are either real (computed from attempts this framework actually logged) or explicitly marked as not-yet-measured - never fabricated precision presented as research.

## HTB Service Priority Matrix

The live source of truth is `service-prioritizer.py --show-matrix` (see Scripts Usage below), not a static table - it prints each service's current basis (`measured: NN% success over N attempts`, or `heuristic priority, no measured data yet`) pulled from `priority_data.py`, which merges `data/baseline-priority-order.json`'s heuristic ordering with `attempt-aggregator.sh`'s real computed rates.

For orientation only - **illustrative example, not live data** (actual values depend entirely on your own session history and will differ):

| Service | Port | Example status | Common Vulnerabilities |
|---------|------|-----------------|------------------------|
| FTP | 21 | heuristic (no data yet) → measured: 82% over 11 attempts | Anonymous access, credential files |
| SMB | 445/139 | heuristic (no data yet) | Null sessions, user enumeration |
| HTTP/HTTPS | 80/443 | heuristic (no data yet) | Web vulnerabilities, default creds |

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
${CLAUDE_PLUGIN_ROOT}/skills/htb-decision-tree/scripts/success-calculator.sh analyze "{service_list}"

# Excluding services already attempted and failed:
${CLAUDE_PLUGIN_ROOT}/skills/htb-decision-tree/scripts/success-calculator.sh --services "{service_list}" --attempts "{tried_ports}"

# Example output - "value"/"basis"/"samples" per service, plus
# overall_basis so you know whether overall_success came from real data,
# a heuristic guess, or a mix:
# {
#   "ftp": {"value": 0.82, "basis": "measured", "samples": 11},
#   "smb": {"value": 0.6, "basis": "heuristic", "samples": 0},
#   "overall_success": 0.93,
#   "overall_basis": "mixed"
# }
```

This is a mechanical combination of `priority_data.py`'s per-service values (measured where enough data exists, heuristic otherwise) — treat it as a starting estimate, not a substitute for judgment, and check `overall_basis` before presenting the number as anything more than a heuristic guess. Adjust it with anything learned in memory (per decision-agent's Memory Usage Policy) before relying on it.

## HTB Pattern Recognition

Unlike the service-priority matrix above, this axis is **permanently heuristic** - Clicky never records a target's actual difficulty tier anywhere, so there's no ground truth to calibrate against, only qualitative frequency labels (`data/pattern-frequencies.json`, via `pattern-matcher.py`):

### Easy Box Patterns
- Anonymous FTP with credentials (common)
- SMB null sessions with user lists (common)
- Default CMS credentials (common)
- SQL injection in login forms (occasional)

### Medium Box Patterns
- Credential reuse across services (occasional)
- Web application vulnerabilities leading to RCE (occasional)
- Service version exploits (occasional)
- Configuration file exposure (occasional)

### Hard Box Patterns
- Chained exploits required (common)
- Custom exploitation needed (common)
- Binary exploitation (occasional)
- Advanced pivoting (occasional)

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
${CLAUDE_PLUGIN_ROOT}/skills/htb-decision-tree/scripts/service-prioritizer.py --services "21,22,80,445" --target {ip}

# Show the full live priority matrix (all known services, not just
# discovered ports) - this is the actual current data behind the
# "illustrative example" table above
${CLAUDE_PLUGIN_ROOT}/skills/htb-decision-tree/scripts/service-prioritizer.py --show-matrix
```

### Pattern Matcher
```bash
# Match current scenario to HTB patterns (finding flags are optional - see
# the script's own docstring for the full list; omitted flags are reported
# as untested candidates rather than assumed false)
${CLAUDE_PLUGIN_ROOT}/skills/htb-decision-tree/scripts/pattern-matcher.py --profile '{"ftp_anonymous": true, "sqli_found": false}' --difficulty "medium"
```

### Success Calculator
```bash
# Calculate success probabilities
${CLAUDE_PLUGIN_ROOT}/skills/htb-decision-tree/scripts/success-calculator.sh --services "{service_list}" --attempts "{tried_exploits}"
```

## Integration Instructions

When analyzing scan results:
1. Execute `service-prioritizer.py` with discovered ports to get the recommended attack sequence
2. Follow the recommended attack sequence
3. Track attempted exploits (via the session's trace log — see `docs/observability.md`) so `success-calculator.sh`'s `--attempts` exclusion and the Failure Recovery Patterns below can avoid repeating a known-failed technique
4. Use `pattern-matcher.py` to identify which HTB difficulty pattern the target resembles as findings come in
5. Adjust strategy based on failure recovery patterns

All three scripts are mechanical helpers over `priority_data.py`'s self-calibrated data (or, for pattern-matcher.py, the permanently-heuristic `data/pattern-frequencies.json`) — the decision-agent should still apply judgment (and anything learned in memory, per its Memory Usage Policy) rather than following their output blindly.

## Performance Metrics

Track these metrics to improve decision making:
- Time to initial access
- Number of attempts before success
- Accuracy of probability predictions
- Pattern matching success rate

## Notes

- Service-priority values are self-calibrated from this operator's own session history (see `priority_data.py`), not an external dataset - they'll be pure heuristic on a fresh install and grow more accurate (and more specific to the kinds of targets you actually test) as `logs/attempts.jsonl` accumulates across engagements
- Pattern-matcher frequencies stay permanently qualitative (see above) - real environments may differ regardless
- Always prioritize services with exposed sensitive data
- Consider the machine difficulty rating when calculating probabilities