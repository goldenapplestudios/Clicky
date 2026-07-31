---
name: report-generation
description: Comprehensive penetration testing report generation including vulnerability documentation, CVSS scoring, evidence collection, and executive summaries
allowed-tools: Bash, Read, Write, Grep
---

# Report Generation Skill

## Purpose
Provides standardized penetration testing report generation with vulnerability documentation, CVSS scoring, evidence collection, and professional formatting for technical and executive audiences.

## Report Structure

### Standard Report Template
```markdown
# Penetration Test Report

## Executive Summary
### Engagement Overview
- **Client**: [Organization Name]
- **Dates**: [Start Date] - [End Date]
- **Scope**: [IP Ranges/Domains]
- **Methodology**: PTES/OWASP/NIST

### Key Findings
- **Critical**: [Count] vulnerabilities requiring immediate attention
- **High**: [Count] vulnerabilities with significant impact
- **Medium**: [Count] vulnerabilities requiring remediation
- **Low**: [Count] informational findings

### Risk Summary
[Brief risk assessment and business impact]

## Technical Report

### Methodology
[Testing approach and tools used]

### Findings
[Detailed vulnerability descriptions]

### Recommendations
[Prioritized remediation guidance]

## Appendices
- A: Tool Output
- B: Evidence Screenshots
- C: Exploitation Code
```

## CVSS Scoring

### CVSS v3.1 Calculator

CVSS 3.1 remains the practical industry anchor as of 2026 even though CVSS 4.0 exists, so score in 3.1 unless the engagement specifically calls for 4.0.

```bash
${CLAUDE_PLUGIN_ROOT}/skills/report-generation/scripts/cvss-calculator.sh \
  --vector "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

Or build the vector manually and check it against the [official FIRST.org calculator](https://www.first.org/cvss/calculator/3.1) if you want a second source to compare against.

```
AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

# CVSS Components:
# Attack Vector (AV): N=Network, A=Adjacent, L=Local, P=Physical
# Attack Complexity (AC): L=Low, H=High
# Privileges Required (PR): N=None, L=Low, H=High
# User Interaction (UI): N=None, R=Required
# Scope (S): U=Unchanged, C=Changed
# Confidentiality (C): N=None, L=Low, H=High
# Integrity (I): N=None, L=Low, H=High
# Availability (A): N=None, L=Low, H=High
```

### Severity Ratings
```bash
# CVSS Score Ranges
Critical: 9.0 - 10.0
High:     7.0 - 8.9
Medium:   4.0 - 6.9
Low:      0.1 - 3.9
None:     0.0
```

## Vulnerability Documentation

### Vulnerability Template
```markdown
## [VULN-ID]: [Vulnerability Name]

**Severity**: [Critical/High/Medium/Low]
**CVSS Score**: [Score] ([Vector String])
**CWE**: CWE-[Number]
**OWASP**: A[Number]:2025-[Category] (or API[Number]:2023-[Category] for API findings — see api-security-testing skill)
**ASVS**: [Chapter/requirement number] (optional — see OWASP ASVS 5.0 Mapping below; use when the finding maps cleanly to a specific verification requirement)
**MITRE ATT&CK**: [Technique ID] (optional — only cite when the finding is genuinely an adversary TTP ATT&CK models, e.g. initial access, credential theft, persistence. Most web-app vulnerability classes like IDOR/SSRF/XXE don't have a clean ATT&CK mapping — use OWASP/CWE for those instead of forcing an ID that doesn't fit)

### Description
[Detailed description of the vulnerability]

### Impact
[Business impact and technical consequences]

### Affected Systems
- [IP/Hostname]: [Service/Application]
- [IP/Hostname]: [Service/Application]

### Proof of Concept
```[language]
[Exploitation code or commands]
```

### Evidence
![Screenshot]({path_to_screenshot})

### Remediation
**Root cause**: [The underlying secure-coding principle violated — e.g. "queries built via string concatenation instead of parameterized queries" for SQLi, "missing output encoding at the render boundary" for XSS. Naming the pattern, not just the instance, is what lets developers avoid the same class of bug elsewhere.]
**Short-term**: [Immediate fixes]
**Long-term**: [Comprehensive solution]

### Detection Opportunity (optional)
[What log source or signal would have caught this technique in progress — pulled from the cited MITRE ATT&CK technique's published Detections, when one applies. Skip this field entirely for findings with no ATT&CK mapping rather than forcing one.]

### References
- [CVE/Advisory URL]
- [Vendor Documentation]
```

## OWASP ASVS 5.0 Mapping

The [OWASP Application Security Verification Standard](https://asvs.dev/) (v5.0, May 2025 — 17 chapters, ~350 requirements) is a different kind of standard than Top 10: Top 10 is "what's most commonly exploited," ASVS is "does this application meet a baseline of security requirements at all." Use it when a finding represents a missing control rather than a specific exploitable bug — it gives remediation guidance something concrete and verifiable to point at, beyond "here's the bug, go fix it."

Chapters most relevant to typical pentest findings:
- **V6 Authentication** — credential-related findings (weak passwords, missing MFA, session fixation)
- **V7 Session Management** — session token predictability, missing session invalidation
- **V8 Authorization** — IDOR, BFLA, privilege escalation findings
- **V11 Cryptography** — weak encryption, hardcoded keys, insecure random number generation
- **V13 Configuration** — security misconfiguration findings
- **V14 Data Protection** — sensitive data exposure

Cite the chapter (and specific requirement number where you can identify one) in the vulnerability template's ASVS field above; don't force a citation where the finding doesn't map cleanly to a verification requirement.

## Evidence Collection

### Screenshot Management
```bash
# Capture evidence
${CLAUDE_PLUGIN_ROOT}/skills/report-generation/scripts/evidence-collector.py screenshot --tag "sqli" --vuln "VULN-001"

# Organize screenshots
/evidence/
├── critical/
│   ├── VULN-001_sql_injection.png
│   └── VULN-002_rce.png
├── high/
├── medium/
└── low/
```

### Command Output Documentation
```bash
# Save command output with context
echo "# Command: nmap -sV target" > evidence/nmap_scan.md
nmap -sV target >> evidence/nmap_scan.md

# Include in report
${CLAUDE_PLUGIN_ROOT}/skills/report-generation/scripts/evidence-collector.py add-output \
  --file evidence/nmap_scan.md \
  --section "reconnaissance"
```

## Report Generation Automation

### Generate Full Report
```bash
# Run report generator
${CLAUDE_PLUGIN_ROOT}/skills/report-generation/scripts/report-generator.sh \
  --session-id {session_id} \
  --format markdown \
  --output pentest_report.md

# Generate with all options
${CLAUDE_PLUGIN_ROOT}/skills/report-generation/scripts/report-generator.sh \
  --session-id {session_id} \
  --format pdf \
  --template executive \
  --include-evidence \
  --include-appendices \
  --output final_report.pdf
```

### Report Formats

#### Markdown Report
```bash
${CLAUDE_PLUGIN_ROOT}/skills/report-generation/scripts/report-generator.sh --format markdown

# Sections included:
- Executive Summary
- Vulnerability Details
- Technical Recommendations
- Evidence Links
- Appendices
```

#### HTML Report
```bash
${CLAUDE_PLUGIN_ROOT}/skills/report-generation/scripts/report-generator.sh --format html

# Features:
- Interactive table of contents
- Sortable vulnerability table
- Embedded screenshots
- Syntax highlighting for code
```

#### PDF Report
```bash
${CLAUDE_PLUGIN_ROOT}/skills/report-generation/scripts/report-generator.sh --format pdf

# Professional features:
- Cover page
- Table of contents
- Page numbers
- Headers/footers
- Embedded images
```

## Vulnerability Categories

### Web Application Vulnerabilities
```markdown
### SQL Injection
- **CWE-89**: Improper Neutralization of Special Elements
- **OWASP A05:2025**: Injection
- **Impact**: Database compromise, data theft
- **CVSS Base**: 9.8 (Critical)

### Cross-Site Scripting (XSS)
- **CWE-79**: Cross-site Scripting
- **OWASP A05:2025**: Injection
- **Impact**: Session hijacking, defacement
- **CVSS Base**: 6.1 (Medium)

### Authentication Bypass
- **CWE-287**: Improper Authentication
- **OWASP A07:2025**: Authentication Failures
- **Impact**: Unauthorized access
- **CVSS Base**: 8.2 (High)
```

### Infrastructure Vulnerabilities
```markdown
### Unpatched Services
- **Impact**: Remote code execution
- **CVSS**: Varies by CVE
- **Remediation**: Apply security patches

### Default Credentials
- **CWE-798**: Use of Hard-coded Credentials
- **Impact**: Unauthorized access
- **CVSS Base**: 7.5 (High)

### Misconfigured Services
- **Impact**: Information disclosure, unauthorized access
- **CVSS**: Varies by configuration
```

## Executive Summary Generation

### Risk Matrix
```markdown
| Risk Level | Count | Business Impact |
|------------|-------|-----------------|
| Critical   | 2     | Immediate breach possible |
| High       | 5     | Significant security gaps |
| Medium     | 8     | Moderate risk exposure |
| Low        | 12    | Minor security improvements needed |
```

### Key Metrics
```bash
# Generate metrics
${CLAUDE_PLUGIN_ROOT}/skills/report-generation/scripts/report-generator.sh metrics

# Output:
- Total vulnerabilities: 27
- Average CVSS score: 6.8
- Systems tested: 15
- Services identified: 42
- Credentials compromised: 8
- Time to first compromise: 2 hours
```

## Compliance Mapping

### Regulatory Compliance
```markdown
## PCI DSS v4.0.1 Compliance
- **Illustrative example only** — PCI DSS v4.0.1 (current since 2024/2025, superseding v3.2.1) renumbered requirements significantly. Look up the actual current requirement numbers in the official PCI SSC "Summary of Changes from v3.2.1 to v4.0" document rather than assuming the old numbering still applies; do not cite specific requirement numbers without verifying them against that document first.
- Example finding shape: **[Requirement N.N]**: [what was tested] [✓/❌]

## HIPAA Compliance
- **§164.308(a)(1)**: Security risk assessment ✓
- **§164.312(a)(1)**: Access controls insufficient ❌

## GDPR Compliance
- **Article 32**: Security of processing gaps identified
- **Article 25**: Privacy by design issues found
```

## Remediation Priorities

### Priority Matrix
```bash
# Generate priority matrix
${CLAUDE_PLUGIN_ROOT}/skills/report-generation/scripts/report-generator.sh priorities

Priority 1 (Immediate):
- [ ] Patch critical RCE vulnerability (CVE-2024-XXX)
- [ ] Change default credentials on admin interfaces
- [ ] Disable unnecessary services

Priority 2 (30 days):
- [ ] Implement WAF for web applications
- [ ] Update all software to latest versions
- [ ] Enable logging and monitoring

Priority 3 (90 days):
- [ ] Conduct security awareness training
- [ ] Implement network segmentation
- [ ] Deploy EDR solution
```

## Report Quality Checks

### Pre-Delivery Checklist
```bash
# Text-lint a rendered report file (CVSS mentioned, evidence/PoC present,
# remediation included, no obvious cleartext creds left in)
${CLAUDE_PLUGIN_ROOT}/skills/report-generation/scripts/report-generator.sh validate --input report.md

# Structurally validate findings.json for a session: any CRITICAL/HIGH
# finding that failed Tier 1 trace validation or was refuted by Tier 2
# review (see docs/workflow.md) is a hard FAIL, regardless of what the
# rendered report text says
${CLAUDE_PLUGIN_ROOT}/skills/report-generation/scripts/report-generator.sh validate --session-id "$SESSION_ID"

# Both flags can be combined in one call. `generate` itself always splits
# output into "Confirmed Findings" and "Unverified / Needs Manual Review"
# sections based on the same validation data - nothing unverified is ever
# presented as confirmed.
```

### Sensitive Data Sanitization
```bash
# Sanitize report
${CLAUDE_PLUGIN_ROOT}/skills/report-generation/scripts/report-generator.sh sanitize \
  --input draft_report.md \
  --output sanitized_report.md

# Removes:
- Production passwords
- API keys
- Internal IP addresses
- Employee names
- Sensitive file contents
```

## Report Templates

### Penetration Test Report
```bash
${CLAUDE_PLUGIN_ROOT}/skills/report-generation/scripts/report-generator.sh \
  --template pentest \
  --include-sections "exec,technical,appendix"
```

### Vulnerability Assessment Report
```bash
${CLAUDE_PLUGIN_ROOT}/skills/report-generation/scripts/report-generator.sh \
  --template vuln-assessment \
  --include-sections "summary,vulnerabilities,recommendations"
```

### Red Team Report
```bash
${CLAUDE_PLUGIN_ROOT}/skills/report-generation/scripts/report-generator.sh \
  --template red-team \
  --include-sections "objectives,timeline,ttp,detection"
```

### Web Application Assessment
```bash
${CLAUDE_PLUGIN_ROOT}/skills/report-generation/scripts/report-generator.sh \
  --template webapp \
  --include-sections "owasp,vulnerabilities,code-review"
```

## Integration with Session Data

### Extract Session Findings

`$SESSION_ID`/`$SESSION_DIR` are set earlier in the workflow (`commands/pentest.md` Step 1 exports them) — there's no "get the current session" lookup, use the values already in the environment.

```bash
# Aggregate findings
${CLAUDE_PLUGIN_ROOT}/skills/report-generation/scripts/report-generator.sh aggregate \
  --session $SESSION_ID \
  --output findings.json
```

### Automatic Report Population
```bash
# Auto-populate from session
${CLAUDE_PLUGIN_ROOT}/skills/report-generation/scripts/report-generator.sh auto \
  --session $SESSION_ID \
  --detect-vulns \
  --calculate-cvss \
  --collect-evidence
```

## Session Review (Internal — Trace Log Analysis)

Every tool call and subagent completion during a `/pentest` run is logged to a JSONL trace file by hooks (`PostToolUse`, `PostToolUseFailure`, `SubagentStop`), so a run can be walked back through afterward — this is for improving Clicky itself, not something that belongs in the client-facing report above.

```bash
# Review the most recent run
${CLAUDE_PLUGIN_ROOT}/skills/report-generation/scripts/session-review.sh

# Review a specific run by Claude Code session ID
${CLAUDE_PLUGIN_ROOT}/skills/report-generation/scripts/session-review.sh <claude_session_id>

# Review a specific trace file directly
${CLAUDE_PLUGIN_ROOT}/skills/report-generation/scripts/session-review.sh ~/.claude/pentest-traces/<claude_session_id>.jsonl
```

Output includes a chronological walk-through of every tool call and subagent completion, and a summary of failures grouped by agent. Use this to compare real outcomes against the HTB baseline success rates in `decision-agent`'s decision tree, and to feed generalized learnings into its persistent memory (see `docs/agents.md`) — the trace log is the raw ground truth; memory is what gets distilled from it once a pattern repeats across engagements.

For deeper, queryable analysis across many engagements (not just one run), see `docs/observability.md` for Claude Code's built-in OpenTelemetry support.

## Professional Formatting

### Style Guidelines
```markdown
# Professional Writing
- Use passive voice for findings
- Be objective and factual
- Avoid jargon in executive summary
- Include technical details in appendix
- Use consistent terminology

# Visual Elements
- Include network diagrams
- Use risk heat maps
- Add trend analysis graphs
- Include screenshot annotations
```

### Report Sections
```bash
# Standard sections
1. Cover Page
2. Table of Contents
3. Executive Summary
   - Engagement Overview
   - Risk Summary
   - Key Findings
4. Technical Findings
   - Critical Vulnerabilities
   - High Risk Issues
   - Medium Risk Issues
   - Low Risk Issues
5. Recommendations
   - Immediate Actions
   - Short-term Fixes
   - Long-term Improvements
6. Methodology
7. Appendices
   - Tool Output
   - Evidence
   - Glossary
```

## Delivery Formats

### Encrypted Delivery
```bash
# Encrypt report
gpg --encrypt --recipient client@example.com report.pdf

# Password protect PDF
qpdf --encrypt {password} {password} 256 -- report.pdf encrypted_report.pdf

# Create encrypted archive
7z a -p{password} -mhe report.7z report.pdf evidence/
```

## Best Practices

1. **Always validate findings** before including in report
2. **Include clear evidence** for every vulnerability
3. **Provide actionable remediation** guidance
4. **Use consistent formatting** throughout
5. **Sanitize sensitive data** before delivery
6. **Get report reviewed** before sending to client
7. **Keep template updated** with latest standards

## Notes

- Report is often the only deliverable client sees
- Quality reflects on entire engagement
- Always maintain professional tone
- Include positive findings when applicable
- Provide cost-effective remediation options
- Consider client's technical maturity level