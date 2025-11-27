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
```bash
# Run CVSS calculator
scripts/cvss-calculator.sh \
  --vector "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

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
**OWASP**: A[Number]-[Category]

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
**Short-term**: [Immediate fixes]
**Long-term**: [Comprehensive solution]

### References
- [CVE/Advisory URL]
- [Vendor Documentation]
```

## Evidence Collection

### Screenshot Management
```bash
# Capture evidence
scripts/evidence-collector.py screenshot --tag "sqli" --vuln "VULN-001"

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
scripts/evidence-collector.py add-output \
  --file evidence/nmap_scan.md \
  --section "reconnaissance"
```

## Report Generation Automation

### Generate Full Report
```bash
# Run report generator
scripts/report-generator.sh \
  --session-id {session_id} \
  --format markdown \
  --output pentest_report.md

# Generate with all options
scripts/report-generator.sh \
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
scripts/report-generator.sh --format markdown

# Sections included:
- Executive Summary
- Vulnerability Details
- Technical Recommendations
- Evidence Links
- Appendices
```

#### HTML Report
```bash
scripts/report-generator.sh --format html

# Features:
- Interactive table of contents
- Sortable vulnerability table
- Embedded screenshots
- Syntax highlighting for code
```

#### PDF Report
```bash
scripts/report-generator.sh --format pdf

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
- **OWASP A03:2021**: Injection
- **Impact**: Database compromise, data theft
- **CVSS Base**: 9.8 (Critical)

### Cross-Site Scripting (XSS)
- **CWE-79**: Cross-site Scripting
- **OWASP A03:2021**: Injection
- **Impact**: Session hijacking, defacement
- **CVSS Base**: 6.1 (Medium)

### Authentication Bypass
- **CWE-287**: Improper Authentication
- **OWASP A07:2021**: Identification and Authentication Failures
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
scripts/report-generator.sh metrics

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
## PCI DSS Compliance
- **Requirement 2.1**: Default passwords changed ❌
- **Requirement 6.5**: Secure coding violations found ❌
- **Requirement 11.3**: Penetration test conducted ✓

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
scripts/report-generator.sh priorities

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
# Run quality checks
scripts/report-generator.sh validate

Validation Checks:
✓ All findings have CVSS scores
✓ Evidence provided for each finding
✓ Remediation guidance included
✓ No sensitive data exposed
✓ Client information accurate
✓ Spell check passed
✓ Grammar check passed
✓ Formatting consistent
```

### Sensitive Data Sanitization
```bash
# Sanitize report
scripts/report-generator.sh sanitize \
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
scripts/report-generator.sh \
  --template pentest \
  --include-sections "exec,technical,appendix"
```

### Vulnerability Assessment Report
```bash
scripts/report-generator.sh \
  --template vuln-assessment \
  --include-sections "summary,vulnerabilities,recommendations"
```

### Red Team Report
```bash
scripts/report-generator.sh \
  --template red-team \
  --include-sections "objectives,timeline,ttp,detection"
```

### Web Application Assessment
```bash
scripts/report-generator.sh \
  --template webapp \
  --include-sections "owasp,vulnerabilities,code-review"
```

## Integration with Session Data

### Extract Session Findings
```bash
# Pull data from session
SESSION_ID=$(scripts/session-manager.sh current)
SESSION_DIR="$HOME/.claude/sessions/$SESSION_ID"

# Aggregate findings
scripts/report-generator.sh aggregate \
  --session $SESSION_ID \
  --output findings.json
```

### Automatic Report Population
```bash
# Auto-populate from session
scripts/report-generator.sh auto \
  --session $SESSION_ID \
  --detect-vulns \
  --calculate-cvss \
  --collect-evidence
```

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