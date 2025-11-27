---
name: service-enumeration
description: Deep service enumeration beyond basic port scanning, including banner grabbing, version detection, and service-specific enumeration techniques
allowed-tools: Bash, Read, Write, Grep
---

# Service Enumeration Skill

## Purpose
Provides comprehensive service enumeration techniques for detailed reconnaissance beyond basic port scanning, including banner grabbing, version fingerprinting, and service-specific enumeration methods.

## Service Detection Methodology

### Initial Service Identification
```bash
# Quick service detection
scripts/service-detector.sh --target {ip} --ports "{port_list}"

# Banner grabbing
scripts/banner-grabber.py --target {ip} --port {port}

# Version fingerprinting
scripts/port-analyzer.sh --deep --target {ip}
```

## Service-Specific Enumeration

### FTP (Port 21)
```bash
# Anonymous access check
echo -e "USER anonymous\nPASS anonymous\nQUIT" | nc {target} 21

# Banner grab for version
nc -nv {target} 21

# FTP commands enumeration
ftp {target}
> anonymous
> anonymous@domain.com
> ls -la
> binary
> passive

# Check for FTP bounce
nmap -Pn -n -p 21 --script ftp-bounce {target}
```

### SSH (Port 22)
```bash
# Version and algorithm enumeration
ssh -vv {target}
nmap -p22 --script ssh2-enum-algos {target}

# Username enumeration (OpenSSH < 7.7)
python ssh-user-enum.py -u users.txt {target}

# SSH key acceptance
ssh-keyscan -t rsa,dsa,ecdsa,ed25519 {target}

# Authentication methods
nmap -p22 --script ssh-auth-methods --script-args="ssh.user=root" {target}
```

### Telnet (Port 23)
```bash
# Banner grabbing
telnet {target} 23

# Automated interaction
echo -e "\n\n" | telnet {target} 23

# Check for backdoors
nmap -p23 --script telnet-encryption,telnet-ntlm-info {target}
```

### SMTP (Port 25/587/465)
```bash
# User enumeration
smtp-user-enum -M VRFY -U users.txt -t {target}
smtp-user-enum -M EXPN -U users.txt -t {target}
smtp-user-enum -M RCPT -U users.txt -t {target}

# Manual enumeration
nc -nv {target} 25
> EHLO domain.com
> VRFY root
> EXPN admin
> MAIL FROM: test@test.com
> RCPT TO: admin@{target}

# Version detection
nmap -p25 --script smtp-commands,smtp-enum-users {target}
```

### DNS (Port 53)
```bash
# Zone transfer attempt
dnsrecon -d {domain} -t axfr
dig axfr @{target} {domain}
host -l {domain} {target}

# DNS enumeration
dnsenum {domain}
fierce --domain {domain}

# Reverse DNS
dnsrecon -r {ip_range} -n {target}

# DNS cache snooping
nmap -sU -p53 --script dns-cache-snoop {target}
```

### HTTP/HTTPS (Port 80/443/8080/8443)
```bash
# Technology detection
whatweb -v {target}
wappalyzer {target}

# Header analysis
curl -I -X OPTIONS http://{target}
curl -I -X TRACE http://{target}

# Virtual host discovery
gobuster vhost -u http://{target} -w {wordlist}
ffuf -w {wordlist} -u http://{target} -H "Host: FUZZ.{domain}"

# Web server enumeration
nikto -h http://{target}
nmap -p80 --script http-enum,http-methods,http-headers {target}

# SSL/TLS analysis
testssl.sh https://{target}
nmap -p443 --script ssl-enum-ciphers,ssl-cert {target}
```

### POP3 (Port 110/995)
```bash
# Banner and capabilities
nc -nv {target} 110
> USER test
> PASS test
> LIST
> STAT
> QUIT

# User enumeration
nmap -p110 --script pop3-capabilities,pop3-ntlm-info {target}
```

### IMAP (Port 143/993)
```bash
# Capabilities enumeration
nc -nv {target} 143
> A1 CAPABILITY
> A2 LOGIN test test
> A3 LIST "" "*"
> A4 LOGOUT

# IMAP enumeration
nmap -p143 --script imap-capabilities,imap-ntlm-info {target}
```

### SMB/NetBIOS (Port 139/445)
```bash
# Comprehensive SMB enumeration
enum4linux -a {target}
nbtscan {target}
smbclient -L //{target} -N
smbmap -H {target}
crackmapexec smb {target} -u '' -p ''

# Share enumeration
smbclient -L //{target} -U%
rpcclient -U "" -N {target}

# User enumeration via RID cycling
impacket-lookupsid {target}
rpcclient -U "" {target} -N -c "enumdomusers"

# Version detection
nmap -p445 --script smb-protocols,smb-os-discovery {target}
```

### LDAP (Port 389/636/3268/3269)
```bash
# Anonymous bind enumeration
ldapsearch -x -h {target} -s base
ldapsearch -x -h {target} -b "dc=domain,dc=com"

# Naming contexts
ldapsearch -x -h {target} -s base namingcontexts

# Full dump attempt
ldapsearch -x -h {target} -b "dc=domain,dc=com" "(objectclass=*)"

# LDAP enumeration scripts
nmap -p389 --script ldap-search,ldap-rootdse {target}
```

### MySQL (Port 3306)
```bash
# Version and auth detection
nmap -p3306 --script mysql-info,mysql-empty-password {target}

# Anonymous access
mysql -h {target} -u root
mysql -h {target} -u root -p''

# Database enumeration
mysql -h {target} -u {user} -p{pass} -e "SHOW DATABASES;"
mysql -h {target} -u {user} -p{pass} -e "SELECT user,host FROM mysql.user;"
```

### PostgreSQL (Port 5432)
```bash
# Version detection
nmap -p5432 --script postgresql-info {target}

# Connection attempt
psql -h {target} -U postgres -W

# Database enumeration
psql -h {target} -U {user} -c "\list"
psql -h {target} -U {user} -c "\du"
```

### MSSQL (Port 1433)
```bash
# Version and instance detection
nmap -p1433 --script ms-sql-info,ms-sql-ntlm-info {target}

# Authentication testing
sqsh -S {target} -U sa -P ''
impacket-mssqlclient {domain}/{user}:{password}@{target}

# Database enumeration
sqlcmd -S {target} -U sa -P {password} -Q "SELECT name FROM sys.databases"
```

### MongoDB (Port 27017)
```bash
# Anonymous access
mongo {target}:27017

# Database enumeration
mongo {target}:27017 --eval "db.adminCommand('listDatabases')"

# Version detection
nmap -p27017 --script mongodb-info,mongodb-databases {target}
```

### Redis (Port 6379)
```bash
# Anonymous access
redis-cli -h {target}

# Information gathering
redis-cli -h {target} INFO
redis-cli -h {target} CONFIG GET "*"
redis-cli -h {target} CLIENT LIST

# Key enumeration
redis-cli -h {target} --scan
```

### RDP (Port 3389)
```bash
# RDP information
nmap -p3389 --script rdp-ntlm-info,rdp-enum-encryption {target}

# Security check
rdp-sec-check {target}

# Connection test
xfreerdp /v:{target} /cert:ignore /sec:nla /u:""
```

### VNC (Port 5900-5906)
```bash
# VNC info gathering
nmap -p5900-5906 --script vnc-info,vnc-title {target}

# Authentication check
vncviewer {target}::5900

# Brute force
hydra -s 5900 -P {passwords} -t 4 {target} vnc
```

### SNMP (Port 161/162 UDP)
```bash
# Community string enumeration
onesixtyone -c community.txt {target}
snmp-check {target}

# SNMP walk
snmpwalk -v1 -c public {target}
snmpwalk -v2c -c public {target} 1.3.6.1.2.1.1
snmpwalk -v3 -u {user} -l authPriv -a SHA -A {auth_pass} -x AES -X {priv_pass} {target}

# MIB enumeration
snmpenum {target} public windows.txt
```

## Advanced Enumeration Techniques

### Service Version Mapping
```bash
# Create service version database
scripts/port-analyzer.sh --export-versions > service_versions.json

# Match against vulnerability database
scripts/service-detector.sh --match-vulns service_versions.json
```

### Banner Analysis
```bash
# Extract and analyze all banners
for port in $(cat open_ports.txt); do
    scripts/banner-grabber.py --target {target} --port $port >> banners.txt
done

# Parse for versions
grep -oE "[0-9]+\.[0-9]+\.[0-9]+" banners.txt | sort -u
```

### Service Correlation
```bash
# Correlate services for attack paths
scripts/service-correlator.py --services "{service_list}"

# Example output:
# Web + MySQL = SQL injection potential
# SSH + FTP = Credential reuse opportunity
# SMB + LDAP = Active Directory environment
```

## Enumeration Workflow

1. **Quick Identification**
   - Run service-detector.sh on all open ports
   - Grab banners for version information

2. **Deep Enumeration**
   - Run service-specific enumeration for each service
   - Test for anonymous/guest access
   - Enumerate users if possible

3. **Version Analysis**
   - Map exact versions to CVEs
   - Check for default configurations
   - Identify outdated services

4. **Documentation**
   - Record all service versions
   - Note authentication mechanisms
   - Document enumerated users/resources

## Integration with Other Skills

### Session Management
```bash
# Store enumeration results
SESSION_ID=$(scripts/session-manager.sh current)
scripts/state-persistence.sh record "$SESSION_ID" "services" "{service_name}" "{version_info}"
```

### Credential Testing
```bash
# Test enumerated users
USERS=$(cat enumerated_users.txt)
scripts/credential-manager.sh spray --users "$USERS" --service {service}
```

## Output Format

Service enumeration results should be structured as:
```json
{
  "target": "ip_address",
  "services": [
    {
      "port": 22,
      "service": "SSH",
      "version": "OpenSSH 7.4",
      "banner": "SSH-2.0-OpenSSH_7.4",
      "authentication": ["password", "publickey"],
      "users": [],
      "vulnerabilities": ["CVE-2018-15473"]
    }
  ],
  "enumeration_time": "2025-11-27T00:00:00Z"
}
```

## Best Practices

1. **Start with passive enumeration** - Banner grabbing first
2. **Be mindful of noise** - Some enumeration is loud
3. **Document everything** - Version strings are critical
4. **Check for defaults** - Many services have default configs
5. **Correlate information** - Services often share users/passwords
6. **Respect rate limits** - Don't overwhelm services

## Notes

- Service enumeration can trigger IDS/IPS alerts
- Some services log enumeration attempts
- Always verify versions before exploit attempts
- Consider using proxychains for anonymity
- Update enumeration scripts with new techniques