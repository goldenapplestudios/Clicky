---
name: nmap-scanning
description: Advanced nmap scanning techniques for comprehensive port and service enumeration during penetration testing
allowed-tools: Bash, Read, Write
---

# Nmap Scanning Skill

## Purpose
This skill provides comprehensive nmap scanning capabilities for penetration testing, including various scan types, timing options, and output formats.

## Instructions

### Quick TCP Scan (Top 1000 ports)
```bash
nmap -sS -sV -O -T4 -Pn {target_ip} -oN quick_scan.txt
```
- `-sS`: SYN stealth scan
- `-sV`: Service version detection
- `-O`: OS detection
- `-T4`: Aggressive timing
- `-Pn`: Skip ping discovery

### Full TCP Port Scan
```bash
nmap -sS -p- -T4 -Pn {target_ip} -oN all_ports.txt
```
- `-p-`: Scan all 65535 ports
- Identifies all open TCP ports

### Detailed Service Enumeration
```bash
nmap -sV -sC -A -p {ports} {target_ip} -oN detailed_scan.txt
```
- `-sC`: Default NSE scripts
- `-A`: Aggressive scan (OS detection, version detection, script scanning, traceroute)
- Use after identifying open ports

### UDP Scan (Top 100)
```bash
sudo nmap -sU --top-ports 100 -sV {target_ip} -oN udp_scan.txt
```
- `-sU`: UDP scan
- `--top-ports 100`: Most common UDP ports
- Requires root/sudo privileges

### Vulnerability Scanning
```bash
nmap --script vuln -p {ports} {target_ip} -oN vuln_scan.txt
```
- Runs vulnerability detection scripts
- Target specific ports for efficiency

### Web Service Enumeration
```bash
nmap --script http-enum,http-headers,http-methods,http-title -p 80,443,8080,8443 {target_ip} -oN web_scan.txt
```
- Comprehensive web service analysis
- Identifies directories, methods, headers

### SMB/NetBIOS Enumeration
```bash
nmap --script smb-enum-*,smb-vuln-* -p 139,445 {target_ip} -oN smb_scan.txt
```
- SMB shares enumeration
- SMB vulnerability detection

### SSL/TLS Analysis
```bash
nmap --script ssl-* -p 443,8443 {target_ip} -oN ssl_scan.txt
```
- SSL certificate information
- Cipher suite analysis
- SSL vulnerabilities

## Scan Timing Templates

| Template | Speed | Use Case |
|----------|-------|----------|
| `-T0` | Paranoid | IDS evasion, very slow |
| `-T1` | Sneaky | IDS evasion, slow |
| `-T2` | Polite | Less bandwidth usage |
| `-T3` | Normal | Default speed |
| `-T4` | Aggressive | Fast, reliable network |
| `-T5` | Insane | Very fast, may miss ports |

## Output Formats

Always save scan results in multiple formats:
```bash
nmap {options} {target} -oA scan_name
```
- Creates .nmap, .xml, and .gnmap files
- XML useful for parsing with other tools

## Firewall/IDS Evasion

### Fragmentation
```bash
nmap -f -sS {target_ip}
```

### Decoy Scanning
```bash
nmap -D RND:10 {target_ip}
```

### Source Port Manipulation
```bash
nmap --source-port 53 {target_ip}
```

## Best Practices

1. **Start with quick scans** to identify live hosts and common services
2. **Follow up with comprehensive scans** on discovered services
3. **Save all output** for documentation and further analysis
4. **Use appropriate timing** based on network conditions
5. **Verify critical findings** with targeted scans
6. **Respect scope boundaries** - only scan authorized targets

## Common Workflows

### Standard Enumeration Flow
1. Quick TCP scan (top 1000 ports)
2. Full TCP port scan if time permits
3. Detailed service scan on discovered ports
4. Vulnerability scanning on critical services
5. UDP scan for completeness

### Web Application Testing
1. Identify web ports (80, 443, 8080, 8443, etc.)
2. Run http-enum scripts
3. Check SSL/TLS configuration
4. Document findings for web app testing phase

### Network Service Testing
1. Identify network services (SMB, SSH, FTP, etc.)
2. Run service-specific NSE scripts
3. Check for default credentials
4. Test for known vulnerabilities

## Troubleshooting

- **Slow scans**: Adjust timing with -T parameter
- **Blocked scans**: Try different scan techniques (TCP connect, UDP)
- **Missing services**: Ensure comprehensive port coverage
- **Rate limiting**: Reduce parallelism with --max-rate

## Integration Notes

This skill works best when:
- Running on Kali Linux with latest nmap version
- User has appropriate permissions (sudo for some scans)
- Network allows ICMP and various TCP/UDP traffic
- Results are saved for progressive analysis