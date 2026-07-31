---
name: osint-gathering
description: Comprehensive OSINT (Open Source Intelligence) gathering techniques for passive reconnaissance including domain enumeration, social media analysis, and data correlation
allowed-tools: Bash, Read, Write, WebFetch, Grep
---

# OSINT Gathering Skill

## Purpose
Provides extensive OSINT techniques for passive information gathering about targets including organizations, individuals, infrastructure, and digital footprints without direct interaction with target systems.

## Domain and DNS Intelligence

### DNS Enumeration
```bash
# Basic DNS queries
host target.com
dig target.com ANY
nslookup target.com

# DNS zone transfer attempt
dig axfr @ns1.target.com target.com
dnsrecon -d target.com -t axfr

# Subdomain enumeration
# Using subfinder
subfinder -d target.com -all -o subdomains.txt

# Using amass
amass enum -passive -d target.com
amass enum -active -d target.com -brute -w /usr/share/wordlists/subdomains.txt

# Using sublist3r
sublist3r -d target.com -b -t 50 -o subdomains.txt

# DNS brute forcing
dnsrecon -d target.com -t brt -D /usr/share/wordlists/dns.txt
fierce --domain target.com --subdomain-file subdomains.txt

# Historical DNS records
# Use SecurityTrails API
curl -X GET "https://api.securitytrails.com/v1/domain/target.com/dns" \
  -H "APIKEY: {api_key}"
```

### Certificate Transparency
```bash
# SSL certificate enumeration
# Using crt.sh
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Using certspotter
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | jq '.[].dns_names[]' | sort -u

# SSL certificate details
openssl s_client -connect target.com:443 -servername target.com < /dev/null | openssl x509 -text -noout

# Using sslscan
sslscan target.com
testssl.sh target.com
```

### WHOIS and ASN Information
```bash
# WHOIS lookup
whois target.com
whois -h whois.arin.net 192.168.1.1

# Reverse WHOIS (find domains by registrant)
# Using DomainTools API
curl "https://api.domaintools.com/v1/reverse-whois/?terms=company_name"

# ASN enumeration
whois -h whois.cymru.com " -v 192.168.1.1"
nmap --script targets-asn --script-args targets-asn.asn=AS12345

# IP range discovery
whois -h whois.radb.net AS12345
curl https://ipinfo.io/AS12345
```

## Web Intelligence

### Search Engine Dorking
```bash
# Google dorks
site:target.com filetype:pdf
site:target.com intext:"password" OR intext:"username"
site:target.com ext:sql OR ext:bak OR ext:old
site:target.com intitle:"index of /"
"@target.com" -site:target.com  # Find email addresses
site:linkedin.com "target company"
site:github.com "target.com"

# Bing dorks
ip:192.168.1.1
site:target.com && (ext:doc OR ext:pdf OR ext:xls)

# DuckDuckGo
site:target.com

# Shodan queries
hostname:target.com
org:"Target Company"
ssl:"target.com"
http.favicon.hash:116323821

# Using automated tools
# GoogleScraper
GoogleScraper -m http -q "site:target.com" --num-results 500

# Dorky
python3 dorky.py -d target.com -o results.txt
```

### Wayback Machine and Archives
```bash
# Wayback Machine URLs
curl -s "http://web.archive.org/cdx/search/cdx?url=target.com/*&output=json&fl=original&collapse=urlkey" | jq -r '.[][0]' | sort -u

# Using waybackurls
waybackurls target.com | grep -E "\\.js$" | sort -u > js_files.txt
waybackurls target.com | grep -E "\\?.*=" | sort -u > parameters.txt

# Archive.today
curl -s "http://archive.md/target.com"

# Common Crawl data
# Download index files
aws s3 ls s3://commoncrawl/crawl-data/ --no-sign-request
```

### Website Technology Stack
```bash
# Using Wappalyzer CLI
wappalyzer https://target.com

# Using WhatWeb
whatweb -v target.com

# Using webtech
webtech -u https://target.com

# BuiltWith API
curl "https://api.builtwith.com/v20/api.json?KEY={api_key}&LOOKUP=target.com"

# Manual detection
curl -s -I https://target.com | grep -E "Server:|X-Powered-By:"
```

## Social Media Intelligence

### LinkedIn Research
```bash
# Company employees enumeration
# Using linkedin2username
python3 linkedin2username.py -c "Target Company"

# InSpy tool
python3 inspy.py --empspy "Target Company" wordlist.txt

# Manual search patterns
# site:linkedin.com "Target Company" "current"
# site:linkedin.com "Target Company" "security" OR "administrator" OR "engineer"
```

### Twitter/X Analysis
```bash
# Using Twint (now Nitter scraping)
# Search tweets
twint -s "target company" -o tweets.csv --csv

# User timeline
twint -u targetuser -o timeline.json --json

# Followers/Following
twint -u targetuser --followers -o followers.txt
twint -u targetuser --following -o following.txt

# Social Analyzer
python3 social-analyzer.py -n "John Doe" -o report.html
```

### GitHub Intelligence
```bash
# Search for company code
# Using GitHub API
curl -H "Authorization: token {github_token}" \
  "https://api.github.com/search/code?q=target.com+in:file"

# GitDorker
python3 GitDorker.py -t {github_token} -q target.com -d dorks.txt

# Gitrob (for organization analysis)
gitrob analyze target-org

# TruffleHog for secrets
trufflehog git https://github.com/target-org --regex --entropy

# Git-secrets
git-secrets --scan-history

# Manual searches
# filename:.env target.com
# filename:config.php target.com password
# filename:id_rsa OR filename:id_dsa
```

### Other Social Platforms
```bash
# Instagram
# Using Instalooter
instalooter user targetuser -n 50 -d ./downloads/

# Facebook
# Using facebook-scraper
facebook-scraper --pages 5 targetpage

# Reddit
# Using PRAW (Python Reddit API Wrapper)
python3 -c "
import praw
reddit = praw.Reddit(client_id='id', client_secret='secret', user_agent='agent')
for post in reddit.subreddit('all').search('target.com', limit=100):
    print(post.title, post.url)
"

# Discord/Slack
# Search for invite links
# site:discord.gg "target"
# site:slack.com "target"
```

## Email Intelligence

### Email Enumeration
```bash
# Hunter.io
curl "https://api.hunter.io/v2/domain-search?domain=target.com&api_key={key}"

# Using theHarvester
theHarvester -d target.com -b all -l 500

# EmailHarvester
python3 EmailHarvester.py -d target.com -e all

# Using h8mail for breach data
h8mail -t user@target.com --local-breach-list breaches.txt

# Verify email addresses
# Using verify-email
verify-email user@target.com

# Email pattern detection
# Using EmailFinder
python3 emailfinder.py -d target.com -f "{first}.{last}"
```

### Email OSINT Tools
```bash
# Phonebook.cz
curl "https://phonebook.cz/api?email=user@target.com"

# Have I Been Pwned
curl "https://haveibeenpwned.com/api/v3/breachedaccount/user@target.com" \
  -H "hibp-api-key: {key}"

# IntelX
curl -X POST "https://2.intelx.io/phonebook/search" \
  -H "x-key: {api_key}" \
  -d '{"term":"@target.com"}'

# Clearbit API
curl "https://person.clearbit.com/v2/people/find?email=user@target.com" \
  -H "Authorization: Bearer {api_key}"
```

## Infrastructure Mapping

### IP and Network Discovery
```bash
# ASN mapping
amass intel -asn AS12345
bgpview-api AS12345

# IP ranges
nmap -sL 192.168.1.0/24 | grep "report" | awk '{print $5}'

# Cloud IP detection
# AWS
curl https://ip-ranges.amazonaws.com/ip-ranges.json | jq '.prefixes[] | select(.service=="EC2")'

# Azure
curl https://www.microsoft.com/en-us/download/details.aspx?id=56519

# GCP
curl https://www.gstatic.com/ipranges/cloud.json

# CDN detection
# Cloudflare
nslookup target.com | grep -q "cloudflare" && echo "Uses Cloudflare"

# Real IP behind CDN
# Using CrimeFlare
python3 crimeflare.py target.com
```

### Port and Service Discovery (Passive)
```bash
# Shodan
shodan host 192.168.1.1
shodan search hostname:target.com

# Censys
censys search "target.com"
censys view 192.168.1.1

# Fofa
# https://fofa.info/result?q=domain="target.com"

# ZoomEye
# Using API
curl -X POST "https://api.zoomeye.org/host/search" \
  -H "Authorization: JWT {token}" \
  -d '{"query":"site:target.com"}'

# BinaryEdge
curl "https://api.binaryedge.io/v2/query/domains/target.com" \
  -H "X-Key: {api_key}"
```

## Document and Metadata Analysis

### Document Harvesting
```bash
# Using metagoofil
metagoofil -d target.com -t pdf,doc,xls,ppt,docx,xlsx,pptx -l 100 -n 10 -o docs -f results.html

# Using FOCA (Windows)
# GUI tool for document metadata extraction

# Manual document search
# Google: site:target.com filetype:pdf
# Download all PDFs
wget -r -l 1 -H -t 1 -nd -N -np -A.pdf -erobots=off https://target.com

# Extract metadata
exiftool *.pdf
pdfinfo document.pdf

# Using pymeta
pymeta -d target.com -s all -csv results.csv
```

### Metadata Extraction
```bash
# Images
exiftool -a -u -g1 image.jpg
strings image.jpg | grep -E "GPS|Location"

# Office documents
python3 -c "
import olefile
ole = olefile.OleFileIO('document.doc')
meta = ole.get_metadata()
for prop in meta.SUMMARY_ATTRIBS:
    print(f'{prop}: {getattr(meta, prop)}')
"

# PDFs
pdfinfo document.pdf
strings document.pdf | grep -E "Author|Creator|Producer"
```

## People and Identity OSINT

### Username Search
```bash
# Sherlock
python3 sherlock username

# WhatsMyName
python3 whatsmyname.py -u username

# Maigret
maigret username

# Social Searcher
curl "https://api.social-searcher.com/v2/search?q=username&network=all"

# UserRecon
python3 userrecon.py username
```

### Person Search Engines
```bash
# Pipl (requires API key)
curl "https://api.pipl.com/search/v5/?email=user@example.com&key={api_key}"

# TruePeopleSearch
# Manual search at truepeoplesearch.com

# Spokeo API
curl "https://api.spokeo.com/v1/search?email=user@example.com" \
  -H "Authorization: Bearer {token}"

# BeenVerified
# Manual or API access
```

### Image Reverse Search
```bash
# Using Google Images
# Upload image to images.google.com

# TinEye API
curl -X POST "https://api.tineye.com/rest/search" \
  -F "image=@face.jpg" \
  -F "api_key={key}"

# Yandex Images
# https://yandex.com/images/

# PimEyes (facial recognition)
# Manual search at pimeyes.com

# Using Face++ API for facial analysis
curl -X POST "https://api-us.faceplusplus.com/facepp/v3/detect" \
  -F "api_key={key}" \
  -F "api_secret={secret}" \
  -F "image_file=@face.jpg"
```

## Breach and Leak Analysis

### Breach Database Search
```bash
# Local breach database search
grep -r "target.com" /path/to/breach/databases/

# Using pwndb
python3 pwndb.py --target @target.com

# Scylla.sh API
curl "https://scylla.sh/search?q=email:user@target.com"

# LeakCheck API
curl "https://leakcheck.io/api/?key={api_key}&check=user@target.com"

# Dehashed API
curl "https://api.dehashed.com/search?query=domain:target.com" \
  -u username:password
```

### Paste Sites Monitoring
```bash
# Pastebin search
# Using PastebinAPI
curl "https://psbdmp.ws/api/search/target.com"

# Gist search
curl "https://api.github.com/gists/public?page=1&per_page=100" | grep -i target

# Using PasteHunter
python3 pastehunter.py

# AIL Framework (Analysis Information Leak)
# Full framework for paste monitoring
```

## Threat Intelligence

### Threat Feeds
```bash
# VirusTotal
curl "https://www.virustotal.com/api/v3/domains/target.com" \
  -H "x-apikey: {api_key}"

# ThreatCrowd
curl "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=target.com"

# AlienVault OTX
curl "https://otx.alienvault.com/api/v1/indicators/domain/target.com/general" \
  -H "X-OTX-API-KEY: {key}"

# URLVoid
curl "https://api.urlvoid.com/api/v1/domain/target.com?key={api_key}"
```

### Reputation Analysis
```bash
# Check blacklists
# Using multi.valli.org
host target.com.multi.valli.org

# Spamhaus
host target.com.zen.spamhaus.org

# SURBL
host target.com.multi.surbl.org

# Talos Intelligence
curl "https://talosintelligence.com/reputation_center/lookup?search=target.com"
```

## Automated OSINT Frameworks

### Comprehensive Tools
```bash
# Recon-ng
recon-ng
> marketplace install all
> workspaces create target_recon
> db insert domains target.com
> modules load recon/domains-hosts/hackertarget
> run

# SpiderFoot
python3 sf.py -s target.com -m all

# OSINT Framework
# Web-based collection at osintframework.com

# Maltego
# GUI tool for relationship mapping

# Sn1per
sniper -t target.com -m osint

# Datasploit
python3 datasploit.py -d target.com
```

### Custom OSINT Script
```bash
#!/bin/bash
# Automated OSINT collection script

TARGET="$1"
OUTPUT_DIR="osint_${TARGET}_$(date +%Y%m%d)"

mkdir -p "$OUTPUT_DIR"/{dns,web,social,docs,emails}

echo "[*] Starting OSINT collection for $TARGET"

# DNS enumeration
echo "[*] DNS Enumeration..."
subfinder -d "$TARGET" -o "$OUTPUT_DIR/dns/subdomains.txt" 2>/dev/null
amass enum -passive -d "$TARGET" -o "$OUTPUT_DIR/dns/amass.txt" 2>/dev/null

# Certificate transparency
echo "[*] Certificate Transparency..."
curl -s "https://crt.sh/?q=%.$TARGET&output=json" | jq -r '.[].name_value' | sort -u > "$OUTPUT_DIR/dns/certs.txt"

# Email harvesting
echo "[*] Email Harvesting..."
theHarvester -d "$TARGET" -b all -f "$OUTPUT_DIR/emails/harvested" 2>/dev/null

# Web archive
echo "[*] Wayback Machine..."
waybackurls "$TARGET" > "$OUTPUT_DIR/web/wayback_urls.txt" 2>/dev/null

# Google dorking
echo "[*] Google Dorking..."
for dork in "filetype:pdf" "filetype:doc" "filetype:xls" "intext:password" "intitle:index.of"; do
  echo "site:$TARGET $dork" >> "$OUTPUT_DIR/web/google_dorks.txt"
done

# GitHub search
echo "[*] GitHub Search..."
curl -s "https://api.github.com/search/code?q=$TARGET" > "$OUTPUT_DIR/social/github.json" 2>/dev/null

# Generate report
echo "[*] Generating report..."
cat > "$OUTPUT_DIR/report.md" << EOF
# OSINT Report for $TARGET
Generated: $(date)

## Subdomains Found
$(wc -l < "$OUTPUT_DIR/dns/subdomains.txt") unique subdomains

## Emails Discovered
$(grep -E "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" "$OUTPUT_DIR/emails/"* 2>/dev/null | sort -u | wc -l) unique emails

## Web Archive URLs
$(wc -l < "$OUTPUT_DIR/web/wayback_urls.txt") historical URLs

## Certificates
$(wc -l < "$OUTPUT_DIR/dns/certs.txt") certificates found
EOF

echo "[*] OSINT collection complete. Results in $OUTPUT_DIR/"
```

## Best Practices

1. **Always use passive techniques first** to avoid detection
2. **Verify information from multiple sources** for accuracy
3. **Document all findings** with timestamps and sources
4. **Respect rate limits** on APIs and services
5. **Use VPN/Tor** for anonymity when appropriate
6. **Check legal requirements** for your jurisdiction
7. **Maintain OPSEC** - don't expose your investigation
8. **Cross-reference data** to build complete picture

## Integration Notes

- Feeds into recon-agent for initial reconnaissance
- Provides context for social-engineering campaigns
- Supports target-validation with background information
- Assists exploit-agent with attack surface mapping
- Helps with report-generation by providing comprehensive data