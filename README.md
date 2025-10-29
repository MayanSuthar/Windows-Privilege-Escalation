# Windows Privilege Escalation — Quick Reference

A concise checklist for Windows privilege escalation enumeration and common attack vectors.

---

## Well-known SIDs
| SID | Name |
|---|---|
| `S-1-0-0` | Nobody |
| `S-1-1-0` | Everybody |
| `S-1-5-11` | Authenticated Users |
| `S-1-5-18` | Local System |
| `S-1-5-<domain>-500` | Administrator (default RID 500) |

**Reference:** PayloadsAllTheThings — Windows Privilege Escalation methodology.  
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md

---

## Quick start
1. Import PowerUp / run automated checks (if available):

```powershell
# Launch PowerShell with relaxed policy
powershell.exe -ExecutionPolicy Bypass

# If using PowerUp/PowerUp.ps1, import/run:
# .\PowerUp.ps1
# Invoke-AllChecks```

Username & hostname

whoami


Group memberships

whoami /groups


Existing users & groups

net user            # or Get-LocalUser
net localgroup      # or Get-LocalGroup
Get-LocalGroupMember Users


Operating system, version & architecture

systeminfo


Network information

ipconfig /all
route print
netstat -ano


Installed applications

# 32-bit registry uninstall keys
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName

# 64-bit registry uninstall keys
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName

# Also check:
C:\Program Files
C:\Program Files (x86)


Running processes

Get-Process
Get-Process | Select-Object Name, Path, Id, CPU


Running services (important — look for non-default service paths)

Get-CimInstance -ClassName Win32_Service | 
  Select-Object Name, State, PathName |
  Where-Object { $_.State -like 'Running' }


Runas usage / credential reuse

runas /user:backupadmin cmd
# Example PowerShell usage (requires relevant module/helper)
Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "whoami"


PowerShell history & ScriptBlock logging

Get-History
(Get-PSReadlineOption).HistorySavePath


Check PSReadLine history files: %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\

Check Event Viewer: Applications and Services Logs → Microsoft → Windows → PowerShell — filter for ScriptBlock events.

Filesystem enumeration

icacls <path>
tree /f /a
cmdkey /list          # saved credentials
Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue


Use where on Windows similar to which on Linux:

where <command>


Paste this block under your existing headings in README.md — it matches the style used in your # Windows Privilege Escalation — Quick Reference section. If you want this as a standalone file (ESSENTIALS.md) or with a linked Table of Contents, I can generate that too.
