# Windows Privilege Escalation Cheatsheet

### Well-known SIDs in the Context of Privilege Escalation

| SID                       | Meaning                |
|---------------------------|------------------------|
| S-1-0-0                   | Nobody                 |
| S-1-1-0                   | Everybody              |
| S-1-5-11                  | Authenticated Users    |
| S-1-5-18                  | Local System           |
| S-1-5-domainidentifier-500 | Administrator         |

Refer to: [PayloadsAllTheThings Windows Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

---

## Initial PowerUp.ps1 Import

powershell.exe -ExecutionPolicy Bypass
Invoke-AllChecks


---

## Key Information to Collect

1. **Username and Hostname**
   - `whoami`

2. **Group Memberships of Current User**
   - `whoami /groups`

3. **Existing Users and Groups**
   - `net user` or `Get-LocalUser`
   - `net localgroup` or `Get-LocalGroup`
   - `Get-LocalGroupMember Users`

4. **OS, Version, Architecture**
   - `systeminfo`

5. **Network Information**
   - `ipconfig /all`
   - `route print`
   - `netstat -ano`

6. **Installed Applications**
   - 32bit: `Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`
   - 64bit: `Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`
   - Check 32-bit and 64-bit Program Files directories located in `C:\`

7. **Running Processes**
   - `Get-Process`
   - `Get-Process NonStandardProcess | Format-list *`
   - `Get-Process | Select-Object -Property Name, ProcessName, Path, Id, CPU`

8. **Running Services (IMP)**
   - Lock for services with non-default paths:  
     `Get-CimInstance -ClassName win32_service | Select Name, State, PathName | Where-Object {$_.State -like 'Running'}`

9. **Ranas**
   - `runas /user:backupadmin cmd`
   - `Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "whoami"`

10. **PowerShell History & Event Viewer Script Block Logging**
    - `Get-History`
    - `(Get-PSReadlineOption).HistorySavePath`
    - `cd C:\Users\<username>\appdata\roaming\microsoft\windows\powershell\psreadline`

    *Script Block:*
    - Launch Event Viewer via RDP
    - Expand Applications and Services Logs > Microsoft > Windows > Powershell  
    - Use right side filter to search for "ScriptBlock"

11. **Enum File System**
    - `icacls`, `tree /f /a`
    - `cmdkey /list`
    - `cd C:\Users\<username>\appdata\roaming\microsoft\windows\powershell\psreadline`
    - `Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.xls,*.ini,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue`
    - Use `which` as `where` in Linux

---

## Tools to Use

- [Seatbelt.exe](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Seatbelt.exe)
- [winPEASx64.exe](https://github.com/carlospolop/PEASS-ng/releases/download/20230101/winPEASx64.exe)

---

## To-Do List

- Situational Awareness
- Hidden in Plain View
- Information Goldmine PowerShell
- Automated Enumeration

---

## Possible Attack Vectors

- Service Binary Hijacking
- DLL Hijacking
- Unquoted Service Paths
- Scheduled Tasks
- Application version Exploits
- Windows kernel Exploits
- Windows Privilege (`whoami /priv`)

---

## PowerShell: Bypass AV Policy Change

To change the policy globally:

- `Get-ExecutionPolicy -Scope CurrentUser # Show the Current execution Policy`
- `Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser # Change the EP`

# Audit Commands

## 1. Check Audit Policy Status

View all audit policy settings
auditpol /get /category:*

List all subcategories for granular audit configuration
auditpol /list /subcategory:*

## 2. Set/Enable Key Audit Policies

Enable auditing for successful and failed logon attempts
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

Enable auditing for privilege use
auditpol /set /subcategory:"Privilege Use" /success:enable /failure:enable

Enable file system object auditing
auditpol /set /subcategory:"File System" /success:enable /failure:enable


## 3. Audit File/Folder Access

- GUI: Right-click folder > Properties > Security > Advanced > Auditing > Add
- CLI example for setting audit rules on a folder (using icacls):
  
icacls "C:\SensitiveData" /setaudit S-1-1-0:(0x1301f)

## 4. Check User and Group Memberships

List all local administrators
net localgroup administrators

List members of a group
Get-LocalGroupMember -Group "Administrators"


## 5. Check Service and Registry Permissions

List services with unquoted paths (potential privilege escalation risk)
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\" | findstr /i /v "C:\Program Files\"

Find world-writable registry keys (using accesschk from Sysinternals)
accesschk.exe -wuv -k HKLM


## 6. Check for Missing Patches

List installed hotfixes
wmic qfe get Caption,Description,HotFixID,InstalledOn


## 7. Review Scheduled Tasks

Get scheduled tasks basic info
schtasks /query /fo LIST /v

Detailed scheduled task info
Get-ScheduledTask | Get-ScheduledTaskInfo


## 8. List Running Processes with Command Lines

Get-WmiObject Win32_Process | select ProcessId,CommandLine | Format-List



## 9. Review Group Policy Results

gpresult /h C:\gpresult.html

Open the HTML report for reviewing applied policies and audit settings



