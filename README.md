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
undefined
