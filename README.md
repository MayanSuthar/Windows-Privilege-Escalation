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
# Invoke-AllChecks

Essential information to collect

Always gather these pieces of information early in your assessment.

Username & hostname
whoami
