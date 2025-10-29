# Windows-Privilege-Escalation

Well-known SIDs in the context of privilege escalation.
	1. S-1-0-0                       Nobody        
	2. S-1-1-0	                      Everybody
	3. S-1-5-11                      Authenticated Users
	4. S-1-5-18                      Local System
	5. S-1-5-domainidentifier-500    Administrator

Refer this : https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md

First Thing to do is Import the PowerUp.ps1 
# powershell.exe -ExecutionPolicy Bypass
# Invoke-AllChecks

There are several key pieces of information we should always obtain:
	1. Username and hostname 
		a. whoami
	2. Group memberships of the current user
		a. whoami /groups
	3. Existing users and groups 
		a. net user or Get-LocalUser
		b. net localgroup or Get-LocalGroup
		c. Get-LocalGroupMember Users
	4. Operating system, version and architecture
		a. systeminfo
	5. Network information
		a. ipconfig /all
		b. route print
		c. netstat -ano
	6. Installed applications
		a. 32bit: Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
		b. Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
		c.  check 32-bit and 64-bit Program Files directories located in C:\
	7. Running processes
		a. Get-Process
		b. Get-Process NonStandardProcess | Format-list *
		c. Get-Process | Select-Object -Property Name, ProcessName, Path, Id, CPU
	8. Running Services (IMP) [Lock for the service with non-default path (DP:C:\Windows\System32)]
		a. Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'} 
	9. Ranas
		a. runas /user:backupadmin cmd
		b. Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "whoami"
	10. PowerShell History & Event Viewer Script Block Logging
		a. Get-History
		b. (Get-PSReadlineOption).HistorySavePath 
		c. cd C:\Users\<username>\appdata\roaming\microsoft\windows\powershell\psreadline
		Script Block
		d. Launch the Event Viewer application through RDP
		e. Expand Applications and Services Logs > Microsoft > Windows > Powershell.
		f. User Filter from the right side to search for "ScriptBlock"
			
	11. Enum File system
		a. icacls , tree /f /a
		b. cmdkey /list
		c. cd C:\Users\<username>\appdata\roaming\microsoft\windows\powershell\psreadline
		d. Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.xls,*.ini,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
		e. Use 'which' command as 'where' in Linux 

Tool that can be used:
	→ https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Seatbelt.exe
	→ https://github.com/carlospolop/PEASS-ng/releases/download/20230101/winPEASx64.exe


To Do list:
	Situational Awareness
	Hidden in Plain View
	Information Goldmine PowerShell
	Automated Enumeration 

Possible Attack:
	Service Binary Hijacking 
	DLL Hijiacking 
	Unquoted Service Paths
	Scheduled Tasks
	Application version Exploits 
	Windows kerneal Exploits
	Windows Privilege (whoami /priv)
	
PowerShell bypass the AV
To change the policy globally
# Get-ExecutionPolicy -Scope CurrentUser   (Show the Current execution Policy)
# Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser  (This will Change the EP)

![Uploading image.png…]()
