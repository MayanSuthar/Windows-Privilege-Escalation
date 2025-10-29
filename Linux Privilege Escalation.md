# Linux Privilege Escalation Checklist

## Manual Checks

- Check system logs for errors:
  - `/var/log/syslog`
- Check sudo rights:
  - `sudo -l` *(commands current user can run with sudo)*
- Check for cronjobs:
  - `cat /etc/crontab`
  - `ls -lah /etc/cron*`
- Check bash history for credentials:
  - `cat .bash_history`
- List running processes:
  - `ps aux`
  - `ps -aux | grep otherUsername`
- Mounted filesystems:
  - `mount`
- Installed applications:
  - `dpkg -l` *(for Debian/Ubuntu)*
  - `rpm -qa` *(for Red Hat/CentOS)*
- Environment variables (look for credentials):
  - `env`
- Kernel exploits / version info:
  - `Run the linux_exploit_suggester` *(match version)*
  - `ldd --version`
  - `lsb_release -a` **or** `cat /etc/lsb-release`
  - `uname -ar`
- Check running services:
  - `ss -tulnp`
  - `netstat -an -p tcp`
- List file capabilities:
  - `getcap -r / 2>/dev/null`
- Find SUID/SGID files:
  - `find / -perm -u=s -type f 2>/dev/null`
  - `find / -perm -g=s -type f 2>/dev/null`
- Sudo version (possible public exploits):
  - `sudo --version`
- Docker/LXD group memberships:
  - `id`
- Check sensitive files for permissions:
  - `ls -la /etc/passwd` *(writable /etc/passwd)*
  - `ls -la /etc/shadow` *(writable /etc/shadow)*
- Get password hashes:
  - `cat /etc/passwd`
- Look for credentials in configuration files.
- Enumerate and check for:
  - PATH hijacking
  - Password guessing
  - Password reuse
- Automated enumeration tools or brute force:
  - Transfer `linpeas` and perform brute force (linpeas parameter `-a`).
- Check environment variable hijacking:
  - Test with SETENV or `LD_PRELOAD`.
- Search all files for potential passwords:
  - `cd / && grep -rnH "password" . 2>/dev/null`

---

## Automated Scripts

- `linpeas`
- `linenum`
- `linux exploit suggester`
- `pspy`
