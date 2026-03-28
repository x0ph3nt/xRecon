# x0ph3nt – Automated Recon & Vulnerability Scanner 🚀

x0ph3nt is a **Bash-based automated reconnaissance and vulnerability scanning tool** designed for penetration testers, security researchers, and ethical hackers.

It automates the process of:
- Target discovery
- Service enumeration
- Basic vulnerability detection

---

## 🔹 Features

- 🔍 Live host detection (IP & Domain)
- 🌐 WHOIS lookup for domain intelligence
- ⚡ Nmap scanning:
  - Service detection (-sV)
  - Default scripts (-sC)
  - OS detection (-O)
- 🛠️ Detection of outdated software:
  - Apache (< 2.4)
  - OpenSSH (< 7.2)
  - vsftpd 2.3.x
  - MySQL (< 5.5)
- 🌍 Web vulnerability scanning with Nikto
- 🚨 Automatic parsing of high/critical vulnerabilities
- ⚙️ Parallel scanning support (GNU Parallel)
- 🧾 Organized output per target
- 📝 Logging system with timestamps
- 📦 Auto-install required dependencies

---

## 🔹 Installation

```bash
git clone https://github.com/<your-username>/x0ph3nt.git
cd x0ph3nt
chmod +x x0ph3nt.sh
```

---

## 🔹 Usage

### ▶️ Scan single target
```bash
./x0ph3nt.sh example.com
```

### ▶️ Scan multiple targets
```bash
./x0ph3nt.sh target1.com target2.com 192.168.1.1
```

### ▶️ Scan from file
```bash
./x0ph3nt.sh -f targets.txt
```

---

## 🔹 Output Structure

```
output/
├── logs.txt
├── vulnerabilities.txt
└── <target>/
    ├── whois.txt
    ├── nmap.txt
    ├── nikto.txt
```

---

## 🔹 How It Works

1. Checks required tools and installs missing dependencies
2. Verifies if target is alive:
   - Ping (for IPs)
   - Common ports (fallback)
   - DNS resolution (for domains)
3. Runs WHOIS lookup
4. Performs Nmap scan
5. Detects outdated services
6. If web service detected:
   - Runs Nikto scan
   - Extracts critical findings
7. Saves all results in structured output

---

## 🔹 Requirements

- Linux (Kali, Ubuntu, Debian)
- Bash
- Root privileges (for installation & scanning)

---

## 🔹 Disclaimer ⚠️

This tool is intended for:

- ✅ Ethical hacking
- ✅ Penetration testing labs (TryHackMe, Hack The Box)
- ✅ Educational purposes

**Do NOT use against targets without permission. Unauthorized scanning is illegal.**

---

## 🔹 Author

👨‍💻 x0ph3nt

---

## 🔹 License

MIT License
