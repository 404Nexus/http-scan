# 🌐 http-scan
A powerful and modular Python-based HTTP vulnerability scanner for Linux systems, built for penetration testers, VAPT analysts, and cybersecurity learners.

# 🔍 HTTP Scanner (2025 Edition)

A Linux-compatible HTTP scanner for discovering web server vulnerabilities via banner grabbing, known version detection, and web path reconnaissance.

---

## 🚀 Features

- 🌐 Domain/IP/CIDR scanning
- 🔍 Banner grabbing (`Server` header)
- ⚠ Detect vulnerable versions (with CVE reference)
- 🛠 Custom port scanning (default: 80, 443)
- 📁 Sensitive path discovery (`/admin`, `/login`, `/robots.txt`, etc.)
- 📋 Output result to file
- 🧠 Verbose output with `-v`
- 🆘 Help menu with `-h` / `--help`

---

## 📥 How to Install

> 🔧 **Requirements:**  
> - Python 3.x  
> - Linux system (Kali, Parrot, Ubuntu, etc.)

### 🧪 Step-by-step:

```bash
# 1. Clone the repository
git clone https://github.com/yourname/http-scan.git
cd http-scan

# 2. (Optional) Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the scanner
python3 http_scanner.py -h
```
### Usage:
```bash
usage: http-scan.py [-h] [-d DOMAIN] [-t TARGET] [-p PORT [PORT ...]] [-o OUTPUT] [-v]

HTTP Vulnerability Scanner - by kuldeep (latest version)

options:
  -h, --help            Show this help message and exit

  -d DOMAIN, --domain DOMAIN
                        Target domain to scan (e.g., example.com)

  -t TARGET, --target TARGET
                        Target IP or CIDR range (e.g., 192.168.1.10 or 192.168.1.0/24)

  -p PORT [PORT ...], --port PORT [PORT ...]
                        Custom ports to scan (default: 80 443)

  -o OUTPUT, --output OUTPUT
                        Output file to save results (optional)

  -v, --verbose         Enable verbose logging (show server banner, response headers, etc.)
```
### Use Cases:
Reconnaissance phase of bug bounty

Internal VAPT auditing

Web application footprinting

Educational projects

#### ⚠ Legal Disclaimer
This tool is intended only for authorized testing and educational purposes.
Do not use it against systems you don’t own or don’t have permission to test.
Unauthorized use is illegal.

### ✍ Author
Coded by: 404Nexus
🔍 Bug Bounty Hunter | 🛡 Ethical Hacker | ⚙ VAPT | 📅 2025



