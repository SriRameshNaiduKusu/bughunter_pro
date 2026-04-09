# BugHunter Pro

**Comprehensive Security Reconnaissance & Vulnerability Scanner**

## Features

- **Subdomain Enumeration** (DNS brute-force, crt.sh, ThreatCrowd)
- **Technology Fingerprinting** (60+ technologies)
- **Web Crawling** (links, forms, JS files, parameters)
- **Shodan Integration** (ports, CVEs, services)
- **DNS & WHOIS Enumeration**
- **SQL Injection Scanner**
- **Cross-Site Scripting (XSS) Scanner**
- **Server-Side Request Forgery (SSRF) Scanner**
- **CORS Misconfiguration Scanner**
- **Cloud Storage Misconfiguration** (S3, Azure, GCP)
- **Directory & API Brute-Forcing** (powered by SecLists)
- **Security Header Analysis**
- **Open Redirect & CRLF Injection Scanners**
- **Target Intelligence** (industry detection, attack surface mapping)
- **Interactive HTML Report** with attack surface graph
- **Tor Integration** for anonymous scanning (Linux/macOS)

## Quick Install

### Linux (Kali / Parrot / Ubuntu / Debian / Arch)
```bash
git clone https://github.com/SriRameshNaiduKusu/bughunter-pro.git
cd bughunter-pro
chmod +x install.sh
./install.sh
```

### MacOS
```bash
git clone https://github.com/yourusername/bughunter-pro.git
cd bughunter-pro
chmod +x install.sh
./install.sh
```

### Windows
```bash
git clone https://github.com/yourusername/bughunter-pro.git
cd bughunter-pro
.\install.ps1
```

### Manual Install (Any OS)
```bash
pip install .
bughunter-install    # Downloads SecLists
```
## Usage

```bash
# Basic scan
bughunter -d example.com

# Full scan with Tor
bughunter -d example.com --full --tor

# Specific modules
bughunter -d example.com -m recon,scan --threads 30

# With Shodan API key
bughunter -d example.com --shodan-key YOUR_KEY --tor

# Verbose output
bughunter -d example.com --full --tor -v
```

## ⚠️ Legal Disclaimer
**This tool is developed for educational and authorized security testing only.**
**Always obtain proper written authorization before scanning any target.**
**Unauthorized scanning is illegal and unethical.**