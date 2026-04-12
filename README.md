<div align="center">

# 🛡️ BugHunter Pro

### Comprehensive Security Reconnaissance & Vulnerability Scanner

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)]()
[![SecLists](https://img.shields.io/badge/wordlists-SecLists-orange.svg)](https://github.com/danielmiessler/SecLists)
[![Tor](https://img.shields.io/badge/anonymity-Tor%20Network-purple.svg)](https://www.torproject.org/)

<img src="https://img.icons8.com/fluency/128/shield.png" width="120" alt="BugHunter Pro Logo">

*An all-in-one command-line security tool and interactive dashboard for bug bounty hunters and penetration testers*




</div>

---

## Table of Contents

- [Features](#features)
- [Usage](#usage)
- [Installation](#installation)
  - [Linux (Kali / Parrot / Ubuntu)](#linux-kali--parrot--ubuntu--debian)
  - [macOS](#macos)
  - [Windows](#windows)
  - [Manual Installation](#manual-installation-any-os)
- [Quick Start](#quick-start)
- [Streamlit Dashboard](#streamlit-dashboard)
- [Modules](#modules)
  - [Reconnaissance](#reconnaissance)
  - [Vulnerability Scanners](#vulnerability-scanners)
  - [Intelligence](#intelligence)
  - [Reporting](#reporting)
- [Tor Integration](#tor-integration)
- [SecLists Integration](#seclists-integration)
- [Command Reference](#command-reference)
- [Report Management](#report-management-1)
- [Legal Disclaimer](#legal-disclaimer)
- [Contributing](#contributing)
- [Acknowledgements](#acknowledgements)
- [License](#license)

---

## Features

### 🔍 Reconnaissance
| Feature | Description |
|---------|-------------|
| **Subdomain Enumeration** | DNS brute-force, crt.sh certificate transparency, ThreatCrowd API |
| **Technology Fingerprinting** | 60+ technology signatures (web servers, frameworks, CMS, CDNs, analytics) |
| **Web Crawling** | Recursive crawler that discovers links, forms, JS files, parameters, and emails |
| **Shodan Integration** | Query Shodan for open ports, services, known CVEs, and organization info |
| **DNS Enumeration** | A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA records + zone transfer detection |
| **WHOIS Lookup** | Domain registration info, registrar, creation/expiration dates |

### 🔓 Vulnerability Scanning
| Scanner | Severity | Description |
|---------|----------|-------------|
| **SQL Injection** | 🔴 HIGH | Error-based SQLi detection in URL params and forms |
| **Cross-Site Scripting** | 🔴 HIGH | Reflected XSS detection with 10+ payload patterns |
| **SSRF** | 🔴 CRITICAL | Server-Side Request Forgery with cloud metadata detection |
| **CORS Misconfiguration** | 🟠 HIGH | Tests for wildcard, null origin, and credential leaks |
| **Open Redirect** | 🟡 MEDIUM | Detects unvalidated redirects in URL parameters |
| **CRLF Injection** | 🟠 HIGH | Header injection detection via response splitting |
| **Cloud Misconfig** | 🔴 HIGH | Public S3 buckets, Azure blobs, GCP storage buckets |
| **Security Headers** | 🟡 MEDIUM | Missing HSTS, CSP, X-Frame-Options, cookie security |
| **Directory Brute-Force** | 🟡 MEDIUM | Discover hidden paths using SecLists wordlists |
| **API Discovery** | 🟡 MEDIUM | Find API endpoints, check auth, discover allowed methods |

### 🎯 Intelligence
| Feature | Description |
|---------|-------------|
| **Industry Detection** | Automatically infers target industry (finance, healthcare, etc.) |
| **Subdomain Analysis** | Categorizes subdomains (dev, admin, API, database, CI/CD, etc.) |
| **Attack Vector Suggestions** | Context-aware attack recommendations based on discovered assets |
| **Risk Scoring** | 0-100 risk score based on findings, exposure, and industry |
| **Security Recommendations** | Prioritized remediation advice |

### 📊 Reporting & Dashboard
| Feature | Description |
|---------|-------------|
| **Interactive Streamlit Dashboard** | Full-featured web UI with charts, graphs, and tables |
| **Attack Surface Graph** | Visual network graph of domains, technologies, and vulnerabilities |
| **Report Navigation** | Browse, filter, and compare reports across multiple domains |
| **JSON & CSV Export** | Machine-readable export formats |
| **HTML Report** | Self-contained interactive HTML report with vis.js graph |
| **Persistent Storage** | All scan reports saved and accessible from dashboard |

### 🔒 Anonymity & Cross-Platform
| Feature | Description |
|---------|-------------|
| **Tor Integration** | Auto-start Tor on Linux/macOS, SOCKS5 proxy for all requests |
| **Circuit Renewal** | Automatic Tor identity rotation during scans |
| **Cross-Platform** | Works on Linux, macOS, and Windows |
| **Multi-Threaded** | Configurable thread pool for fast concurrent scanning |
| **Rate Limiting** | Configurable delays to avoid detection and blocking |

---

## Usage

```bash
usage: bughunter [-h] -d DOMAIN [-m MODULES] [--full] [-t THREADS]
                 [--timeout TIMEOUT] [--delay DELAY]
                 [--max-crawl-depth N] [--max-crawl-pages N]
                 [--tor] [--tor-port PORT] [--tor-renew N]
                 [--shodan-key KEY] [--seclists-size {small,medium,large}]
                 [--subdomain-wordlist PATH] [--dir-wordlist PATH]
                 [--api-wordlist PATH]
                 [-o OUTPUT] [--no-html] [-v]
```
|Option |	Default	| Description |
|-------|-------------|-------------|
|-d, --domain |	required |	Target domain |   
|-m, --modules |	all	| Comma-separated module list|
|--full	| —	 | Run all modules |
| -t, --threads	 | 20 |	Concurrent threads |
|--timeout |	10 |	Request timeout (seconds) |
|--delay |	0.1	| Delay between requests (seconds) |
|--tor |	— |	Enable Tor routing|
|--tor-port	| 9050 |	Tor SOCKS5 port|
|--tor-renew |	50 |	Renew circuit every N requests|
|--shodan-key |	— |	Shodan API key|
|--seclists-size | 	medium |	Wordlist size (small/medium/large)|
|-o, --output |	bughunter_output |	Output directory|
|-v, --verbose |	— |	Debug logging|


### Environment Variables

|Variable|	Description|
|---------|-------------|
|SHODAN_API_KEY	| Shodan API key (alternative to --shodan-key)|
                 
---
---
## Installation

### Prerequisites

- **Python 3.9+** [Download](https://www.python.org/downloads/)
- **Git** [Download](https://git-scm.com/downloads)
- **~2GB disk space** (for SecLists wordlists)

### Linux (Kali / Parrot / Ubuntu / Debian)

```bash
# Clone the repository
git clone https://github.com/SriRameshNaiduKusu/bughunter_pro.git
cd bughunter_pro

# Run the automated installer
chmod +x install.sh
./install.sh
```
The installer will:

- Detect your Linux distribution 
- Install system dependencies (git, tor, python3-pip)
- Create a Python virtual environment
- Install BugHunter Pro and all dependencies
- Download SecLists wordlists (~2GB)
- Configure and start Tor service
- Add bughunter to your PATH

### macOS

```bash
git clone https://github.com/SriRameshNaiduKusu/bughunter_pro.git
cd bughunter_pro
chmod +x install.sh
./install.sh
```

"Note: Requires Homebrew. The installer will install it if missing."

### Windows

#### Option 1: PowerShell (Recommended)

```powershell
# Run PowerShell as Administrator
git clone https://github.com/SriRameshNaiduKusu/bughunter_pro.git
cd bughunter_pro
Set-ExecutionPolicy Bypass -Scope Process
.\install.ps1
```

#### Option 2: CMD

```cmd
git clone https://github.com/SriRameshNaiduKusu/bughunter_pro.git
cd bughunter_pro
install.bat
```

> Note: Tor auto-configuration is not available on Windows. 
> Download the Tor Expert Bundle and run tor.exe manually if you need Tor support.

### Manual Installation (Any OS)

```bash
# Clone
git clone https://github.com/SriRameshNaiduKusu/bughunter_pro.git
cd bughunter_pro

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# OR
venv\Scripts\activate     # Windows

# Install
pip install -e .

# Download SecLists
bughunter-install

# Verify
bughunter --help
```
---
## Quick Start


```bash
# Basic Scan
bughunter -d example.com

# Full Scan with Tor
bughunter -d example.com --full --tor

# Scan zomato.com
bughunter -d zomato.com --full --tor -o reports/zomato

# Scan netflix.com
bughunter -d netflix.com --full --tor -o reports/netflix

# View all reports in dashboard
bughunter-dashboard
```
---

## Streamlit Dashboard

The dashboard provides a rich web interface for viewing, comparing, and
managing scan reports.

### Launch the Dashboard

```bash
# Using the CLI command
bughunter-dashboard

# OR using Streamlit directly
streamlit run dashboard/app.py

# OR with custom options
streamlit run dashboard/app.py --server.port 8080
```
### Dashboard Pages

| Page                | Description                                                          |
|---------------------|----------------------------------------------------------------------|
| **Overview**        | Global statistics, severity breakdown, scan timeline, domain summary |
| **Scan Reports**    | Detailed view of individual scan reports with all findings           |
| **Vulnerabilities** | Deep-dive vulnerability explorer with filtering and search           |
| **Attack Surface**  | Interactive network graph of the target's attack surface             |
| **Compare Scans**   | Side-by-side comparison of two scan reports with radar chart         |
| **Settings**        | Report management, import/export, system info                        |


### Report Navigation
Reports are automatically saved after each scan. The dashboard provides:

- Domain filtering — Filter reports by scanned domain
- Report selection — Browse all scans chronologically
- Persistent storage — Reports survive across sessions
- Import/Export — Upload external JSON reports, export CSV
- Comparison — Compare two scans side-by-side (e.g., zomato.com vs netflix.com)
- Delete management — Remove individual or all reports

Example Workflow

```bash
# Day 1: Scan zomato.com
bughunter -d zomato.com --full --tor

# Day 2: Scan netflix.com
bughunter -d netflix.com --full --tor

# Day 3: Rescan zomato.com after fixes
bughunter -d zomato.com --full --tor

# View all results and compare
bughunter-dashboard
# → Navigate to "Compare Scans"
# → Select zomato.com (Day 1) vs zomato.com (Day 3)
# → See what improved!
```
---

## Modules

### Reconnaissance

```bash
bughunter -d target.com -m recon --tor
```

| Module | CLI Flag	| Description|
|---------|-------------|------------|
|Subdomain Enum	| recon, subdomains |	crt.sh, ThreatCrowd, DNS brute-force |
|DNS Records |	recon, dns |	All record types + zone transfer |
|WHOIS |	recon, whois |	Registration and ownership data |
|Tech Detection |	recon, tech |	60+ technology fingerprints |
|Shodan |	recon, shodan |	Requires --shodan-key |
|Web Crawling |	crawl |	Links, forms, JS, params, emails |

### Vulnerability Scanners

```bash
bughunter -d target.com -m scan --tor
```

| Module	          | CLI Flag	        | Payloads                         |
|------------------|------------------|----------------------------------|
| SQL Injection    | 	scan, sqli	     | 15 built-in + SecLists           |
| XSS              | 	scan, xss	      | 10 built-in + SecLists           |
| SSRF             | 	scan, ssrf	     | 10 cloud metadata payloads       |
| CORS             | 	scan, cors	     | 6 origin bypass techniques       |
| Open Redirect    | 	scan, redirect	 | 8 redirect payloads              |
| CRLF Injection   | 	scan, crlf	     | 5 header injection payloads      |
| Cloud Misconfig  | 	scan, cloud	    | S3, Azure Blob, GCP checks       |
| Security Headers | 	scan, headers	  | 8 security headers + cookies     |
| Dir Brute-Force  | 	dirbrute	       | SecLists directory wordlists     |
| API Discovery    | 	apibrute	       | SecLists API endpoint wordlists  |


### Intelligence

```bash
bughunter -d target.com -m intel
```

- Industry detection (finance, healthcare, tech, etc.)
- Subdomain categorization (dev, admin, API, database, CI/CD)
- Attack vector suggestions based on discovered assets 
- Risk score calculation (0-100)
- Technology-specific attack recommendations

### Reporting

All scans automatically generate:
- JSON report — Machine-readable, stored in report DB 
- HTML report — Self-contained with interactive graph 
- Dashboard entry — Viewable in Streamlit dashboard

---

## Tor Integration

|Platform	| Behavior |
|---------|-------------|
|Linux	|Auto-detects, installs (if needed), and starts Tor service|
|macOS |	Auto-detects via Homebrew, starts Tor service|
|Windows |	Skips auto-start; uses Tor if manually running|

#### Tor Features
- Automatic setup — Detects OS, installs Tor, starts service 
- Connection verification — Confirms traffic routes through Tor 
- Circuit renewal — Rotates IP address during scans 
- Graceful fallback — Continues without Tor if setup fails

#### Verify Tor Connection
```bash
bughunter -d example.com --tor -v

# Look for:
# [TOR]  Tor is working! Tor IP: x.x.x.x (Original: y.y.y.y)
```
---

## SecLists Integration
BugHunter Pro uses SecLists — the
security tester's companion collection of wordlists.

### Wordlists Used

|Category | 	SecLists Path                                       |	Entries | 
|---------|------------------------------------------------------|---------|
|Subdomains (small)	| Discovery/DNS/subdomains-top1million-5000.txt	       | 5,000|
|Subdomains (medium)	| Discovery/DNS/subdomains-top1million-20000.txt	      | 20,000  |
|Subdomains (large)	| Discovery/DNS/subdomains-top1million-110000.txt	     | 110,000                                         |
|Directories	| Discovery/Web-Content/directory-list-2.3-medium.txt	 | 220,000+                                         |
|API Endpoints	| Discovery/Web-Content/api/api-endpoints.txt	         | 1,000+                                               |
|SQLi Payloads	| Fuzzing/SQLi/Generic-SQLi.txt	                       | 260+                                                 |
|XSS Payloads	| Fuzzing/XSS/XSS-Jhaddix.txt	                         | 2,600+                                               |

### Manage SecLists
```bash
bughunter-install              # Download/update SecLists
bughunter-install --info       # Show available wordlists
bughunter-install --force      # Force re-download
bughunter-install --fallback-only  # Minimal wordlists only
```

---
## Command Reference

### Sacaning
```bash
# Full scan with Tor
bughunter -d target.com --full --tor

# Reconnaissance only
bughunter -d target.com -m recon --tor

# Only vulnerability scanning
bughunter -d target.com -m scan --tor

# Specific modules
bughunter -d target.com -m recon,sqli,xss --tor

# With Shodan
bughunter -d target.com --full --tor --shodan-key YOUR_KEY

# Large wordlists
bughunter -d target.com --full --tor --seclists-size large

# High-performance
bughunter -d target.com --full --tor -t 50 --delay 0.05

# Stealth mode (slow and careful)
bughunter -d target.com --full --tor -t 5 --delay 1.0
```
### Dashboard
```bash
# Start dashboard
bughunter-dashboard

# Custom port
streamlit run dashboard/app.py --server.port 9090
```

### Report Management
```bash
# View wordlist info
bughunter-install --info

# All reports are stored in: ~/.bughunter_pro/reports/
# Manage via dashboard Settings page
```
---
## Report Management
### Report Storage
All scan reports are automatically saved to:
```bash
~/.bughunter_pro/reports/
├── index.json                          # Report index
├── example.com_20240115_143022.json     # Full report
├── example.com_20240114_091500.json    # Full report
└── example.com_20240116_100000.json     # Re-scan report
```
### Accessing Reports

1. Dashboard (recommended): bughunter-dashboard
2. JSON files: Check ~/.bughunter_pro/reports/
3. Output directory: Check bughunter_output/ in CWD
4. HTML report: Open the .html file in any browser
---
## Legal Disclaimer
> ⚠️ IMPORTANT: This tool is designed for AUTHORIZED security testing ONLY.

- Always obtain written permission before scanning any target 
- Only scan systems you own or have explicit authorization to test 
- Unauthorized scanning is illegal in most jurisdictions 
- This tool is developed for educational purposes as part of an academic project 
- The developers are not responsible for any misuse of this tool 
- Bug bounty hunters: Always follow the program's rules of engagement 
- Comply with all applicable local, national, and international laws

---

## Contributing

**Contributions are welcome! This is an academic project, but improvements are appreciated.**

---

## Acknowledgements

- **[SecLists](https://github.com/danielmiessler/SecLists)** — Daniel Miessler's wordlist collection
- **[Shodan](https://www.shodan.io/)** — Internet-connected device search engine
- **[Tor Project](https://www.torproject.org/)** — Anonymous communication network
- **[Streamlit](https://streamlit.io/)** — Python web application framework
- **[Plotly](https://plotly.com/)** — Interactive charting library
- **[vis.js](https://visjs.org/)** — Network graph visualization
- **[Beautiful Soup](https://www.crummy.com/software/BeautifulSoup/)** — HTML parsing
- **[dnspython](https://www.dnspython.org/)** — DNS toolkit for Python

---
## License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---
<h2 align="center" >
Made with ❤️ for the Cyber Security community
</h2>