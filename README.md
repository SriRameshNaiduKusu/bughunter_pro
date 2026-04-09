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

**University of Hertfordshire — Cyber Security Academic Project**

---

[Features](#-features) •
[Installation](#-installation) •
[Quick Start](#-quick-start) •
[Dashboard](#-streamlit-dashboard) •
[Modules](#-modules) •
[Architecture](#-architecture) •
[Configuration](#%EF%B8%8F-configuration) •
[Contributing](#-contributing)

</div>

---

## 📋 Table of Contents

- [Features](#-features)
- [Usage](#usage)
- [Installation](#-installation)
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
- [Tor Integration](#-tor-integration)
- [SecLists Integration](#-seclists-integration)
- [Command Reference](#-command-reference)
- [Report Management](#-report-management)
- [Legal Disclaimer](#%EF%B8%8F-legal-disclaimer)
- [Contributing](#-contributing)
- [Acknowledgements](#-acknowledgements)
- [License](#-license)

---

## ✨ Features

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

                 
---

## 🚀 Installation

### Prerequisites

- **Python 3.9+** [Download](https://www.python.org/downloads/)
- **Git** [Download](https://git-scm.com/downloads)
- **~2GB disk space** (for SecLists wordlists)

### Linux (Kali / Parrot / Ubuntu / Debian)

```bash
# Clone the repository
git clone https://github.com/yourusername/bughunter-pro.git
cd bughunter-pro

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
git clone https://github.com/yourusername/bughunter-pro.git
cd bughunter-pro
chmod +x install.sh
./install.sh
```

"Note: Requires Homebrew. The installer will install it if missing."

### Windows

#### Option 1: PowerShell (Recommended)

```powershell
# Run PowerShell as Administrator
git clone https://github.com/yourusername/bughunter-pro.git
cd bughunter-pro
Set-ExecutionPolicy Bypass -Scope Process
.\install.ps1
```

#### Option 2: CMD

```cmd
git clone https://github.com/yourusername/bughunter-pro.git
cd bughunter-pro
install.bat
```

> Note: Tor auto-configuration is not available on Windows. 
> Download the Tor Expert Bundle and run tor.exe manually if you need Tor support.

### Manual Installation (Any OS)

```bash
# Clone
git clone https://github.com/yourusername/bughunter-pro.git
cd bughunter-pro

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

