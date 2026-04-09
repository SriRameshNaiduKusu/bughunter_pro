#!/usr/bin/env python3
"""
BugHunter Pro - Comprehensive Security Reconnaissance & Vulnerability Scanner
==============================================================================

Usage:
    python main.py -d <domain> [options]

Examples:
    python main.py -d example.com
    python main.py -d example.com -m recon,scan --threads 30 -v
    python main.py -d example.com --full --shodan-key YOUR_API_KEY
"""

import sys
import os
import argparse
import time
import warnings
from datetime import datetime

# Suppress SSL warnings for testing
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import Config
from core.logger import setup_logger

# --- Banner ---
BANNER = r"""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████╗  ║
║   ██╔══██╗██║   ██║██╔════╝ ██║  ██║██║   ██║████╗  ██║╚══██║  ║
║   ██████╔╝██║   ██║██║  ███╗███████║██║   ██║██╔██╗ ██║  ██╔╝  ║
║   ██╔══██╗██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║  ╚═╝   ║
║   ██████╔╝╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║  ██╗  ║
║   ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝  ╚═╝  ║
║                                                                  ║
║          BugHunter Pro v1.0 - Security Recon & Scanner           ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="BugHunter Pro - Comprehensive Security Reconnaissance & Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Module options for -m / --modules:
  recon       - Subdomain enumeration, DNS, WHOIS, tech detection, Shodan
  crawl       - Web crawling and link discovery
  scan        - All vulnerability scanners (SQLi, XSS, SSRF, etc.)
  cloud       - Cloud storage misconfiguration checks
  dirbrute    - Directory brute-forcing
  apibrute    - API endpoint brute-forcing
  headers     - Security header analysis
  cors        - CORS misconfiguration scanning
  intel       - Target intelligence analysis
  all         - Run everything (default)

Examples:
  python main.py -d example.com
  python main.py -d example.com -m recon,scan -t 30
  python main.py -d example.com --full -o ./reports -v
        """,
    )

    parser.add_argument(
        "-d", "--domain", required=True,
        help="Target domain to scan (e.g., example.com)",
    )
    parser.add_argument(
        "-m", "--modules", default="all",
        help="Comma-separated list of modules to run (default: all)",
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=20,
        help="Number of concurrent threads (default: 20)",
    )
    parser.add_argument(
        "-o", "--output", default="bughunter_output",
        help="Output directory (default: bughunter_output)",
    )
    parser.add_argument(
        "--timeout", type=int, default=10,
        help="Request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--delay", type=float, default=0.1,
        help="Delay between requests in seconds (default: 0.1)",
    )
    parser.add_argument(
        "--max-crawl-depth", type=int, default=3,
        help="Maximum crawl depth (default: 3)",
    )
    parser.add_argument(
        "--max-crawl-pages", type=int, default=200,
        help="Maximum pages to crawl (default: 200)",
    )
    parser.add_argument(
        "--shodan-key", default="",
        help="Shodan API key (or set SHODAN_API_KEY env var)",
    )
    parser.add_argument(
        "--subdomain-wordlist", default="",
        help="Path to custom subdomain wordlist",
    )
    parser.add_argument(
        "--dir-wordlist", default="",
        help="Path to custom directory wordlist",
    )
    parser.add_argument(
        "--api-wordlist", default="",
        help="Path to custom API endpoint wordlist",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose/debug output",
    )
    parser.add_argument(
        "--full", action="store_true",
        help="Run all modules (alias for -m all)",
    )
    parser.add_argument(
        "--no-html", action="store_true",
        help="Skip HTML report generation",
    )

    return parser.parse_args()


def build_config(args: argparse.Namespace) -> Config:
    """Build Config object from parsed arguments."""
    config = Config()
    config.target_domain = args.domain.strip().lower()

    # Strip protocol if provided
    if config.target_domain.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        parsed = urlparse(config.target_domain)
        config.target_domain = parsed.hostname
    config.base_url = f"https://{config.target_domain}"

    config.threads = args.threads
    config.output_dir = args.output
    config.timeout = args.timeout
    config.delay_between_requests = args.delay
    config.max_crawl_depth = args.max_crawl_depth
    config.max_crawl_pages = args.max_crawl_pages
    config.verbose = args.verbose

    if args.shodan_key:
        config.shodan_api_key = args.shodan_key

    if args.subdomain_wordlist:
        config.subdomain_wordlist = args.subdomain_wordlist
    if args.dir_wordlist:
        config.directory_wordlist = args.dir_wordlist
    if args.api_wordlist:
        config.api_wordlist = args.api_wordlist

    if args.full:
        config.modules_to_run = ["all"]
    else:
        config.modules_to_run = [
            m.strip().lower() for m in args.modules.split(",")
        ]

    return config


def should_run(module_name: str, config: Config) -> bool:
    """Check if a specific module should be run."""
    return "all" in config.modules_to_run or module_name in config.modules_to_run


def main():
    """Main execution flow."""
    print(BANNER)

    args = parse_arguments()
    config = build_config(args)
    logger = setup_logger(
        output_dir=config.output_dir,
        verbose=config.verbose,
    )

    start_time = time.time()
    logger.info(f"Starting BugHunter Pro scan on: {config.target_domain}")
    logger.info(f"Modules: {', '.join(config.modules_to_run)}")
    logger.info(f"Threads: {config.threads}")
    logger.info(f"Output: {config.output_dir}")

    # ============================
    # Storage for all results
    # ============================
    results = {
        "subdomains": [],
        "technologies": {},
        "crawl_data": {},
        "dns_records": {},
        "whois_data": {},
        "shodan_data": {},
        "vulnerability_findings": {
            "sqli": [],
            "xss": [],
            "ssrf": [],
            "cors": [],
            "open_redirect": [],
            "crlf": [],
            "cloud_misconfig": [],
            "dir_bruteforce": [],
            "api_bruteforce": [],
            "headers": [],
        },
        "intelligence": {},
    }

    # ============================
    # PHASE 1: RECONNAISSANCE
    # ============================
    logger.info("=" * 60)
    logger.info("PHASE 1: RECONNAISSANCE")
    logger.info("=" * 60)

    # --- Subdomain Enumeration ---
    if should_run("recon", config) or should_run("subdomains", config):
        try:
            from recon.subdomain_enum import SubdomainEnumerator
            enumerator = SubdomainEnumerator(config)
            results["subdomains"] = enumerator.enumerate()
        except Exception as e:
            logger.error(f"Subdomain enumeration failed: {e}")

    # --- DNS Enumeration ---
    if should_run("recon", config) or should_run("dns", config):
        try:
            from recon.dns_enum import DNSEnumerator
            dns_enum = DNSEnumerator(config)
            results["dns_records"] = dns_enum.enumerate()
        except Exception as e:
            logger.error(f"DNS enumeration failed: {e}")

    # --- WHOIS Lookup ---
    if should_run("recon", config) or should_run("whois", config):
        try:
            from recon.whois_lookup import WhoisLookup
            whois = WhoisLookup(config)
            results["whois_data"] = whois.lookup() or {}
        except Exception as e:
            logger.error(f"WHOIS lookup failed: {e}")

    # --- Technology Detection ---
    if should_run("recon", config) or should_run("tech", config):
        try:
            from recon.tech_detect import TechDetector
            detector = TechDetector(config)
            results["technologies"] = detector.detect()
        except Exception as e:
            logger.error(f"Technology detection failed: {e}")

    # --- Shodan Reconnaissance ---
    if should_run("recon", config) or should_run("shodan", config):
        try:
            from recon.shodan_recon import ShodanRecon
            shodan_recon = ShodanRecon(config)
            results["shodan_data"] = shodan_recon.search() or {}
        except Exception as e:
            logger.error(f"Shodan recon failed: {e}")

    # ============================
    # PHASE 2: CRAWLING
    # ============================
    if should_run("crawl", config) or should_run("all", config):
        logger.info("=" * 60)
        logger.info("PHASE 2: WEB CRAWLING")
        logger.info("=" * 60)

        try:
            from recon.crawler import WebCrawler
            crawler = WebCrawler(config)
            results["crawl_data"] = crawler.crawl()
        except Exception as e:
            logger.error(f"Web crawling failed: {e}")

    # ============================
    # PHASE 3: VULNERABILITY SCANNING
    # ============================
    logger.info("=" * 60)
    logger.info("PHASE 3: VULNERABILITY SCANNING")
    logger.info("=" * 60)

    crawl_data = results.get("crawl_data", {})
    param_urls = crawl_data.get("parameterized_urls", [])
    forms = crawl_data.get("forms", [])
    all_links = crawl_data.get("links", [])

    # --- Security Headers ---
    if should_run("scan", config) or should_run("headers", config):
        try:
            from scanners.header_scanner import HeaderScanner
            header_scanner = HeaderScanner(config)
            results["vulnerability_findings"]["headers"] = header_scanner.scan()
        except Exception as e:
            logger.error(f"Header scan failed: {e}")

    # --- CORS Misconfiguration ---
    if should_run("scan", config) or should_run("cors", config):
        try:
            from scanners.cors_scanner import CORSScanner
            cors_scanner = CORSScanner(config)
            target_urls = list(set([config.base_url] + all_links[:50]))
            results["vulnerability_findings"]["cors"] = cors_scanner.scan(target_urls)
        except Exception as e:
            logger.error(f"CORS scan failed: {e}")

    # --- SQL Injection ---
    if should_run("scan", config) or should_run("sqli", config):
        try:
            from scanners.sqli_scanner import SQLiScanner
            sqli_scanner = SQLiScanner(config)
            sqli_scanner.scan_urls(param_urls)
            sqli_scanner.scan_forms(forms)
            results["vulnerability_findings"]["sqli"] = sqli_scanner.findings
        except Exception as e:
            logger.error(f"SQLi scan failed: {e}")

    # --- Cross-Site Scripting ---
    if should_run("scan", config) or should_run("xss", config):
        try:
            from scanners.xss_scanner import XSSScanner
            xss_scanner = XSSScanner(config)
            xss_scanner.scan_urls(param_urls)
            xss_scanner.scan_forms(forms)
            results["vulnerability_findings"]["xss"] = xss_scanner.findings
        except Exception as e:
            logger.error(f"XSS scan failed: {e}")

    # --- Server-Side Request Forgery ---
    if should_run("scan", config) or should_run("ssrf", config):
        try:
            from scanners.ssrf_scanner import SSRFScanner
            ssrf_scanner = SSRFScanner(config)
            ssrf_scanner.scan_urls(param_urls)
            ssrf_scanner.scan_forms(forms)
            results["vulnerability_findings"]["ssrf"] = ssrf_scanner.findings
        except Exception as e:
            logger.error(f"SSRF scan failed: {e}")

    # --- Open Redirect ---
    if should_run("scan", config) or should_run("redirect", config):
        try:
            from scanners.open_redirect import OpenRedirectScanner
            redirect_scanner = OpenRedirectScanner(config)
            results["vulnerability_findings"]["open_redirect"] = redirect_scanner.scan_urls(param_urls)
        except Exception as e:
            logger.error(f"Open redirect scan failed: {e}")

    # --- CRLF Injection ---
    if should_run("scan", config) or should_run("crlf", config):
        try:
            from scanners.crlf_scanner import CRLFScanner
            crlf_scanner = CRLFScanner(config)
            results["vulnerability_findings"]["crlf"] = crlf_scanner.scan_urls(param_urls)
        except Exception as e:
            logger.error(f"CRLF scan failed: {e}")

    # --- Cloud Misconfiguration ---
    if should_run("scan", config) or should_run("cloud", config):
        try:
            from scanners.cloud_misconfig import CloudMisconfigScanner
            cloud_scanner = CloudMisconfigScanner(config)
            results["vulnerability_findings"]["cloud_misconfig"] = cloud_scanner.scan()
        except Exception as e:
            logger.error(f"Cloud misconfiguration scan failed: {e}")

    # --- Directory Brute-Force ---
    if should_run("dirbrute", config) or should_run("all", config):
        try:
            from scanners.dir_bruteforce import DirectoryBruteforcer
            dir_bruter = DirectoryBruteforcer(config)
            results["vulnerability_findings"]["dir_bruteforce"] = dir_bruter.scan()
        except Exception as e:
            logger.error(f"Directory brute-force failed: {e}")

    # --- API Endpoint Brute-Force ---
    if should_run("apibrute", config) or should_run("all", config):
        try:
            from scanners.api_bruteforce import APIBruteforcer
            api_bruter = APIBruteforcer(config)
            results["vulnerability_findings"]["api_bruteforce"] = api_bruter.scan()
        except Exception as e:
            logger.error(f"API brute-force failed: {e}")

    # ============================
    # PHASE 4: TARGET INTELLIGENCE
    # ============================
    if should_run("intel", config) or should_run("all", config):
        logger.info("=" * 60)
        logger.info("PHASE 4: TARGET INTELLIGENCE")
        logger.info("=" * 60)

        try:
            from intelligence.target_intel import TargetIntelligence
            intel = TargetIntelligence(config)
            results["intelligence"] = intel.analyse(
                subdomains=results["subdomains"],
                technologies=results["technologies"],
                dns_records=results["dns_records"],
                shodan_data=results["shodan_data"] or None,
                crawl_data=results["crawl_data"] or None,
            )
        except Exception as e:
            logger.error(f"Target intelligence analysis failed: {e}")

    # ============================
    # PHASE 5: REPORTING
    # ============================
    logger.info("=" * 60)
    logger.info("PHASE 5: REPORT GENERATION")
    logger.info("=" * 60)

    # Flatten all findings for reporting
    all_findings = []
    for category, findings in results["vulnerability_findings"].items():
        if isinstance(findings, list):
            all_findings.extend(findings)

    # --- Build Attack Surface Graph ---
    graph_data = {"nodes": [], "edges": [], "metadata": {}}
    try:
        from intelligence.attack_surface import AttackSurfaceMapper
        mapper = AttackSurfaceMapper(config)
        graph_data = mapper.build_graph(
            subdomains=results["subdomains"],
            technologies=results["technologies"],
            crawl_data=results.get("crawl_data"),
            dns_records=results["dns_records"],
            shodan_data=results.get("shodan_data"),
            vulnerability_findings=all_findings,
            intel_profile=results.get("intelligence", {}),
        )
    except Exception as e:
        logger.error(f"Attack surface mapping failed: {e}")

    # Prepare flat results for reporters
    flat_results = {
        "subdomains": results["subdomains"],
        "technologies": results["technologies"],
        "crawl_data": results["crawl_data"],
        "dns_records": results["dns_records"],
        "whois_data": results["whois_data"],
        "shodan_data": results["shodan_data"],
        "intelligence": results["intelligence"],
    }
    # Add all finding lists at top level so reporters can iterate
    for category, findings in results["vulnerability_findings"].items():
        flat_results[f"vuln_{category}"] = findings

    # --- JSON Report ---
    try:
        from reporting.json_report import JSONReporter
        json_reporter = JSONReporter(config)
        json_path = json_reporter.generate(flat_results)
    except Exception as e:
        logger.error(f"JSON report generation failed: {e}")

    # --- HTML Report ---
    if not args.no_html:
        try:
            from reporting.html_report import HTMLReporter
            html_reporter = HTMLReporter(config)
            html_path = html_reporter.generate(flat_results, graph_data)
        except Exception as e:
            logger.error(f"HTML report generation failed: {e}")

    # ============================
    # FINAL SUMMARY
    # ============================
    elapsed = time.time() - start_time

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for finding in all_findings:
        sev = finding.get("severity", "INFO").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    logger.info("=" * 60)
    logger.info("SCAN COMPLETE - SUMMARY")
    logger.info("=" * 60)
    logger.info(f"Target:            {config.target_domain}")
    logger.info(f"Duration:          {elapsed:.1f} seconds")
    logger.info(f"Subdomains found:  {len(results['subdomains'])}")
    logger.info(f"Pages crawled:     {results.get('crawl_data', {}).get('pages_crawled', 0) if isinstance(results.get('crawl_data'), dict) else 0}")
    logger.info(f"Total findings:    {len(all_findings)}")
    logger.info(f"  CRITICAL:        {severity_counts['CRITICAL']}")
    logger.info(f"  HIGH:            {severity_counts['HIGH']}")
    logger.info(f"  MEDIUM:          {severity_counts['MEDIUM']}")
    logger.info(f"  LOW:             {severity_counts['LOW']}")
    logger.info(f"  INFO:            {severity_counts['INFO']}")

    risk_score = results.get("intelligence", {}).get("risk_score", 0) if isinstance(results.get("intelligence"), dict) else 0
    logger.info(f"Risk Score:        {risk_score}/100")
    logger.info(f"Reports saved in:  {config.output_dir}/")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()