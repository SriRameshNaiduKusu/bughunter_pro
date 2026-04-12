#!/usr/bin/env python3
"""
BugHunter Pro - Comprehensive Security Reconnaissance & Vulnerability Scanner
==============================================================================

Usage:
    bughunter -d <domain> [options]
    python -m bughunter_pro -d <domain> [options]

Examples:
    bughunter -d example.com --tor
    bughunter -d example.com -m recon,scan --threads 30 --tor -v
    bughunter -d example.com --full --shodan-key YOUR_KEY --tor
"""

import sys
import os
import argparse
import time
import warnings
import platform
from datetime import datetime

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Ensure package is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bughunter_pro.config import Config
from bughunter_pro.core.logger import setup_logger
from bughunter_pro.core.utils import set_global_proxies, set_global_config

BANNER = r"""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████╗     ║
║   ██╔══██╗██║   ██║██╔════╝ ██║  ██║██║   ██║████╗  ██║╚══██║    ║
║   ██████╔╝██║   ██║██║  ███╗███████║██║   ██║██╔██╗ ██║  ██╔╝    ║
║   ██╔══██╗██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║  ╚═╝     ║
║   ██████╔╝╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║  ██╗     ║
║   ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝  ╚═╝     ║
║                                                                  ║
║          BugHunter Pro v1.0 - Security Recon & Scanner           ║
║                                                                  ║
║             For AUTHORIZED security testing ONLY                 ║
╚══════════════════════════════════════════════════════════════════╝
"""


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "BugHunter Pro - Comprehensive Security "
            "Reconnaissance & Vulnerability Scanner"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Module options for -m / --modules:
  recon       - Subdomain enum, DNS, WHOIS, tech detection, Shodan
  crawl       - Web crawling and link discovery
  scan        - All vulnerability scanners
  cloud       - Cloud storage misconfiguration checks
  dirbrute    - Directory brute-forcing (uses SecLists)
  apibrute    - API endpoint brute-forcing (uses SecLists)
  headers     - Security header analysis
  cors        - CORS misconfiguration scanning
  intel       - Target intelligence analysis
  all         - Run everything (default)

Tor Usage:
  --tor             Enable Tor (auto-starts on Linux/macOS)
  --tor-port 9050   Custom Tor SOCKS5 port
  --tor-renew 50    Renew Tor circuit every N requests

Examples:
  bughunter -d example.com --tor
  bughunter -d example.com -m recon,scan -t 30 --tor
  bughunter -d example.com --full --shodan-key YOUR_KEY --tor -v
        """,
    )

    # Target
    parser.add_argument(
        "-d", "--domain", required=True,
        help="Target domain to scan (e.g., example.com)",
    )

    # Modules
    parser.add_argument(
        "-m", "--modules", default="all",
        help="Comma-separated list of modules (default: all)",
    )
    parser.add_argument(
        "--full", action="store_true",
        help="Run all modules (alias for -m all)",
    )

    # Performance
    parser.add_argument(
        "-t", "--threads", type=int, default=20,
        help="Number of concurrent threads (default: 20)",
    )
    parser.add_argument(
        "--timeout", type=int, default=10,
        help="Request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--delay", type=float, default=0.1,
        help="Delay between requests in seconds (default: 0.1)",
    )

    # Crawling
    parser.add_argument(
        "--max-crawl-depth", type=int, default=3,
        help="Maximum crawl depth (default: 3)",
    )
    parser.add_argument(
        "--max-crawl-pages", type=int, default=200,
        help="Maximum pages to crawl (default: 200)",
    )

    # Tor
    parser.add_argument(
        "--tor", action="store_true",
        help="Route traffic through Tor (auto-start on Linux/macOS)",
    )
    parser.add_argument(
        "--tor-port", type=int, default=9050,
        help="Tor SOCKS5 port (default: 9050)",
    )
    parser.add_argument(
        "--tor-control-port", type=int, default=9051,
        help="Tor control port (default: 9051)",
    )
    parser.add_argument(
        "--tor-password", default="",
        help="Tor control port password",
    )
    parser.add_argument(
        "--tor-renew", type=int, default=50,
        help="Renew Tor circuit every N requests (default: 50)",
    )

    # API Keys
    parser.add_argument(
        "--shodan-key", default="",
        help="Shodan API key (or set SHODAN_API_KEY env var)",
    )

    # Wordlists
    parser.add_argument(
        "--subdomain-wordlist", default="",
        help="Path to custom subdomain wordlist (overrides SecLists)",
    )
    parser.add_argument(
        "--dir-wordlist", default="",
        help="Path to custom directory wordlist (overrides SecLists)",
    )
    parser.add_argument(
        "--api-wordlist", default="",
        help="Path to custom API endpoint wordlist (overrides SecLists)",
    )
    parser.add_argument(
        "--seclists-size", default="medium",
        choices=["small", "medium", "large"],
        help="SecLists wordlist size preference (default: medium)",
    )

    # Output
    parser.add_argument(
        "-o", "--output", default="bughunter_output",
        help="Output directory (default: bughunter_output)",
    )
    parser.add_argument(
        "--no-html", action="store_true",
        help="Skip HTML report generation",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose/debug output",
    )

    return parser.parse_args()


def build_config(args: argparse.Namespace) -> Config:
    """Build Config object from parsed arguments."""
    config = Config()

    # Domain
    domain = args.domain.strip().lower()
    if domain.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        parsed = urlparse(domain)
        domain = parsed.hostname
    config.target_domain = domain
    config.base_url = f"https://{domain}"

    # Performance
    config.threads = args.threads
    config.timeout = args.timeout
    config.delay_between_requests = args.delay
    config.max_crawl_depth = args.max_crawl_depth
    config.max_crawl_pages = args.max_crawl_pages
    config.verbose = args.verbose

    # Tor
    config.use_tor = args.tor
    config.tor_socks_port = args.tor_port
    config.tor_control_port = args.tor_control_port
    config.tor_control_password = args.tor_password
    config.tor_renew_every = args.tor_renew

    # API Keys
    if args.shodan_key:
        config.shodan_api_key = args.shodan_key

    # Custom wordlists override SecLists
    if args.subdomain_wordlist:
        config.subdomain_wordlist = args.subdomain_wordlist
    else:
        # Select SecLists size
        size_map = {
            "small": 0,   # subdomains-top1million-5000
            "medium": 1,  # subdomains-top1million-20000
            "large": 2,   # subdomains-top1million-110000
        }
        idx = size_map.get(args.seclists_size, 1)
        sl_path = config.get_seclists_wordlist("subdomains", idx)
        if sl_path:
            config.subdomain_wordlist = sl_path

    if args.dir_wordlist:
        config.directory_wordlist = args.dir_wordlist
    else:
        size_map = {"small": 2, "medium": 0, "large": 3}
        idx = size_map.get(args.seclists_size, 0)
        sl_path = config.get_seclists_wordlist("directories", idx)
        if sl_path:
            config.directory_wordlist = sl_path

    if args.api_wordlist:
        config.api_wordlist = args.api_wordlist

    # Load enhanced payloads from SecLists if available
    sqli_payloads = config.load_seclists_payloads("sqli")
    if sqli_payloads:
        config.sqli_payloads = (
            config.sqli_payloads + sqli_payloads[:100]
        )  # Merge with built-in

    xss_payloads = config.load_seclists_payloads("xss")
    if xss_payloads:
        config.xss_payloads = config.xss_payloads + xss_payloads[:100]

    # Output
    config.output_dir = args.output

    # Modules
    if args.full:
        config.modules_to_run = ["all"]
    else:
        config.modules_to_run = [
            m.strip().lower() for m in args.modules.split(",")
        ]

    return config


def should_run(module_name: str, config: Config) -> bool:
    """Check if a specific module should be run."""
    return (
        "all" in config.modules_to_run
        or module_name in config.modules_to_run
    )


def setup_tor(config: Config, logger) -> 'TorManager':
    """Initialize and start Tor if requested."""
    from bughunter_pro.core.tor_manager import TorManager

    tor = TorManager(
        socks_port=config.tor_socks_port,
        control_port=config.tor_control_port,
        control_password=config.tor_control_password,
    )

    if config.use_tor:
        logger.info("=" * 60)
        logger.info("TOR SETUP")
        logger.info("=" * 60)

        success = tor.setup()
        if success:
            proxies = tor.get_proxy_dict()
            set_global_proxies(proxies)

            status = tor.get_status()
            logger.info(f"[TOR] Status: Connected={status['connected']}")
            logger.info(f"[TOR] Proxy: {status['socks_proxy']}")
            logger.info(f"[TOR] Original IP: {status['original_ip']}")
            logger.info(f"[TOR] Tor IP: {status['tor_ip']}")
        else:
            logger.warning(
                "[TOR] Tor setup failed. Continuing WITHOUT Tor proxy."
            )
            logger.warning(
                "[TOR] Your real IP will be visible to the target."
            )
            config.use_tor = False
    else:
        logger.info("[TOR] Tor not enabled. Use --tor to route through Tor.")

    return tor


def main():
    """Main execution flow."""
    print(BANNER)

    args = parse_arguments()
    config = build_config(args)
    set_global_config(config)

    logger = setup_logger(
        output_dir=config.output_dir,
        verbose=config.verbose,
    )

    start_time = time.time()

    logger.info(f"Target:     {config.target_domain}")
    logger.info(f"Modules:    {', '.join(config.modules_to_run)}")
    logger.info(f"Threads:    {config.threads}")
    logger.info(f"Tor:        {'Enabled' if config.use_tor else 'Disabled'}")
    logger.info(f"Platform:   {platform.system()} {platform.release()}")
    logger.info(f"Python:     {platform.python_version()}")
    logger.info(f"Output:     {config.output_dir}")
    logger.info(f"Wordlists:  SecLists={'found' if os.path.isdir(config.seclists_dir) else 'not found (using fallback)'}")

    # ============================
    # TOR SETUP
    # ============================
    tor_manager = setup_tor(config, logger)

    # ============================
    # RESULTS STORAGE
    # ============================
    results = {
        "subdomains": [],
        "technologies": {},
        "crawl_data": {},
        "dns_records": {},
        "whois_data": {},
        "shodan_data": {},
        "vulnerability_findings": {
            "sqli": [], "xss": [], "ssrf": [], "cors": [],
            "open_redirect": [], "crlf": [], "cloud_misconfig": [],
            "dir_bruteforce": [], "api_bruteforce": [], "headers": [],
        },
        "intelligence": {},
        "tor_status": tor_manager.get_status() if config.use_tor else {},
    }

    # ============================
    # PHASE 1: RECONNAISSANCE
    # ============================
    logger.info("=" * 60)
    logger.info("PHASE 1: RECONNAISSANCE")
    logger.info("=" * 60)

    if should_run("recon", config) or should_run("subdomains", config):
        try:
            from bughunter_pro.recon.subdomain_enum import SubdomainEnumerator
            enumerator = SubdomainEnumerator(config)
            results["subdomains"] = enumerator.enumerate()
        except Exception as e:
            logger.error(f"Subdomain enumeration failed: {e}")

    if should_run("recon", config) or should_run("dns", config):
        try:
            from bughunter_pro.recon.dns_enum import DNSEnumerator
            dns_enum = DNSEnumerator(config)
            results["dns_records"] = dns_enum.enumerate()
        except Exception as e:
            logger.error(f"DNS enumeration failed: {e}")

    if should_run("recon", config) or should_run("whois", config):
        try:
            from bughunter_pro.recon.whois_lookup import WhoisLookup
            whois = WhoisLookup(config)
            results["whois_data"] = whois.lookup() or {}
        except Exception as e:
            logger.error(f"WHOIS lookup failed: {e}")

    if should_run("recon", config) or should_run("tech", config):
        try:
            from bughunter_pro.recon.tech_detect import TechDetector
            detector = TechDetector(config)
            results["technologies"] = detector.detect()
        except Exception as e:
            logger.error(f"Technology detection failed: {e}")

    if should_run("recon", config) or should_run("shodan", config):
        try:
            from bughunter_pro.recon.shodan_recon import ShodanRecon
            shodan_recon = ShodanRecon(config)
            results["shodan_data"] = shodan_recon.search() or {}
        except Exception as e:
            logger.error(f"Shodan recon failed: {e}")

    # Renew Tor circuit after recon
    if config.use_tor and tor_manager.is_connected:
        tor_manager.renew_circuit()

    # ============================
    # PHASE 2: CRAWLING
    # ============================
    if should_run("crawl", config) or should_run("all", config):
        logger.info("=" * 60)
        logger.info("PHASE 2: WEB CRAWLING")
        logger.info("=" * 60)

        try:
            from bughunter_pro.recon.crawler import WebCrawler
            crawler = WebCrawler(config)
            results["crawl_data"] = crawler.crawl()
        except Exception as e:
            logger.error(f"Web crawling failed: {e}")

    # Renew Tor circuit after crawling
    if config.use_tor and tor_manager.is_connected:
        tor_manager.renew_circuit()

    # ============================
    # PHASE 3: VULNERABILITY SCANNING
    # ============================
    logger.info("=" * 60)
    logger.info("PHASE 3: VULNERABILITY SCANNING")
    logger.info("=" * 60)

    crawl_data = results.get("crawl_data", {})
    param_urls = (
        crawl_data.get("parameterized_urls", [])
        if isinstance(crawl_data, dict) else []
    )
    forms = (
        crawl_data.get("forms", [])
        if isinstance(crawl_data, dict) else []
    )
    all_links = (
        crawl_data.get("links", [])
        if isinstance(crawl_data, dict) else []
    )

    if should_run("scan", config) or should_run("headers", config):
        try:
            from bughunter_pro.scanners.header_scanner import HeaderScanner
            scanner = HeaderScanner(config)
            results["vulnerability_findings"]["headers"] = scanner.scan()
        except Exception as e:
            logger.error(f"Header scan failed: {e}")

    if should_run("scan", config) or should_run("cors", config):
        try:
            from bughunter_pro.scanners.cors_scanner import CORSScanner
            scanner = CORSScanner(config)
            target_urls = list(set([config.base_url] + all_links[:50]))
            results["vulnerability_findings"]["cors"] = scanner.scan(
                target_urls
            )
        except Exception as e:
            logger.error(f"CORS scan failed: {e}")

    if should_run("scan", config) or should_run("sqli", config):
        try:
            from bughunter_pro.scanners.sqli_scanner import SQLiScanner
            scanner = SQLiScanner(config)
            scanner.scan_urls(param_urls)
            scanner.scan_forms(forms)
            results["vulnerability_findings"]["sqli"] = scanner.findings
        except Exception as e:
            logger.error(f"SQLi scan failed: {e}")

    # Renew Tor circuit mid-scan
    if config.use_tor and tor_manager.is_connected:
        tor_manager.renew_circuit()

    if should_run("scan", config) or should_run("xss", config):
        try:
            from bughunter_pro.scanners.xss_scanner import XSSScanner
            scanner = XSSScanner(config)
            scanner.scan_urls(param_urls)
            scanner.scan_forms(forms)
            results["vulnerability_findings"]["xss"] = scanner.findings
        except Exception as e:
            logger.error(f"XSS scan failed: {e}")

    if should_run("scan", config) or should_run("ssrf", config):
        try:
            from bughunter_pro.scanners.ssrf_scanner import SSRFScanner
            scanner = SSRFScanner(config)
            scanner.scan_urls(param_urls)
            scanner.scan_forms(forms)
            results["vulnerability_findings"]["ssrf"] = scanner.findings
        except Exception as e:
            logger.error(f"SSRF scan failed: {e}")

    if should_run("scan", config) or should_run("redirect", config):
        try:
            from bughunter_pro.scanners.open_redirect import (
                OpenRedirectScanner,
            )
            scanner = OpenRedirectScanner(config)
            results["vulnerability_findings"]["open_redirect"] = (
                scanner.scan_urls(param_urls)
            )
        except Exception as e:
            logger.error(f"Open redirect scan failed: {e}")

    if should_run("scan", config) or should_run("crlf", config):
        try:
            from bughunter_pro.scanners.crlf_scanner import CRLFScanner
            scanner = CRLFScanner(config)
            results["vulnerability_findings"]["crlf"] = (
                scanner.scan_urls(param_urls)
            )
        except Exception as e:
            logger.error(f"CRLF scan failed: {e}")

    if should_run("scan", config) or should_run("cloud", config):
        try:
            from bughunter_pro.scanners.cloud_misconfig import (
                CloudMisconfigScanner,
            )
            scanner = CloudMisconfigScanner(config)
            results["vulnerability_findings"]["cloud_misconfig"] = (
                scanner.scan()
            )
        except Exception as e:
            logger.error(f"Cloud misconfiguration scan failed: {e}")

    # Renew Tor circuit before brute-forcing
    if config.use_tor and tor_manager.is_connected:
        tor_manager.renew_circuit()

    if should_run("dirbrute", config) or should_run("all", config):
        try:
            from bughunter_pro.scanners.dir_bruteforce import (
                DirectoryBruteforcer,
            )
            scanner = DirectoryBruteforcer(config)
            results["vulnerability_findings"]["dir_bruteforce"] = (
                scanner.scan()
            )
        except Exception as e:
            logger.error(f"Directory brute-force failed: {e}")

    if should_run("apibrute", config) or should_run("all", config):
        try:
            from bughunter_pro.scanners.api_bruteforce import APIBruteforcer
            scanner = APIBruteforcer(config)
            results["vulnerability_findings"]["api_bruteforce"] = (
                scanner.scan()
            )
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
            from bughunter_pro.intelligence.target_intel import (
                TargetIntelligence,
            )
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

    # Flatten all findings
    all_findings = []
    for category, findings in results["vulnerability_findings"].items():
        if isinstance(findings, list):
            all_findings.extend(findings)

    # Build attack surface graph
    graph_data = {"nodes": [], "edges": [], "metadata": {}}
    try:
        from bughunter_pro.intelligence.attack_surface import (
            AttackSurfaceMapper,
        )
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
        "tor_status": results.get("tor_status", {}),
    }
    for category, findings in results["vulnerability_findings"].items():
        flat_results[f"vuln_{category}"] = findings

    # JSON Report
    # --- JSON Report (UPDATED with duration tracking) ---
    try:
        from bughunter_pro.reporting.json_report import JSONReporter
        json_reporter = JSONReporter(config)
        elapsed_so_far = time.time() - start_time
        json_path = json_reporter.generate(
            flat_results,
            scan_duration=elapsed_so_far,
        )
    except Exception as e:
        logger.error(f"JSON report generation failed: {e}")

    # HTML Report
    if not args.no_html:
        try:
            from bughunter_pro.reporting.html_report import HTMLReporter
            html_reporter = HTMLReporter(config)
            html_path = html_reporter.generate(flat_results, graph_data)
        except Exception as e:
            logger.error(f"HTML report generation failed: {e}")

    # ============================
    # TOR TEARDOWN
    # ============================
    if config.use_tor:
        tor_manager.teardown()

    # ============================
    # FINAL SUMMARY
    # ============================
    elapsed = time.time() - start_time

    severity_counts = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
    }
    for finding in all_findings:
        sev = finding.get("severity", "INFO").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    logger.info("=" * 60)
    logger.info("SCAN COMPLETE - SUMMARY")
    logger.info("=" * 60)
    logger.info(f"Target:            {config.target_domain}")
    logger.info(f"Duration:          {elapsed:.1f} seconds")
    logger.info(
        f"Tor:               "
        f"{'Connected (' + (tor_manager.tor_ip or 'N/A') + ')' if config.use_tor and tor_manager.is_connected else 'Disabled'}"
    )
    logger.info(f"Subdomains found:  {len(results['subdomains'])}")
    logger.info(
        f"Pages crawled:     "
        f"{results.get('crawl_data', {}).get('pages_crawled', 0) if isinstance(results.get('crawl_data'), dict) else 0}"
    )
    logger.info(f"Total findings:    {len(all_findings)}")
    logger.info(f"  CRITICAL:        {severity_counts['CRITICAL']}")
    logger.info(f"  HIGH:            {severity_counts['HIGH']}")
    logger.info(f"  MEDIUM:          {severity_counts['MEDIUM']}")
    logger.info(f"  LOW:             {severity_counts['LOW']}")
    logger.info(f"  INFO:            {severity_counts['INFO']}")

    risk_score = (
        results.get("intelligence", {}).get("risk_score", 0)
        if isinstance(results.get("intelligence"), dict) else 0
    )
    logger.info(f"Risk Score:        {risk_score}/100")
    logger.info(f"Reports saved in:  {config.output_dir}/")
    logger.info("=" * 60)

    logger.info("")
    logger.info("📊 To view reports in the dashboard:")
    logger.info("   bughunter-dashboard")
    logger.info("   Then open http://localhost:8501")
    logger.info("")

    # Return exit code based on findings
    if severity_counts["CRITICAL"] > 0:
        sys.exit(2)
    elif severity_counts["HIGH"] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()