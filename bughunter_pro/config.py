"""
BugHunter Pro - Global Configuration (UPDATED)
"""

import os
import platform
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional


def _find_package_root() -> Path:
    """Find the package installation root directory."""
    return Path(__file__).resolve().parent.parent


@dataclass
class Config:
    """Central configuration for the entire tool."""

    # --- Target ---
    target_domain: str = ""
    base_url: str = ""

    # --- General ---
    threads: int = 20
    timeout: int = 10
    max_retries: int = 3
    delay_between_requests: float = 0.1
    user_agent: str = (
        "BugHunterPro/1.0 (Academic Security Research; "
        "University of Hertfordshire)"
    )
    verify_ssl: bool = False

    # --- Tor ---
    use_tor: bool = False
    tor_socks_port: int = 9050
    tor_control_port: int = 9051
    tor_control_password: str = ""
    tor_renew_every: int = 50  # Renew circuit every N requests

    # --- API Keys ---
    shodan_api_key: str = os.getenv("SHODAN_API_KEY", "")

    # --- Paths ---
    project_root: str = ""
    wordlist_dir: str = ""
    seclists_dir: str = ""
    subdomain_wordlist: str = ""
    directory_wordlist: str = ""
    api_wordlist: str = ""

    # --- Output ---
    output_dir: str = "bughunter_output"
    verbose: bool = False

    # --- Scan Scope ---
    modules_to_run: List[str] = field(default_factory=lambda: ["all"])
    max_crawl_depth: int = 3
    max_crawl_pages: int = 200

    # --- Scanner Payloads ---
    sqli_payloads: List[str] = field(default_factory=lambda: [
        "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--",
        "\" OR 1=1--", "'; DROP TABLE users--", "1' ORDER BY 1--",
        "1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--",
        "' AND '1'='1", "' AND SLEEP(5)--",
        "1; WAITFOR DELAY '0:0:5'--", "' OR ''='", "admin'--",
    ])

    xss_payloads: List[str] = field(default_factory=lambda: [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "<body onload=alert('XSS')>",
        "<iframe src=\"javascript:alert('XSS')\">",
        "{{7*7}}", "${7*7}",
        "<details open ontoggle=alert('XSS')>",
        "<marquee onstart=alert('XSS')>",
    ])

    ssrf_payloads: List[str] = field(default_factory=lambda: [
        "http://127.0.0.1", "http://localhost", "http://0.0.0.0",
        "http://[::1]",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        "http://127.0.0.1:80", "http://127.0.0.1:443",
        "http://127.0.0.1:22",
    ])

    open_redirect_payloads: List[str] = field(default_factory=lambda: [
        "//evil.com", "https://evil.com", "/\\evil.com",
        "////evil.com", "https:///evil.com",
        "HtTp://evil.com", "http://evil.com%2f%2f",
        "////evil.com/%2f%2e%2e",
    ])

    crlf_payloads: List[str] = field(default_factory=lambda: [
        "%0d%0aSet-Cookie:crlf=injection",
        "%0aSet-Cookie:crlf=injection",
        "%0dSet-Cookie:crlf=injection",
        "\\r\\nSet-Cookie:crlf=injection",
        "%E5%98%8A%E5%98%8DSet-Cookie:crlf=injection",
    ])

    s3_bucket_patterns: List[str] = field(default_factory=lambda: [
        "{domain}", "{domain}-backup", "{domain}-assets",
        "{domain}-static", "{domain}-media", "{domain}-uploads",
        "{domain}-data", "{domain}-dev", "{domain}-staging",
        "{domain}-prod", "{domain}-logs", "{domain}-private",
        "{domain}-public", "{domain}-internal", "{domain}-cdn",
        "{domain}-images", "{domain}-files", "{domain}-docs",
        "{domain}-db-backup", "{domain}-config",
    ])

    industry_keywords: dict = field(default_factory=lambda: {
        "finance": [
            "bank", "finance", "pay", "money", "invest", "trade",
            "crypto", "wallet", "loan", "credit", "insurance",
        ],
        "healthcare": [
            "health", "medical", "pharma", "hospital", "clinic",
            "patient", "care", "doctor", "drug", "therapy",
        ],
        "ecommerce": [
            "shop", "store", "buy", "cart", "product", "order",
            "checkout", "catalog", "retail", "marketplace",
        ],
        "education": [
            "edu", "learn", "school", "university", "course",
            "student", "teach", "academy", "training",
        ],
        "technology": [
            "tech", "software", "app", "cloud", "data", "api",
            "dev", "code", "platform", "saas", "digital",
        ],
        "media": [
            "news", "media", "blog", "press", "content",
            "publish", "video", "stream", "social",
        ],
        "government": [
            "gov", "government", "public", "federal", "state",
            "municipal", "civic", "citizen",
        ],
    })

    def __post_init__(self):
        # Resolve paths
        root = _find_package_root()
        self.project_root = str(root)
        self.wordlist_dir = str(root / "wordlists")
        self.seclists_dir = str(root / "wordlists" / "SecLists")

        # Set SecLists-based wordlist paths
        self._resolve_wordlist_paths()

        # Set base URL from domain
        if self.target_domain:
            if not self.target_domain.startswith(("http://", "https://")):
                self.base_url = f"https://{self.target_domain}"
            else:
                self.base_url = self.target_domain

    def _resolve_wordlist_paths(self) -> None:
        """Resolve wordlist paths, preferring SecLists over fallbacks."""
        try:
            from bughunter_pro.installer import get_seclists_path
            self.subdomain_wordlist = (
                get_seclists_path("subdomains") or
                os.path.join(self.wordlist_dir, "fallback", "subdomains.txt")
            )
            self.directory_wordlist = (
                get_seclists_path("directories") or
                os.path.join(self.wordlist_dir, "fallback", "directories.txt")
            )
            self.api_wordlist = (
                get_seclists_path("api_endpoints") or
                os.path.join(
                    self.wordlist_dir, "fallback", "api_endpoints.txt"
                )
            )
        except ImportError:
            # Fallback paths if installer module not available
            self.subdomain_wordlist = os.path.join(
                self.wordlist_dir, "fallback", "subdomains.txt"
            )
            self.directory_wordlist = os.path.join(
                self.wordlist_dir, "fallback", "directories.txt"
            )
            self.api_wordlist = os.path.join(
                self.wordlist_dir, "fallback", "api_endpoints.txt"
            )

    def get_seclists_wordlist(
        self, category: str, index: int = 0
    ) -> Optional[str]:
        """
        Get a specific SecLists wordlist by category and preference index.
        Categories: subdomains, directories, api_endpoints, sqli, xss,
                    lfi, passwords, usernames
        """
        try:
            from bughunter_pro.installer import get_seclists_path
            return get_seclists_path(category, index)
        except ImportError:
            return None

    def load_seclists_payloads(self, category: str) -> List[str]:
        """Load payloads from SecLists for a specific category."""
        wordlist_path = self.get_seclists_wordlist(category)
        if wordlist_path and os.path.isfile(wordlist_path):
            with open(
                wordlist_path, "r", encoding="utf-8", errors="ignore"
            ) as fh:
                return [
                    line.strip() for line in fh
                    if line.strip() and not line.startswith("#")
                ]
        return []