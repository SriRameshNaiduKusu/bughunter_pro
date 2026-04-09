"""
BugHunter Pro - Security Header Analysis Module
"""

import logging
from typing import List, Dict

from bughunter_pro.config import Config
from bughunter_pro.core.utils import make_request
from bughunter_pro.core.thread_pool import ThreadPoolManager

logger = logging.getLogger("bughunter")

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "MEDIUM",
        "description": "HSTS header missing. Site may be vulnerable to protocol downgrade attacks.",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "description": "CSP header missing. Site may be vulnerable to XSS and data injection.",
        "recommendation": "Implement a strict Content-Security-Policy header.",
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "description": "X-Content-Type-Options header missing. Browser may MIME-sniff responses.",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "X-Frame-Options header missing. Site may be vulnerable to clickjacking.",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    "X-XSS-Protection": {
        "severity": "LOW",
        "description": "X-XSS-Protection header missing.",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block (note: deprecated in modern browsers)",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Referrer-Policy header missing. Referrer information may leak.",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "Permissions-Policy header missing.",
        "recommendation": "Add Permissions-Policy to restrict browser feature access.",
    },
    "X-Permitted-Cross-Domain-Policies": {
        "severity": "LOW",
        "description": "X-Permitted-Cross-Domain-Policies header missing.",
        "recommendation": "Add: X-Permitted-Cross-Domain-Policies: none",
    },
}

DANGEROUS_HEADERS = {
    "Server": {
        "severity": "INFO",
        "description": "Server header exposes web server software and version.",
        "recommendation": "Remove or obscure the Server header.",
    },
    "X-Powered-By": {
        "severity": "INFO",
        "description": "X-Powered-By header exposes backend technology.",
        "recommendation": "Remove the X-Powered-By header.",
    },
    "X-AspNet-Version": {
        "severity": "LOW",
        "description": "ASP.NET version disclosed.",
        "recommendation": "Remove the X-AspNet-Version header.",
    },
    "X-AspNetMvc-Version": {
        "severity": "LOW",
        "description": "ASP.NET MVC version disclosed.",
        "recommendation": "Remove the X-AspNetMvc-Version header.",
    },
}


class HeaderScanner:
    """Analyses security headers of the target."""

    def __init__(self, config: Config):
        self.config = config
        self.findings: List[Dict] = []

    def scan(self, url: str = None) -> List[Dict]:
        """Analyse security headers on the target URL."""
        target_url = url or self.config.base_url
        logger.info(f"[HEADERS] Analysing security headers on {target_url}")

        resp = make_request(target_url, config=self.config)
        if not resp:
            logger.warning("[HEADERS] Could not reach the target")
            return self.findings

        headers = resp.headers

        # Check for missing security headers
        for header_name, info in SECURITY_HEADERS.items():
            if header_name.lower() not in {k.lower() for k in headers}:
                finding = {
                    "type": "Missing Security Header",
                    "severity": info["severity"],
                    "url": target_url,
                    "header": header_name,
                    "description": info["description"],
                    "recommendation": info["recommendation"],
                }
                self.findings.append(finding)
                logger.info(
                    f"[HEADERS] Missing: {header_name} [{info['severity']}]"
                )

        # Check for dangerous headers that disclose info
        for header_name, info in DANGEROUS_HEADERS.items():
            for resp_header in headers:
                if resp_header.lower() == header_name.lower():
                    finding = {
                        "type": "Information Disclosure Header",
                        "severity": info["severity"],
                        "url": target_url,
                        "header": header_name,
                        "value": headers[resp_header],
                        "description": info["description"],
                        "recommendation": info["recommendation"],
                    }
                    self.findings.append(finding)
                    logger.info(
                        f"[HEADERS] Disclosure: {header_name}: "
                        f"{headers[resp_header]} [{info['severity']}]"
                    )

        # Check cookie security
        self._check_cookies(resp, target_url)

        logger.info(
            f"[HEADERS] Analysis complete. "
            f"{len(self.findings)} issues found."
        )
        return self.findings

    def _check_cookies(self, resp, url: str) -> None:
        """Check cookies for security flags."""
        for cookie in resp.cookies:
            issues = []

            cookie_str = resp.headers.get("set-cookie", "").lower()

            if not cookie.secure:
                issues.append("Missing Secure flag")
            if "httponly" not in cookie_str:
                issues.append("Missing HttpOnly flag")
            if "samesite" not in cookie_str:
                issues.append("Missing SameSite attribute")

            if issues:
                finding = {
                    "type": "Insecure Cookie",
                    "severity": "MEDIUM" if "Secure" in str(issues) else "LOW",
                    "url": url,
                    "cookie_name": cookie.name,
                    "issues": issues,
                    "description": (
                        f"Cookie '{cookie.name}' is missing security attributes: "
                        f"{', '.join(issues)}"
                    ),
                }
                self.findings.append(finding)
                logger.info(
                    f"[HEADERS] Insecure cookie '{cookie.name}': "
                    f"{', '.join(issues)}"
                )