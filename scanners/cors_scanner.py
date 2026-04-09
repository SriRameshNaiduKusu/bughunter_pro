"""
BugHunter Pro - CORS Misconfiguration Scanner
"""

import logging
from typing import List, Dict

from config import Config
from core.utils import make_request

logger = logging.getLogger("bughunter")

TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://{domain}.evil.com",
    "https://evil{domain}",
    "https://{domain}evil.com",
]


class CORSScanner:
    """Scans for CORS misconfiguration vulnerabilities."""

    def __init__(self, config: Config):
        self.config = config
        self.domain = config.target_domain
        self.findings: List[Dict] = []

    def scan(self, urls: List[str]) -> List[Dict]:
        """Scan a list of URLs for CORS misconfigurations."""
        logger.info(f"[CORS] Scanning {len(urls)} URLs for CORS misconfigurations")

        # Deduplicate to unique origins (scheme + host)
        seen_origins = set()
        unique_urls = []
        for url in urls:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            origin_key = f"{parsed.scheme}://{parsed.netloc}"
            if origin_key not in seen_origins:
                seen_origins.add(origin_key)
                unique_urls.append(url)

        for url in unique_urls[:50]:  # Limit checks
            self._test_cors(url)

        logger.info(
            f"[CORS] Scan complete. "
            f"{len(self.findings)} misconfigurations found."
        )
        return self.findings

    def _test_cors(self, url: str) -> None:
        """Test a single URL for CORS misconfigurations."""
        for origin_template in TEST_ORIGINS:
            origin = origin_template.replace("{domain}", self.domain)

            resp = make_request(
                url,
                config=self.config,
                headers={"Origin": origin},
            )
            if not resp:
                continue

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if not acao:
                continue

            # Wildcard with credentials is a vulnerability
            if acao == "*" and acac.lower() == "true":
                self._add_finding(url, origin, acao, acac, "CRITICAL",
                                  "Wildcard origin with credentials allowed")
                return

            # Reflected arbitrary origin
            if acao == origin and origin not in ("null",):
                severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
                self._add_finding(url, origin, acao, acac, severity,
                                  "Arbitrary origin reflected")
                return

            # Null origin accepted
            if acao == "null" and origin == "null":
                severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
                self._add_finding(url, origin, acao, acac, severity,
                                  "Null origin accepted")
                return

            # Wildcard (without credentials)
            if acao == "*":
                self._add_finding(url, origin, acao, acac, "LOW",
                                  "Wildcard origin (no credentials)")
                return

    def _add_finding(self, url: str, origin: str, acao: str,
                     acac: str, severity: str, description: str) -> None:
        """Record a CORS misconfiguration finding."""
        finding = {
            "type": "CORS Misconfiguration",
            "severity": severity,
            "url": url,
            "test_origin": origin,
            "access_control_allow_origin": acao,
            "access_control_allow_credentials": acac,
            "description": description,
        }
        self.findings.append(finding)
        logger.warning(
            f"[CORS] {severity}: {description} on {url} "
            f"(Origin: {origin}, ACAO: {acao}, ACAC: {acac})"
        )