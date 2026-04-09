"""
BugHunter Pro - CRLF Injection Scanner
"""

import logging
from typing import List, Dict, Optional

from bughunter_pro.config import Config
from bughunter_pro.core.utils import make_request, inject_payload_into_url, extract_params_from_url
from bughunter_pro.core.thread_pool import ThreadPoolManager

logger = logging.getLogger("bughunter")


class CRLFScanner:
    """Scans for CRLF injection vulnerabilities."""

    def __init__(self, config: Config):
        self.config = config
        self.findings: List[Dict] = []

    def scan_urls(self, urls: List[str]) -> List[Dict]:
        """Scan parameterized URLs for CRLF injection."""
        logger.info(f"[CRLF] Scanning {len(urls)} URLs for CRLF injection")

        tasks = []
        for url in urls:
            params = extract_params_from_url(url)
            for param_name in params:
                for payload in self.config.crlf_payloads:
                    tasks.append((url, param_name, payload))

        if not tasks:
            logger.info("[CRLF] No parameterized URLs to scan")
            return self.findings

        pool = ThreadPoolManager(max_workers=self.config.threads)
        pool.run(
            lambda task: self._test_crlf(*task),
            tasks,
            description="CRLF scan",
        )

        logger.info(
            f"[CRLF] Scan complete. "
            f"{len(self.findings)} potential issues found."
        )
        return self.findings

    def _test_crlf(self, url: str, param: str,
                   payload: str) -> Optional[Dict]:
        """Test a single parameter for CRLF injection."""
        test_url = inject_payload_into_url(url, param, payload)
        resp = make_request(
            test_url, config=self.config, allow_redirects=False,
        )

        if not resp:
            return None

        # Check if injected header appears in response headers
        for header_name, header_value in resp.headers.items():
            if "crlf=injection" in header_value.lower():
                finding = {
                    "type": "CRLF Injection",
                    "severity": "HIGH",
                    "url": test_url,
                    "parameter": param,
                    "payload": payload,
                    "evidence": f"Injected header found: {header_name}: {header_value}",
                    "method": "GET",
                }
                self.findings.append(finding)
                logger.warning(
                    f"[CRLF] POTENTIAL CRLF injection! "
                    f"URL: {url}, Param: {param}"
                )
                return finding

        # Also check for header injection in response body (reflected)
        if resp.text and "Set-Cookie:crlf=injection" in resp.text:
            finding = {
                "type": "CRLF Injection (Reflected)",
                "severity": "MEDIUM",
                "url": test_url,
                "parameter": param,
                "payload": payload,
                "evidence": "CRLF payload reflected in response body",
                "method": "GET",
            }
            self.findings.append(finding)
            logger.warning(
                f"[CRLF] POTENTIAL CRLF reflection! "
                f"URL: {url}, Param: {param}"
            )
            return finding

        return None