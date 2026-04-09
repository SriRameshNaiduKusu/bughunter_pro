"""
BugHunter Pro - Open Redirect Scanner
"""

import logging
from typing import List, Dict, Optional
from urllib.parse import urlparse

from config import Config
from core.utils import (
    make_request, inject_payload_into_url,
    extract_params_from_url,
)
from core.thread_pool import ThreadPoolManager

logger = logging.getLogger("bughunter")

REDIRECT_PARAM_KEYWORDS = [
    "url", "uri", "redirect", "return", "next", "target",
    "rurl", "dest", "destination", "redir", "redirect_url",
    "redirect_uri", "return_url", "return_to", "returnTo",
    "go", "goto", "link", "forward", "continue", "checkout_url",
    "login_url", "image_url", "callback", "out", "view",
]


class OpenRedirectScanner:
    """Scans for open redirect vulnerabilities."""

    def __init__(self, config: Config):
        self.config = config
        self.findings: List[Dict] = []

    def scan_urls(self, urls: List[str]) -> List[Dict]:
        """Scan parameterized URLs for open redirects."""
        logger.info(f"[REDIRECT] Scanning {len(urls)} URLs for open redirects")

        tasks = []
        for url in urls:
            params = extract_params_from_url(url)
            for param_name in params:
                if any(kw in param_name.lower() for kw in REDIRECT_PARAM_KEYWORDS):
                    for payload in self.config.open_redirect_payloads:
                        tasks.append((url, param_name, payload))

        if not tasks:
            logger.info("[REDIRECT] No redirect-candidate parameters found")
            return self.findings

        pool = ThreadPoolManager(max_workers=self.config.threads)
        pool.run(
            lambda task: self._test_redirect(*task),
            tasks,
            description="Open redirect scan",
        )

        logger.info(
            f"[REDIRECT] Scan complete. "
            f"{len(self.findings)} potential open redirects found."
        )
        return self.findings

    def _test_redirect(self, url: str, param: str,
                       payload: str) -> Optional[Dict]:
        """Test a single parameter for open redirect."""
        test_url = inject_payload_into_url(url, param, payload)
        resp = make_request(
            test_url, config=self.config, allow_redirects=False,
        )

        if not resp:
            return None

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            if self._is_external_redirect(location):
                finding = {
                    "type": "Open Redirect",
                    "severity": "MEDIUM",
                    "url": test_url,
                    "parameter": param,
                    "payload": payload,
                    "redirect_location": location,
                    "status_code": resp.status_code,
                }
                self.findings.append(finding)
                logger.warning(
                    f"[REDIRECT] POTENTIAL open redirect! "
                    f"URL: {url}, Param: {param}, "
                    f"Redirects to: {location}"
                )
                return finding

        return None

    def _is_external_redirect(self, location: str) -> bool:
        """Check if the redirect location points to an external domain."""
        if not location:
            return False
        try:
            parsed = urlparse(location)
            if parsed.hostname:
                return not parsed.hostname.endswith(
                    self.config.target_domain
                )
            # Protocol-relative URLs like //evil.com
            if location.startswith("//"):
                return True
        except Exception:
            pass
        return False