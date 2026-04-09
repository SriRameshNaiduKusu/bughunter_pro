"""
BugHunter Pro - XSS Scanner (UPDATED imports)
"""

import re
import logging
from typing import List, Dict, Optional

from bughunter_pro.config import Config
from bughunter_pro.core.utils import (
    make_request, inject_payload_into_url, extract_params_from_url,
)
from bughunter_pro.core.thread_pool import ThreadPoolManager

logger = logging.getLogger("bughunter")


class XSSScanner:
    """Scans for reflected XSS vulnerabilities."""

    def __init__(self, config: Config):
        self.config = config
        self.findings: List[Dict] = []

    def scan_urls(self, urls: List[str]) -> List[Dict]:
        """Scan parameterized URLs for reflected XSS."""
        logger.info(f"[XSS] Scanning {len(urls)} parameterized URLs")

        tasks = []
        for url in urls:
            params = extract_params_from_url(url)
            for param_name in params:
                for payload in self.config.xss_payloads:
                    tasks.append((url, param_name, payload))

        pool = ThreadPoolManager(max_workers=self.config.threads)
        pool.run(
            lambda task: self._test_url_param(*task),
            tasks,
            description="XSS URL scan",
        )

        logger.info(f"[XSS] URL scan complete. {len(self.findings)} potential issues found.")
        return self.findings

    def scan_forms(self, forms: List[Dict]) -> List[Dict]:
        """Scan forms for reflected XSS."""
        logger.info(f"[XSS] Scanning {len(forms)} forms")

        for form in forms:
            self._test_form(form)

        logger.info(f"[XSS] Form scan complete. {len(self.findings)} total issues.")
        return self.findings

    def _test_url_param(self, url: str, param: str, payload: str) -> Optional[Dict]:
        """Test a URL parameter for reflected XSS."""
        test_url = inject_payload_into_url(url, param, payload)
        resp = make_request(test_url, config=self.config)

        if resp and self._check_xss_reflection(resp.text, payload):
            finding = {
                "type": "Cross-Site Scripting (XSS)",
                "severity": "HIGH",
                "url": test_url,
                "parameter": param,
                "payload": payload,
                "evidence": f"Payload reflected in response body",
                "method": "GET",
            }
            self.findings.append(finding)
            logger.warning(
                f"[XSS] POTENTIAL XSS found! URL: {url}, "
                f"Param: {param}"
            )
            return finding
        return None

    def _test_form(self, form: Dict) -> None:
        """Test a form for reflected XSS."""
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        for target_input in inputs:
            if target_input["type"] in ("submit", "button", "hidden"):
                continue

            for payload in self.config.xss_payloads:
                form_data = {}
                for inp in inputs:
                    if inp["name"] == target_input["name"]:
                        form_data[inp["name"]] = payload
                    else:
                        form_data[inp["name"]] = inp["value"] or "test"

                if method == "POST":
                    resp = make_request(
                        action, method="POST", data=form_data,
                        config=self.config,
                    )
                else:
                    resp = make_request(
                        action, params=form_data, config=self.config,
                    )

                if resp and self._check_xss_reflection(resp.text, payload):
                    finding = {
                        "type": "Cross-Site Scripting (XSS)",
                        "severity": "HIGH",
                        "url": action,
                        "parameter": target_input["name"],
                        "payload": payload,
                        "evidence": "Payload reflected in response body",
                        "method": method,
                        "form_page": form.get("page", ""),
                    }
                    self.findings.append(finding)
                    logger.warning(
                        f"[XSS] POTENTIAL XSS in form! "
                        f"Action: {action}, Input: {target_input['name']}"
                    )
                    break

    def _check_xss_reflection(self, body: str, payload: str) -> bool:
        """Check if the XSS payload is reflected unescaped in the response."""
        if not body:
            return False
        # Direct reflection
        if payload in body:
            return True
        # Check for partial reflection of dangerous tags
        dangerous_patterns = [
            r"<script", r"<img\s", r"<svg\s", r"<iframe\s",
            r"onerror\s*=", r"onload\s*=", r"ontoggle\s*=",
            r"onstart\s*=", r"javascript:",
        ]
        payload_lower = payload.lower()
        body_lower = body.lower()
        if payload_lower in body_lower:
            return True
        return False