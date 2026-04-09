"""
BugHunter Pro - SSRF Scanner (UPDATED imports)
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

SSRF_PARAM_KEYWORDS = [
    "url", "uri", "path", "dest", "redirect", "return",
    "next", "target", "rurl", "page", "feed", "host",
    "site", "html", "data", "reference", "ref", "callback",
    "link", "navigate", "open", "domain", "load", "file",
    "val", "image", "img", "src", "source",
]

# Indicators in the response that SSRF worked
SSRF_INDICATORS = [
    r"ami-id",  # AWS metadata
    r"instance-id",
    r"local-hostname",
    r"public-hostname",
    r"iam/security-credentials",
    r"computeMetadata",  # GCP
    r"root:.*:0:0:",  # /etc/passwd
    r"localhost",
    r"127\.0\.0\.1",
    r"0\.0\.0\.0",
    r"Connection refused",
    r"No route to host",
    r"SSH-2\.0",
]


class SSRFScanner:
    """Scans for Server-Side Request Forgery vulnerabilities."""

    def __init__(self, config: Config):
        self.config = config
        self.findings: List[Dict] = []

    def scan_urls(self, urls: List[str]) -> List[Dict]:
        """Scan parameterized URLs for SSRF."""
        logger.info(f"[SSRF] Scanning {len(urls)} parameterized URLs")

        tasks = []
        for url in urls:
            params = extract_params_from_url(url)
            for param_name in params:
                # Focus on parameters with SSRF-relevant names
                if any(kw in param_name.lower() for kw in SSRF_PARAM_KEYWORDS):
                    for payload in self.config.ssrf_payloads:
                        tasks.append((url, param_name, payload))

        if not tasks:
            logger.info("[SSRF] No SSRF-candidate parameters found")
            return self.findings

        pool = ThreadPoolManager(max_workers=self.config.threads)
        pool.run(
                lambda task: self._test_url_param(*task),
                tasks,
                description="SSRF URL scan",
            )

        logger.info(f"[SSRF] Scan complete. {len(self.findings)} potential issues found.")
        return self.findings

    def scan_forms(self, forms: List[Dict]) -> List[Dict]:
            """Scan forms for SSRF in relevant input fields."""
            logger.info(f"[SSRF] Scanning {len(forms)} forms")

            for form in forms:
                self._test_form(form)

            logger.info(f"[SSRF] Form scan complete. {len(self.findings)} total issues.")
            return self.findings

    def _test_url_param(self, url: str, param: str, payload: str) -> Optional[Dict]:
            """Test a single URL parameter with an SSRF payload."""
            test_url = inject_payload_into_url(url, param, payload)
            resp = make_request(test_url, config=self.config, timeout=15)

            if resp and self._check_ssrf_response(resp):
                finding = {
                    "type": "Server-Side Request Forgery (SSRF)",
                    "severity": "CRITICAL",
                    "url": test_url,
                    "parameter": param,
                    "payload": payload,
                    "evidence": self._extract_evidence(resp.text),
                    "method": "GET",
                    "status_code": resp.status_code,
                }
                self.findings.append(finding)
                logger.warning(
                    f"[SSRF] POTENTIAL SSRF found! URL: {url}, "
                    f"Param: {param}, Payload: {payload}"
                )
                return finding
            return None

    def _test_form(self, form: Dict) -> None:
            """Test form inputs for SSRF."""
            action = form["action"]
            method = form["method"]
            inputs = form["inputs"]

            for target_input in inputs:
                input_name = target_input["name"].lower()
                if not any(kw in input_name for kw in SSRF_PARAM_KEYWORDS):
                    continue

                for payload in self.config.ssrf_payloads:
                    form_data = {}
                    for inp in inputs:
                        if inp["name"] == target_input["name"]:
                            form_data[inp["name"]] = payload
                        else:
                            form_data[inp["name"]] = inp["value"] or "test"

                    if method == "POST":
                        resp = make_request(
                            action, method="POST", data=form_data,
                            config=self.config, timeout=15,
                        )
                    else:
                        resp = make_request(
                            action, params=form_data,
                            config=self.config, timeout=15,
                        )

                    if resp and self._check_ssrf_response(resp):
                        finding = {
                            "type": "Server-Side Request Forgery (SSRF)",
                            "severity": "CRITICAL",
                            "url": action,
                            "parameter": target_input["name"],
                            "payload": payload,
                            "evidence": self._extract_evidence(resp.text),
                            "method": method,
                            "form_page": form.get("page", ""),
                            "status_code": resp.status_code,
                        }
                        self.findings.append(finding)
                        logger.warning(
                            f"[SSRF] POTENTIAL SSRF in form! "
                            f"Action: {action}, Input: {target_input['name']}"
                        )
                        break

    def _check_ssrf_response(self, resp) -> bool:
            """Analyse response for SSRF indicators."""
            if not resp:
                return False

            body = resp.text or ""
            for pattern in SSRF_INDICATORS:
                if re.search(pattern, body, re.IGNORECASE):
                    return True

            # Check if response differs significantly (e.g. internal page returned)
            content_length = len(body)
            if content_length > 0 and resp.status_code == 200:
                # Look for signs of an internal service response
                internal_markers = [
                    "<!DOCTYPE", "<html", "Apache", "nginx",
                    "IIS", "404", "Index of /",
                ]
                for marker in internal_markers:
                    if marker.lower() in body.lower()[:500]:
                        # Additional heuristic: check if different from normal error
                        return False  # Too many false positives, keep strict

            return False

    def _extract_evidence(self, body: str) -> str:
            """Extract matching evidence from response body."""
            if not body:
                return ""
            for pattern in SSRF_INDICATORS:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    start = max(0, match.start() - 40)
                    end = min(len(body), match.end() + 40)
                    return body[start:end].strip()
            return ""