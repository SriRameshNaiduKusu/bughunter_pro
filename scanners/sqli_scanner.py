"""
BugHunter Pro - SQL Injection Scanner Module

Tests URL parameters and form inputs for SQL injection indicators.
"""

import re
import logging
from typing import List, Dict, Optional

from config import Config
from core.utils import make_request, inject_payload_into_url, extract_params_from_url
from core.thread_pool import ThreadPoolManager

logger = logging.getLogger("bughunter")

SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"microsoft ole db provider for sql server",
    r"ora-\d{5}",
    r"pg_query\(\)",
    r"pg_exec\(\)",
    r"syntax error.*postgresql",
    r"sqlite3\.OperationalError",
    r"sqlite.*error",
    r"jdbc\.sqlserver",
    r"com\.mysql\.jdbc",
    r"MariaDB server version",
    r"mysqlclient",
    r"SQL syntax.*?MySQL",
    r"valid MySQL result",
    r"SQL Server.*Driver",
    r"ODBC SQL Server Driver",
    r"SQLServer JDBC Driver",
    r"Oracle error",
    r"Oracle.*Driver",
    r"DB2 SQL error",
    r"dynamic SQL error",
    r"Sybase message",
]


class SQLiScanner:
    """Scans for SQL injection vulnerabilities."""

    def __init__(self, config: Config):
        self.config = config
        self.findings: List[Dict] = []

    def scan_urls(self, urls: List[str]) -> List[Dict]:
        """Scan a list of parameterized URLs for SQLi."""
        logger.info(f"[SQLi] Scanning {len(urls)} parameterized URLs")

        tasks = []
        for url in urls:
            params = extract_params_from_url(url)
            for param_name in params:
                for payload in self.config.sqli_payloads:
                    tasks.append((url, param_name, payload))

        pool = ThreadPoolManager(max_workers=self.config.threads)
        pool.run(
            lambda task: self._test_url_param(*task),
            tasks,
            description="SQLi URL scan",
        )

        logger.info(f"[SQLi] URL scan complete. {len(self.findings)} potential issues found.")
        return self.findings

    def scan_forms(self, forms: List[Dict]) -> List[Dict]:
        """Scan discovered forms for SQLi."""
        logger.info(f"[SQLi] Scanning {len(forms)} forms")

        for form in forms:
            self._test_form(form)

        logger.info(f"[SQLi] Form scan complete. {len(self.findings)} total issues.")
        return self.findings

    def _test_url_param(self, url: str, param: str, payload: str) -> Optional[Dict]:
        """Test a single URL parameter with a single payload."""
        test_url = inject_payload_into_url(url, param, payload)
        resp = make_request(test_url, config=self.config)

        if resp and self._check_sqli_response(resp.text):
            finding = {
                "type": "SQL Injection",
                "severity": "HIGH",
                "url": test_url,
                "parameter": param,
                "payload": payload,
                "evidence": self._extract_error(resp.text),
                "method": "GET",
            }
            self.findings.append(finding)
            logger.warning(
                f"[SQLi] POTENTIAL SQLi found! URL: {url}, "
                f"Param: {param}, Payload: {payload}"
            )
            return finding
        return None

    def _test_form(self, form: Dict) -> None:
        """Test a form's inputs for SQLi."""
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        for target_input in inputs:
            if target_input["type"] in ("submit", "button", "hidden", "checkbox", "radio"):
                continue

            for payload in self.config.sqli_payloads:
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

                if resp and self._check_sqli_response(resp.text):
                    finding = {
                        "type": "SQL Injection",
                        "severity": "HIGH",
                        "url": action,
                        "parameter": target_input["name"],
                        "payload": payload,
                        "evidence": self._extract_error(resp.text),
                        "method": method,
                        "form_page": form.get("page", ""),
                    }
                    self.findings.append(finding)
                    logger.warning(
                        f"[SQLi] POTENTIAL SQLi in form! "
                        f"Action: {action}, Input: {target_input['name']}"
                    )
                    break  # Move to next input

    def _check_sqli_response(self, body: str) -> bool:
        """Check if the response body contains SQL error patterns."""
        if not body:
            return False
        for pattern in SQL_ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                return True
        return False

    def _extract_error(self, body: str) -> str:
        """Extract the matching SQL error snippet."""
        for pattern in SQL_ERROR_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 50)
                end = min(len(body), match.end() + 50)
                return body[start:end].strip()
        return ""