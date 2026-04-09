"""
BugHunter Pro - API Endpoint Brute-Force Module
"""

import json
import logging
from typing import List, Dict, Optional

from config import Config
from core.utils import make_request, load_wordlist, generate_default_wordlist
from core.thread_pool import ThreadPoolManager

logger = logging.getLogger("bughunter")


class APIBruteforcer:
    """Discovers API endpoints through brute-forcing."""

    def __init__(self, config: Config):
        self.config = config
        self.base_url = config.base_url.rstrip("/")
        self.findings: List[Dict] = []

    def scan(self) -> List[Dict]:
        """Run API endpoint discovery."""
        logger.info(f"[API] Starting API endpoint brute-force on {self.base_url}")

        wordlist_path = self.config.api_wordlist
        words = load_wordlist(wordlist_path)
        if not words:
            logger.warning(
                f"[API] Wordlist not found at {wordlist_path}. "
                "Generating default..."
            )
            generate_default_wordlist(wordlist_path, "api_endpoints")
            words = load_wordlist(wordlist_path)

        pool = ThreadPoolManager(max_workers=self.config.threads)
        pool.run(
            self._check_endpoint, words,
            description="API brute-force",
        )

        logger.info(
            f"[API] Scan complete. "
            f"{len(self.findings)} API endpoints found."
        )
        return self.findings

    def _check_endpoint(self, path: str) -> Optional[Dict]:
        """Check a single API endpoint."""
        url = f"{self.base_url}/{path.lstrip('/')}"

        # Try GET request
        resp = make_request(
            url, config=self.config,
            headers={"Accept": "application/json"},
            allow_redirects=False,
        )

        if not resp:
            return None

        if resp.status_code in (404, 502, 503):
            return None

        is_json = self._is_json_response(resp)
        auth_required = resp.status_code in (401, 403)
        method_not_allowed = resp.status_code == 405

        finding = {
            "type": "API Endpoint Discovery",
            "severity": self._classify_severity(
                resp.status_code, path, auth_required
            ),
            "url": url,
            "status_code": resp.status_code,
            "content_type": resp.headers.get("content-type", ""),
            "is_json": is_json,
            "auth_required": auth_required,
            "content_length": len(resp.text),
            "path": path,
            "allowed_methods": [],
        }

        # If method not allowed or interesting, check OPTIONS
        if method_not_allowed or resp.status_code in (200, 201, 401, 403):
            allowed = self._check_options(url)
            finding["allowed_methods"] = allowed

        self.findings.append(finding)
        logger.info(
            f"[API] Found: {url} [{resp.status_code}] "
            f"JSON={is_json} Auth={auth_required}"
        )
        return finding

    def _check_options(self, url: str) -> List[str]:
        """Send an OPTIONS request to discover allowed HTTP methods."""
        resp = make_request(url, method="OPTIONS", config=self.config)
        if resp:
            allow = resp.headers.get("allow", "")
            if allow:
                return [m.strip().upper() for m in allow.split(",")]
            # Try Access-Control-Allow-Methods
            acam = resp.headers.get("access-control-allow-methods", "")
            if acam:
                return [m.strip().upper() for m in acam.split(",")]
        return []

    def _is_json_response(self, resp) -> bool:
        """Check if response is JSON."""
        ct = resp.headers.get("content-type", "")
        if "json" in ct:
            return True
        try:
            json.loads(resp.text)
            return True
        except (json.JSONDecodeError, ValueError):
            return False

    def _classify_severity(self, status_code: int, path: str,
                           auth_required: bool) -> str:
        """Classify severity of an API endpoint finding."""
        sensitive_paths = [
            "admin", "internal", "private", "debug",
            "config", "settings", "swagger", "graphql",
            "test", "staging",
        ]
        path_lower = path.lower()

        if any(s in path_lower for s in sensitive_paths):
            if not auth_required:
                return "HIGH"
            return "MEDIUM"
        if status_code == 200 and not auth_required:
            return "MEDIUM"
        if auth_required:
            return "LOW"
        return "INFO"