"""
BugHunter Pro - Directory Brute-Force Module
"""
import logging
from typing import List, Dict, Optional

from bughunter_pro.config import Config
from bughunter_pro.core.utils import make_request, load_wordlist
from bughunter_pro.core.thread_pool import ThreadPoolManager

logger = logging.getLogger("bughunter")

INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}


class DirectoryBruteforcer:
    """Brute-forces directories and files on the target."""

    def __init__(self, config: Config):
        self.config = config
        self.base_url = config.base_url.rstrip("/")
        self.findings: List[Dict] = []
        self.not_found_size: Optional[int] = None

    def scan(self) -> List[Dict]:
        """Run directory brute-force scan."""
        logger.info(
            f"[DIRBRUTE] Starting directory brute-force on {self.base_url}"
        )
        logger.info(
            f"[DIRBRUTE] Wordlist: {self.config.directory_wordlist}"
        )

        self._calibrate_404()

        wordlist_path = self.config.directory_wordlist
        words = load_wordlist(wordlist_path)

        if not words:
            logger.warning(
                f"[DIRBRUTE] Wordlist not found at {wordlist_path}. "
                "Trying fallback..."
            )
            # Try fallback
            import os
            fallback_path = os.path.join(
                self.config.wordlist_dir, "fallback", "directories.txt"
            )
            words = load_wordlist(fallback_path)

        if not words:
            logger.error("[DIRBRUTE] No wordlist available. Skipping.")
            return self.findings

        logger.info(f"[DIRBRUTE] Loaded {len(words)} words")

        pool = ThreadPoolManager(max_workers=self.config.threads)
        pool.run(
            self._check_path, words,
            description="Directory brute-force",
        )

        logger.info(
            f"[DIRBRUTE] Scan complete. "
            f"{len(self.findings)} interesting paths found."
        )
        return self.findings

    def _calibrate_404(self) -> None:
        """Learn 404 response characteristics."""
        dummy = (
            f"{self.base_url}/"
            "bughunterpro_nonexistent_calibration_page_xyz"
        )
        resp = make_request(dummy, config=self.config)
        if resp:
            self.not_found_size = len(resp.text)
            logger.debug(
                f"[DIRBRUTE] 404 calibration: status={resp.status_code}, "
                f"size={self.not_found_size}"
            )

    def _check_path(self, path: str) -> Optional[Dict]:
        """Check a single path."""
        url = f"{self.base_url}/{path.lstrip('/')}"
        resp = make_request(url, config=self.config, allow_redirects=False)

        if not resp:
            return None

        if resp.status_code not in INTERESTING_CODES:
            return None

        if resp.status_code == 200 and self.not_found_size:
            if abs(len(resp.text) - self.not_found_size) < 50:
                return None

        severity = self._classify_severity(resp.status_code, path)

        finding = {
            "type": "Directory/File Discovery",
            "severity": severity,
            "url": url,
            "status_code": resp.status_code,
            "content_length": len(resp.text),
            "content_type": resp.headers.get("content-type", ""),
            "path": path,
        }
        self.findings.append(finding)

        log_level = (
            logging.WARNING
            if severity in ("HIGH", "CRITICAL") else logging.INFO
        )
        logger.log(
            log_level,
            f"[DIRBRUTE] Found: {url} "
            f"[{resp.status_code}] ({len(resp.text)} bytes) [{severity}]"
        )
        return finding

    def _classify_severity(self, status_code: int, path: str) -> str:
        """Classify the severity of a directory finding."""
        critical_paths = [
            ".env", ".git", ".git/HEAD", ".git/config",
            ".svn", ".htpasswd", "wp-config.php",
            "config.php", "database.yml", "secrets.yml",
            "id_rsa", ".ssh",
        ]
        high_paths = [
            "admin", "administrator", "phpmyadmin", "adminer",
            "phpinfo.php", "server-status", "server-info",
            ".htaccess", "debug", "trace", "backup",
            "wp-admin", "console",
        ]
        medium_paths = [
            "robots.txt", "sitemap.xml", ".well-known",
            "swagger", "api/docs", "graphql",
        ]

        path_lower = path.lower()

        if any(p in path_lower for p in critical_paths):
            return "CRITICAL"
        if status_code == 401:
            return "MEDIUM"
        if status_code == 403:
            if any(p in path_lower for p in critical_paths + high_paths):
                return "HIGH"
            return "LOW"
        if any(p in path_lower for p in high_paths):
            return "HIGH"
        if any(p in path_lower for p in medium_paths):
            return "MEDIUM"
        if status_code in (301, 302, 307, 308):
            return "INFO"
        return "LOW"