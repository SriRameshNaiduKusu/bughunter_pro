"""
BugHunter Pro - Cloud Storage Misconfiguration Scanner

Checks for publicly accessible S3 buckets, Azure blobs,
and GCP storage buckets.
"""

import logging
import xml.etree.ElementTree as ET
from typing import List, Dict

from config import Config
from core.utils import make_request, get_base_domain
from core.thread_pool import ThreadPoolManager

logger = logging.getLogger("bughunter")


class CloudMisconfigScanner:
    """Scans for misconfigured cloud storage buckets."""

    def __init__(self, config: Config):
        self.config = config
        self.domain = config.target_domain
        self.findings: List[Dict] = []

    def scan(self) -> List[Dict]:
        """Run all cloud misconfiguration checks."""
        logger.info("[CLOUD] Starting cloud storage misconfiguration scan")

        self._scan_s3_buckets()
        self._scan_azure_blobs()
        self._scan_gcp_buckets()

        logger.info(
            f"[CLOUD] Scan complete. "
            f"{len(self.findings)} misconfigured buckets found."
        )
        return self.findings

    def _generate_bucket_names(self) -> List[str]:
        """Generate potential bucket names based on the target domain."""
        base = get_base_domain(self.domain).split(".")[0]
        names = set()

        for pattern in self.config.s3_bucket_patterns:
            names.add(pattern.format(domain=base))
            names.add(pattern.format(domain=self.domain.replace(".", "-")))
            names.add(pattern.format(domain=self.domain.replace(".", "")))

        return sorted(names)

    def _scan_s3_buckets(self) -> None:
        """Check for publicly accessible AWS S3 buckets."""
        logger.info("[CLOUD] Scanning for S3 bucket misconfigurations...")
        bucket_names = self._generate_bucket_names()

        pool = ThreadPoolManager(max_workers=self.config.threads)
        pool.run(
            self._check_s3_bucket, bucket_names,
            description="S3 bucket scan",
        )

    def _check_s3_bucket(self, name: str) -> Dict | None:
        """Check a single S3 bucket for public access."""
        urls = [
            f"https://{name}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{name}",
        ]

        for url in urls:
            resp = make_request(url, config=self.config, timeout=8)
            if not resp:
                continue

            if resp.status_code == 200:
                # Bucket is publicly listable
                finding = {
                    "type": "Cloud Misconfiguration - S3 Public Listing",
                    "severity": "HIGH",
                    "url": url,
                    "bucket_name": name,
                    "evidence": "Bucket returns 200 and lists contents",
                    "details": self._parse_s3_listing(resp.text),
                }
                self.findings.append(finding)
                logger.warning(
                    f"[CLOUD] PUBLIC S3 bucket found: {url}"
                )
                return finding

            elif resp.status_code == 403:
                # Bucket exists but not listable — check for write access
                finding = {
                    "type": "Cloud Misconfiguration - S3 Bucket Exists",
                    "severity": "LOW",
                    "url": url,
                    "bucket_name": name,
                    "evidence": "Bucket exists (403 Forbidden)",
                }
                self.findings.append(finding)
                logger.info(f"[CLOUD] S3 bucket exists (403): {name}")
                return finding

        return None

    def _parse_s3_listing(self, xml_body: str) -> List[str]:
        """Parse S3 XML listing for file keys."""
        files = []
        try:
            root = ET.fromstring(xml_body)
            ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
            for contents in root.findall(".//s3:Contents", ns):
                key = contents.find("s3:Key", ns)
                size = contents.find("s3:Size", ns)
                if key is not None:
                    entry = key.text
                    if size is not None:
                        entry += f" ({size.text} bytes)"
                    files.append(entry)
        except ET.ParseError:
            pass
        # Also try without namespace
        if not files:
            try:
                root = ET.fromstring(xml_body)
                for contents in root.findall(".//Contents"):
                    key = contents.find("Key")
                    if key is not None:
                        files.append(key.text)
            except ET.ParseError:
                pass
        return files[:50]  # Limit output

    def _scan_azure_blobs(self) -> None:
        """Check for publicly accessible Azure Blob Storage."""
        logger.info("[CLOUD] Scanning for Azure Blob misconfigurations...")
        base = get_base_domain(self.domain).split(".")[0]
        containers = ["public", "data", "files", "uploads", "assets",
                       "backup", "media", "images", "static", "content"]

        for container in containers:
            url = (
                f"https://{base}.blob.core.windows.net/"
                f"{container}?restype=container&comp=list"
            )
            resp = make_request(url, config=self.config, timeout=8)
            if resp and resp.status_code == 200:
                finding = {
                    "type": "Cloud Misconfiguration - Azure Blob Public Listing",
                    "severity": "HIGH",
                    "url": url,
                    "container_name": container,
                    "evidence": "Container returns 200 with listing",
                }
                self.findings.append(finding)
                logger.warning(f"[CLOUD] PUBLIC Azure Blob: {url}")

    def _scan_gcp_buckets(self) -> None:
        """Check for publicly accessible GCP Storage buckets."""
        logger.info("[CLOUD] Scanning for GCP bucket misconfigurations...")
        bucket_names = self._generate_bucket_names()

        for name in bucket_names:
            url = f"https://storage.googleapis.com/{name}"
            resp = make_request(url, config=self.config, timeout=8)
            if resp and resp.status_code == 200:
                finding = {
                    "type": "Cloud Misconfiguration - GCP Bucket Public Listing",
                    "severity": "HIGH",
                    "url": url,
                    "bucket_name": name,
                    "evidence": "Bucket returns 200 and lists contents",
                }
                self.findings.append(finding)
                logger.warning(f"[CLOUD] PUBLIC GCP bucket: {url}")