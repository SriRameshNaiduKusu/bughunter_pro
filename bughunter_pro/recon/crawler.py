"""
BugHunter Pro - Web Crawler Module (UPDATED for package imports)
"""

import re
import logging
from typing import Set, List, Dict, Optional
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

from bughunter_pro.config import Config
from bughunter_pro.core.utils import make_request, normalize_url, is_same_domain

logger = logging.getLogger("bughunter")


class WebCrawler:
    """Crawls the target to discover links, forms, and parameters."""

    def __init__(self, config: Config):
        self.config = config
        self.domain = config.target_domain
        self.base_url = config.base_url
        self.visited: Set[str] = set()
        self.links: Set[str] = set()
        self.forms: List[Dict] = []
        self.js_files: Set[str] = set()
        self.parameterized_urls: Set[str] = set()
        self.emails: Set[str] = set()

    def crawl(self) -> Dict:
        """Begin crawling from the base URL."""
        logger.info(f"[CRAWLER] Starting crawl of {self.base_url}")
        self._crawl_recursive(self.base_url, depth=0)

        results = {
            "links": sorted(self.links),
            "forms": self.forms,
            "js_files": sorted(self.js_files),
            "parameterized_urls": sorted(self.parameterized_urls),
            "emails": sorted(self.emails),
            "pages_crawled": len(self.visited),
        }

        logger.info(
            f"[CRAWLER] Crawl complete. "
            f"Pages: {results['pages_crawled']}, "
            f"Links: {len(results['links'])}, "
            f"Forms: {len(results['forms'])}, "
            f"JS files: {len(results['js_files'])}, "
            f"Parameterized URLs: {len(results['parameterized_urls'])}, "
            f"Emails: {len(results['emails'])}"
        )
        return results

    def _crawl_recursive(self, url: str, depth: int) -> None:
        """Recursively crawl pages up to the configured depth."""
        if depth > self.config.max_crawl_depth:
            return
        if len(self.visited) >= self.config.max_crawl_pages:
            return
        if url in self.visited:
            return
        if not is_same_domain(url, self.domain):
            return

        self.visited.add(url)
        resp = make_request(url, config=self.config)
        if not resp:
            return

        content_type = resp.headers.get("content-type", "")
        if "text/html" not in content_type:
            return

        soup = BeautifulSoup(resp.text, "html.parser")

        # Extract links
        for tag in soup.find_all("a", href=True):
            href = normalize_url(tag["href"], url)
            if href:
                self.links.add(href)
                parsed = urlparse(href)
                if parsed.query:
                    self.parameterized_urls.add(href)
                if is_same_domain(href, self.domain) and href not in self.visited:
                    self._crawl_recursive(href, depth + 1)

        # Extract forms
        for form in soup.find_all("form"):
            form_data = self._extract_form(form, url)
            if form_data:
                self.forms.append(form_data)

        # Extract JS files
        for script in soup.find_all("script", src=True):
            js_url = normalize_url(script["src"], url)
            if js_url:
                self.js_files.add(js_url)

        # Extract emails
        email_pattern = r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
        found_emails = re.findall(email_pattern, resp.text)
        self.emails.update(found_emails)

        # Additional URL sources
        for tag in soup.find_all(
            ["link", "img", "source", "video", "audio"], src=True
        ):
            src_url = normalize_url(
                tag.get("src") or tag.get("href"), url
            )
            if src_url:
                self.links.add(src_url)

    def _extract_form(self, form, page_url: str) -> Optional[Dict]:
        """Extract form details (action, method, inputs)."""
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        action_url = normalize_url(action, page_url) if action else page_url

        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            input_data = {
                "name": inp.get("name", ""),
                "type": inp.get("type", "text"),
                "value": inp.get("value", ""),
            }
            if input_data["name"]:
                inputs.append(input_data)

        if not inputs:
            return None

        return {
            "action": action_url,
            "method": method,
            "inputs": inputs,
            "page": page_url,
        }