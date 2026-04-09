"""
BugHunter Pro - Subdomain Enumeration Module (UPDATED for package imports)
"""

import json
import logging
import dns.resolver
from typing import List, Set

from bughunter_pro.config import Config
from bughunter_pro.core.utils import load_wordlist, make_request
from bughunter_pro.core.thread_pool import ThreadPoolManager
from bughunter_pro.installer import generate_fallback_wordlists, WORDLIST_DIR

logger = logging.getLogger("bughunter")


class SubdomainEnumerator:
    """Discovers subdomains for a target domain."""

    def __init__(self, config: Config):
        self.config = config
        self.domain = config.target_domain
        self.found: Set[str] = set()

    def enumerate(self) -> List[str]:
        """Run all subdomain enumeration techniques."""
        logger.info(f"[SUBDOMAIN] Starting enumeration for {self.domain}")
        logger.info(f"[SUBDOMAIN] Wordlist: {self.config.subdomain_wordlist}")

        self._crtsh_enum()
        self._threatcrowd_enum()
        self._dns_bruteforce()

        sorted_results = sorted(self.found)
        logger.info(
            f"[SUBDOMAIN] Enumeration complete. "
            f"Found {len(sorted_results)} unique subdomains."
        )
        return sorted_results

    def _crtsh_enum(self) -> None:
        """Query crt.sh for certificate transparency logs."""
        logger.info("[SUBDOMAIN] Querying crt.sh...")
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        resp = make_request(url, config=self.config, timeout=30)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(self.domain) and "*" not in sub:
                            self.found.add(sub)
                logger.info(
                    f"[SUBDOMAIN] crt.sh returned {len(data)} entries"
                )
            except (json.JSONDecodeError, KeyError) as e:
                logger.debug(f"[SUBDOMAIN] crt.sh parse error: {e}")
        else:
            logger.warning("[SUBDOMAIN] crt.sh query failed or timed out")

    def _threatcrowd_enum(self) -> None:
        """Query ThreatCrowd API."""
        logger.info("[SUBDOMAIN] Querying ThreatCrowd...")
        url = (
            f"https://www.threatcrowd.org/searchApi/v2/domain/report/"
            f"?domain={self.domain}"
        )
        resp = make_request(url, config=self.config, timeout=20)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                subdomains = data.get("subdomains", [])
                for sub in subdomains:
                    sub = sub.strip().lower()
                    if sub.endswith(self.domain):
                        self.found.add(sub)
                logger.info(
                    f"[SUBDOMAIN] ThreatCrowd returned "
                    f"{len(subdomains)} entries"
                )
            except (json.JSONDecodeError, KeyError) as e:
                logger.debug(f"[SUBDOMAIN] ThreatCrowd parse error: {e}")
        else:
            logger.debug("[SUBDOMAIN] ThreatCrowd query failed")

    def _dns_bruteforce(self) -> None:
        """Brute-force subdomains using a wordlist and DNS resolution."""
        logger.info("[SUBDOMAIN] Starting DNS brute-force...")

        wordlist_path = self.config.subdomain_wordlist
        words = load_wordlist(wordlist_path)

        if not words:
            logger.warning(
                f"[SUBDOMAIN] Wordlist not found at {wordlist_path}. "
                "Generating fallback..."
            )
            try:
                generate_fallback_wordlists(
                    logging.getLogger("bughunter_installer")
                )
            except Exception:
                pass
            # Try fallback path
            import os
            fallback_path = os.path.join(
                str(WORDLIST_DIR), "fallback", "subdomains.txt"
            )
            words = load_wordlist(fallback_path)

        if not words:
            logger.error("[SUBDOMAIN] No wordlist available. Skipping brute-force.")
            return

        logger.info(f"[SUBDOMAIN] Loaded {len(words)} words from wordlist")

        pool = ThreadPoolManager(max_workers=self.config.threads)

        def resolve(word):
            subdomain = f"{word}.{self.domain}"
            try:
                dns.resolver.resolve(subdomain, "A")
                return subdomain
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.NoNameservers,
                dns.resolver.Timeout,
                Exception,
            ):
                return None

        results = pool.run(
            resolve, words, description="DNS brute-force"
        )
        for sub in results:
            self.found.add(sub)
        logger.info(
            f"[SUBDOMAIN] DNS brute-force found {len(results)} subdomains"
        )