"""
BugHunter Pro - DNS Enumeration Module
"""

import logging
from typing import Dict, List

import dns.resolver

from config import Config

logger = logging.getLogger("bughunter")

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "CAA"]


class DNSEnumerator:
    """Enumerates DNS records for the target domain."""

    def __init__(self, config: Config):
        self.config = config
        self.domain = config.target_domain

    def enumerate(self) -> Dict[str, List[str]]:
        """Query DNS for various record types."""
        logger.info(f"[DNS] Enumerating DNS records for {self.domain}")
        results: Dict[str, List[str]] = {}

        for rtype in RECORD_TYPES:
            try:
                answers = dns.resolver.resolve(self.domain, rtype)
                records = [str(rdata) for rdata in answers]
                results[rtype] = records
                logger.info(
                    f"[DNS] {rtype}: {len(records)} record(s) found"
                )
            except dns.resolver.NoAnswer:
                logger.debug(f"[DNS] No {rtype} records")
            except dns.resolver.NXDOMAIN:
                logger.warning(f"[DNS] Domain {self.domain} does not exist")
                break
            except dns.resolver.Timeout:
                logger.debug(f"[DNS] Timeout querying {rtype}")
            except Exception as e:
                logger.debug(f"[DNS] Error querying {rtype}: {e}")

        # Check for zone transfer
        self._check_zone_transfer(results)

        return results

    def _check_zone_transfer(self, results: Dict) -> None:
        """Attempt a zone transfer (AXFR) against NS servers."""
        ns_records = results.get("NS", [])
        if not ns_records:
            return

        logger.info("[DNS] Attempting zone transfers...")
        for ns in ns_records:
            ns = ns.rstrip(".")
            try:
                import dns.zone
                import dns.query as dns_query

                zone = dns.zone.from_xfr(
                    dns_query.xfr(ns, self.domain, timeout=10)
                )
                names = zone.nodes.keys()
                records = [str(n) for n in names]
                results["AXFR"] = records
                logger.warning(
                    f"[DNS] Zone transfer SUCCESSFUL on {ns}! "
                    f"({len(records)} records)"
                )
                break
            except Exception:
                logger.debug(f"[DNS] Zone transfer failed on {ns}")