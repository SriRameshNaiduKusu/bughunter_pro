"""
BugHunter Pro - WHOIS Lookup Module (UPDATED for package imports)
"""

import logging
from typing import Dict, Optional

from bughunter_pro.config import Config

logger = logging.getLogger("bughunter")


class WhoisLookup:
    """Performs WHOIS lookups on the target domain."""

    def __init__(self, config: Config):
        self.config = config
        self.domain = config.target_domain

    def lookup(self) -> Optional[Dict]:
        """Execute a WHOIS query and return structured data."""
        logger.info(f"[WHOIS] Looking up {self.domain}")

        try:
            import whois
        except ImportError:
            logger.warning("[WHOIS] python-whois not installed. Skipping.")
            return None

        try:
            w = whois.whois(self.domain)
            result = {
                "domain_name": self._normalize(w.domain_name),
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "updated_date": str(w.updated_date),
                "name_servers": self._normalize(w.name_servers),
                "status": self._normalize(w.status),
                "registrant": w.get("registrant_name") or w.get("name"),
                "org": w.get("org"),
                "country": w.get("country"),
                "emails": self._normalize(w.emails),
            }
            logger.info(
                f"[WHOIS] Registrar: {result['registrar']}, "
                f"Created: {result['creation_date']}"
            )
            return result
        except Exception as e:
            logger.error(f"[WHOIS] Lookup failed: {e}")
            return None

    @staticmethod
    def _normalize(value):
        """Normalize WHOIS values that may be str or list."""
        if isinstance(value, list):
            return [str(v) for v in value]
        return str(value) if value else None