"""
BugHunter Pro - Shodan Reconnaissance Module
"""

import logging
import socket
from typing import Dict, Optional

from config import Config

logger = logging.getLogger("bughunter")


class ShodanRecon:
    """Queries Shodan for intelligence about the target."""

    def __init__(self, config: Config):
        self.config = config
        self.domain = config.target_domain
        self.api_key = config.shodan_api_key

    def search(self) -> Optional[Dict]:
        """Perform Shodan host lookup."""
        if not self.api_key:
            logger.warning(
                "[SHODAN] No API key configured. "
                "Set SHODAN_API_KEY environment variable. Skipping."
            )
            return None

        try:
            import shodan
        except ImportError:
            logger.warning("[SHODAN] shodan library not installed. Skipping.")
            return None

        logger.info(f"[SHODAN] Querying Shodan for {self.domain}")

        try:
            ip = socket.gethostbyname(self.domain)
            logger.info(f"[SHODAN] Resolved {self.domain} -> {ip}")
        except socket.gaierror:
            logger.error(f"[SHODAN] Could not resolve {self.domain}")
            return None

        try:
            api = shodan.Shodan(self.api_key)
            host = api.host(ip)

            result = {
                "ip": host.get("ip_str", ip),
                "organization": host.get("org", "N/A"),
                "os": host.get("os", "N/A"),
                "ports": host.get("ports", []),
                "hostnames": host.get("hostnames", []),
                "vulns": host.get("vulns", []),
                "services": [],
            }

            for item in host.get("data", []):
                service = {
                    "port": item.get("port"),
                    "transport": item.get("transport", "tcp"),
                    "product": item.get("product", ""),
                    "version": item.get("version", ""),
                    "banner": item.get("data", "")[:200],
                }
                result["services"].append(service)

            logger.info(
                f"[SHODAN] Found {len(result['ports'])} open ports, "
                f"{len(result['vulns'])} known vulnerabilities"
            )
            return result

        except shodan.APIError as e:
            logger.error(f"[SHODAN] API error: {e}")
            return None
        except Exception as e:
            logger.error(f"[SHODAN] Unexpected error: {e}")
            return None