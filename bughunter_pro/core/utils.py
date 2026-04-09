"""
BugHunter Pro - Shared Utility Functions (UPDATED with Tor support)
"""

import os
import time
import random
import requests
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse

# Will be set by main.py after Tor setup
_global_proxies: Dict[str, str] = {}
_global_config = None


def set_global_proxies(proxies: Dict[str, str]) -> None:
    """Set the global proxy configuration (called by main after Tor setup)."""
    global _global_proxies
    _global_proxies = proxies


def get_global_proxies() -> Dict[str, str]:
    """Get the current global proxy configuration."""
    return _global_proxies


def set_global_config(config) -> None:
    """Set the global config reference."""
    global _global_config
    _global_config = config


def get_global_config():
    """Get the global config reference."""
    return _global_config


def load_wordlist(filepath: str) -> List[str]:
    """Load a wordlist file into a list of strings."""
    if not filepath or not os.path.isfile(filepath):
        return []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
        return [
            line.strip() for line in fh
            if line.strip() and not line.startswith("#")
        ]


def make_request(
    url: str,
    method: str = "GET",
    config=None,
    params: Optional[Dict] = None,
    data: Optional[Dict] = None,
    headers: Optional[Dict] = None,
    allow_redirects: bool = True,
    timeout: Optional[int] = None,
    use_tor: bool = True,
) -> Optional[requests.Response]:
    """
    Wrapper around requests with:
      - Tor SOCKS5 proxy support
      - Rate limiting
      - Retries with exponential backoff
      - Error handling
    """
    cfg = config or _global_config
    if cfg:
        req_timeout = timeout or cfg.timeout
        user_agent = cfg.user_agent
        max_retries = cfg.max_retries
        delay = cfg.delay_between_requests
        verify_ssl = cfg.verify_ssl
    else:
        req_timeout = timeout or 10
        user_agent = "BugHunterPro/1.0"
        max_retries = 3
        delay = 0.1
        verify_ssl = False

    req_headers = {"User-Agent": user_agent}
    if headers:
        req_headers.update(headers)

    # Determine proxy settings
    proxies = {}
    if use_tor and _global_proxies:
        proxies = _global_proxies

    for attempt in range(max_retries):
        try:
            time.sleep(delay)
            resp = requests.request(
                method=method.upper(),
                url=url,
                params=params,
                data=data,
                headers=req_headers,
                timeout=req_timeout,
                verify=verify_ssl,
                allow_redirects=allow_redirects,
                proxies=proxies,
            )
            return resp
        except requests.exceptions.ConnectionError:
            time.sleep(2 ** attempt)
        except requests.exceptions.Timeout:
            time.sleep(2 ** attempt)
        except requests.exceptions.RequestException:
            break
    return None


def extract_params_from_url(url: str) -> Dict[str, List[str]]:
    """Extract query parameters from a URL."""
    parsed = urlparse(url)
    return parse_qs(parsed.query)


def inject_payload_into_url(url: str, param: str, payload: str) -> str:
    """Replace a specific query parameter value with a payload."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def get_base_domain(domain: str) -> str:
    """Strip subdomains to get the base registrable domain."""
    try:
        import tldextract
        ext = tldextract.extract(domain)
        return f"{ext.domain}.{ext.suffix}"
    except ImportError:
        parts = domain.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return domain


def normalize_url(url: str, base_url: str) -> Optional[str]:
    """Normalize a possibly-relative URL against a base."""
    if not url:
        return None
    url = url.strip()
    if url.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
        return None
    return urljoin(base_url, url)


def is_same_domain(url: str, domain: str) -> bool:
    """Check whether a URL belongs to the same domain."""
    try:
        parsed = urlparse(url)
        return parsed.hostname and (
            parsed.hostname == domain
            or parsed.hostname.endswith(f".{domain}")
        )
    except Exception:
        return False