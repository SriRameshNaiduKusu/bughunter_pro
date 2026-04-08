"""
BugHunter Pro - Shared Utility Functions
"""

import os
import time
import random
import requests
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from config import Config


def load_wordlist(filepath: str) -> List[str]:
    """Load a wordlist file into a list of strings."""
    if not os.path.isfile(filepath):
        return []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]


def make_request(
    url: str,
    method: str = "GET",
    config: Optional[Config] = None,
    params: Optional[Dict] = None,
    data: Optional[Dict] = None,
    headers: Optional[Dict] = None,
    allow_redirects: bool = True,
    timeout: Optional[int] = None,
) -> Optional[requests.Response]:
    """Wrapper around requests with rate limiting, retries, and error handling."""
    cfg = config or Config()
    req_timeout = timeout or cfg.timeout
    req_headers = {
        "User-Agent": cfg.user_agent,
    }
    if headers:
        req_headers.update(headers)

    for attempt in range(cfg.max_retries):
        try:
            time.sleep(cfg.delay_between_requests)
            resp = requests.request(
                method=method.upper(),
                url=url,
                params=params,
                data=data,
                headers=req_headers,
                timeout=req_timeout,
                verify=cfg.verify_ssl,
                allow_redirects=allow_redirects,
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
            parsed.hostname == domain or parsed.hostname.endswith(f".{domain}")
        )
    except Exception:
        return False


def generate_default_wordlist(filepath: str, wordlist_type: str) -> None:
    """Generate a small default wordlist when none is provided."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)

    if wordlist_type == "subdomains":
        words = [
            "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
            "beta", "portal", "app", "m", "mobile", "blog", "shop", "store",
            "cdn", "media", "static", "assets", "img", "images", "video",
            "docs", "wiki", "help", "support", "status", "monitor",
            "dashboard", "panel", "auth", "login", "sso", "oauth", "vpn",
            "remote", "git", "gitlab", "github", "jenkins", "ci", "cd",
            "deploy", "build", "release", "internal", "intranet", "corp",
            "hr", "crm", "erp", "billing", "invoice", "payment", "pay",
            "checkout", "cart", "search", "elastic", "kibana", "grafana",
            "prometheus", "nagios", "zabbix", "splunk", "log", "logs",
            "syslog", "backup", "bak", "old", "new", "v2", "v3", "sandbox",
            "demo", "preview", "uat", "qa", "stage", "preprod", "prod",
            "ns1", "ns2", "mx", "smtp", "pop", "imap", "webmail",
            "autodiscover", "exchange", "owa", "cpanel", "whm", "plesk",
            "db", "database", "mysql", "postgres", "redis", "mongo",
            "elasticsearch", "solr", "rabbitmq", "queue", "mq", "kafka",
            "ws", "websocket", "socket", "realtime", "push", "notify",
            "notification", "webhook", "callback", "proxy", "gateway",
            "lb", "loadbalancer", "cache", "varnish", "memcached",
            "s3", "storage", "bucket", "files", "upload", "download",
        ]
    elif wordlist_type == "directories":
        words = [
            "admin", "administrator", "login", "wp-admin", "wp-login.php",
            "dashboard", "panel", "cpanel", "phpmyadmin", "adminer",
            "api", "api/v1", "api/v2", "api/v3", "graphql", "swagger",
            "docs", "documentation", "readme", "changelog",
            "config", "configuration", "settings", "setup", "install",
            "backup", "backups", "bak", "old", "temp", "tmp", "test",
            "debug", "trace", "info", "phpinfo.php", "server-status",
            "server-info", ".env", ".git", ".git/HEAD", ".git/config",
            ".svn", ".svn/entries", ".htaccess", ".htpasswd",
            "robots.txt", "sitemap.xml", "crossdomain.xml",
            "wp-content", "wp-includes", "wp-json", "xmlrpc.php",
            "uploads", "images", "img", "css", "js", "static", "assets",
            "media", "files", "download", "downloads",
            "cgi-bin", "bin", "scripts", "includes", "inc",
            "private", "secret", "hidden", "internal", "restricted",
            "user", "users", "account", "accounts", "profile", "register",
            "signup", "signin", "auth", "authenticate", "oauth",
            "token", "tokens", "session", "sessions",
            "search", "query", "find", "lookup",
            "status", "health", "healthcheck", "ping", "version",
            "metrics", "monitoring", "monitor",
            "console", "terminal", "shell", "cmd",
            "database", "db", "sql", "mysql", "dump",
            "log", "logs", "error", "errors", "debug.log", "error.log",
            "archive", "archives", "data", "export", "import",
            "cron", "jobs", "tasks", "queue", "worker",
            "socket.io", "websocket", "ws", "wss",
            "vendor", "node_modules", "packages", "bower_components",
            "dist", "build", "target", "out", "output",
            ".well-known", ".well-known/security.txt",
            "favicon.ico", "manifest.json", "service-worker.js",
        ]
    elif wordlist_type == "api_endpoints":
        words = [
            "api/users", "api/user", "api/account", "api/accounts",
            "api/login", "api/register", "api/auth", "api/token",
            "api/refresh", "api/logout", "api/session",
            "api/profile", "api/me", "api/whoami",
            "api/admin", "api/admin/users", "api/admin/settings",
            "api/config", "api/settings", "api/options",
            "api/search", "api/query", "api/find",
            "api/upload", "api/download", "api/file", "api/files",
            "api/image", "api/images", "api/media",
            "api/post", "api/posts", "api/article", "api/articles",
            "api/comment", "api/comments",
            "api/product", "api/products", "api/item", "api/items",
            "api/order", "api/orders", "api/cart", "api/checkout",
            "api/payment", "api/payments", "api/invoice", "api/invoices",
            "api/notification", "api/notifications", "api/message",
            "api/messages", "api/chat", "api/conversations",
            "api/status", "api/health", "api/version", "api/info",
            "api/metrics", "api/stats", "api/analytics",
            "api/webhook", "api/webhooks", "api/callback",
            "api/graphql", "api/rest", "api/rpc",
            "api/v1/users", "api/v1/auth", "api/v1/search",
            "api/v2/users", "api/v2/auth", "api/v2/search",
            "api/internal", "api/private", "api/public",
            "api/docs", "api/swagger", "api/openapi",
            "api/debug", "api/test", "api/ping",
        ]
    else:
        words = []

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write("\n".join(words) + "\n")