"""
BugHunter Pro - Technology Detection Module (UPDATED for package imports)
"""

import re
import logging
from typing import Dict, List, Optional
from bughunter_pro.config import Config
from bughunter_pro.core.utils import make_request

logger = logging.getLogger("bughunter")

# Full signature database (unchanged from previous version)
TECH_SIGNATURES = [
    ("web_server", "Nginx", {"headers": {"server": r"nginx"}}),
    ("web_server", "Apache", {"headers": {"server": r"apache"}}),
    ("web_server", "IIS", {"headers": {"server": r"microsoft-iis"}}),
    ("web_server", "LiteSpeed", {"headers": {"server": r"litespeed"}}),
    ("web_server", "Cloudflare", {"headers": {"server": r"cloudflare"}}),
    ("framework", "PHP", {"headers": {"x-powered-by": r"php"}}),
    ("framework", "ASP.NET", {"headers": {"x-powered-by": r"asp\.net"}}),
    ("framework", "Express.js", {"headers": {"x-powered-by": r"express"}}),
    ("framework", "Django", {"body": r"csrfmiddlewaretoken"}),
    ("framework", "Ruby on Rails", {"headers": {"x-powered-by": r"phusion"}, "body": r"csrf-token"}),
    ("framework", "Laravel", {"cookies": r"laravel_session"}),
    ("framework", "Spring", {"headers": {"x-application-context": r"."}}),
    ("framework", "Flask", {"headers": {"server": r"werkzeug"}}),
    ("cms", "WordPress", {"body": r"wp-content|wp-includes|wp-json"}),
    ("cms", "Joomla", {"body": r"/media/jui/|/components/com_"}),
    ("cms", "Drupal", {"body": r"Drupal\.settings|sites/default/files"}),
    ("cms", "Shopify", {"body": r"cdn\.shopify\.com"}),
    ("cms", "Magento", {"body": r"mage/cookies|Magento_"}),
    ("js_framework", "React", {"body": r"react\.production\.min\.js|_reactRoot|__NEXT_DATA__"}),
    ("js_framework", "Angular", {"body": r"ng-version|angular\.min\.js|ng-app"}),
    ("js_framework", "Vue.js", {"body": r"vue\.min\.js|vue\.runtime|v-bind:|v-on:"}),
    ("js_framework", "jQuery", {"body": r"jquery[\.-][\d]+\.[\d]+|jquery\.min\.js"}),
    ("js_framework", "Next.js", {"body": r"__NEXT_DATA__|_next/static"}),
    ("js_framework", "Nuxt.js", {"body": r"__NUXT__|_nuxt/"}),
    ("cdn", "Cloudflare", {"headers": {"cf-ray": r"."}}),
    ("cdn", "AWS CloudFront", {"headers": {"x-amz-cf-id": r"."}}),
    ("cdn", "Akamai", {"headers": {"x-akamai-transformed": r"."}}),
    ("cdn", "Fastly", {"headers": {"x-served-by": r"cache-", "x-fastly-request-id": r"."}}),
    ("analytics", "Google Analytics", {"body": r"google-analytics\.com|gtag\(|ga\("}),
    ("analytics", "Google Tag Manager", {"body": r"googletagmanager\.com"}),
    ("analytics", "Facebook Pixel", {"body": r"fbq\(|facebook\.com/tr"}),
    ("analytics", "Hotjar", {"body": r"hotjar\.com|_hjSettings"}),
    ("security", "reCAPTCHA", {"body": r"google\.com/recaptcha"}),
    ("security", "hCaptcha", {"body": r"hcaptcha\.com"}),
]


class TechDetector:
    """Fingerprints technologies used on a target."""

    def __init__(self, config: Config):
        self.config = config
        self.results: Dict[str, List[str]] = {}

    def detect(self, url: Optional[str] = None) -> Dict[str, List[str]]:
        """Perform technology detection on the target URL."""
        target_url = url or self.config.base_url
        logger.info(f"[TECH] Detecting technologies on {target_url}")

        resp = make_request(target_url, config=self.config)
        if not resp:
            logger.warning("[TECH] Could not reach the target")
            return self.results

        headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
        body = resp.text.lower() if resp.text else ""
        cookies = "; ".join(
            [f"{c.name}={c.value}" for c in resp.cookies]
        ).lower()

        for category, name, patterns in TECH_SIGNATURES:
            matched = False

            if "headers" in patterns:
                for header_name, pattern in patterns["headers"].items():
                    header_val = headers.get(header_name, "")
                    if header_val and re.search(pattern, header_val, re.I):
                        matched = True
                        break

            if not matched and "body" in patterns:
                if re.search(patterns["body"], body, re.I):
                    matched = True

            if not matched and "cookies" in patterns:
                if re.search(patterns["cookies"], cookies, re.I):
                    matched = True

            if matched:
                self.results.setdefault(category, [])
                if name not in self.results[category]:
                    self.results[category].append(name)
                    logger.info(f"[TECH] Detected {category}: {name}")

        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        if server:
            self.results.setdefault("raw_headers", []).append(
                f"Server: {server}"
            )
        if powered:
            self.results.setdefault("raw_headers", []).append(
                f"X-Powered-By: {powered}"
            )

        logger.info(
            f"[TECH] Detection complete. Found "
            f"{sum(len(v) for v in self.results.values())} technologies."
        )
        return self.results