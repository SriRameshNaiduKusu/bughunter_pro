"""
BugHunter Pro - Target Intelligence Module

Analyses the target domain to infer industry, technology stack,
and suggest targeted attack vectors.
"""

import re
import logging
from typing import Dict, List, Optional
from urllib.parse import urlparse

from bughunter_pro.config import Config
from bughunter_pro.core.utils import get_base_domain

# Class body remains IDENTICAL

logger = logging.getLogger("bughunter")


class TargetIntelligence:
    """Builds a threat-intelligence profile for the target."""

    def __init__(self, config: Config):
        self.config = config
        self.domain = config.target_domain
        self.profile: Dict = {
            "domain": self.domain,
            "industry": "unknown",
            "industry_confidence": 0.0,
            "subdomain_analysis": [],
            "attack_vectors": [],
            "risk_score": 0,
            "technology_insights": [],
            "recommendations": [],
        }

    def analyse(
        self,
        subdomains: List[str],
        technologies: Dict,
        dns_records: Dict,
        shodan_data: Optional[Dict],
        crawl_data: Optional[Dict],
    ) -> Dict:
        """Run full target intelligence analysis."""
        logger.info(f"[INTEL] Analysing target intelligence for {self.domain}")

        self._detect_industry(subdomains)
        self._analyse_subdomains(subdomains)
        self._analyse_technologies(technologies)
        self._analyse_dns(dns_records)
        self._analyse_shodan(shodan_data)
        self._analyse_crawl_data(crawl_data)
        self._calculate_risk_score()
        self._generate_recommendations()

        logger.info(
            f"[INTEL] Analysis complete. Industry: {self.profile['industry']} "
            f"(confidence: {self.profile['industry_confidence']:.0%}), "
            f"Risk score: {self.profile['risk_score']}/100"
        )
        return self.profile

    def _detect_industry(self, subdomains: List[str]) -> None:
        """Infer the target's industry from domain and subdomain names."""
        text_corpus = " ".join(subdomains + [self.domain]).lower()

        scores = {}
        for industry, keywords in self.config.industry_keywords.items():
            score = sum(1 for kw in keywords if kw in text_corpus)
            if score > 0:
                scores[industry] = score

        if scores:
            best_industry = max(scores, key=scores.get)
            max_possible = max(
                len(v) for v in self.config.industry_keywords.values()
            )
            confidence = min(scores[best_industry] / (max_possible * 0.5), 1.0)
            self.profile["industry"] = best_industry
            self.profile["industry_confidence"] = confidence
            logger.info(
                f"[INTEL] Detected industry: {best_industry} "
                f"(confidence: {confidence:.0%})"
            )

    def _analyse_subdomains(self, subdomains: List[str]) -> None:
        """Analyse subdomains for interesting patterns and attack vectors."""
        subdomain_categories = {
            "development": {
                "patterns": ["dev", "develop", "test", "testing", "staging",
                             "stage", "uat", "qa", "sandbox", "demo",
                             "preview", "beta", "alpha", "preprod"],
                "risk": "HIGH",
                "attack_vectors": [
                    "Development environments often have weaker security",
                    "May contain debug endpoints or verbose error messages",
                    "Default credentials may be in use",
                    "May expose internal API documentation",
                ],
            },
            "api": {
                "patterns": ["api", "rest", "graphql", "gateway",
                             "ws", "websocket", "rpc", "grpc"],
                "risk": "HIGH",
                "attack_vectors": [
                    "API endpoints may lack proper authentication",
                    "Test for BOLA/IDOR vulnerabilities",
                    "Check for rate limiting issues",
                    "Look for API versioning exposing deprecated endpoints",
                    "Test for mass assignment vulnerabilities",
                ],
            },
            "admin": {
                "patterns": ["admin", "administrator", "panel", "dashboard",
                             "manage", "management", "control", "cms"],
                "risk": "CRITICAL",
                "attack_vectors": [
                    "Admin panels are high-value targets",
                    "Test for default/weak credentials",
                    "Check for authentication bypass",
                    "Look for privilege escalation vectors",
                ],
            },
            "mail": {
                "patterns": ["mail", "smtp", "imap", "pop", "webmail",
                             "email", "mx", "exchange", "owa"],
                "risk": "MEDIUM",
                "attack_vectors": [
                    "Email systems may be vulnerable to spoofing",
                    "Check SPF, DKIM, DMARC records",
                    "OWA/webmail may have authentication issues",
                    "Test for user enumeration via SMTP VRFY",
                ],
            },
            "database": {
                "patterns": ["db", "database", "mysql", "postgres", "mongo",
                             "redis", "elastic", "elasticsearch", "solr",
                             "memcached", "phpmyadmin", "adminer"],
                "risk": "CRITICAL",
                "attack_vectors": [
                    "Database management interfaces exposed to internet",
                    "Check for unauthenticated access",
                    "Default credentials on database consoles",
                    "Data exfiltration risk",
                ],
            },
            "ci_cd": {
                "patterns": ["jenkins", "ci", "cd", "deploy", "build",
                             "gitlab", "github", "bitbucket", "travis",
                             "circleci", "drone", "argo"],
                "risk": "HIGH",
                "attack_vectors": [
                    "CI/CD systems may expose build logs with secrets",
                    "Check for unauthenticated Jenkins/GitLab access",
                    "Pipeline configurations may leak credentials",
                    "Test for RCE through build configurations",
                ],
            },
            "monitoring": {
                "patterns": ["monitor", "monitoring", "grafana", "kibana",
                             "prometheus", "nagios", "zabbix", "splunk",
                             "datadog", "newrelic", "sentry", "status"],
                "risk": "MEDIUM",
                "attack_vectors": [
                    "Monitoring dashboards may expose system internals",
                    "Check for unauthenticated Grafana/Kibana access",
                    "Log aggregation may contain sensitive data",
                    "Status pages may reveal infrastructure details",
                ],
            },
            "storage": {
                "patterns": ["cdn", "static", "assets", "media", "files",
                             "upload", "storage", "s3", "bucket", "blob",
                             "download", "img", "images"],
                "risk": "MEDIUM",
                "attack_vectors": [
                    "File upload functionality may allow malicious files",
                    "Check for directory listing on asset servers",
                    "CDN bypass may expose origin server",
                    "Misconfigured storage permissions",
                ],
            },
            "vpn_remote": {
                "patterns": ["vpn", "remote", "rdp", "ssh", "jump",
                             "bastion", "gateway", "tunnel", "proxy"],
                "risk": "HIGH",
                "attack_vectors": [
                    "VPN endpoints may have known CVEs",
                    "Check for weak VPN configurations",
                    "SSH brute-force potential",
                    "Remote access without MFA",
                ],
            },
        }

        for subdomain in subdomains:
            sub_prefix = subdomain.replace(f".{self.domain}", "").lower()
            parts = re.split(r"[.\-_]", sub_prefix)

            for category, info in subdomain_categories.items():
                for pattern in info["patterns"]:
                    if pattern in parts or pattern in sub_prefix:
                        analysis = {
                            "subdomain": subdomain,
                            "category": category,
                            "risk_level": info["risk"],
                            "suggested_attack_vectors": info["attack_vectors"],
                        }
                        self.profile["subdomain_analysis"].append(analysis)

                        for vector in info["attack_vectors"]:
                            if vector not in self.profile["attack_vectors"]:
                                self.profile["attack_vectors"].append(vector)

                        logger.info(
                            f"[INTEL] Subdomain '{subdomain}' categorised as "
                            f"'{category}' (risk: {info['risk']})"
                        )
                        break

    def _analyse_technologies(self, technologies: Dict) -> None:
        """Generate insights based on detected technologies."""
        tech_vectors = {
            "WordPress": [
                "Check for WordPress plugin vulnerabilities (WPScan)",
                "Test xmlrpc.php for brute-force and SSRF",
                "Check for user enumeration via ?author=1",
                "Look for wp-config.php backup files",
            ],
            "Joomla": [
                "Check for Joomla component vulnerabilities",
                "Test administrator login for brute-force",
                "Look for configuration.php.bak",
            ],
            "Drupal": [
                "Check for Drupalgeddon vulnerabilities",
                "Test for user enumeration",
                "Check for accessible update.php",
            ],
            "PHP": [
                "Test for LFI/RFI vulnerabilities",
                "Check for PHP info pages",
                "Look for common PHP backdoors",
            ],
            "Django": [
                "Check for Django debug mode enabled",
                "Test for SSTI in template engine",
                "Look for exposed admin panel at /admin/",
            ],
            "React": [
                "Check for exposed source maps",
                "Look for API keys in JavaScript bundles",
                "Test for prototype pollution",
            ],
            "Next.js": [
                "Check for _next/data path traversal",
                "Look for exposed API routes",
                "Test for SSRF in image optimization",
            ],
            "Nginx": [
                "Test for Nginx off-by-slash alias traversal",
                "Check for exposed Nginx status page",
            ],
            "Apache": [
                "Check for Apache mod_status exposure",
                "Test for .htaccess bypass",
                "Look for Apache Struts vulnerabilities",
            ],
        }

        for category, tech_list in technologies.items():
            for tech_name in tech_list:
                insight = {
                    "technology": tech_name,
                    "category": category,
                    "attack_vectors": tech_vectors.get(tech_name, []),
                }
                self.profile["technology_insights"].append(insight)

                for vector in tech_vectors.get(tech_name, []):
                    if vector not in self.profile["attack_vectors"]:
                        self.profile["attack_vectors"].append(vector)

    def _analyse_dns(self, dns_records: Dict) -> None:
        """Check DNS records for security insights."""
        # Check for SPF
        txt_records = dns_records.get("TXT", [])
        has_spf = any("v=spf1" in r for r in txt_records)
        has_dmarc = any("v=DMARC1" in r for r in txt_records)
        has_dkim = any("DKIM" in r.upper() for r in txt_records)

        if not has_spf:
            self.profile["attack_vectors"].append(
                "No SPF record found - email spoofing may be possible"
            )
        if not has_dmarc:
            self.profile["attack_vectors"].append(
                "No DMARC record found - email spoofing risk"
            )

        # Zone transfer
        if "AXFR" in dns_records:
            self.profile["attack_vectors"].append(
                "DNS Zone Transfer allowed! Full zone data exposed."
            )

    def _analyse_shodan(self, shodan_data: Optional[Dict]) -> None:
        """Incorporate Shodan findings into intelligence."""
        if not shodan_data:
            return

        vulns = shodan_data.get("vulns", [])
        if vulns:
            self.profile["attack_vectors"].append(
                f"Shodan reports {len(vulns)} known CVEs: "
                f"{', '.join(vulns[:10])}"
            )

        ports = shodan_data.get("ports", [])
        risky_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
            27017: "MongoDB", 9200: "Elasticsearch",
            11211: "Memcached", 5900: "VNC",
        }
        for port in ports:
            if port in risky_ports:
                self.profile["attack_vectors"].append(
                    f"Port {port} ({risky_ports[port]}) is exposed to internet"
                )

    def _analyse_crawl_data(self, crawl_data: Optional[Dict]) -> None:
        """Analyse crawl results for intelligence."""
        if not crawl_data:
            return

        forms = crawl_data.get("forms", [])
        if forms:
            login_forms = [
                f for f in forms
                if any(
                    inp.get("type") == "password"
                    for inp in f.get("inputs", [])
                )
            ]
            if login_forms:
                self.profile["attack_vectors"].append(
                    f"Found {len(login_forms)} login form(s) - "
                    "test for credential stuffing/brute-force"
                )

        param_urls = crawl_data.get("parameterized_urls", [])
        if param_urls:
            self.profile["attack_vectors"].append(
                f"Found {len(param_urls)} URLs with parameters - "
                "test each for injection vulnerabilities"
            )

    def _calculate_risk_score(self) -> None:
        """Calculate an overall risk score (0-100)."""
        score = 0

        # Industry risk
        high_risk_industries = ["finance", "healthcare", "government"]
        if self.profile["industry"] in high_risk_industries:
            score += 15

        # Subdomain analysis
        for analysis in self.profile["subdomain_analysis"]:
            risk = analysis["risk_level"]
            if risk == "CRITICAL":
                score += 8
            elif risk == "HIGH":
                score += 5
            elif risk == "MEDIUM":
                score += 3

        # Attack vectors count
        score += min(len(self.profile["attack_vectors"]) * 2, 40)

        self.profile["risk_score"] = min(score, 100)

    def _generate_recommendations(self) -> None:
        """Generate prioritised security recommendations."""
        recommendations = []

        if self.profile["risk_score"] >= 70:
            recommendations.append({
                "priority": "CRITICAL",
                "text": "High risk score detected. Immediate security review recommended.",
            })

        # Industry-specific
        industry = self.profile["industry"]
        if industry == "finance":
            recommendations.extend([
                {"priority": "HIGH", "text": "Ensure PCI-DSS compliance for payment processing."},
                {"priority": "HIGH", "text": "Implement strong authentication (MFA) on all financial endpoints."},
            ])
        elif industry == "healthcare":
            recommendations.extend([
                {"priority": "HIGH", "text": "Ensure HIPAA compliance for patient data handling."},
                {"priority": "HIGH", "text": "Encrypt all health data in transit and at rest."},
            ])

        # Subdomain-based
        critical_subs = [
            a for a in self.profile["subdomain_analysis"]
            if a["risk_level"] == "CRITICAL"
        ]
        if critical_subs:
            recommendations.append({
                "priority": "HIGH",
                "text": (
                    f"Found {len(critical_subs)} critical subdomains "
                    "(admin/database). Ensure these are not publicly accessible."
                ),
            })

        dev_subs = [
            a for a in self.profile["subdomain_analysis"]
            if a["category"] == "development"
        ]
        if dev_subs:
            recommendations.append({
                "priority": "MEDIUM",
                "text": (
                    f"Found {len(dev_subs)} development/staging subdomains. "
                    "Ensure these are access-restricted."
                ),
            })

        self.profile["recommendations"] = recommendations