"""
BugHunter Pro - Attack Surface Mapping Module

Builds a structured graph of the target's attack surface
for visualization and reporting.
"""

import logging
from typing import Dict, List, Optional
from urllib.parse import urlparse

from config import Config

logger = logging.getLogger("bughunter")


class AttackSurfaceMapper:
    """Maps the complete attack surface into a graph data structure."""

    def __init__(self, config: Config):
        self.config = config
        self.domain = config.target_domain
        self.nodes: List[Dict] = []
        self.edges: List[Dict] = []
        self._node_id_counter = 0

    def build_graph(
        self,
        subdomains: List[str],
        technologies: Dict,
        crawl_data: Optional[Dict],
        dns_records: Dict,
        shodan_data: Optional[Dict],
        vulnerability_findings: List[Dict],
        intel_profile: Dict,
    ) -> Dict:
        """Build the full attack surface graph."""
        logger.info("[SURFACE] Building attack surface graph")

        # Root node
        root_id = self._add_node(
            self.domain, "domain", "root",
            {"industry": intel_profile.get("industry", "unknown"),
             "risk_score": intel_profile.get("risk_score", 0)}
        )

        # Subdomain nodes
        sub_group_id = self._add_node(
            "Subdomains", "group", "subdomain_group",
            {"count": len(subdomains)}
        )
        self._add_edge(root_id, sub_group_id, "has_subdomains")

        for sub in subdomains:
            sub_id = self._add_node(sub, "subdomain", "asset")
            self._add_edge(sub_group_id, sub_id, "includes")

            # Categorize subdomain
            for analysis in intel_profile.get("subdomain_analysis", []):
                if analysis["subdomain"] == sub:
                    cat_id = self._add_node(
                        analysis["category"], "category",
                        analysis["risk_level"].lower(),
                    )
                    self._add_edge(sub_id, cat_id, "categorized_as")

        # Technology nodes
        tech_group_id = self._add_node(
            "Technologies", "group", "tech_group",
            {"count": sum(len(v) for v in technologies.values())}
        )
        self._add_edge(root_id, tech_group_id, "uses_technologies")

        for category, tech_list in technologies.items():
            cat_id = self._add_node(category, "tech_category", "info")
            self._add_edge(tech_group_id, cat_id, "category")
            for tech in tech_list:
                tech_id = self._add_node(tech, "technology", "info")
                self._add_edge(cat_id, tech_id, "includes")

        # DNS nodes
        dns_group_id = self._add_node("DNS Records", "group", "dns_group")
        self._add_edge(root_id, dns_group_id, "dns_records")
        for rtype, records in dns_records.items():
            rtype_id = self._add_node(
                f"DNS {rtype}", "dns_type", "info",
                {"count": len(records)}
            )
            self._add_edge(dns_group_id, rtype_id, "record_type")

        # Shodan nodes
        if shodan_data:
            shodan_group_id = self._add_node(
                "Shodan Intel", "group", "shodan_group"
            )
            self._add_edge(root_id, shodan_group_id, "shodan_data")

            for port in shodan_data.get("ports", []):
                port_id = self._add_node(
                    f"Port {port}", "port", "warning"
                )
                self._add_edge(shodan_group_id, port_id, "open_port")

            for vuln in shodan_data.get("vulns", [])[:20]:
                vuln_id = self._add_node(vuln, "cve", "critical")
                self._add_edge(shodan_group_id, vuln_id, "known_cve")

        # Crawl data nodes
        if crawl_data:
            crawl_group_id = self._add_node(
                "Crawl Results", "group", "crawl_group"
            )
            self._add_edge(root_id, crawl_group_id, "crawl_data")

            # Forms
            forms = crawl_data.get("forms", [])
            if forms:
                forms_id = self._add_node(
                    f"Forms ({len(forms)})", "forms", "warning"
                )
                self._add_edge(crawl_group_id, forms_id, "discovered")

            # JS files
            js_files = crawl_data.get("js_files", [])
            if js_files:
                js_id = self._add_node(
                    f"JS Files ({len(js_files)})", "js_files", "info"
                )
                self._add_edge(crawl_group_id, js_id, "discovered")

            # Parameterized URLs
            param_urls = crawl_data.get("parameterized_urls", [])
            if param_urls:
                param_id = self._add_node(
                    f"Param URLs ({len(param_urls)})",
                    "param_urls", "warning",
                )
                self._add_edge(crawl_group_id, param_id, "discovered")

        # Vulnerability nodes
        if vulnerability_findings:
            vuln_group_id = self._add_node(
                "Vulnerabilities", "group", "vuln_group",
                {"count": len(vulnerability_findings)}
            )
            self._add_edge(root_id, vuln_group_id, "vulnerabilities")

            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for finding in vulnerability_findings:
                sev = finding.get("severity", "INFO")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            for severity, count in severity_counts.items():
                if count > 0:
                    sev_id = self._add_node(
                        f"{severity} ({count})", "severity",
                        severity.lower(),
                        {"count": count}
                    )
                    self._add_edge(vuln_group_id, sev_id, "severity_level")

            # Add individual vulnerability type groups
            vuln_types = {}
            for finding in vulnerability_findings:
                vtype = finding.get("type", "Unknown")
                if vtype not in vuln_types:
                    vuln_types[vtype] = []
                vuln_types[vtype].append(finding)

            for vtype, findings_list in vuln_types.items():
                vtype_id = self._add_node(
                    f"{vtype} ({len(findings_list)})",
                    "vuln_type",
                    self._severity_to_level(findings_list[0].get("severity", "INFO")),
                    {"count": len(findings_list)}
                )
                self._add_edge(vuln_group_id, vtype_id, "vuln_category")

                # Add up to 5 individual findings per type
                for finding in findings_list[:5]:
                    finding_url = finding.get("url", "unknown")
                    # Truncate URL for display
                    display_url = finding_url[:80] + "..." if len(finding_url) > 80 else finding_url
                    finding_id = self._add_node(
                        display_url,
                        "vulnerability",
                        finding.get("severity", "info").lower(),
                        {
                            "full_url": finding_url,
                            "parameter": finding.get("parameter", ""),
                            "payload": finding.get("payload", ""),
                            "evidence": finding.get("evidence", ""),
                        }
                    )
                    self._add_edge(vtype_id, finding_id, "instance")

        # Attack vectors from intelligence
        vectors = intel_profile.get("attack_vectors", [])
        if vectors:
            vectors_group_id = self._add_node(
                "Suggested Attack Vectors", "group", "vectors_group",
                {"count": len(vectors)}
            )
            self._add_edge(root_id, vectors_group_id, "attack_vectors")
            for i, vector in enumerate(vectors[:25]):
                vec_id = self._add_node(
                    vector, "attack_vector", "warning",
                    {"index": i}
                )
                self._add_edge(vectors_group_id, vec_id, "suggests")

        graph = {
            "nodes": self.nodes,
            "edges": self.edges,
            "metadata": {
                "domain": self.domain,
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "risk_score": intel_profile.get("risk_score", 0),
                "industry": intel_profile.get("industry", "unknown"),
            }
        }

        logger.info(
            f"[SURFACE] Graph built: {len(self.nodes)} nodes, "
            f"{len(self.edges)} edges"
        )
        return graph

    def _add_node(self, label: str, node_type: str, level: str,
                  data: Optional[Dict] = None) -> int:
        """Add a node to the graph and return its ID."""
        node_id = self._node_id_counter
        self._node_id_counter += 1

        node = {
            "id": node_id,
            "label": label,
            "type": node_type,
            "level": level,
            "data": data or {},
        }
        self.nodes.append(node)
        return node_id

    def _add_edge(self, source: int, target: int, relationship: str) -> None:
        """Add an edge between two nodes."""
        edge = {
            "source": source,
            "target": target,
            "relationship": relationship,
        }
        self.edges.append(edge)

    def _severity_to_level(self, severity: str) -> str:
        """Convert severity string to a level for styling."""
        mapping = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "INFO": "info",
        }
        return mapping.get(severity.upper(), "info")

    def get_summary(self) -> Dict:
        """Return a summary of the attack surface."""
        type_counts = {}
        level_counts = {}

        for node in self.nodes:
            ntype = node["type"]
            nlevel = node["level"]
            type_counts[ntype] = type_counts.get(ntype, 0) + 1
            level_counts[nlevel] = level_counts.get(nlevel, 0) + 1

        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "node_types": type_counts,
            "node_levels": level_counts,
        }