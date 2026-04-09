"""
BugHunter Pro - JSON Report Generator (UPDATED with ReportStore integration)
"""

import json
import os
import logging
import time
from datetime import datetime
from typing import Dict, Any

from bughunter_pro.config import Config
from bughunter_pro.reporting.report_store import ReportStore

logger = logging.getLogger("bughunter")


class JSONReporter:
    """Generates JSON reports and saves to the central report store."""

    def __init__(self, config: Config):
        self.config = config
        self.store = ReportStore()

    def generate(
        self,
        scan_results: Dict[str, Any],
        scan_duration: float = 0.0,
    ) -> str:
        """Generate JSON report, save to output dir AND to report store."""
        os.makedirs(self.config.output_dir, exist_ok=True)

        # Save to central report store (for dashboard)
        report_id = self.store.save_report(
            domain=self.config.target_domain,
            scan_results=scan_results,
            scan_duration=scan_duration,
            tor_used=self.config.use_tor,
            modules_run=self.config.modules_to_run,
        )

        # Also save a copy to the output directory
        report = {
            "meta": {
                "tool": "BugHunter Pro",
                "version": "1.0.0",
                "author": "University of Hertfordshire - Cyber Security",
                "target": self.config.target_domain,
                "base_url": self.config.base_url,
                "scan_date": datetime.now().isoformat(),
                "report_id": report_id,
                "modules_run": self.config.modules_to_run,
            },
            "summary": self._build_summary(scan_results),
            "results": scan_results,
        }

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = (
            f"bughunter_report_{self.config.target_domain}_{timestamp}.json"
        )
        filepath = os.path.join(self.config.output_dir, filename)

        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)

        logger.info(f"[REPORT] JSON report saved to {filepath}")
        logger.info(f"[REPORT] Report stored in dashboard DB: {report_id}")
        return filepath

    def _build_summary(self, results: Dict) -> Dict:
        """Build a summary section from all results."""
        all_findings = []
        for key, value in results.items():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict) and "severity" in item:
                        all_findings.append(item)

        # Also check vulnerability_findings dict
        vuln_findings = results.get("vulnerability_findings", {})
        if isinstance(vuln_findings, dict):
            for cat, findings in vuln_findings.items():
                if isinstance(findings, list):
                    for item in findings:
                        if isinstance(item, dict) and "severity" in item:
                            if item not in all_findings:
                                all_findings.append(item)

        severity_counts = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
        }
        for finding in all_findings:
            sev = finding.get("severity", "INFO").upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        vuln_types = {}
        for finding in all_findings:
            vtype = finding.get("type", "Unknown")
            vuln_types[vtype] = vuln_types.get(vtype, 0) + 1

        subdomains = results.get("subdomains", [])
        technologies = results.get("technologies", {})
        crawl_data = results.get("crawl_data", {})

        return {
            "total_findings": len(all_findings),
            "severity_breakdown": severity_counts,
            "vulnerability_types": vuln_types,
            "subdomains_found": len(subdomains),
            "technologies_detected": sum(
                len(v) for v in technologies.values()
            ) if isinstance(technologies, dict) else 0,
            "pages_crawled": (
                crawl_data.get("pages_crawled", 0)
                if isinstance(crawl_data, dict) else 0
            ),
            "forms_found": (
                len(crawl_data.get("forms", []))
                if isinstance(crawl_data, dict) else 0
            ),
            "risk_score": (
                results.get("intelligence", {}).get("risk_score", 0)
                if isinstance(results.get("intelligence"), dict) else 0
            ),
        }