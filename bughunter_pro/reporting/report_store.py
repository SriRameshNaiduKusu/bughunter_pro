"""
BugHunter Pro - Report Storage Manager

Manages saving, loading, listing, and deleting scan reports.
Reports are stored as JSON files in a dedicated reports directory
with an index file for fast lookups.
"""

import os
import json
import shutil
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger("bughunter")

DEFAULT_REPORTS_DIR = os.path.join(
    os.path.expanduser("~"), ".bughunter_pro", "reports"
)


class ReportStore:
    """Manages persistent storage of scan reports."""

    def __init__(self, reports_dir: Optional[str] = None):
        self.reports_dir = Path(reports_dir or DEFAULT_REPORTS_DIR)
        self.index_file = self.reports_dir / "index.json"
        self._ensure_dirs()

    def _ensure_dirs(self) -> None:
        """Create reports directory if it doesn't exist."""
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        if not self.index_file.exists():
            self._save_index([])

    def _load_index(self) -> List[Dict]:
        """Load the reports index."""
        try:
            with open(self.index_file, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, FileNotFoundError):
            return []

    def _save_index(self, index: List[Dict]) -> None:
        """Save the reports index."""
        with open(self.index_file, "w", encoding="utf-8") as fh:
            json.dump(index, fh, indent=2, default=str)

    def save_report(
        self,
        domain: str,
        scan_results: Dict[str, Any],
        scan_duration: float = 0.0,
        tor_used: bool = False,
        modules_run: Optional[List[str]] = None,
    ) -> str:
        """
        Save a scan report and update the index.
        Returns the report ID.
        """
        timestamp = datetime.now()
        report_id = f"{domain}_{timestamp.strftime('%Y%m%d_%H%M%S')}"
        report_filename = f"{report_id}.json"
        report_path = self.reports_dir / report_filename

        # Build metadata
        all_findings = self._extract_all_findings(scan_results)
        severity_counts = self._count_severities(all_findings)

        metadata = {
            "report_id": report_id,
            "domain": domain,
            "scan_date": timestamp.isoformat(),
            "scan_date_display": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "scan_duration_seconds": round(scan_duration, 1),
            "tor_used": tor_used,
            "modules_run": modules_run or ["all"],
            "total_findings": len(all_findings),
            "severity_counts": severity_counts,
            "subdomains_found": len(scan_results.get("subdomains", [])),
            "technologies_detected": sum(
                len(v) for v in scan_results.get("technologies", {}).values()
                if isinstance(v, list)
            ),
            "pages_crawled": (
                scan_results.get("crawl_data", {}).get("pages_crawled", 0)
                if isinstance(scan_results.get("crawl_data"), dict) else 0
            ),
            "risk_score": (
                scan_results.get("intelligence", {}).get("risk_score", 0)
                if isinstance(scan_results.get("intelligence"), dict) else 0
            ),
            "industry": (
                scan_results.get("intelligence", {}).get("industry", "unknown")
                if isinstance(scan_results.get("intelligence"), dict)
                else "unknown"
            ),
            "report_filename": report_filename,
        }

        # Save full report
        full_report = {
            "metadata": metadata,
            "results": scan_results,
        }

        with open(report_path, "w", encoding="utf-8") as fh:
            json.dump(full_report, fh, indent=2, default=str)

        # Update index
        index = self._load_index()
        index.insert(0, metadata)  # Newest first
        self._save_index(index)

        logger.info(
            f"[REPORT_STORE] Report saved: {report_id} "
            f"({len(all_findings)} findings)"
        )
        return report_id

    def list_reports(self) -> List[Dict]:
        """List all saved reports (metadata only)."""
        return self._load_index()

    def list_reports_by_domain(self, domain: str) -> List[Dict]:
        """List reports for a specific domain."""
        index = self._load_index()
        return [r for r in index if r["domain"] == domain]

    def get_unique_domains(self) -> List[str]:
        """Get list of unique domains that have been scanned."""
        index = self._load_index()
        domains = []
        seen = set()
        for report in index:
            d = report["domain"]
            if d not in seen:
                domains.append(d)
                seen.add(d)
        return domains

    def load_report(self, report_id: str) -> Optional[Dict]:
        """Load a full report by its ID."""
        index = self._load_index()
        for entry in index:
            if entry["report_id"] == report_id:
                report_path = self.reports_dir / entry["report_filename"]
                if report_path.exists():
                    with open(report_path, "r", encoding="utf-8") as fh:
                        return json.load(fh)
        return None

    def load_latest_report(self, domain: str) -> Optional[Dict]:
        """Load the most recent report for a domain."""
        reports = self.list_reports_by_domain(domain)
        if reports:
            return self.load_report(reports[0]["report_id"])
        return None

    def delete_report(self, report_id: str) -> bool:
        """Delete a report and remove it from the index."""
        index = self._load_index()
        updated = []
        deleted = False
        for entry in index:
            if entry["report_id"] == report_id:
                report_path = self.reports_dir / entry["report_filename"]
                if report_path.exists():
                    report_path.unlink()
                deleted = True
            else:
                updated.append(entry)

        if deleted:
            self._save_index(updated)
            logger.info(f"[REPORT_STORE] Report deleted: {report_id}")
        return deleted

    def delete_domain_reports(self, domain: str) -> int:
        """Delete all reports for a domain. Returns count deleted."""
        reports = self.list_reports_by_domain(domain)
        count = 0
        for report in reports:
            if self.delete_report(report["report_id"]):
                count += 1
        return count

    def get_report_stats(self) -> Dict:
        """Get aggregate statistics across all reports."""
        index = self._load_index()

        total_reports = len(index)
        unique_domains = len(set(r["domain"] for r in index))
        total_findings = sum(r.get("total_findings", 0) for r in index)

        aggregate_severity = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
        }
        for report in index:
            for sev, count in report.get("severity_counts", {}).items():
                aggregate_severity[sev] = (
                    aggregate_severity.get(sev, 0) + count
                )

        return {
            "total_reports": total_reports,
            "unique_domains": unique_domains,
            "total_findings": total_findings,
            "aggregate_severity": aggregate_severity,
            "latest_scan": index[0]["scan_date_display"] if index else "N/A",
        }

    def export_report_csv(self, report_id: str) -> Optional[str]:
        """Export a report's findings as CSV. Returns file path."""
        report = self.load_report(report_id)
        if not report:
            return None

        import csv

        findings = self._extract_all_findings(report.get("results", {}))
        csv_path = self.reports_dir / f"{report_id}_findings.csv"

        with open(csv_path, "w", newline="", encoding="utf-8") as fh:
            if findings:
                writer = csv.DictWriter(fh, fieldnames=findings[0].keys())
                writer.writeheader()
                writer.writerows(findings)

        return str(csv_path)

    @staticmethod
    def _extract_all_findings(results: Dict) -> List[Dict]:
        """Extract all vulnerability findings from results."""
        all_findings = []

        vuln_findings = results.get("vulnerability_findings", {})
        if isinstance(vuln_findings, dict):
            for category, findings in vuln_findings.items():
                if isinstance(findings, list):
                    for f in findings:
                        if isinstance(f, dict) and "severity" in f:
                            f["category"] = category
                            all_findings.append(f)

        # Also check top-level vuln_ keys
        for key, value in results.items():
            if key.startswith("vuln_") and isinstance(value, list):
                for f in value:
                    if isinstance(f, dict) and "severity" in f:
                        if f not in all_findings:
                            f["category"] = key.replace("vuln_", "")
                            all_findings.append(f)

        return all_findings

    @staticmethod
    def _count_severities(findings: List[Dict]) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity", "INFO").upper()
            counts[sev] = counts.get(sev, 0) + 1
        return counts