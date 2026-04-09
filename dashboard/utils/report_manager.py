"""
BugHunter Pro Dashboard - Report Manager

Bridges the Streamlit dashboard with the ReportStore backend.
Handles caching, pagination, and data preparation.
"""

import streamlit as st
from typing import Dict, List, Optional
from bughunter_pro.reporting.report_store import ReportStore


@st.cache_resource
def get_report_store() -> ReportStore:
    """Get or create a singleton ReportStore instance."""
    return ReportStore()


def list_all_reports() -> List[Dict]:
    """Get all report metadata, sorted newest first."""
    store = get_report_store()
    return store.list_reports()


def get_domains() -> List[str]:
    """Get list of unique scanned domains."""
    store = get_report_store()
    return store.get_unique_domains()


def get_domain_reports(domain: str) -> List[Dict]:
    """Get reports for a specific domain."""
    store = get_report_store()
    return store.list_reports_by_domain(domain)


def load_report(report_id: str) -> Optional[Dict]:
    """Load a full report by ID."""
    store = get_report_store()
    return store.load_report(report_id)


def load_latest_report(domain: str) -> Optional[Dict]:
    """Load the latest report for a domain."""
    store = get_report_store()
    return store.load_latest_report(domain)


def delete_report(report_id: str) -> bool:
    """Delete a report by ID."""
    store = get_report_store()
    return store.delete_report(report_id)


def get_global_stats() -> Dict:
    """Get aggregate statistics across all scans."""
    store = get_report_store()
    return store.get_report_stats()


def export_csv(report_id: str) -> Optional[str]:
    """Export a report as CSV."""
    store = get_report_store()
    return store.export_report_csv(report_id)