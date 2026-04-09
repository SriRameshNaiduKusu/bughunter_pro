"""
BugHunter Pro Dashboard - Metric Card Components
"""

import streamlit as st
from typing import Dict


def render_severity_metrics(severity_counts: Dict[str, int]) -> None:
    """Render severity count metrics in columns."""
    cols = st.columns(5)

    severity_config = [
        ("CRITICAL", "🔴", "Critical"),
        ("HIGH", "🟠", "High"),
        ("MEDIUM", "🟡", "Medium"),
        ("LOW", "🟢", "Low"),
        ("INFO", "🔵", "Info"),
    ]

    for i, (key, emoji, label) in enumerate(severity_config):
        with cols[i]:
            count = severity_counts.get(key, 0)
            st.metric(f"{emoji} {label}", count)


def render_scan_metrics(metadata: Dict) -> None:
    """Render general scan metrics."""
    cols = st.columns(4)

    with cols[0]:
        st.metric("🌐 Subdomains", metadata.get("subdomains_found", 0))
    with cols[1]:
        st.metric("🔧 Technologies", metadata.get("technologies_detected", 0))
    with cols[2]:
        st.metric("📄 Pages Crawled", metadata.get("pages_crawled", 0))
    with cols[3]:
        st.metric("⏱️ Duration", f"{metadata.get('scan_duration_seconds', 0)}s")


def render_global_stats(stats: Dict) -> None:
    """Render global statistics across all scans."""
    cols = st.columns(4)

    with cols[0]:
        st.metric("📊 Total Scans", stats.get("total_reports", 0))
    with cols[1]:
        st.metric("🌐 Domains Scanned", stats.get("unique_domains", 0))
    with cols[2]:
        st.metric("🔓 Total Findings", stats.get("total_findings", 0))
    with cols[3]:
        st.metric("📅 Latest Scan", stats.get("latest_scan", "N/A"))