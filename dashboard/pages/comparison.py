"""
BugHunter Pro Dashboard - Scan Comparison Page
"""

import streamlit as st
import pandas as pd
from dashboard.utils.report_manager import (
    list_all_reports, load_report,
)
from dashboard.utils.data_processor import (
    extract_findings, severity_chart_data, findings_to_dataframe,
)
from dashboard.components.charts import (
    comparison_radar_chart, severity_donut_chart,
)
from dashboard.components.metrics import render_severity_metrics


def render(nav_state: dict) -> None:
    """Render the scan comparison page."""
    st.title("📊 Compare Scans")

    reports = list_all_reports()

    if len(reports) < 2:
        st.warning(
            "Need at least 2 scan reports to compare. "
            "Run more scans first!"
        )
        return

    report_labels = [
        f"{r['domain']} — {r['scan_date_display']}" for r in reports
    ]

    # Selection
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📋 Report A")
        label_a = st.selectbox(
            "Select first report",
            report_labels,
            index=0,
            key="compare_a",
        )

    with col2:
        st.subheader("📋 Report B")
        default_b = min(1, len(report_labels) - 1)
        label_b = st.selectbox(
            "Select second report",
            report_labels,
            index=default_b,
            key="compare_b",
        )

    idx_a = report_labels.index(label_a)
    idx_b = report_labels.index(label_b)

    meta_a = reports[idx_a]
    meta_b = reports[idx_b]

    if meta_a["report_id"] == meta_b["report_id"]:
        st.warning("Please select two different reports to compare.")
        return

    st.markdown("---")

    # Radar comparison
    st.subheader("🎯 Radar Comparison")
    radar_fig = comparison_radar_chart(meta_a, meta_b)
    st.plotly_chart(radar_fig, use_container_width=True)

    st.markdown("---")

    # Side-by-side metrics
    st.subheader("📊 Side-by-Side Metrics")

    metrics_to_compare = [
        ("Total Findings", "total_findings"),
        ("Subdomains", "subdomains_found"),
        ("Technologies", "technologies_detected"),
        ("Pages Crawled", "pages_crawled"),
        ("Risk Score", "risk_score"),
        ("Duration (s)", "scan_duration_seconds"),
    ]

    header_cols = st.columns([2, 1, 1, 1])
    with header_cols[0]:
        st.markdown("**Metric**")
    with header_cols[1]:
        st.markdown(f"**{meta_a['domain']}** ({meta_a.get('scan_date_display', '')[:10]})")
    with header_cols[2]:
        st.markdown(f"**{meta_b['domain']}** ({meta_b.get('scan_date_display', '')[:10]})")
    with header_cols[3]:
        st.markdown("**Delta**")

    for label, key in metrics_to_compare:
        val_a = meta_a.get(key, 0)
        val_b = meta_b.get(key, 0)
        delta = val_b - val_a

        row_cols = st.columns([2, 1, 1, 1])
        with row_cols[0]:
            st.markdown(label)
        with row_cols[1]:
            st.markdown(str(val_a))
        with row_cols[2]:
            st.markdown(str(val_b))
        with row_cols[3]:
            if delta > 0:
                st.markdown(f"🔺 +{delta}")
            elif delta < 0:
                st.markdown(f"🔻 {delta}")
            else:
                st.markdown("➖ 0")

    st.markdown("---")

    # Severity comparison
    st.subheader("🎯 Severity Comparison")

    sev_col1, sev_col2 = st.columns(2)

    with sev_col1:
        st.markdown(f"**{meta_a['domain']}**")
        sev_a = meta_a.get("severity_counts", {})
        render_severity_metrics(sev_a)
        st.plotly_chart(
            severity_donut_chart(sev_a), use_container_width=True,
        )

    with sev_col2:
        st.markdown(f"**{meta_b['domain']}**")
        sev_b = meta_b.get("severity_counts", {})
        render_severity_metrics(sev_b)
        st.plotly_chart(
            severity_donut_chart(sev_b), use_container_width=True,
        )

    st.markdown("---")

    # Unique findings comparison
    st.subheader("🔍 Findings Comparison")

    report_a = load_report(meta_a["report_id"])
    report_b = load_report(meta_b["report_id"])

    if report_a and report_b:
        findings_a = extract_findings(report_a)
        findings_b = extract_findings(report_b)

        types_a = set(f.get("type", "") for f in findings_a)
        types_b = set(f.get("type", "") for f in findings_b)

        only_a = types_a - types_b
        only_b = types_b - types_a
        common = types_a & types_b

        cmp_col1, cmp_col2, cmp_col3 = st.columns(3)

        with cmp_col1:
            st.markdown(f"**Only in {meta_a['domain']}:**")
            if only_a:
                for t in sorted(only_a):
                    st.markdown(f"- 🟡 {t}")
            else:
                st.info("None")

        with cmp_col2:
            st.markdown("**Common:**")
            if common:
                for t in sorted(common):
                    st.markdown(f"- 🔵 {t}")
            else:
                st.info("None")

        with cmp_col3:
            st.markdown(f"**Only in {meta_b['domain']}:**")
            if only_b:
                for t in sorted(only_b):
                    st.markdown(f"- 🟡 {t}")
            else:
                st.info("None")