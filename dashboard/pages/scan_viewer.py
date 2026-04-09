"""
BugHunter Pro Dashboard - Individual Scan Report Viewer
"""

import streamlit as st
import json
from dashboard.utils.report_manager import (
    load_report, delete_report, export_csv, get_domain_reports,
)
from dashboard.utils.data_processor import (
    extract_findings, findings_to_dataframe, severity_chart_data,
    vulnerability_type_chart_data, technology_data,
    subdomain_category_data,
)
from dashboard.components.charts import (
    severity_donut_chart, vulnerability_type_bar_chart, risk_gauge_chart,
)
from dashboard.components.metrics import (
    render_severity_metrics, render_scan_metrics,
)
from dashboard.components.tables import findings_table


def render(nav_state: dict) -> None:
    """Render the scan report viewer page."""
    st.title("🔍 Scan Report Viewer")

    report_id = nav_state.get("selected_report_id")
    if not report_id:
        st.warning("Select a report from the sidebar to view it.")
        return

    report = load_report(report_id)
    if not report:
        st.error(f"Report '{report_id}' not found.")
        return

    metadata = report.get("metadata", {})
    results = report.get("results", {})

    # Header
    st.markdown(f"## 🌐 {metadata.get('domain', 'Unknown')}")
    st.caption(
        f"Scanned on {metadata.get('scan_date_display', 'N/A')} | "
        f"Duration: {metadata.get('scan_duration_seconds', 0)}s | "
        f"Tor: {'✅' if metadata.get('tor_used') else '❌'} | "
        f"Industry: {metadata.get('industry', 'N/A').title()}"
    )

    # Action buttons
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        if st.button("📥 Export JSON"):
            st.download_button(
                "Download JSON",
                data=json.dumps(report, indent=2, default=str),
                file_name=f"{report_id}.json",
                mime="application/json",
            )
    with col2:
        if st.button("📥 Export CSV"):
            csv_path = export_csv(report_id)
            if csv_path:
                with open(csv_path, "r") as f:
                    st.download_button(
                        "Download CSV", data=f.read(),
                        file_name=f"{report_id}.csv", mime="text/csv",
                    )
    with col3:
        pass
    with col4:
        if st.button("🗑️ Delete Report", type="secondary"):
            if delete_report(report_id):
                st.success("Report deleted!")
                st.rerun()

    st.markdown("---")

    # Scan metrics
    render_scan_metrics(metadata)
    st.markdown("---")

    # Severity overview
    st.subheader("🎯 Severity Overview")
    severity_counts = metadata.get("severity_counts", {})
    render_severity_metrics(severity_counts)

    # Charts
    chart_col1, chart_col2, chart_col3 = st.columns(3)

    with chart_col1:
        st.plotly_chart(
            severity_donut_chart(severity_counts),
            use_container_width=True,
        )

    with chart_col2:
        findings = extract_findings(report)
        type_counts = vulnerability_type_chart_data(findings)
        st.plotly_chart(
            vulnerability_type_bar_chart(type_counts),
            use_container_width=True,
        )

    with chart_col3:
        risk_score = metadata.get("risk_score", 0)
        st.plotly_chart(
            risk_gauge_chart(risk_score),
            use_container_width=True,
        )

    st.markdown("---")

    # Findings table
    st.subheader(f"🔓 Vulnerability Findings ({metadata.get('total_findings', 0)})")
    df = findings_to_dataframe(findings)
    findings_table(df)

    st.markdown("---")

    # Subdomains
    subdomains = results.get("subdomains", [])
    if subdomains:
        with st.expander(
            f"🌐 Subdomains ({len(subdomains)})", expanded=False
        ):
            cols = st.columns(3)
            for i, sub in enumerate(subdomains):
                with cols[i % 3]:
                    st.code(sub)

    # Technologies
    technologies = results.get("technologies", {})
    if technologies:
        with st.expander("🔧 Detected Technologies", expanded=False):
            tech_df = technology_data(technologies)
            if not tech_df.empty:
                st.dataframe(tech_df, use_container_width=True)

    # DNS Records
    dns_records = results.get("dns_records", {})
    if dns_records:
        with st.expander("📡 DNS Records", expanded=False):
            for rtype, records in dns_records.items():
                st.markdown(f"**{rtype}:**")
                if isinstance(records, list):
                    for r in records:
                        st.code(str(r))
                else:
                    st.code(str(records))

    # Intelligence
    intel = results.get("intelligence", {})
    if intel and isinstance(intel, dict):
        with st.expander("🎯 Target Intelligence", expanded=False):
            st.json(intel)

    # Shodan
    shodan_data = results.get("shodan_data", {})
    if shodan_data and isinstance(shodan_data, dict):
        with st.expander("🔭 Shodan Data", expanded=False):
            st.json(shodan_data)

    # WHOIS
    whois_data = results.get("whois_data", {})
    if whois_data and isinstance(whois_data, dict):
        with st.expander("📋 WHOIS Data", expanded=False):
            st.json(whois_data)