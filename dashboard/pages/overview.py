"""
BugHunter Pro Dashboard - Overview Page
"""

import streamlit as st
from dashboard.utils.report_manager import (
    list_all_reports, get_global_stats, get_domains,
)
from dashboard.utils.data_processor import (
    severity_chart_data, timeline_data, extract_findings,
)
from dashboard.components.charts import (
    severity_donut_chart, timeline_chart,
)
from dashboard.components.metrics import (
    render_global_stats, render_severity_metrics,
)
from dashboard.components.tables import reports_table


def render(nav_state: dict) -> None:
    """Render the overview dashboard page."""
    st.title("🏠 Dashboard Overview")
    st.markdown("---")

    stats = get_global_stats()
    render_global_stats(stats)

    st.markdown("---")

    if stats["total_reports"] == 0:
        st.warning(
            "No scan reports found. Run a scan to get started:\n\n"
            "```bash\nbughunter -d example.com --tor\n```"
        )
        return

    # Aggregate severity chart
    agg_severity = stats.get("aggregate_severity", {})
    render_severity_metrics(agg_severity)

    st.markdown("---")

    # Charts row
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📊 Overall Severity Distribution")
        fig = severity_donut_chart(agg_severity)
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("📈 Scan Timeline")
        reports = list_all_reports()
        tl_data = timeline_data(reports)
        if not tl_data.empty:
            fig = timeline_chart(tl_data)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Run multiple scans to see timeline data.")

    st.markdown("---")

    # Scanned domains summary
    st.subheader("🌐 Scanned Domains")
    domains = get_domains()
    if domains:
        domain_cols = st.columns(min(len(domains), 4))
        for i, domain in enumerate(domains):
            with domain_cols[i % len(domain_cols)]:
                from dashboard.utils.report_manager import get_domain_reports
                domain_reports = get_domain_reports(domain)
                latest = domain_reports[0] if domain_reports else {}
                risk = latest.get("risk_score", 0)

                if risk >= 70:
                    risk_emoji = "🔴"
                elif risk >= 40:
                    risk_emoji = "🟡"
                else:
                    risk_emoji = "🟢"

                st.markdown(
                    f"### {risk_emoji} {domain}\n"
                    f"- **Scans:** {len(domain_reports)}\n"
                    f"- **Latest Risk:** {risk}/100\n"
                    f"- **Findings:** {latest.get('total_findings', 0)}"
                )

    st.markdown("---")

    # Recent scans table
    st.subheader("📋 Recent Scans")
    reports = list_all_reports()[:20]
    reports_table(reports)