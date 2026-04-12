"""
BugHunter Pro Dashboard - Navigation Sidebar
"""

import streamlit as st
from dashboard.utils.report_manager import get_domains, list_all_reports


def render_sidebar() -> dict:
    """
    Render the navigation sidebar.
    Returns a dict with the user's current selections.
    """
    st.sidebar.image(
        "https://img.icons8.com/fluency/96/shield.png",
        width=60,
    )
    st.sidebar.title("🛡️ BugHunter Pro")
    st.sidebar.caption("Security Recon & Scanner Dashboard")
    st.sidebar.markdown("---")

    # Navigation
    pages = {
        "🏠 Overview": "overview",
        "🔍 Scan Reports": "scan_viewer",
        "🔓 Vulnerabilities": "vulnerability_explorer",
        "🕸️ Attack Surface": "attack_surface",
        "📊 Compare Scans": "comparison",
        "⚙️ Settings": "settings",
    }

    selected_page = st.sidebar.radio(
        "Navigation",
        list(pages.keys()),
        label_visibility="collapsed",
    )

    st.sidebar.markdown("---")

    # Domain filter
    domains = get_domains()
    selected_domain = None

    if domains:
        domain_options = ["All Domains"] + domains
        selected_domain = st.sidebar.selectbox(
            "🌐 Filter by Domain",
            domain_options,
        )
        if selected_domain == "All Domains":
            selected_domain = None
    else:
        st.sidebar.info("No scan reports yet. Run a scan first!")

    # Report selector
    reports = list_all_reports()
    selected_report_id = None

    if reports:
        if selected_domain:
            reports = [
                r for r in reports if r["domain"] == selected_domain
            ]

        if reports:
            report_labels = [
                f"{r['domain']} — {r['scan_date_display']}"
                for r in reports
            ]
            selected_label = st.sidebar.selectbox(
                "📋 Select Report",
                report_labels,
            )
            idx = report_labels.index(selected_label)
            selected_report_id = reports[idx]["report_id"]

    st.sidebar.markdown("---")

    # Quick stats
    if reports:
        total = len(list_all_reports())
        st.sidebar.metric("Total Scans", total)
        st.sidebar.metric("Domains Scanned", len(get_domains()))

    st.sidebar.markdown("---")
    st.sidebar.markdown(
        "<small>Cyber Security Project</small>",
        unsafe_allow_html=True,
    )

    return {
        "page": pages[selected_page],
        "selected_domain": selected_domain,
        "selected_report_id": selected_report_id,
    }