"""
BugHunter Pro Dashboard - Settings Page
"""

import os
import streamlit as st
from pathlib import Path
from dashboard.utils.report_manager import (
    list_all_reports, get_domains, delete_report, get_report_store,
)
from bughunter_pro.reporting.report_store import DEFAULT_REPORTS_DIR


def render(nav_state: dict) -> None:
    """Render the settings page."""
    st.title("⚙️ Settings")

    # Report Storage
    st.subheader("📂 Report Storage")

    reports_dir = DEFAULT_REPORTS_DIR
    dir_size = _get_dir_size(reports_dir)
    total_reports = len(list_all_reports())

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Storage Location", reports_dir)
    with col2:
        st.metric("Total Reports", total_reports)
    with col3:
        st.metric("Storage Size", f"{dir_size:.1f} MB")

    st.markdown("---")

    # Import report
    st.subheader("📥 Import Report")
    st.markdown(
        "Upload a BugHunter Pro JSON report to add it to the dashboard."
    )

    uploaded_file = st.file_uploader(
        "Upload JSON Report",
        type=["json"],
        help="Upload a BugHunter Pro scan report JSON file",
    )

    if uploaded_file is not None:
        try:
            import json
            report_data = json.loads(uploaded_file.read())

            # Validate structure
            if "results" in report_data or "meta" in report_data:
                results = report_data.get("results", report_data)
                meta = report_data.get("meta", {})
                domain = meta.get("target", "imported_domain")

                store = get_report_store()
                report_id = store.save_report(
                    domain=domain,
                    scan_results=results,
                )
                st.success(f"Report imported successfully! ID: {report_id}")
                st.rerun()
            else:
                st.error(
                    "Invalid report format. "
                    "Expected BugHunter Pro JSON structure."
                )
        except Exception as e:
            st.error(f"Import failed: {e}")

    st.markdown("---")

    # Manage reports
    st.subheader("🗑️ Manage Reports")

    reports = list_all_reports()
    if not reports:
        st.info("No reports to manage.")
        return

    # Delete by domain
    st.markdown("**Delete all reports for a domain:**")
    domains = get_domains()
    if domains:
        domain_to_delete = st.selectbox(
            "Select domain", domains, key="delete_domain",
        )
        if st.button(
            f"Delete all reports for {domain_to_delete}",
            type="secondary",
        ):
            store = get_report_store()
            count = store.delete_domain_reports(domain_to_delete)
            st.success(f"Deleted {count} reports for {domain_to_delete}")
            st.rerun()

    st.markdown("---")

    # Delete individual reports
    st.markdown("**Delete individual reports:**")

    for report in reports[:50]:
        col_info, col_btn = st.columns([4, 1])
        with col_info:
            st.text(
                f"{report['domain']} | "
                f"{report.get('scan_date_display', 'N/A')} | "
                f"{report.get('total_findings', 0)} findings"
            )
        with col_btn:
            if st.button(
                "🗑️", key=f"del_{report['report_id']}",
                help=f"Delete {report['report_id']}",
            ):
                delete_report(report["report_id"])
                st.rerun()

    st.markdown("---")

    # Danger zone
    st.subheader("⚠️ Danger Zone")
    st.warning("These actions are irreversible!")

    if st.button("🗑️ Delete ALL Reports", type="secondary"):
        confirm = st.checkbox(
            "I understand this will delete all scan reports permanently"
        )
        if confirm:
            store = get_report_store()
            for report in reports:
                store.delete_report(report["report_id"])
            st.success("All reports deleted.")
            st.rerun()

    st.markdown("---")

    # About
    st.subheader("ℹ️ About")
    st.markdown("""
    **BugHunter Pro** v1.0.0

    Comprehensive Security Reconnaissance & Vulnerability Scanner

    Developed as an academic project for the
    **University of Hertfordshire — Cyber Security Programme**

    **Features:**
    - Subdomain enumeration (DNS brute-force, crt.sh, ThreatCrowd)
    - Technology fingerprinting (60+ signatures)
    - Web crawling (links, forms, JS files, parameters)
    - SQL Injection, XSS, SSRF, CORS, CRLF, Open Redirect scanning
    - Cloud storage misconfiguration detection
    - Directory & API endpoint brute-forcing (SecLists)
    - Target intelligence & industry detection
    - Tor integration for anonymous scanning
    - Interactive Streamlit dashboard

    **License:** MIT
    """)

    # System info
    with st.expander("🖥️ System Information"):
        import platform
        import sys

        st.code(f"""
Platform:   {platform.system()} {platform.release()}
Python:     {sys.version}
Reports:    {reports_dir}
SecLists:   {_check_seclists()}
        """)


def _get_dir_size(path: str) -> float:
    """Get directory size in MB."""
    total = 0
    try:
        for dirpath, dirnames, filenames in os.walk(path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                if os.path.isfile(fp):
                    total += os.path.getsize(fp)
    except Exception:
        pass
    return total / (1024 * 1024)


def _check_seclists() -> str:
    """Check if SecLists is installed."""
    try:
        from bughunter_pro.installer import SECLISTS_DIR
        if SECLISTS_DIR.exists():
            return f"Installed at {SECLISTS_DIR}"
        return "Not installed (run: bughunter-install)"
    except ImportError:
        return "Unknown"