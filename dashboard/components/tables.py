"""
BugHunter Pro Dashboard - Table Components
"""

import streamlit as st
import pandas as pd
from typing import List, Dict


SEVERITY_BADGES = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "INFO": "🔵",
}


def findings_table(df: pd.DataFrame, page_size: int = 25) -> None:
    """Render a paginated, filterable findings table."""
    if df.empty:
        st.info("No findings to display.")
        return

    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        severity_filter = st.multiselect(
            "Filter Severity",
            options=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            default=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        )
    with col2:
        type_options = sorted(df["Type"].unique().tolist())
        type_filter = st.multiselect(
            "Filter Type",
            options=type_options,
            default=type_options,
        )
    with col3:
        search_term = st.text_input("🔍 Search", "")

    # Apply filters
    filtered = df[
        df["Severity"].isin(severity_filter) & df["Type"].isin(type_filter)
    ]

    if search_term:
        mask = filtered.apply(
            lambda row: search_term.lower() in str(row).lower(), axis=1
        )
        filtered = filtered[mask]

    # Add badges
    display_df = filtered.copy()
    display_df["Severity"] = display_df["Severity"].apply(
        lambda s: f"{SEVERITY_BADGES.get(s, '')} {s}"
    )

    # Pagination
    total_rows = len(display_df)
    total_pages = max(1, (total_rows + page_size - 1) // page_size)

    if total_pages > 1:
        page = st.number_input(
            f"Page (1-{total_pages})",
            min_value=1, max_value=total_pages, value=1,
        )
    else:
        page = 1

    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    page_df = display_df.iloc[start_idx:end_idx]

    st.dataframe(
        page_df,
        use_container_width=True,
        height=min(800, 40 + len(page_df) * 35),
    )

    st.caption(
        f"Showing {start_idx + 1}-{min(end_idx, total_rows)} "
        f"of {total_rows} findings"
    )


def reports_table(reports: List[Dict]) -> None:
    """Render a table of scan reports."""
    if not reports:
        st.info("No reports available.")
        return

    rows = []
    for r in reports:
        sc = r.get("severity_counts", {})
        rows.append({
            "Domain": r.get("domain", ""),
            "Date": r.get("scan_date_display", ""),
            "Findings": r.get("total_findings", 0),
            "🔴 Crit": sc.get("CRITICAL", 0),
            "🟠 High": sc.get("HIGH", 0),
            "🟡 Med": sc.get("MEDIUM", 0),
            "Risk": r.get("risk_score", 0),
            "Subdomains": r.get("subdomains_found", 0),
            "Tor": "✅" if r.get("tor_used") else "❌",
            "Duration": f"{r.get('scan_duration_seconds', 0)}s",
        })

    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True)