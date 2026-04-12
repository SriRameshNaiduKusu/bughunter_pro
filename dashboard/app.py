#!/usr/bin/env python3
"""
BugHunter Pro - Streamlit Dashboard Application

Launch with:
    streamlit run dashboard/app.py
    OR
    bughunter-dashboard
"""

import sys
import os
import streamlit as st

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def configure_page():
    """Configure the Streamlit page settings."""
    st.set_page_config(
        page_title="BugHunter Pro Dashboard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
        menu_items={
            "Get Help": "https://github.com/SriRameshNaiduKusu/bughunter_pro",
            "Report a Bug": "https://github.com/SriRameshNaiduKusu/bughunter_pro/issues",
            "About": (
                "BugHunter Pro v1.0 — Comprehensive Security "
                "Reconnaissance & Vulnerability Scanner\n\n"
            ),
        },
    )


def inject_custom_css():
    """Inject custom CSS for dark theme consistency."""
    st.markdown("""
    <style>
        /* Dark theme overrides */
        .stApp {
            background-color: #0d1117;
        }

        section[data-testid="stSidebar"] {
            background-color: #161b22;
            border-right: 1px solid #30363d;
        }

        .stMetric {
            background-color: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 16px;
        }

        .stExpander {
            background-color: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
        }

        div[data-testid="stDataFrame"] {
            border: 1px solid #30363d;
            border-radius: 8px;
        }

        .stTabs [data-baseweb="tab-list"] {
            background-color: #161b22;
        }

        /* Code blocks */
        .stCodeBlock {
            background-color: #161b22 !important;
        }

        /* Links */
        a { color: #58a6ff; }
        a:hover { color: #79c0ff; }

        /* Badge-like metric styling */
        [data-testid="stMetricValue"] {
            font-size: 1.8rem;
        }

        /* Custom scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        ::-webkit-scrollbar-track {
            background: #0d1117;
        }
        ::-webkit-scrollbar-thumb {
            background: #30363d;
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: #484f58;
        }

        /* Hide Streamlit branding */
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        header {visibility: hidden;}
    </style>
    """, unsafe_allow_html=True)


def render_page(page_name: str, nav_state: dict) -> None:
    """Route to the appropriate page renderer."""
    if page_name == "overview":
        from dashboard.pages.overview import render
        render(nav_state)

    elif page_name == "scan_viewer":
        from dashboard.pages.scan_viewer import render
        render(nav_state)

    elif page_name == "vulnerability_explorer":
        from dashboard.pages.vulnerability_explorer import render
        render(nav_state)

    elif page_name == "attack_surface":
        from dashboard.pages.attack_surface import render
        render(nav_state)

    elif page_name == "comparison":
        from dashboard.pages.comparison import render
        render(nav_state)

    elif page_name == "settings":
        from dashboard.pages.settings import render
        render(nav_state)

    else:
        st.error(f"Unknown page: {page_name}")


def run_dashboard():
    """Main dashboard entry point."""
    configure_page()
    inject_custom_css()

    from dashboard.components.sidebar import render_sidebar
    nav_state = render_sidebar()

    render_page(nav_state["page"], nav_state)


def main():
    """Entry point for the bughunter-dashboard command."""
    import subprocess
    import sys

    app_path = os.path.abspath(__file__)

    cmd = [
        sys.executable, "-m", "streamlit", "run",
        app_path,
        "--server.headless=true",
        "--server.port=8501",
        "--browser.gatherUsageStats=false",
        "--theme.base=dark",
        "--theme.primaryColor=#58a6ff",
        "--theme.backgroundColor=#0d1117",
        "--theme.secondaryBackgroundColor=#161b22",
        "--theme.textColor=#c9d1d9",
    ]

    print("\n🛡️  BugHunter Pro Dashboard")
    print("=" * 50)
    print(f"  URL: http://localhost:8501")
    print(f"  Press Ctrl+C to stop")
    print("=" * 50 + "\n")

    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n\nDashboard stopped.")
        sys.exit(0)


# This is called by Streamlit when running the file directly
if __name__ == "__main__":
    # Check if we're being run by Streamlit
    if "streamlit" in sys.modules:
        run_dashboard()
    else:
        main()
else:
    # Being imported by Streamlit
    run_dashboard()