"""
BugHunter Pro Dashboard - Attack Surface Graph Page
"""

import streamlit as st
from dashboard.utils.report_manager import load_report
from dashboard.utils.data_processor import (
    extract_findings, build_graph_nodes_edges,
    subdomain_category_data, vulnerability_type_chart_data,
)
from dashboard.components.metrics import render_severity_metrics


def render(nav_state: dict) -> None:
    """Render the attack surface visualization page."""
    st.title("🕸️ Attack Surface Map")

    report_id = nav_state.get("selected_report_id")
    if not report_id:
        st.warning("Select a report from the sidebar.")
        return

    report = load_report(report_id)
    if not report:
        st.error("Report not found.")
        return

    metadata = report.get("metadata", {})
    results = report.get("results", {})
    intel = results.get("intelligence", {}) if isinstance(results.get("intelligence"), dict) else {}

    st.markdown(
        f"### 🌐 {metadata.get('domain', 'Unknown')} — "
        f"Attack Surface Analysis"
    )
    st.caption(
        f"Scanned: {metadata.get('scan_date_display', 'N/A')} | "
        f"Industry: {intel.get('industry', 'N/A').title()} | "
        f"Risk Score: {intel.get('risk_score', 0)}/100"
    )

    st.markdown("---")

    # Severity overview
    severity_counts = metadata.get("severity_counts", {})
    render_severity_metrics(severity_counts)

    st.markdown("---")

    # Interactive Graph
    st.subheader("🕸️ Interactive Attack Surface Graph")

    try:
        from streamlit_agraph import agraph, Config as AGraphConfig

        nodes, edges = build_graph_nodes_edges(report)

        if nodes:
            # Graph configuration
            graph_config = AGraphConfig(
                width="100%",
                height=650,
                directed=True,
                physics={
                    "enabled": True,
                    "barnesHut": {
                        "gravitationalConstant": -3000,
                        "centralGravity": 0.3,
                        "springLength": 120,
                        "springConstant": 0.04,
                        "damping": 0.09,
                    },
                    "stabilization": {
                        "enabled": True,
                        "iterations": 150,
                    },
                },
                nodeHighlightBehavior=True,
                highlightColor="#58a6ff",
                collapsible=True,
                node={
                    "labelProperty": "label",
                    "renderLabel": True,
                },
                link={
                    "labelProperty": "label",
                    "renderLabel": False,
                    "color": "#30363d",
                    "strokeWidth": 1.5,
                },
            )

            # Graph controls
            ctrl_col1, ctrl_col2, ctrl_col3 = st.columns(3)
            with ctrl_col1:
                physics_enabled = st.checkbox("Enable Physics", value=True)
            with ctrl_col2:
                show_labels = st.checkbox("Show Edge Labels", value=False)
            with ctrl_col3:
                max_nodes = st.slider(
                    "Max Nodes", 10, 200,
                    value=min(100, len(nodes)),
                )

            # Apply controls
            graph_config.physics["enabled"] = physics_enabled
            graph_config.link["renderLabel"] = show_labels

            # Limit nodes if needed
            display_nodes = nodes[:max_nodes]
            display_node_ids = {n.id for n in display_nodes}
            display_edges = [
                e for e in edges
                if e.source in display_node_ids and e.to in display_node_ids
            ]

            agraph(
                nodes=display_nodes,
                edges=display_edges,
                config=graph_config,
            )
        else:
            st.info("No graph data available for this scan.")

    except ImportError:
        st.warning(
            "Install `streamlit-agraph` for interactive graph visualization:\n\n"
            "```bash\npip install streamlit-agraph\n```"
        )
        st.info("Showing text-based attack surface summary instead.")
        _render_text_surface(results, intel)

    except Exception as e:
        st.warning(f"Graph rendering error: {e}")
        st.info("Showing text-based attack surface summary instead.")
        _render_text_surface(results, intel)

    st.markdown("---")

    # Subdomain Analysis
    st.subheader("🏷️ Subdomain Analysis")

    sub_df = subdomain_category_data(intel)
    if not sub_df.empty:
        # Category summary
        category_counts = sub_df["Category"].value_counts()
        cat_cols = st.columns(min(len(category_counts), 5))
        for i, (cat, count) in enumerate(category_counts.items()):
            with cat_cols[i % len(cat_cols)]:
                st.metric(cat, count)

        st.dataframe(sub_df, use_container_width=True)
    else:
        st.info("No subdomain categorization data available.")

    st.markdown("---")

    # Attack Vectors
    st.subheader("🎯 Suggested Attack Vectors")

    vectors = intel.get("attack_vectors", [])
    if vectors:
        for i, vector in enumerate(vectors, 1):
            st.markdown(f"**{i}.** {vector}")
    else:
        st.info("No attack vectors suggested for this target.")

    st.markdown("---")

    # Recommendations
    st.subheader("📋 Security Recommendations")

    recommendations = intel.get("recommendations", [])
    if recommendations:
        for rec in recommendations:
            priority = rec.get("priority", "INFO")
            emoji = {
                "CRITICAL": "🔴", "HIGH": "🟠",
                "MEDIUM": "🟡", "LOW": "🟢",
            }.get(priority, "🔵")
            st.markdown(f"{emoji} **[{priority}]** {rec.get('text', '')}")
    else:
        st.info("No specific recommendations generated.")

    # Technology Insights
    tech_insights = intel.get("technology_insights", [])
    if tech_insights:
        st.markdown("---")
        st.subheader("🔧 Technology-Specific Attack Vectors")
        for insight in tech_insights:
            tech_name = insight.get("technology", "Unknown")
            vectors = insight.get("attack_vectors", [])
            if vectors:
                with st.expander(f"🔧 {tech_name}"):
                    for v in vectors:
                        st.markdown(f"- {v}")


def _render_text_surface(results: dict, intel: dict) -> None:
    """Fallback text-based attack surface rendering."""
    subdomains = results.get("subdomains", [])
    technologies = results.get("technologies", {})

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**Subdomains:**")
        if subdomains:
            for sub in subdomains[:30]:
                st.code(sub)
            if len(subdomains) > 30:
                st.caption(f"... and {len(subdomains) - 30} more")
        else:
            st.info("No subdomains found.")

    with col2:
        st.markdown("**Technologies:**")
        if technologies:
            for cat, tech_list in technologies.items():
                if isinstance(tech_list, list):
                    st.markdown(f"*{cat}:* {', '.join(tech_list)}")
        else:
            st.info("No technologies detected.")