"""
BugHunter Pro Dashboard - Data Processing Utilities

Transforms raw report data into structures suitable for
Plotly charts, Streamlit tables, and graph visualizations.
"""

import pandas as pd
from typing import Dict, List, Optional, Any
from datetime import datetime


def extract_findings(report: Dict) -> List[Dict]:
    """Extract all vulnerability findings from a report."""
    results = report.get("results", {})
    all_findings = []

    vuln_data = results.get("vulnerability_findings", {})
    if isinstance(vuln_data, dict):
        for category, findings in vuln_data.items():
            if isinstance(findings, list):
                for f in findings:
                    if isinstance(f, dict):
                        f_copy = f.copy()
                        f_copy["category"] = category
                        all_findings.append(f_copy)

    for key, value in results.items():
        if key.startswith("vuln_") and isinstance(value, list):
            for f in value:
                if isinstance(f, dict) and f not in all_findings:
                    f_copy = f.copy()
                    f_copy["category"] = key.replace("vuln_", "")
                    all_findings.append(f_copy)

    return all_findings


def findings_to_dataframe(findings: List[Dict]) -> pd.DataFrame:
    """Convert findings list to a pandas DataFrame."""
    if not findings:
        return pd.DataFrame()

    rows = []
    for f in findings:
        rows.append({
            "Severity": f.get("severity", "INFO"),
            "Type": f.get("type", "Unknown"),
            "URL": f.get("url", "N/A"),
            "Parameter": f.get("parameter", ""),
            "Evidence": f.get("evidence", f.get("description", "")),
            "Method": f.get("method", ""),
            "Category": f.get("category", ""),
        })

    df = pd.DataFrame(rows)
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    df["Severity"] = pd.Categorical(
        df["Severity"], categories=severity_order, ordered=True
    )
    df = df.sort_values("Severity")
    return df


def severity_chart_data(findings: List[Dict]) -> Dict[str, int]:
    """Prepare severity counts for chart display."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def vulnerability_type_chart_data(findings: List[Dict]) -> Dict[str, int]:
    """Prepare vulnerability type counts for chart display."""
    types = {}
    for f in findings:
        vtype = f.get("type", "Unknown")
        types[vtype] = types.get(vtype, 0) + 1
    return dict(sorted(types.items(), key=lambda x: x[1], reverse=True))


def timeline_data(reports: List[Dict]) -> pd.DataFrame:
    """Prepare scan timeline data for line charts."""
    rows = []
    for r in reports:
        rows.append({
            "Date": r.get("scan_date_display", ""),
            "Domain": r.get("domain", ""),
            "Total Findings": r.get("total_findings", 0),
            "Critical": r.get("severity_counts", {}).get("CRITICAL", 0),
            "High": r.get("severity_counts", {}).get("HIGH", 0),
            "Medium": r.get("severity_counts", {}).get("MEDIUM", 0),
            "Risk Score": r.get("risk_score", 0),
        })
    return pd.DataFrame(rows)


def subdomain_category_data(intel: Dict) -> pd.DataFrame:
    """Prepare subdomain analysis data."""
    analysis = intel.get("subdomain_analysis", [])
    if not analysis:
        return pd.DataFrame()

    rows = []
    for a in analysis:
        rows.append({
            "Subdomain": a.get("subdomain", ""),
            "Category": a.get("category", "").title(),
            "Risk Level": a.get("risk_level", "INFO"),
        })
    return pd.DataFrame(rows)


def technology_data(technologies: Dict) -> pd.DataFrame:
    """Prepare technology data for display."""
    rows = []
    if isinstance(technologies, dict):
        for category, tech_list in technologies.items():
            if isinstance(tech_list, list):
                for tech in tech_list:
                    rows.append({
                        "Category": category.replace("_", " ").title(),
                        "Technology": tech,
                    })
    return pd.DataFrame(rows)


def build_graph_nodes_edges(report: Dict) -> tuple:
    """
    Build nodes and edges for streamlit-agraph from report data.
    Returns (nodes_list, edges_list) compatible with agraph.
    """
    try:
        from streamlit_agraph import Node, Edge

        results = report.get("results", {})
        intel = results.get("intelligence", {})
        domain = report.get("metadata", {}).get("domain", "target")
        subdomains = results.get("subdomains", [])
        technologies = results.get("technologies", {})

        nodes = []
        edges = []

        color_map = {
            "root": "#58a6ff",
            "subdomain": "#79c0ff",
            "technology": "#bc8cff",
            "category": "#d29922",
            "vulnerability": "#f85149",
            "info": "#8b949e",
        }

        # Root node
        nodes.append(Node(
            id="root",
            label=domain,
            size=40,
            color=color_map["root"],
            font={"color": "#ffffff"},
        ))

        # Subdomains (limit to 50)
        for i, sub in enumerate(subdomains[:50]):
            node_id = f"sub_{i}"
            risk_color = color_map["subdomain"]
            for analysis in intel.get("subdomain_analysis", []):
                if analysis["subdomain"] == sub:
                    risk = analysis.get("risk_level", "INFO")
                    if risk == "CRITICAL":
                        risk_color = "#f85149"
                    elif risk == "HIGH":
                        risk_color = "#f0883e"
                    elif risk == "MEDIUM":
                        risk_color = "#d29922"
                    break

            nodes.append(Node(
                id=node_id,
                label=sub.replace(f".{domain}", ""),
                size=15,
                color=risk_color,
                font={"color": "#c9d1d9"},
            ))
            edges.append(Edge(source="root", target=node_id))

        # Technologies
        for cat, tech_list in technologies.items():
            if not isinstance(tech_list, list):
                continue
            cat_id = f"techcat_{cat}"
            nodes.append(Node(
                id=cat_id,
                label=cat.replace("_", " ").title(),
                size=20,
                color=color_map["category"],
                font={"color": "#c9d1d9"},
            ))
            edges.append(Edge(source="root", target=cat_id))

            for j, tech in enumerate(tech_list):
                tech_id = f"tech_{cat}_{j}"
                nodes.append(Node(
                    id=tech_id,
                    label=tech,
                    size=12,
                    color=color_map["technology"],
                    font={"color": "#c9d1d9"},
                ))
                edges.append(Edge(source=cat_id, target=tech_id))

        # Vulnerability summary nodes
        findings = extract_findings(report)
        if findings:
            vuln_root = "vuln_root"
            nodes.append(Node(
                id=vuln_root,
                label=f"Vulnerabilities ({len(findings)})",
                size=25,
                color=color_map["vulnerability"],
                font={"color": "#ffffff"},
            ))
            edges.append(Edge(source="root", target=vuln_root))

            type_counts = vulnerability_type_chart_data(findings)
            for k, (vtype, count) in enumerate(
                list(type_counts.items())[:15]
            ):
                vtype_id = f"vtype_{k}"
                nodes.append(Node(
                    id=vtype_id,
                    label=f"{vtype} ({count})",
                    size=10 + min(count * 2, 20),
                    color=color_map["vulnerability"],
                    font={"color": "#c9d1d9"},
                ))
                edges.append(Edge(source=vuln_root, target=vtype_id))

        return nodes, edges

    except ImportError:
        return [], []