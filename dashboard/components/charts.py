"""
BugHunter Pro Dashboard - Chart Components
"""

import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import pandas as pd
from typing import Dict, List


SEVERITY_COLORS = {
    "CRITICAL": "#f85149",
    "HIGH": "#f0883e",
    "MEDIUM": "#d29922",
    "LOW": "#3fb950",
    "INFO": "#58a6ff",
}


def severity_donut_chart(severity_counts: Dict[str, int]) -> go.Figure:
    """Create a donut chart for severity distribution."""
    labels = list(severity_counts.keys())
    values = list(severity_counts.values())
    colors = [SEVERITY_COLORS.get(s, "#8b949e") for s in labels]

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.5,
        marker=dict(colors=colors),
        textinfo="label+value",
        textfont=dict(size=12, color="white"),
    )])

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#c9d1d9"),
        margin=dict(l=20, r=20, t=30, b=20),
        height=350,
        legend=dict(font=dict(color="#c9d1d9")),
    )
    return fig


def vulnerability_type_bar_chart(type_counts: Dict[str, int]) -> go.Figure:
    """Create a horizontal bar chart for vulnerability types."""
    types = list(type_counts.keys())[:15]
    counts = [type_counts[t] for t in types]

    fig = go.Figure(data=[go.Bar(
        x=counts,
        y=types,
        orientation="h",
        marker_color="#58a6ff",
        text=counts,
        textposition="auto",
    )])

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#c9d1d9"),
        margin=dict(l=20, r=20, t=30, b=20),
        height=max(300, len(types) * 35),
        yaxis=dict(autorange="reversed"),
        xaxis=dict(title="Count"),
    )
    return fig


def timeline_chart(df: pd.DataFrame) -> go.Figure:
    """Create a timeline line chart of scan results over time."""
    if df.empty:
        return go.Figure()

    fig = go.Figure()

    for severity, color in [
        ("Critical", "#f85149"),
        ("High", "#f0883e"),
        ("Medium", "#d29922"),
    ]:
        if severity in df.columns:
            fig.add_trace(go.Scatter(
                x=df["Date"],
                y=df[severity],
                mode="lines+markers",
                name=severity,
                line=dict(color=color, width=2),
                marker=dict(size=8),
            ))

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#c9d1d9"),
        margin=dict(l=20, r=20, t=30, b=20),
        height=350,
        xaxis=dict(title="Scan Date"),
        yaxis=dict(title="Finding Count"),
        legend=dict(font=dict(color="#c9d1d9")),
    )
    return fig


def risk_gauge_chart(score: int) -> go.Figure:
    """Create a gauge chart for risk score."""
    if score >= 70:
        bar_color = "#f85149"
    elif score >= 40:
        bar_color = "#d29922"
    else:
        bar_color = "#3fb950"

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        title={"text": "Risk Score", "font": {"color": "#c9d1d9"}},
        gauge={
            "axis": {"range": [0, 100], "tickfont": {"color": "#8b949e"}},
            "bar": {"color": bar_color},
            "steps": [
                {"range": [0, 40], "color": "rgba(63,185,80,0.2)"},
                {"range": [40, 70], "color": "rgba(210,153,34,0.2)"},
                {"range": [70, 100], "color": "rgba(248,81,73,0.2)"},
            ],
            "threshold": {
                "line": {"color": "white", "width": 2},
                "thickness": 0.75,
                "value": score,
            },
        },
        number={"font": {"color": "#c9d1d9", "size": 40}},
    ))

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#c9d1d9"),
        margin=dict(l=30, r=30, t=60, b=20),
        height=280,
    )
    return fig


def comparison_radar_chart(
    report1_meta: Dict, report2_meta: Dict
) -> go.Figure:
    """Create a radar chart comparing two scan reports."""
    categories = [
        "Subdomains", "Findings", "Critical",
        "High", "Medium", "Risk Score",
    ]

    def get_values(meta):
        sc = meta.get("severity_counts", {})
        return [
            min(meta.get("subdomains_found", 0), 100),
            min(meta.get("total_findings", 0), 100),
            min(sc.get("CRITICAL", 0) * 10, 100),
            min(sc.get("HIGH", 0) * 5, 100),
            min(sc.get("MEDIUM", 0) * 3, 100),
            meta.get("risk_score", 0),
        ]

    fig = go.Figure()
    fig.add_trace(go.Scatterpolar(
        r=get_values(report1_meta),
        theta=categories,
        fill="toself",
        name=f"{report1_meta['domain']} ({report1_meta.get('scan_date_display', '')})",
        line_color="#58a6ff",
    ))
    fig.add_trace(go.Scatterpolar(
        r=get_values(report2_meta),
        theta=categories,
        fill="toself",
        name=f"{report2_meta['domain']} ({report2_meta.get('scan_date_display', '')})",
        line_color="#f0883e",
    ))

    fig.update_layout(
        polar=dict(
            bgcolor="rgba(0,0,0,0)",
            radialaxis=dict(
                visible=True, range=[0, 100],
                gridcolor="#30363d", tickfont=dict(color="#8b949e"),
            ),
            angularaxis=dict(
                gridcolor="#30363d", tickfont=dict(color="#c9d1d9"),
            ),
        ),
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#c9d1d9"),
        margin=dict(l=60, r=60, t=40, b=40),
        height=450,
        legend=dict(font=dict(color="#c9d1d9")),
    )
    return fig