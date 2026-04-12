"""
BugHunter Pro - Interactive HTML Report Generator

Generates a self-contained HTML report with:
  - Executive summary dashboard
  - Interactive attack surface graph (using vis.js)
  - Detailed findings tables
  - Filterable vulnerability list
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, Any

from bughunter_pro.config import Config

logger = logging.getLogger("bughunter")


class HTMLReporter:
    """Generates an interactive HTML report with embedded graph visualization."""

    def __init__(self, config: Config):
        self.config = config

    def generate(self, scan_results: Dict[str, Any],
                 graph_data: Dict) -> str:
        """Generate and save the HTML report."""
        os.makedirs(self.config.output_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"bughunter_report_{self.config.target_domain}_{timestamp}.html"
        filepath = os.path.join(self.config.output_dir, filename)

        html_content = self._build_html(scan_results, graph_data)

        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write(html_content)

        logger.info(f"[REPORT] Interactive HTML report saved to {filepath}")
        return filepath

    def _build_html(self, results: Dict, graph_data: Dict) -> str:
        """Build the complete HTML document."""
        # Collect all findings
        all_findings = []
        for key, value in results.items():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict) and "severity" in item:
                        all_findings.append(item)

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in all_findings:
            sev = f.get("severity", "INFO").upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        intel = results.get("intelligence", {})
        subdomains = results.get("subdomains", [])
        technologies = results.get("technologies", {})
        crawl_data = results.get("crawl_data", {})
        dns_records = results.get("dns_records", {})
        shodan_data = results.get("shodan_data", {})

        graph_json = json.dumps(graph_data, default=str)
        findings_json = json.dumps(all_findings, default=str)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BugHunter Pro Report - {self.config.target_domain}</title>
    <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --border-color: #30363d;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-red: #f85149;
            --accent-orange: #d29922;
            --accent-purple: #bc8cff;
            --critical-bg: rgba(248, 81, 73, 0.15);
            --high-bg: rgba(248, 81, 73, 0.10);
            --medium-bg: rgba(210, 153, 34, 0.10);
            --low-bg: rgba(63, 185, 80, 0.10);
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }}

        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}

        header {{
            background: linear-gradient(135deg, #1a1e2e 0%, #0d1117 100%);
            border-bottom: 1px solid var(--border-color);
            padding: 30px 0;
            margin-bottom: 30px;
        }}

        header h1 {{
            font-size: 2em;
            background: linear-gradient(90deg, var(--accent-blue), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        header .meta {{ color: var(--text-secondary); margin-top: 8px; }}

        .dashboard {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 30px;
        }}

        .stat-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}

        .stat-card .value {{
            font-size: 2.5em;
            font-weight: bold;
            display: block;
        }}

        .stat-card .label {{
            color: var(--text-secondary);
            font-size: 0.9em;
            margin-top: 4px;
        }}

        .stat-card.critical .value {{ color: var(--accent-red); }}
        .stat-card.high .value {{ color: #f0883e; }}
        .stat-card.medium .value {{ color: var(--accent-orange); }}
        .stat-card.low .value {{ color: var(--accent-green); }}
        .stat-card.info .value {{ color: var(--accent-blue); }}

        .section {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 24px;
            overflow: hidden;
        }}

        .section-header {{
            background: var(--bg-tertiary);
            padding: 16px 20px;
            border-bottom: 1px solid var(--border-color);
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .section-header:hover {{ background: #282e36; }}
        .section-header h2 {{ font-size: 1.2em; }}
        .section-content {{ padding: 20px; }}
        .section-content.collapsed {{ display: none; }}

        .toggle-icon {{ font-size: 1.2em; transition: transform 0.2s; }}
        .section-header.collapsed .toggle-icon {{ transform: rotate(-90deg); }}

        #graph-container {{
            width: 100%;
            height: 600px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            background: var(--bg-primary);
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9em;
        }}

        th, td {{
            padding: 10px 14px;
            border-bottom: 1px solid var(--border-color);
            text-align: left;
        }}

        th {{
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.8em;
            letter-spacing: 0.5px;
        }}

        tr:hover {{ background: var(--bg-tertiary); }}

        .badge {{
            display: inline-block;
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: 600;
        }}

        .badge.critical {{ background: var(--critical-bg); color: var(--accent-red); border: 1px solid var(--accent-red); }}
        .badge.high {{ background: var(--high-bg); color: #f0883e; border: 1px solid #f0883e; }}
        .badge.medium {{ background: var(--medium-bg); color: var(--accent-orange); border: 1px solid var(--accent-orange); }}
        .badge.low {{ background: var(--low-bg); color: var(--accent-green); border: 1px solid var(--accent-green); }}
        .badge.info {{ background: rgba(88, 166, 255, 0.1); color: var(--accent-blue); border: 1px solid var(--accent-blue); }}

        .risk-meter {{
            width: 100%;
            height: 30px;
            background: var(--bg-tertiary);
            border-radius: 15px;
            overflow: hidden;
            margin: 10px 0;
        }}

        .risk-meter-fill {{
            height: 100%;
            border-radius: 15px;
            transition: width 1s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 0.85em;
        }}

        .filter-bar {{
            display: flex;
            gap: 8px;
            margin-bottom: 16px;
            flex-wrap: wrap;
        }}

        .filter-btn {{
            padding: 6px 14px;
            border-radius: 16px;
            border: 1px solid var(--border-color);
            background: var(--bg-tertiary);
            color: var(--text-primary);
            cursor: pointer;
            font-size: 0.85em;
        }}

        .filter-btn:hover {{ border-color: var(--accent-blue); }}
        .filter-btn.active {{ background: var(--accent-blue); color: #fff; border-color: var(--accent-blue); }}

        .tag {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            margin: 2px;
        }}

        .subdomain-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 8px;
        }}

        .subdomain-item {{
            background: var(--bg-tertiary);
            padding: 8px 12px;
            border-radius: 4px;
            border: 1px solid var(--border-color);
            font-family: monospace;
            font-size: 0.85em;
            word-break: break-all;
        }}

        .evidence-box {{
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            padding: 8px 12px;
            font-family: monospace;
            font-size: 0.8em;
            max-height: 100px;
            overflow-y: auto;
            word-break: break-all;
            margin-top: 4px;
        }}

        .url-cell {{
            max-width: 400px;
            word-break: break-all;
            font-family: monospace;
            font-size: 0.8em;
        }}

        .graph-controls {{
            display: flex;
            gap: 8px;
            margin-bottom: 10px;
        }}

        .graph-controls button {{
            padding: 6px 14px;
            border-radius: 4px;
            border: 1px solid var(--border-color);
            background: var(--bg-tertiary);
            color: var(--text-primary);
            cursor: pointer;
        }}

        .graph-controls button:hover {{ background: var(--accent-blue); color: #fff; }}

        footer {{
            text-align: center;
            color: var(--text-secondary);
            padding: 30px 0;
            border-top: 1px solid var(--border-color);
            margin-top: 30px;
        }}

        @media (max-width: 768px) {{
            .dashboard {{ grid-template-columns: repeat(2, 1fr); }}
            .stat-card .value {{ font-size: 1.8em; }}
        }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>🛡️ BugHunter Pro - Security Report</h1>
            <div class="meta">
                <strong>Target:</strong> {self.config.target_domain} &nbsp;|&nbsp;
                <strong>Date:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} &nbsp;|&nbsp;
                <strong>Industry:</strong> {intel.get('industry', 'N/A').title() if isinstance(intel, dict) else 'N/A'}
            </div>
        </div>
    </header>

    <div class="container">
        <!-- Dashboard -->
        <div class="dashboard">
            <div class="stat-card critical">
                <span class="value">{severity_counts['CRITICAL']}</span>
                <span class="label">Critical</span>
            </div>
            <div class="stat-card high">
                <span class="value">{severity_counts['HIGH']}</span>
                <span class="label">High</span>
            </div>
            <div class="stat-card medium">
                <span class="value">{severity_counts['MEDIUM']}</span>
                <span class="label">Medium</span>
            </div>
            <div class="stat-card low">
                <span class="value">{severity_counts['LOW']}</span>
                <span class="label">Low</span>
            </div>
            <div class="stat-card info">
                <span class="value">{severity_counts['INFO']}</span>
                <span class="label">Info</span>
            </div>
            <div class="stat-card info">
                <span class="value">{len(subdomains)}</span>
                <span class="label">Subdomains</span>
            </div>
            <div class="stat-card info">
                <span class="value">{len(all_findings)}</span>
                <span class="label">Total Findings</span>
            </div>
        </div>

        <!-- Risk Score -->
        <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>📊 Risk Assessment</h2>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                <p>Overall Risk Score: <strong>{intel.get('risk_score', 0) if isinstance(intel, dict) else 0}/100</strong></p>
                <div class="risk-meter">
                    <div class="risk-meter-fill" style="width: {intel.get('risk_score', 0) if isinstance(intel, dict) else 0}%;
                        background: {'#f85149' if (intel.get('risk_score', 0) if isinstance(intel, dict) else 0) >= 70 else '#d29922' if (intel.get('risk_score', 0) if isinstance(intel, dict) else 0) >= 40 else '#3fb950'};">
                        {intel.get('risk_score', 0) if isinstance(intel, dict) else 0}%
                    </div>
                </div>
                {self._build_recommendations_html(intel.get('recommendations', []) if isinstance(intel, dict) else [])}
            </div>
        </div>

        <!-- Attack Surface Graph -->
        <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>🕸️ Attack Surface Graph</h2>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                <div class="graph-controls">
                    <button onclick="graphFit()">Fit View</button>
                    <button onclick="graphTogglePhysics()">Toggle Physics</button>
                    <button onclick="graphStabilize()">Stabilize</button>
                </div>
                <div id="graph-container"></div>
            </div>
        </div>

        <!-- Vulnerabilities -->
        <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>🔓 Vulnerability Findings ({len(all_findings)})</h2>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                <div class="filter-bar">
                    <button class="filter-btn active" onclick="filterFindings('all', this)">All</button>
                    <button class="filter-btn" onclick="filterFindings('CRITICAL', this)">Critical</button>
                    <button class="filter-btn" onclick="filterFindings('HIGH', this)">High</button>
                    <button class="filter-btn" onclick="filterFindings('MEDIUM', this)">Medium</button>
                    <button class="filter-btn" onclick="filterFindings('LOW', this)">Low</button>
                    <button class="filter-btn" onclick="filterFindings('INFO', this)">Info</button>
                </div>
                <table id="findings-table">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Type</th>
                            <th>URL</th>
                            <th>Parameter</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody id="findings-tbody">
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Subdomains -->
        <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>🌐 Subdomains ({len(subdomains)})</h2>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                <div class="subdomain-grid">
                    {''.join(f'<div class="subdomain-item">{sub}</div>' for sub in subdomains[:200])}
                </div>
            </div>
        </div>

        <!-- Technologies -->
        <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>🔧 Detected Technologies</h2>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                {self._build_tech_html(technologies)}
            </div>
        </div>

        <!-- DNS Records -->
        <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>📡 DNS Records</h2>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                {self._build_dns_html(dns_records)}
            </div>
        </div>

        <!-- Target Intelligence -->
        <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>🎯 Target Intelligence</h2>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                {self._build_intel_html(intel)}
            </div>
        </div>

    </div>

    <footer>
        <p>BugHunter Pro v1.0 - Academic Security Research Tool</p>
        <p>Report generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </footer>

    <script>
        // --- Graph Visualization ---
        const graphData = {graph_json};
        const findingsData = {findings_json};

        let network = null;
        let physicsEnabled = true;

        function initGraph() {{
            const container = document.getElementById('graph-container');
            if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {{
                container.innerHTML = '<p style="text-align:center;padding:40px;color:#8b949e;">No graph data available</p>';
                return;
            }}

            const colorMap = {{
                'root': '#58a6ff',
                'subdomain_group': '#58a6ff',
                'tech_group': '#bc8cff',
                'dns_group': '#3fb950',
                'shodan_group': '#f0883e',
                'crawl_group': '#d29922',
                'vuln_group': '#f85149',
                'vectors_group': '#d29922',
                'asset': '#79c0ff',
                'info': '#8b949e',
                'warning': '#d29922',
                'critical': '#f85149',
                'high': '#f0883e',
                'medium': '#d29922',
                'low': '#3fb950',
            }};

            const shapeMap = {{
                'domain': 'diamond',
                'group': 'box',
                'subdomain': 'dot',
                'technology': 'triangle',
                'tech_category': 'box',
                'vulnerability': 'star',
                'vuln_type': 'box',
                'severity': 'box',
                'port': 'square',
                'cve': 'star',
                'attack_vector': 'triangleDown',
                'dns_type': 'dot',
                'category': 'box',
            }};

            const nodes = new vis.DataSet(graphData.nodes.map(n => ({{
                id: n.id,
                label: n.label.length > 40 ? n.label.substring(0, 40) + '...' : n.label,
                title: n.label + '\\nType: ' + n.type + '\\nLevel: ' + n.level,
                color: {{ background: colorMap[n.level] || '#8b949e', border: '#30363d' }},
                shape: shapeMap[n.type] || 'dot',
                font: {{ color: '#c9d1d9', size: 11 }},
                size: n.type === 'domain' ? 40 : n.type === 'group' ? 25 : 15,
            }})));

            const edges = new vis.DataSet(graphData.edges.map((e, i) => ({{
                id: i,
                from: e.source,
                to: e.target,
                label: e.relationship,
                color: {{ color: '#30363d', highlight: '#58a6ff' }},
                font: {{ color: '#8b949e', size: 8, strokeWidth: 0 }},
                arrows: 'to',
                smooth: {{ type: 'cubicBezier' }},
            }})));

            const options = {{
                physics: {{
                    enabled: true,
                    barnesHut: {{
                        gravitationalConstant: -3000,
                        centralGravity: 0.3,
                        springLength: 150,
                        springConstant: 0.04,
                    }},
                    stabilization: {{ iterations: 150 }},
                }},
                interaction: {{
                    hover: true,
                    tooltipDelay: 200,
                    zoomView: true,
                    dragView: true,
                }},
                layout: {{ improvedLayout: true }},
            }};

            network = new vis.Network(container, {{ nodes, edges }}, options);
        }}

        function graphFit() {{ if (network) network.fit(); }}
        function graphTogglePhysics() {{
            physicsEnabled = !physicsEnabled;
            if (network) network.setOptions({{ physics: {{ enabled: physicsEnabled }} }});
        }}
        function graphStabilize() {{ if (network) network.stabilize(100); }}

        // --- Findings Table ---
        function populateFindings(filter) {{
            const tbody = document.getElementById('findings-tbody');
            tbody.innerHTML = '';

            const filtered = filter === 'all'
                ? findingsData
                : findingsData.filter(f => f.severity === filter);

            filtered.forEach(f => {{
                const row = document.createElement('tr');
                row.setAttribute('data-severity', f.severity);
                row.innerHTML = `
                    <td><span class="badge ${{f.severity.toLowerCase()}}">${{f.severity}}</span></td>
                    <td>${{f.type || 'N/A'}}</td>
                    <td class="url-cell">${{f.url || 'N/A'}}</td>
                    <td>${{f.parameter || 'N/A'}}</td>
                    <td>${{f.evidence || f.description || f.payload || 'N/A'}}</td>
                `;
                tbody.appendChild(row);
            }});
        }}

        function filterFindings(severity, btn) {{
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            populateFindings(severity);
        }}

        // --- Section Toggle ---
        function toggleSection(header) {{
            const content = header.nextElementSibling;
            header.classList.toggle('collapsed');
            content.classList.toggle('collapsed');
        }}

        // --- Initialize ---
        window.addEventListener('load', () => {{
            initGraph();
            populateFindings('all');
        }});
    </script>
</body>
</html>"""
        return html

    def _build_recommendations_html(self, recommendations: list) -> str:
        """Build HTML for recommendations."""
        if not recommendations:
            return "<p>No specific recommendations generated.</p>"

        html = "<h3 style='margin-top:16px;'>Recommendations</h3><ul>"
        for rec in recommendations:
            priority = rec.get("priority", "INFO")
            text = rec.get("text", "")
            html += f'<li><span class="badge {priority.lower()}">{priority}</span> {text}</li>'
        html += "</ul>"
        return html

    def _build_tech_html(self, technologies: dict) -> str:
        """Build HTML for technologies section."""
        if not technologies or not isinstance(technologies, dict):
            return "<p>No technologies detected.</p>"

        html = "<table><thead><tr><th>Category</th><th>Technologies</th></tr></thead><tbody>"
        for category, tech_list in technologies.items():
            techs = ", ".join(tech_list) if isinstance(tech_list, list) else str(tech_list)
            html += f"<tr><td>{category}</td><td>"
            if isinstance(tech_list, list):
                for t in tech_list:
                    html += f'<span class="tag">{t}</span> '
            else:
                html += str(tech_list)
            html += "</td></tr>"
        html += "</tbody></table>"
        return html

    def _build_dns_html(self, dns_records: dict) -> str:
        """Build HTML for DNS records section."""
        if not dns_records or not isinstance(dns_records, dict):
            return "<p>No DNS records retrieved.</p>"

        html = "<table><thead><tr><th>Record Type</th><th>Values</th></tr></thead><tbody>"
        for rtype, records in dns_records.items():
            values = "<br>".join(str(r) for r in records) if isinstance(records, list) else str(records)
            html += f"<tr><td><strong>{rtype}</strong></td><td style='font-family:monospace;font-size:0.85em;'>{values}</td></tr>"
        html += "</tbody></table>"
        return html

    def _build_intel_html(self, intel: dict) -> str:
        """Build HTML for target intelligence section."""
        if not intel or not isinstance(intel, dict):
            return "<p>No intelligence data available.</p>"

        html = f"""
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px;">
            <div class="stat-card">
                <span class="value" style="color:var(--accent-blue);font-size:1.5em;">{intel.get('industry', 'Unknown').title()}</span>
                <span class="label">Detected Industry (confidence: {intel.get('industry_confidence', 0):.0%})</span>
            </div>
            <div class="stat-card">
                <span class="value" style="color:var(--accent-purple);font-size:1.5em;">{len(intel.get('attack_vectors', []))}</span>
                <span class="label">Suggested Attack Vectors</span>
            </div>
            <div class="stat-card">
                <span class="value" style="color:var(--accent-orange);font-size:1.5em;">{len(intel.get('subdomain_analysis', []))}</span>
                <span class="label">Categorised Subdomains</span>
            </div>
        </div>
        """

        # Attack vectors
        vectors = intel.get('attack_vectors', [])
        if vectors:
            html += "<h3 style='margin-top:20px;'>Suggested Attack Vectors</h3><ul>"
            for vec in vectors:
                html += f"<li>{vec}</li>"
            html += "</ul>"

        # Subdomain analysis
        sub_analysis = intel.get('subdomain_analysis', [])
        if sub_analysis:
            html += "<h3 style='margin-top:20px;'>Subdomain Analysis</h3>"
            html += "<table><thead><tr><th>Subdomain</th><th>Category</th><th>Risk</th></tr></thead><tbody>"
            for sa in sub_analysis:
                html += f"""<tr>
                    <td style="font-family:monospace;">{sa.get('subdomain', '')}</td>
                    <td>{sa.get('category', '').title()}</td>
                    <td><span class="badge {sa.get('risk_level', 'info').lower()}">{sa.get('risk_level', 'INFO')}</span></td>
                </tr>"""
            html += "</tbody></table>"

        return html