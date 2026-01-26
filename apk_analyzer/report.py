"""Clean HTML report generation for APK Analyzer."""

import datetime as dt
import html
import os
import shutil
import subprocess
from typing import List, Optional
from collections import Counter

from .utils import Finding


def generate_html_report(findings: List[Finding], output_path: str, metadata: dict) -> None:
    """Generate a clean, interactive HTML security report."""
    created = dt.datetime.now().strftime("%B %d, %Y at %I:%M %p")
    title = metadata.get("title", "APK Security Scan Report")
    pkg = metadata.get("package", "unknown")
    apk_name = metadata.get("apk", "unknown")
    patterns_loaded = metadata.get("patterns_loaded", "N/A")

    # Count severities
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    category_set = set()

    for f in findings:
        sev = f.severity if f.severity in severity_counts else "Medium"
        severity_counts[sev] += 1
        extra = f.extra or {}
        cat = extra.get("category", "Other")
        category_set.add(cat)

    categories = sorted(category_set)
    total_findings = len(findings)

    # Build findings HTML
    findings_html = []
    for idx, f in enumerate(findings, start=1):
        findings_html.append(_render_finding(f, idx, pkg))

    # Build category options
    category_options = '\n'.join(
        f'<option value="{html.escape(cat)}">{html.escape(cat)}</option>'
        for cat in categories
    )

    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(title)}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.1); }}

        /* Header */
        .header {{ border-bottom: 3px solid #6366f1; padding-bottom: 20px; margin-bottom: 30px; }}
        .header h1 {{ color: #1e293b; margin: 0 0 10px 0; font-size: 1.8rem; }}
        .scan-info {{ color: #64748b; font-size: 0.9rem; }}
        .scan-info span {{ margin-right: 20px; }}
        .pkg-name {{ background: #f1f5f9; padding: 4px 10px; border-radius: 6px; font-family: monospace; font-size: 0.85rem; }}

        /* Summary Grid */
        .summary-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin: 25px 0; }}
        .stat-card {{ padding: 20px; border-radius: 10px; text-align: center; border: 2px solid; transition: transform 0.2s; }}
        .stat-card:hover {{ transform: translateY(-2px); }}
        .stat-card.critical {{ border-color: #dc2626; background: #fef2f2; }}
        .stat-card.high {{ border-color: #ea580c; background: #fff7ed; }}
        .stat-card.medium {{ border-color: #ca8a04; background: #fefce8; }}
        .stat-card.low {{ border-color: #16a34a; background: #f0fdf4; }}
        .stat-card.info {{ border-color: #0891b2; background: #ecfeff; }}
        .stat-number {{ font-size: 2.2rem; font-weight: 700; line-height: 1; }}
        .stat-card.critical .stat-number {{ color: #dc2626; }}
        .stat-card.high .stat-number {{ color: #ea580c; }}
        .stat-card.medium .stat-number {{ color: #ca8a04; }}
        .stat-card.low .stat-number {{ color: #16a34a; }}
        .stat-card.info .stat-number {{ color: #0891b2; }}
        .stat-label {{ font-weight: 600; color: #475569; margin-top: 5px; font-size: 0.9rem; }}

        /* Filter Controls */
        .filter-controls {{ background: #f8fafc; padding: 20px; border-radius: 10px; margin: 25px 0; border: 1px solid #e2e8f0; }}
        .filter-controls h3 {{ margin: 0 0 15px 0; color: #334155; font-size: 1rem; }}
        .filter-row {{ display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }}
        .filter-row select {{ padding: 10px 14px; border: 2px solid #e2e8f0; border-radius: 8px; min-width: 180px; font-size: 0.9rem; background: white; cursor: pointer; }}
        .filter-row select:focus {{ border-color: #6366f1; outline: none; }}
        .filter-row button {{ padding: 10px 20px; background: #6366f1; color: white; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 0.9rem; }}
        .filter-row button:hover {{ background: #4f46e5; }}
        .filter-summary {{ background: #6366f1; color: white; padding: 12px 20px; border-radius: 8px; text-align: center; font-weight: 600; margin-top: 15px; }}

        /* Finding Cards */
        .finding-card {{ border: 2px solid; border-radius: 10px; margin: 15px 0; overflow: hidden; }}
        .finding-card.critical {{ border-color: #dc2626; }}
        .finding-card.high {{ border-color: #ea580c; }}
        .finding-card.medium {{ border-color: #ca8a04; }}
        .finding-card.low {{ border-color: #16a34a; }}
        .finding-card.info {{ border-color: #0891b2; }}

        .finding-header {{ padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; cursor: pointer; }}
        .finding-card.critical .finding-header {{ background: #fef2f2; }}
        .finding-card.high .finding-header {{ background: #fff7ed; }}
        .finding-card.medium .finding-header {{ background: #fefce8; }}
        .finding-card.low .finding-header {{ background: #f0fdf4; }}
        .finding-card.info .finding-header {{ background: #ecfeff; }}

        .finding-header h4 {{ margin: 0; color: #1e293b; font-size: 1rem; }}
        .finding-header .badges {{ display: flex; gap: 8px; align-items: center; }}

        .severity-badge {{ padding: 5px 12px; border-radius: 20px; font-size: 0.75rem; font-weight: 700; color: white; text-transform: uppercase; }}
        .severity-badge.critical {{ background: #dc2626; }}
        .severity-badge.high {{ background: #ea580c; }}
        .severity-badge.medium {{ background: #ca8a04; }}
        .severity-badge.low {{ background: #16a34a; }}
        .severity-badge.info {{ background: #0891b2; }}

        .category-badge {{ padding: 5px 12px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; background: #e2e8f0; color: #475569; }}
        .deep-badge {{ padding: 5px 12px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; background: #7c3aed; color: white; }}

        .finding-body {{ padding: 20px; background: white; display: none; }}
        .finding-card.expanded .finding-body {{ display: block; }}
        .expand-icon {{ font-size: 1.2rem; color: #64748b; transition: transform 0.2s; }}
        .finding-card.expanded .expand-icon {{ transform: rotate(180deg); }}

        /* Finding Content */
        .finding-section {{ margin-bottom: 20px; }}
        .finding-section:last-child {{ margin-bottom: 0; }}
        .section-label {{ font-weight: 700; color: #334155; margin-bottom: 8px; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        .section-content {{ color: #475569; line-height: 1.6; }}

        .evidence-box {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; margin-top: 8px; }}
        .evidence-box .file-path {{ color: #6366f1; font-family: monospace; font-size: 0.85rem; margin-bottom: 8px; }}
        .evidence-box code {{ background: #1e293b; color: #a5f3fc; padding: 12px; display: block; border-radius: 6px; font-family: monospace; font-size: 0.85rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}

        .poc-box {{ background: #0f172a; border-radius: 8px; padding: 15px; margin-top: 8px; }}
        .poc-box code {{ color: #4ade80; font-family: monospace; font-size: 0.85rem; white-space: pre-wrap; word-break: break-all; }}
        .poc-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
        .poc-header span {{ color: #94a3b8; font-size: 0.8rem; font-weight: 600; }}
        .copy-btn {{ background: #334155; color: #e2e8f0; border: none; padding: 6px 12px; border-radius: 6px; font-size: 0.75rem; cursor: pointer; }}
        .copy-btn:hover {{ background: #475569; }}

        .remediation-box {{ background: #f0fdf4; border: 1px solid #86efac; border-radius: 8px; padding: 15px; margin-top: 8px; color: #166534; }}

        .cwe-list {{ display: flex; gap: 8px; flex-wrap: wrap; margin-top: 8px; }}
        .cwe-tag {{ background: #fef3c7; color: #92400e; padding: 4px 10px; border-radius: 6px; font-size: 0.8rem; font-weight: 600; }}

        .ref-list {{ list-style: none; padding: 0; margin: 8px 0 0 0; }}
        .ref-list li {{ margin: 6px 0; }}
        .ref-list a {{ color: #6366f1; text-decoration: none; font-size: 0.9rem; }}
        .ref-list a:hover {{ text-decoration: underline; }}

        /* Deep Analysis Box */
        .deep-analysis-box {{ background: linear-gradient(135deg, #faf5ff 0%, #f3e8ff 100%); border: 2px solid #c084fc; border-radius: 8px; padding: 15px; margin-bottom: 15px; }}
        .deep-analysis-box h5 {{ margin: 0 0 12px 0; color: #7c3aed; font-size: 0.9rem; }}
        .config-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; }}
        .config-item {{ background: white; padding: 10px; border-radius: 6px; text-align: center; }}
        .config-item.danger {{ border-left: 3px solid #dc2626; }}
        .config-item.safe {{ border-left: 3px solid #16a34a; }}
        .config-item .label {{ font-size: 0.7rem; color: #64748b; text-transform: uppercase; }}
        .config-item .value {{ font-weight: 700; font-size: 0.85rem; margin-top: 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 {html.escape(title)}</h1>
            <div class="scan-info">
                <span>📅 {created}</span>
                <span>📦 <span class="pkg-name">{html.escape(pkg)}</span></span>
                <span>📄 {html.escape(apk_name)}</span>
                <span>🔎 {total_findings} findings</span>
            </div>
        </div>

        <div class="summary-grid">
            <div class="stat-card critical">
                <div class="stat-number">{severity_counts["Critical"]}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-number">{severity_counts["High"]}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-number">{severity_counts["Medium"]}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="stat-number">{severity_counts["Low"]}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat-card info">
                <div class="stat-number">{severity_counts["Info"]}</div>
                <div class="stat-label">Info</div>
            </div>
        </div>

        <div class="filter-controls">
            <h3>🔍 Filter Findings</h3>
            <div class="filter-row">
                <select id="severityFilter">
                    <option value="all">All Severities</option>
                    <option value="critical">🔴 Critical</option>
                    <option value="high">🟠 High</option>
                    <option value="medium">🟡 Medium</option>
                    <option value="low">🟢 Low</option>
                    <option value="info">🔵 Info</option>
                </select>
                <select id="categoryFilter">
                    <option value="all">All Categories</option>
                    {category_options}
                </select>
                <select id="analysisFilter">
                    <option value="all">All Findings</option>
                    <option value="deep">🔬 Deep Analysis Only</option>
                    <option value="pattern">📋 Pattern Match Only</option>
                </select>
                <button onclick="resetFilters()">Reset</button>
            </div>
            <div class="filter-summary">
                Showing <span id="visibleCount">{total_findings}</span> of <span id="totalCount">{total_findings}</span> findings
            </div>
        </div>

        <div class="findings-section">
            {''.join(findings_html)}
        </div>
    </div>

    <script>
        const allFindings = document.querySelectorAll('.finding-card');

        // Toggle finding expansion
        document.querySelectorAll('.finding-header').forEach(header => {{
            header.addEventListener('click', () => {{
                header.parentElement.classList.toggle('expanded');
            }});
        }});

        // Copy button functionality
        document.querySelectorAll('.copy-btn').forEach(btn => {{
            btn.addEventListener('click', (e) => {{
                e.stopPropagation();
                const code = btn.closest('.poc-box').querySelector('code').textContent;
                navigator.clipboard.writeText(code);
                btn.textContent = 'Copied!';
                setTimeout(() => btn.textContent = 'Copy', 2000);
            }});
        }});

        // Filter functionality
        function applyFilters() {{
            const severity = document.getElementById('severityFilter').value;
            const category = document.getElementById('categoryFilter').value;
            const analysis = document.getElementById('analysisFilter').value;
            let visible = 0;

            allFindings.forEach(card => {{
                const cardSev = card.dataset.severity;
                const cardCat = card.dataset.category;
                const cardDeep = card.dataset.deep === 'true';

                const sevMatch = severity === 'all' || cardSev === severity;
                const catMatch = category === 'all' || cardCat === category;
                const analysisMatch = analysis === 'all' ||
                    (analysis === 'deep' && cardDeep) ||
                    (analysis === 'pattern' && !cardDeep);

                if (sevMatch && catMatch && analysisMatch) {{
                    card.style.display = 'block';
                    visible++;
                }} else {{
                    card.style.display = 'none';
                }}
            }});

            document.getElementById('visibleCount').textContent = visible;
        }}

        function resetFilters() {{
            document.getElementById('severityFilter').value = 'all';
            document.getElementById('categoryFilter').value = 'all';
            document.getElementById('analysisFilter').value = 'all';
            applyFilters();
        }}

        document.getElementById('severityFilter').addEventListener('change', applyFilters);
        document.getElementById('categoryFilter').addEventListener('change', applyFilters);
        document.getElementById('analysisFilter').addEventListener('change', applyFilters);

        // Expand first critical/high finding by default
        const firstImportant = document.querySelector('.finding-card.critical, .finding-card.high');
        if (firstImportant) firstImportant.classList.add('expanded');
    </script>
</body>
</html>'''

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)


def _render_finding(finding: Finding, index: int, package: str) -> str:
    """Render a single finding card."""
    severity = (finding.severity or "Medium").lower()
    extra = finding.extra or {}
    category = extra.get("category", "Other")
    is_deep = extra.get("deep_analysis", False)

    # Build badges
    badges = [f'<span class="severity-badge {severity}">{severity.upper()}</span>']
    if is_deep:
        badges.append('<span class="deep-badge">🔬 Deep Analysis</span>')
    badges.append(f'<span class="category-badge">{html.escape(category)}</span>')

    # Deep analysis context box
    deep_context = ""
    if is_deep and extra.get("webview_config"):
        wv = extra["webview_config"]
        deep_context = f'''
        <div class="deep-analysis-box">
            <h5>🔬 WebView Security Analysis</h5>
            <div class="config-grid">
                <div class="config-item {'danger' if wv.get('js_enabled') else 'safe'}">
                    <div class="label">JavaScript</div>
                    <div class="value">{'Enabled ⚠️' if wv.get('js_enabled') else 'Disabled ✓'}</div>
                </div>
                <div class="config-item {'danger' if wv.get('file_access') else 'safe'}">
                    <div class="label">File Access</div>
                    <div class="value">{'Enabled ⚠️' if wv.get('file_access') else 'Disabled ✓'}</div>
                </div>
                <div class="config-item {'danger' if wv.get('ssl_bypass') else 'safe'}">
                    <div class="label">SSL Bypass</div>
                    <div class="value">{'Yes ⚠️' if wv.get('ssl_bypass') else 'No ✓'}</div>
                </div>
                <div class="config-item {'danger' if wv.get('js_interfaces', 0) > 0 else 'safe'}">
                    <div class="label">JS Interfaces</div>
                    <div class="value">{wv.get('js_interfaces', 0)}</div>
                </div>
            </div>
        </div>'''

    # Evidence/Code
    evidence_html = ""
    if finding.evidence:
        file_path = finding.evidence.file_path
        if '/sources/' in file_path:
            file_path = 'sources/' + file_path.split('/sources/')[-1]
        evidence_html = f'''
        <div class="finding-section">
            <div class="section-label">📍 Location</div>
            <div class="evidence-box">
                <div class="file-path">📄 {html.escape(file_path)} : Line {finding.evidence.line}</div>
                <code>{html.escape(finding.evidence.snippet)}</code>
            </div>
        </div>'''

    # ADB PoC
    poc_html = ""
    if finding.adb_commands:
        if is_deep and finding.adb_commands[0].startswith('#'):
            # Deep analysis detailed PoC
            poc_content = finding.adb_commands[0].replace("<package>", package)
            poc_html = f'''
        <div class="finding-section">
            <div class="section-label">⚡ Proof of Concept</div>
            <div class="poc-box">
                <div class="poc-header">
                    <span>ADB Commands</span>
                    <button class="copy-btn">Copy</button>
                </div>
                <code>{html.escape(poc_content)}</code>
            </div>
        </div>'''
        else:
            adb_cmds = [cmd.replace("<package>", package) for cmd in finding.adb_commands]
            poc_content = '\n'.join(adb_cmds)
            poc_html = f'''
        <div class="finding-section">
            <div class="section-label">⚡ Proof of Concept</div>
            <div class="poc-box">
                <div class="poc-header">
                    <span>ADB Commands</span>
                    <button class="copy-btn">Copy</button>
                </div>
                <code>{html.escape(poc_content)}</code>
            </div>
        </div>'''

    # Remediation
    remediation_html = ""
    if extra.get("remediation"):
        remediation_html = f'''
        <div class="finding-section">
            <div class="section-label">🛠️ Remediation</div>
            <div class="remediation-box">{html.escape(extra["remediation"])}</div>
        </div>'''

    # CWE tags
    cwe_html = ""
    if extra.get("cwe"):
        cwe_tags = ''.join(f'<span class="cwe-tag">{html.escape(cwe)}</span>' for cwe in extra["cwe"])
        cwe_html = f'''
        <div class="finding-section">
            <div class="section-label">🏷️ CWE References</div>
            <div class="cwe-list">{cwe_tags}</div>
        </div>'''

    # References
    refs_html = ""
    if finding.references:
        ref_items = ''.join(f'<li><a href="{html.escape(ref)}" target="_blank">{html.escape(ref)}</a></li>' for ref in finding.references)
        refs_html = f'''
        <div class="finding-section">
            <div class="section-label">📚 References</div>
            <ul class="ref-list">{ref_items}</ul>
        </div>'''

    return f'''
    <div class="finding-card {severity}" data-severity="{severity}" data-category="{html.escape(category)}" data-deep="{str(is_deep).lower()}">
        <div class="finding-header">
            <h4>#{index} - {html.escape(finding.title)}</h4>
            <div class="badges">
                {''.join(badges)}
                <span class="expand-icon">▼</span>
            </div>
        </div>
        <div class="finding-body">
            {deep_context}
            <div class="finding-section">
                <div class="section-label">📋 Description</div>
                <div class="section-content">{html.escape(finding.description)}</div>
            </div>
            {evidence_html}
            {poc_html}
            {remediation_html}
            {cwe_html}
            {refs_html}
        </div>
    </div>'''


def render_pdf_from_html(html_path: str, output_pdf: str) -> Optional[str]:
    """Convert HTML report to PDF using available renderer."""
    wkhtmltopdf = shutil.which("wkhtmltopdf")
    if wkhtmltopdf:
        result = subprocess.run(
            [wkhtmltopdf, "--enable-local-file-access", html_path, output_pdf],
            check=False, capture_output=True
        )
        if result.returncode == 0:
            return output_pdf
    try:
        from weasyprint import HTML
        HTML(filename=html_path).write_pdf(output_pdf)
        return output_pdf
    except:
        pass
    return None
