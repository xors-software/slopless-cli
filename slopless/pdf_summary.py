"""One-page PDF executive summary for Slopless scan findings.

Generates a shareable, non-technical 1-pager summarizing audit findings.
Designed for partners, investors, and non-technical stakeholders — plain
English explanations with severity levels and statuses.

Usage:
    slopless scan . --summary
    slopless scan . --summary --summary-output summary.pdf
"""

import os
import subprocess
import tempfile
from collections import Counter
from datetime import datetime
from pathlib import Path

from rich.console import Console

from slopless.notion import SEVERITY_PREFIX, generate_finding_ids

console = Console()

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#2563eb",
}
SEVERITY_BG = {
    "CRITICAL": "#fef2f2",
    "HIGH": "#fff7ed",
    "MEDIUM": "#fefce8",
    "LOW": "#eff6ff",
}


def _sort_vulns(vulns: list[dict]) -> list[dict]:
    return sorted(vulns, key=lambda v: SEVERITY_ORDER.get(v.get("severity", "MEDIUM").upper(), 99))


def _plain_english_risk(vuln: dict) -> str:
    """Turn a technical finding into a one-sentence plain-English explanation."""
    title = vuln.get("title", "Unnamed finding")
    desc = vuln.get("description", "")
    # Use description if short enough, otherwise just the title
    if desc and len(desc) < 200:
        # Strip markdown-style formatting
        clean = desc.replace("**", "").replace("`", "").replace("###", "").strip()
        # Take first sentence
        first_sentence = clean.split(". ")[0].rstrip(".")
        return first_sentence
    return title


# ---------------------------------------------------------------------------
# HTML template
# ---------------------------------------------------------------------------


def _build_html(
    vulns: list[dict],
    project_name: str,
    scan_date: str,
) -> str:
    """Build the single-page HTML summary."""
    sorted_vulns = _sort_vulns(vulns)
    finding_ids = generate_finding_ids(sorted_vulns)
    severity_counts = Counter(v.get("severity", "MEDIUM").upper() for v in vulns)
    total = len(vulns)

    critical = severity_counts.get("CRITICAL", 0)
    high = severity_counts.get("HIGH", 0)
    medium = severity_counts.get("MEDIUM", 0)
    low = severity_counts.get("LOW", 0)

    # Overall posture
    if critical > 0:
        posture = "Requires Immediate Attention"
        posture_color = SEVERITY_COLORS["CRITICAL"]
        posture_summary = (
            f"The scan identified <strong>{critical} critical</strong> "
            f"finding{'s' if critical != 1 else ''} that pose serious risk "
            "and should be addressed before deployment."
        )
    elif high > 0:
        posture = "Needs Improvement"
        posture_color = SEVERITY_COLORS["HIGH"]
        posture_summary = (
            f"No critical issues were found, but <strong>{high} high-severity</strong> "
            f"finding{'s' if high != 1 else ''} should be resolved promptly to reduce risk."
        )
    elif medium > 0:
        posture = "Moderate"
        posture_color = SEVERITY_COLORS["MEDIUM"]
        posture_summary = (
            "No critical or high-severity issues were found. "
            f"<strong>{medium} medium-severity</strong> finding{'s' if medium != 1 else ''} "
            "should be addressed in upcoming development cycles."
        )
    else:
        posture = "Good"
        posture_color = "#16a34a"
        posture_summary = (
            "No critical, high, or medium-severity issues were found. "
            "The codebase is in good security shape."
        )

    # Build findings rows (limit to keep it on 1 page)
    max_findings = 12
    finding_rows = ""
    for i, vuln in enumerate(sorted_vulns[:max_findings]):
        sev = vuln.get("severity", "MEDIUM").upper()
        color = SEVERITY_COLORS.get(sev, "#6b7280")
        bg = SEVERITY_BG.get(sev, "#f9fafb")
        risk = _plain_english_risk(vuln)
        fid = finding_ids[i]
        status = vuln.get("status", "Open")
        finding_rows += f"""
        <tr>
            <td class="finding-id">{fid}</td>
            <td><span class="severity-badge" style="background:{bg};color:{color};border:1px solid {color};">{sev}</span></td>
            <td class="risk-text">{risk}</td>
            <td class="status-cell">{status}</td>
        </tr>"""

    if total > max_findings:
        remaining = total - max_findings
        finding_rows += f"""
        <tr>
            <td colspan="4" class="more-row">+ {remaining} additional finding{'s' if remaining != 1 else ''} (see full report)</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<style>
@page {{
    size: A4;
    margin: 18mm 16mm 14mm 16mm;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
    font-size: 9.5pt;
    color: #1e293b;
    line-height: 1.45;
}}

/* Header */
.header {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    border-bottom: 2.5px solid #0f172a;
    padding-bottom: 10px;
    margin-bottom: 14px;
}}
.header-left h1 {{
    font-size: 17pt;
    font-weight: 700;
    color: #0f172a;
    letter-spacing: -0.3px;
}}
.header-left .subtitle {{
    font-size: 9pt;
    color: #64748b;
    margin-top: 2px;
}}
.header-right {{
    text-align: right;
    font-size: 8.5pt;
    color: #64748b;
}}
.header-right .project-name {{
    font-weight: 600;
    color: #0f172a;
    font-size: 10pt;
}}

/* Posture banner */
.posture-banner {{
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-left: 4px solid {posture_color};
    border-radius: 4px;
    padding: 10px 14px;
    margin-bottom: 14px;
}}
.posture-banner .posture-label {{
    font-size: 8pt;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: #64748b;
    margin-bottom: 2px;
}}
.posture-banner .posture-value {{
    font-size: 13pt;
    font-weight: 700;
    color: {posture_color};
}}
.posture-banner .posture-desc {{
    font-size: 9pt;
    color: #475569;
    margin-top: 4px;
}}

/* Stats row */
.stats {{
    display: flex;
    gap: 10px;
    margin-bottom: 14px;
}}
.stat-card {{
    flex: 1;
    text-align: center;
    padding: 8px 6px;
    border-radius: 4px;
    border: 1px solid #e2e8f0;
}}
.stat-card .stat-num {{
    font-size: 18pt;
    font-weight: 700;
}}
.stat-card .stat-label {{
    font-size: 7.5pt;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    color: #64748b;
}}

/* Findings table */
.section-title {{
    font-size: 10pt;
    font-weight: 700;
    color: #0f172a;
    margin-bottom: 6px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 12px;
}}
th {{
    background: #f1f5f9;
    font-size: 7.5pt;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: #64748b;
    text-align: left;
    padding: 5px 8px;
    border-bottom: 1px solid #e2e8f0;
}}
td {{
    padding: 5px 8px;
    border-bottom: 1px solid #f1f5f9;
    font-size: 8.5pt;
    vertical-align: middle;
}}
.finding-id {{
    font-family: "Courier New", monospace;
    font-weight: 600;
    font-size: 8pt;
    color: #475569;
    white-space: nowrap;
}}
.severity-badge {{
    display: inline-block;
    padding: 1px 7px;
    border-radius: 3px;
    font-size: 7pt;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.4px;
    white-space: nowrap;
}}
.risk-text {{
    color: #334155;
}}
.status-cell {{
    font-size: 8pt;
    color: #64748b;
    white-space: nowrap;
}}
.more-row {{
    text-align: center;
    color: #94a3b8;
    font-style: italic;
    font-size: 8pt;
    padding: 6px;
}}

/* Footer */
.footer {{
    margin-top: 10px;
    padding-top: 8px;
    border-top: 1px solid #e2e8f0;
    font-size: 7.5pt;
    color: #94a3b8;
    display: flex;
    justify-content: space-between;
}}
</style>
</head>
<body>

<div class="header">
    <div class="header-left">
        <h1>Security Audit Summary</h1>
        <div class="subtitle">Executive overview &mdash; prepared for stakeholder review</div>
    </div>
    <div class="header-right">
        <div class="project-name">{project_name}</div>
        <div>{scan_date}</div>
    </div>
</div>

<div class="posture-banner">
    <div class="posture-label">Overall Security Posture</div>
    <div class="posture-value">{posture}</div>
    <div class="posture-desc">{posture_summary}</div>
</div>

<div class="stats">
    <div class="stat-card" style="background:{SEVERITY_BG['CRITICAL']};">
        <div class="stat-num" style="color:{SEVERITY_COLORS['CRITICAL']};">{critical}</div>
        <div class="stat-label">Critical</div>
    </div>
    <div class="stat-card" style="background:{SEVERITY_BG['HIGH']};">
        <div class="stat-num" style="color:{SEVERITY_COLORS['HIGH']};">{high}</div>
        <div class="stat-label">High</div>
    </div>
    <div class="stat-card" style="background:{SEVERITY_BG['MEDIUM']};">
        <div class="stat-num" style="color:{SEVERITY_COLORS['MEDIUM']};">{medium}</div>
        <div class="stat-label">Medium</div>
    </div>
    <div class="stat-card" style="background:{SEVERITY_BG['LOW']};">
        <div class="stat-num" style="color:{SEVERITY_COLORS['LOW']};">{low}</div>
        <div class="stat-label">Low</div>
    </div>
    <div class="stat-card" style="background:#f0fdf4;">
        <div class="stat-num" style="color:#0f172a;">{total}</div>
        <div class="stat-label">Total</div>
    </div>
</div>

<div class="section-title">Findings Overview</div>
<table>
    <thead>
        <tr>
            <th style="width:70px;">ID</th>
            <th style="width:80px;">Severity</th>
            <th>What&rsquo;s the Risk?</th>
            <th style="width:70px;">Status</th>
        </tr>
    </thead>
    <tbody>
        {finding_rows}
    </tbody>
</table>

<div class="footer">
    <div>Generated by Slopless &mdash; slopless.work</div>
    <div>Confidential &mdash; for authorized recipients only</div>
</div>

</body>
</html>"""


# ---------------------------------------------------------------------------
# PDF generation
# ---------------------------------------------------------------------------


def _generate_pdf_weasyprint(html: str, output_path: str) -> str:
    """Generate PDF using WeasyPrint."""
    from weasyprint import HTML

    HTML(string=html).write_pdf(output_path)
    return output_path


def _generate_pdf_fallback(html: str, output_path: str) -> str:
    """Fallback: save HTML and try wkhtmltopdf or just save as HTML."""
    html_path = output_path.replace(".pdf", ".html")
    Path(html_path).write_text(html, encoding="utf-8")

    # Try wkhtmltopdf
    try:
        subprocess.run(
            ["wkhtmltopdf", "--page-size", "A4", "--quiet", html_path, output_path],
            check=True,
            capture_output=True,
        )
        os.unlink(html_path)
        return output_path
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass

    console.print(f"[yellow]![/yellow] WeasyPrint not available. HTML summary saved to: {html_path}")
    console.print("[dim]Install weasyprint for direct PDF output: pip install weasyprint[/dim]")
    return html_path


def export_findings_to_pdf_summary(
    vulns: list[dict],
    output_path: str | None = None,
    project_name: str | None = None,
) -> str:
    """Generate a 1-page PDF executive summary from scan findings.

    Args:
        vulns: List of vulnerability dicts from the scan.
        output_path: Where to write the PDF. Defaults to ./slopless-summary.pdf.
        project_name: Name shown on the report header.

    Returns:
        Path to the generated file (PDF or HTML fallback).
    """
    if not project_name:
        project_name = Path.cwd().name

    scan_date = datetime.now().strftime("%B %d, %Y")

    if not output_path:
        output_path = str(Path.cwd() / "slopless-summary.pdf")

    # Ensure parent directory exists
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    html = _build_html(vulns, project_name, scan_date)

    try:
        return _generate_pdf_weasyprint(html, output_path)
    except ImportError:
        return _generate_pdf_fallback(html, output_path)
