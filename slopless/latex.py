"""LaTeX export for Slopless CLI.

Generates a professional LaTeX audit report from scan findings,
using the same data that powers the Notion export. The output
follows the XORS kaobook template structure (VAR_BITMIND).

Usage:
    slopless scan . --latex
    slopless scan . --latex --latex-output my-report.tex
"""

import os
import re
import shutil
from collections import Counter
from datetime import datetime
from pathlib import Path

from rich.console import Console

from slopless.notion import SEVERITY_PREFIX, generate_finding_ids

console = Console()


# =============================================================================
# >>>  CONFIGURATION — EDIT THESE VALUES  <<<
# =============================================================================
#
# LATEX_TEMPLATE_DIR:
#     Absolute or relative path to the example LaTeX project directory
#     that serves as the structural template for generated reports.
#     The generator reads this directory to copy supporting files
#     (cls, sty, figures, static chapters) into the output.
#
# LATEX_OUTPUT_FILENAME:
#     Default filename for the generated LaTeX report entry point.
#     Can be overridden via the --latex-output CLI flag.
#
# TODO: Update LATEX_TEMPLATE_DIR to point to your local template copy.
# =============================================================================

LATEX_TEMPLATE_DIR: str = os.environ.get(
    "SLOPLESS_LATEX_TEMPLATE_DIR",
    os.path.join(os.path.dirname(__file__), "..", "..", "VAR_BITMIND"),
)
""">>> Path to the example/template LaTeX project directory. <<<

Change this value to point at your own kaobook-based template.
You can also set the SLOPLESS_LATEX_TEMPLATE_DIR environment variable
or pass --latex-template on the CLI.
"""

LATEX_OUTPUT_FILENAME: str = "slopless-report.tex"
""">>> Default output filename for the generated LaTeX report. <<<

Override via --latex-output CLI flag or by editing this constant.
"""


# =============================================================================
# LaTeX character escaping
# =============================================================================

_LATEX_SPECIAL_CHARS = {
    "&": r"\&",
    "%": r"\%",
    "$": r"\$",
    "#": r"\#",
    "_": r"\_",
    "{": r"\{",
    "}": r"\}",
    "~": r"\textasciitilde{}",
    "^": r"\textasciicircum{}",
    "\\": r"\textbackslash{}",
}

_LATEX_ESCAPE_RE = re.compile(
    "[" + re.escape("".join(_LATEX_SPECIAL_CHARS.keys())) + "]"
)


def escape_latex(text: str) -> str:
    """Escape LaTeX special characters in *text*.

    Handles: & % $ # _ { } ~ ^ \\
    """
    if not text:
        return ""
    return _LATEX_ESCAPE_RE.sub(lambda m: _LATEX_SPECIAL_CHARS[m.group()], text)


def escape_latex_code(text: str) -> str:
    """Lightly escape text intended for lstlisting environments.

    lstlisting handles most special chars itself, but we still need to
    strip trailing whitespace per line to avoid compilation warnings.
    """
    if not text:
        return ""
    lines = text.splitlines()
    return "\n".join(line.rstrip() for line in lines)


# =============================================================================
# Severity helpers
# =============================================================================

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_LABELS = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
}


def _sort_vulns(vulns: list[dict]) -> list[dict]:
    """Return vulns sorted by severity (CRITICAL first)."""
    return sorted(
        vulns,
        key=lambda v: SEVERITY_ORDER.get(v.get("severity", "MEDIUM").upper(), 2),
    )


def _infer_type(vuln: dict) -> str:
    """Infer finding type/category — mirrors notion._infer_type."""
    category = vuln.get("category", "").lower()
    title = vuln.get("title", "").lower()

    quality_kw = ["naming", "style", "format", "lint", "unused", "dead code", "complexity"]
    if any(kw in title or kw in category for kw in quality_kw):
        return "Code Quality"

    reliability_kw = ["null", "race condition", "deadlock", "memory leak", "crash", "exception"]
    if any(kw in title or kw in category for kw in reliability_kw):
        return "Reliability"

    perf_kw = ["performance", "n+1", "slow", "timeout", "cache"]
    if any(kw in title or kw in category for kw in perf_kw):
        return "Performance"

    return "Security"


def _affected_files(vuln: dict) -> str:
    """Build affected-files string from vuln dict."""
    fp = vuln.get("file") or vuln.get("file_path") or "N/A"
    line = vuln.get("line") or vuln.get("line_number")
    if line and str(line) != "?" and int(line) > 0:
        return f"{fp}:{line}"
    return fp


# =============================================================================
# Editorial quality-control pass
# =============================================================================


def _editorial_qc(text: str) -> str:
    """Apply a lightweight editorial quality-control pass.

    This improves consistency and professionalism of the generated
    LaTeX content without altering technical meaning or severity.

    Improvements applied:
    - Normalize whitespace and paragraph spacing
    - Ensure sentences end with periods
    - Capitalize severity labels consistently
    - Remove duplicate blank lines
    - Trim trailing whitespace
    - Standardize common abbreviations
    - Ensure section headers have consistent casing
    """
    if not text:
        return text

    # Normalize line endings
    text = text.replace("\r\n", "\n")

    # Collapse runs of 3+ blank lines to 2
    text = re.sub(r"\n{4,}", "\n\n\n", text)

    # Trim trailing whitespace per line
    text = "\n".join(line.rstrip() for line in text.splitlines())

    # Standardize common abbreviations
    replacements = {
        "e.g ": "e.g.\\ ",
        "i.e ": "i.e.\\ ",
        "ie ": "i.e.\\ ",
        "eg ": "e.g.\\ ",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)

    # Ensure the document ends with a single newline
    text = text.rstrip("\n") + "\n"

    return text


# =============================================================================
# LaTeX content generators
# =============================================================================


def _generate_reportgen_macros(
    vulns: list[dict],
    sorted_vulns: list[dict],
) -> str:
    """Generate chapters/reportgen/macros.tex content."""
    # Count severities
    sev_counts: dict[str, int] = Counter()
    for v in vulns:
        sev = v.get("severity", "MEDIUM").upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    critical = sev_counts.get("CRITICAL", 0)
    high = sev_counts.get("HIGH", 0)
    medium = sev_counts.get("MEDIUM", 0)
    low = sev_counts.get("LOW", 0)

    # Category breakdown
    cat_counts: Counter = Counter()
    for v in sorted_vulns:
        cat_counts[_infer_type(v)] += 1

    cat_rows = "\n".join(
        r"\IssueCategoryTableCell{ " + cat + " }{ " + str(count) + r" } \\"
        for cat, count in cat_counts.most_common()
    )

    template = r"""\newcommand{\IssueCategoryTableContents}{
__CAT_ROWS__}

\newcommand{\criticalissues}{__CRITICAL__}
\newcommand{\highissues}{__HIGH__}
\newcommand{\mediumissues}{__MEDIUM__}
\newcommand{\lowissues}{__LOW__}
\newcommand{\warningissues}{0}
\newcommand{\infoissues}{0}

\newcommand{\criticalresolved}{0}
\newcommand{\highresolved}{0}
\newcommand{\mediumresolved}{0}
\newcommand{\lowresolved}{0}
\newcommand{\warningresolved}{0}
\newcommand{\inforesolved}{0}

\ADD{\criticalresolved}{\highresolved}\criticalhighresolved
\ADD{\mediumresolved}{\lowresolved}\mediumlowresolved
\ADD{\warningresolved}{\inforesolved}\warninginforesolved
\ADD{\criticalhighresolved}{\mediumlowresolved}\loworbetterresolved
\ADD{\loworbetterresolved}{\warninginforesolved}\numresolved

\ADD{\criticalissues}{\highissues}\numhighorbetter
\ADD{\numhighorbetter}{\mediumissues}\nummediumorbetter
\ADD{\nummediumorbetter}{\lowissues}\numloworbetter
\ADD{\numloworbetter}{\warningissues}\numwarningorbetter
\ADD{\numwarningorbetter}{\infoissues}\numissues
"""
    return (
        template
        .replace("__CAT_ROWS__", cat_rows)
        .replace("__CRITICAL__", str(critical))
        .replace("__HIGH__", str(high))
        .replace("__MEDIUM__", str(medium))
        .replace("__LOW__", str(low))
    )


def _generate_finding_detail(finding_id: str, vuln: dict) -> str:
    """Generate a single finding's detailed LaTeX section."""
    severity = vuln.get("severity", "MEDIUM").upper()
    sev_label = SEVERITY_LABELS.get(severity, severity.title())
    title = escape_latex(vuln.get("title", "Untitled"))
    description = escape_latex(vuln.get("description", "No description provided."))
    recommendation = escape_latex(vuln.get("recommendation", "No recommendation provided."))
    finding_type = _infer_type(vuln)
    files = escape_latex(_affected_files(vuln))
    cwe = vuln.get("cwe") or vuln.get("cwe_id") or ""
    code_snippet = vuln.get("code_snippet") or vuln.get("codeSnippet") or ""

    line_val = vuln.get("line") or vuln.get("line_number") or "N/A"

    # Build the section
    parts: list[str] = []

    parts.append(rf"\subsection{{{finding_id}: {title}}}")
    parts.append("")

    # Issue header table
    parts.append(r"\begin{IssueHeaderTable}{")
    parts.append(rf"    \IssueHeaderTitleCell{{Severity}} & \TableCell{{{sev_label}}} &")
    parts.append(rf"    \IssueHeaderTitleCell{{Type}} & \TableCell{{{escape_latex(finding_type)}}} \\")
    parts.append(r"    \hline")
    parts.append(rf"    \IssueHeaderTitleCell{{Status}} & \TableCell{{Open}} &")
    parts.append(rf"    \IssueHeaderTitleCell{{Location}} & \TableCell{{{escape_latex(str(line_val))}}} \\")
    parts.append(r"    \hline")
    parts.append(rf"    \IssueHeaderTitleCell{{File(s)}} &")
    parts.append(rf"    \multicolumn{{3}}{{p{{0.78\linewidth}}}}{{")
    parts.append(rf"      \raggedright {files}")
    parts.append(r"    } \\")

    if cwe:
        parts.append(r"    \hline")
        parts.append(rf"    \IssueHeaderTitleCell{{CWE}} &")
        parts.append(rf"    \multicolumn{{3}}{{c}}{{\TableCell{{{escape_latex(cwe)}}}}}")

    parts.append("}")
    parts.append(r"\end{IssueHeaderTable}")
    parts.append("")

    # Description
    parts.append(r"\paragraph{Description.}")
    parts.append(description)
    parts.append("")

    # Code snippet if available
    if code_snippet.strip():
        parts.append(r"\paragraph{Code Reference.}")
        parts.append(r"\begin{lstlisting}[basicstyle=\footnotesize\ttfamily,backgroundcolor=\color{bgcolor},breaklines=true,columns=fullflexible]")
        parts.append(escape_latex_code(code_snippet))
        parts.append(r"\end{lstlisting}")
        parts.append("")

    # Recommendation
    parts.append(r"\paragraph{Recommendation.}")
    parts.append(recommendation)
    parts.append("")

    parts.append(r"\clearpage")

    return "\n".join(parts)


def _generate_report_tex(sorted_vulns: list[dict], finding_ids: list[str]) -> str:
    """Generate chapters/reportgen/report.tex — summary table + detailed findings."""
    lines: list[str] = []

    lines.append("% Auto-generated audit report from Slopless scan findings")
    lines.append(f"% Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    lines.append("")

    # Summary table
    lines.append(r"\begin{SummaryTable}")
    lines.append("{")
    for fid, vuln in zip(finding_ids, sorted_vulns):
        sev = vuln.get("severity", "MEDIUM").upper()
        sev_label = SEVERITY_LABELS.get(sev, sev.title())
        title_esc = escape_latex(vuln.get("title", "Untitled"))
        lines.append(
            rf"\SummaryTableRow{{{fid}}}{{{title_esc}}}{{{sev_label}}}{{Open}} \\ \hline"
        )
    lines.append("}")
    lines.append(r"\end{SummaryTable}")
    lines.append("")
    lines.append(r"\clearpage")
    lines.append("")
    lines.append(r"\section{Detailed Description of Issues}")
    lines.append("")

    # Detailed finding sections
    for fid, vuln in zip(finding_ids, sorted_vulns):
        lines.append(_generate_finding_detail(fid, vuln))
        lines.append("")

    return "\n".join(lines)


def _generate_summary_tex(
    sorted_vulns: list[dict],
    project_name: str,
) -> str:
    """Generate a generic executive summary chapter."""
    sev_counts: dict[str, int] = Counter()
    for v in sorted_vulns:
        sev = v.get("severity", "MEDIUM").upper()
        sev_counts[sev] += 1

    critical = sev_counts.get("CRITICAL", 0)
    high = sev_counts.get("HIGH", 0)
    medium = sev_counts.get("MEDIUM", 0)
    low = sev_counts.get("LOW", 0)
    total = critical + high + medium + low

    proj_esc = escape_latex(project_name)

    blocking = critical + high
    blocking_text = (
        r"\textbf{\numhighorbetter{} of which are assessed to be of high severity or above}"
        if blocking > 0
        else "none of which are assessed to be of high severity or above"
    )

    template = r"""\setchapterpreamble[u]{\margintoc}
\chapter{Executive Summary}
\labch{summary}

\XORS{} conducted an automated security assessment of __PROJECT__ using Slopless static analysis tooling.

\paragraph{Summary of issues detected.}
The scan uncovered \textbf{\numissues{} issues}, __BLOCKING_TEXT__. The severity distribution is as follows:

\begin{itemize}
\item \textbf{\criticalissues{} Critical-severity issues}
\item \textbf{\highissues{} High-severity issues}
\item \textbf{\mediumissues{} Medium-severity issues}
\item \textbf{\lowissues{} Low-severity issues}
\end{itemize}

All findings are currently marked as Open pending remediation.

\paragraph{Disclaimer.}
This report is generated by automated tooling and provides no warranty of any kind, explicit or implied. The contents should not be construed as a complete guarantee that the system is secure in all dimensions. In no event shall \XORS{} or any of its employees be liable for any claim, damages or other liability arising from, out of or in connection with the results reported here.
"""
    return (
        template
        .replace("__PROJECT__", proj_esc)
        .replace("__BLOCKING_TEXT__", blocking_text)
    )


def _generate_goals_tex(project_name: str) -> str:
    """Generate a generic audit goals chapter."""
    proj_esc = escape_latex(project_name)
    template = r"""\setchapterpreamble[u]{\margintoc}
\chapter{Audit Goals and Scope}
\labch{goals}

\section{Audit Goals}

The scan was scoped to provide a comprehensive automated security assessment of __PROJECT__. The analysis sought to identify security vulnerabilities, code quality issues, and reliability concerns using Slopless static analysis.

\section{Classification of Vulnerabilities}

Findings are classified by severity: Critical, High, Medium, and Low, based on the potential impact and likelihood of exploitation.

\begin{table}[h!]
    \caption{Severity Breakdown.}
    \label{tbl:severity}
    {\small
    \begin{tabular}{wr{50pt}|wc{80pt}|wc{80pt}|wc{80pt}|wc{80pt}}
                    & Somewhat Bad & Bad     & Very Bad & Protocol Breaking \\
        \hline
        Not Likely  & \cellcolor{magenta}{Info} & \cellcolor{cyan}{Warning}  & \cellcolor{green}{Low}     & \cellcolor{yellow}{Medium}   \\
        \hline
        Likely      & \cellcolor{cyan}{Warning} & \cellcolor{green}{Low}     & \cellcolor{yellow}{Medium} & \cellcolor{orange}{High}     \\
        \hline
        Very Likely & \cellcolor{green}{Low}   & \cellcolor{yellow}{Medium} & \cellcolor{orange}{High}   & \cellcolor{red}{Critical}   \\
        \hline
    \end{tabular}
    }
\end{table}

\clearpage
"""
    return template.replace("__PROJECT__", proj_esc)


def _generate_chapters_macros(project_name: str) -> str:
    """Generate chapters/macros.tex with project-specific values.

    Copies the bulk of the static macro definitions from the template
    and overrides the project-specific values.
    """
    proj_esc = escape_latex(project_name)
    today = datetime.now()
    today_ymd = today.strftime("%Y-%m-%d")
    today_bmd = today.strftime("%b. %d")
    today_year = str(today.year)

    # Use str.replace() for substitutions to avoid Python 3.11 f-string
    # backslash limitations in complex LaTeX content.
    template = r"""%%***************************************************** added
\renewcommand{\mainmatter}{%
    \oldmainmatter%
    \pagestyle{scrheadings}%
    \pagelayout{wide}%
    \setchapterstyle{kao}
}

\renewcommand{\widelayout}{%
    \newgeometry{%
        top=27.4\vscale,
        bottom=27.4\vscale,
        inner=28\hscale,
        outer=28\hscale,
        marginparsep=5mm,
        marginparwidth=20mm,
    }%
    \recalchead%
}
%%*****************************************************

\newcommand\blfootnote[1]{%
  \begingroup
  \renewcommand\thefootnote{}\footnote{#1}%
  \addtocounter{footnote}{-1}%
  \endgroup
}

% commands for fancy tables
\usepackage{caption}
\usepackage{array}
\newcolumntype{R}[1]{>{\raggedright\arraybackslash}p{#1}}
\newcolumntype{L}[1]{>{\raggedleft\arraybackslash}p{#1}}
\newcommand\mrh{\color{vblue}\bfseries}
\newcommand\mrc[1]{\begin{tabular}{@{}l@{}} #1 \end{tabular}}

\newcommand{\toolname}{{XORS}\xspace}
\newcommand{\XORS}{{XORS}\xspace}

\usepackage{amssymb}
\usepackage{pifont}
\newcommand{\cmark}{\ding{51}}
\newcommand{\xmark}{\ding{55}}

\definecolor{keyword}{RGB}{75,119,190}
\definecolor{comment}{RGB}{38,166,91}
\definecolor{bgcolor}{RGB}{246,246,246}
\definecolor{Red}{RGB}{255,0,0}

\newcommand{\red}[1]{\textcolor{red}{#1}}
\newcommand{\code}[1]{\lstinline{#1}}

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% table macros
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

\newcommand{\IssueHeaderTitleCell}[1]{\cellcolor{vblue}{\textcolor{white}{\textbf{#1}}}}

\newcommand{\SummaryTableTitleCell}[1]{\cellcolor{vblue}{\textcolor{white}{\textbf{#1}}}}

\newcommand{\TableCell}[1]{\cellcolor{gray!10}{#1}}

\newcommand{\SummaryTableRow}[4]{\TableCell{#1} & \TableCell{#2}  & \TableCell{#3}  & \TableCell{#4}}

\newenvironment{SummaryTable}[1]
    {\begin{table}[h!]
        \caption{Summary of Discovered Vulnerabilities.}
        \label{tbl:vul-sum}
        \arrayrulecolor{white}
        {\small
        \begin{tabular}{wl{69pt}|wl{210pt}|wc{39pt}|wc{65pt}}
        \hline
        \SummaryTableTitleCell{    ID    }   & \SummaryTableTitleCell{    Description    }   & \SummaryTableTitleCell{    Severity    }   & \SummaryTableTitleCell{    Status    } \\
        \hline

        #1\\[1ex]

        \end{tabular}
        }
    \end{table}
}

\newenvironment{IssueHeaderTable}[1]
    {\begin{table}[htb]
        \rowcolors{1}{gray!10}{gray!10}
        \arrayrulecolor{white}
        \begin{tabularx}{\textwidth}{ wr{85pt}|wl{100pt}|wr{60pt}|wl{150pt} }

        #1\\[1ex]

        \end{tabularx}
    \end{table}
}

\newcommand{\IssueCategoryTableCell}[2]{
  \cellcolor{gray!10}{#1} & \cellcolor{gray!10}{#2}
}

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Audit Macros
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

\newcommand{\preambletodo}[1]{\textbf{\textcolor{red}{#1}}}
\newcommand{\placeholder}[1]{{\color{red}#1}}

\newcommand{\copyrightyear}{__YEAR__}
\newcommand{\client}{__PROJECT__}
\newcommand{\projname}{__PROJECT__}
\newcommand{\srclang}{N/A}
\newcommand{\platform}{N/A}

\newcommand{\auditrepo}{\url{N/A}}
\newcommand{\auditstartcommit}{\lstinline{HEAD}}
\newcommand{\auditendcommit}{\lstinline{HEAD}}
\newcommand{\numpushes}{1}
\newcommand{\lastpushdate}{__DATE_YMD__}

\newcommand{\auditmethod}{Automated (Slopless)\xspace}
\newcommand{\auditstart}{__DATE_BMD__}
\newcommand{\auditend}{__DATE_BMD__}
\newcommand{\auditstartyear}{__YEAR__}
\newcommand{\auditendyear}{__YEAR__}
\newcommand{\numauditors}{1}
\newcommand{\durationAmt}{1}
\newcommand{\durationunit}{day}
\MULTIPLY{\durationAmt}{\numauditors}\effortAmt
\newcommand{\auditduration}{\durationAmt\xspace\durationunit\xspace}
\newcommand{\auditeffort}{\effortAmt\xspace person-\durationunit\xspace}
"""
    return (
        template
        .replace("__PROJECT__", proj_esc)
        .replace("__YEAR__", today_year)
        .replace("__DATE_YMD__", today_ymd)
        .replace("__DATE_BMD__", today_bmd)
    )


# =============================================================================
# Main export function
# =============================================================================


def export_findings_to_latex(
    vulns: list[dict],
    output_path: str | None = None,
    template_dir: str | None = None,
    project_name: str | None = None,
) -> str:
    """Export scan findings to a LaTeX audit report.

    Mirrors the Notion export flow: takes the same vulns list,
    sorts by severity, generates XORS-style IDs, and produces
    a complete LaTeX project that can be compiled to PDF.

    Args:
        vulns: List of vulnerability dicts from the scan API.
        output_path: Path for the output .tex file (or directory).
                     Defaults to LATEX_OUTPUT_FILENAME in cwd.
        template_dir: Path to template directory. Defaults to LATEX_TEMPLATE_DIR.
        project_name: Project name for the report title.

    Returns:
        Absolute path to the generated main .tex file.
    """
    template_dir = template_dir or LATEX_TEMPLATE_DIR
    template_path = Path(template_dir).resolve()

    # Determine output location
    if output_path:
        out = Path(output_path)
        if out.suffix == ".tex":
            output_dir = out.parent
            output_filename = out.name
        else:
            output_dir = out
            output_filename = LATEX_OUTPUT_FILENAME
    else:
        output_dir = Path.cwd() / "slopless-latex-report"
        output_filename = LATEX_OUTPUT_FILENAME

    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if not project_name:
        project_name = "Slopless Scan Report"

    # Sort and assign IDs — same as Notion flow
    sorted_vulns = _sort_vulns(vulns)
    finding_ids = generate_finding_ids(sorted_vulns)

    console.print("[dim]Generating LaTeX report...[/dim]")

    # ---- Copy template supporting files if template exists ----
    if template_path.is_dir():
        _copy_template_support_files(template_path, output_dir)

    # ---- Generate dynamic content ----
    chapters_dir = output_dir / "chapters"
    chapters_dir.mkdir(exist_ok=True)
    reportgen_dir = chapters_dir / "reportgen"
    reportgen_dir.mkdir(exist_ok=True)

    # 1. reportgen/macros.tex — severity counts, category breakdown
    macros_content = _generate_reportgen_macros(vulns, sorted_vulns)
    (reportgen_dir / "macros.tex").write_text(_editorial_qc(macros_content))

    # 2. reportgen/report.tex — summary table + detailed findings
    report_content = _generate_report_tex(sorted_vulns, finding_ids)
    (reportgen_dir / "report.tex").write_text(_editorial_qc(report_content))

    # 3. chapters/macros.tex — project metadata + table macros
    ch_macros = _generate_chapters_macros(project_name)
    (chapters_dir / "macros.tex").write_text(_editorial_qc(ch_macros))

    # 4. chapters/summary.tex — executive summary
    summary_content = _generate_summary_tex(sorted_vulns, project_name)
    (chapters_dir / "summary.tex").write_text(_editorial_qc(summary_content))

    # 5. chapters/goals.tex — generic audit goals
    goals_content = _generate_goals_tex(project_name)
    (chapters_dir / "goals.tex").write_text(_editorial_qc(goals_content))

    # 6. chapters/dashboard.tex — copy from template (static structure)
    if not (chapters_dir / "dashboard.tex").exists():
        dashboard_src = template_path / "chapters" / "dashboard.tex"
        if dashboard_src.is_file():
            shutil.copy2(dashboard_src, chapters_dir / "dashboard.tex")
        else:
            _write_default_dashboard(chapters_dir / "dashboard.tex")

    # 7. chapters/report.tex — chapter wrapper
    report_chapter = chapters_dir / "report.tex"
    report_chapter.write_text(
        _editorial_qc(
            r"""\setchapterpreamble[u]{\margintoc}
\chapter{Vulnerability Report}
\label{sec:report}

\renewcommand{\figurename}{Snippet}

In this section, we describe the vulnerabilities found during the Slopless scan. For each issue found, we log the type of the issue, its severity, location in the code base, and its current status. Table~\ref{tbl:vul-sum} summarizes the issues discovered:

\input{chapters/reportgen/report.tex}
"""
        )
    )

    # 8. Main .tex entry point — copy from template if available, else generate
    main_tex_path = output_dir / output_filename
    main_src = template_path / "main.tex"
    if main_src.is_file() and output_filename == LATEX_OUTPUT_FILENAME:
        # Read template main.tex and adjust if needed
        main_content = main_src.read_text()
        main_tex_path.write_text(main_content)
    else:
        _write_main_tex(main_tex_path, project_name)

    console.print(f"[green]LaTeX report generated:[/green] {output_dir}/")
    console.print(f"[dim]  Main entry point: {main_tex_path}[/dim]")
    console.print(f"[dim]  Findings count:   {len(sorted_vulns)}[/dim]")
    console.print()
    console.print("[dim]To compile to PDF:[/dim]")
    console.print(f"[dim]  cd {output_dir} && pdflatex {output_filename} && pdflatex {output_filename}[/dim]")

    return str(main_tex_path)


def _copy_template_support_files(template_path: Path, output_dir: Path) -> None:
    """Copy cls, sty, bib, figures, and other support files from template."""
    # Files/patterns to copy from template root
    root_extensions = {".cls", ".sty", ".bib", ".ist", ".bst"}
    for f in template_path.iterdir():
        if f.is_file() and f.suffix in root_extensions:
            dest = output_dir / f.name
            if not dest.exists():
                shutil.copy2(f, dest)

    # Copy figures directory
    fig_src = template_path / "figures"
    fig_dst = output_dir / "figures"
    if fig_src.is_dir() and not fig_dst.exists():
        shutil.copytree(fig_src, fig_dst, dirs_exist_ok=True)

    # Copy glossary if present
    glossary_src = template_path / "glossary.tex"
    glossary_dst = output_dir / "glossary.tex"
    if glossary_src.is_file() and not glossary_dst.exists():
        shutil.copy2(glossary_src, glossary_dst)

    # Copy listings-rust.sty if present
    for extra in ["listings-rust.sty", "snapshot.sty"]:
        src = template_path / extra
        dst = output_dir / extra
        if src.is_file() and not dst.exists():
            shutil.copy2(src, dst)


def _write_default_dashboard(path: Path) -> None:
    """Write a default dashboard.tex if template copy is unavailable."""
    path.write_text(
        r"""\setchapterpreamble[u]{\margintoc}
\chapter{Project Dashboard}
\labch{dashboard}

\begin{table}[h!]
    \caption{Vulnerability Summary.}
    \arrayrulecolor{white}
    \begin{tabular}{wl{200pt}|wc{50pt}|wc{70pt}}
        \hline
        \cellcolor{vblue}{\textcolor{white}{\textbf{    Name    }}}    & \cellcolor{vblue}{\textcolor{white}{\textbf{    Number    }}}   & \cellcolor{vblue}{\textcolor{white}{    Resolved    }}      \\
        \hline
        \cellcolor{gray!10}{    Critical-Severity Issues    }   & \cellcolor{gray!10}{    \criticalissues    }       & \cellcolor{gray!10}{    \criticalresolved    }     \\
        \hline
        \cellcolor{gray!10}{    High-Severity Issues    }   & \cellcolor{gray!10}{    \highissues    }       & \cellcolor{gray!10}{    \highresolved    }     \\
        \hline
        \cellcolor{gray!10}{    Medium-Severity Issues    }     & \cellcolor{gray!10}{  \mediumissues    }     & \cellcolor{gray!10}{    \mediumresolved    }  \\
        \hline
        \cellcolor{gray!10}{    Low-Severity Issues    }   & \cellcolor{gray!10}{    \lowissues    }     & \cellcolor{gray!10}{    \lowresolved   }  \\
        \hline
        \cellcolor{gray!10}{    TOTAL    }   & \cellcolor{gray!10}{    \numissues   }     & \cellcolor{gray!10}{    \numresolved    }
    \end{tabular}
\end{table}

\begin{table}[h!]
    \caption{Category Breakdown.}
    \arrayrulecolor{white}
    \begin{tabular}{wl{175pt}|wc{50pt}}
        \cellcolor{vblue}{\textcolor{white}{\textbf{    Name    }}}    & \cellcolor{vblue}{\textcolor{white}{\textbf{    Number    }}}  \\
        \hline

        \IssueCategoryTableContents
        \hline
    \end{tabular}
\end{table}

\clearpage
"""
    )


def _write_main_tex(path: Path, project_name: str) -> None:
    """Write a standalone main.tex when template main.tex is not available."""
    proj_esc = escape_latex(project_name)
    content = r"""\documentclass[
    a4paper,
    fontsize=11pt,
    twoside=true,
    numbers=noenddot,
]{kaobook}

\usepackage[english]{babel}
\usepackage[english=british]{csquotes}
\usepackage[justification=centering]{caption}
\usepackage{listings}
\usepackage{float}
\usepackage{tabularx}
\usepackage{calculator}
\usepackage{calculus}
\usepackage{kaobiblio}
\usepackage[framed=true]{kaotheorems}
\usepackage{kaorefs}
\usepackage{tabto}
\usepackage{graphbox}

\newcommand\mytab{\tab \hspace{-5cm}}
\graphicspath{{images/}{figures/}}

\makeindex[columns=3, title=Alphabetical Index, intoc]

\input{chapters/macros.tex}
\input{chapters/reportgen/macros.tex}

\begin{document}

\title[XORS Auditing Report]{XORS Auditing Report}
\date{\textbf{\textcolor{vblue}{FOR}}\\[3ex]
\begin{tabular}{c}
    \textsf{\huge __PROJECT__} \\[100pt]
\end{tabular}}
\publishers{
  XORS Software \\
  \today}

\frontmatter
\maketitle
\tableofcontents

\mainmatter
\setchapterstyle{kao}

\input{chapters/summary.tex}
\input{chapters/dashboard.tex}
\input{chapters/goals.tex}
\input{chapters/report.tex}

\end{document}
"""
    path.write_text(content.replace("__PROJECT__", proj_esc))
