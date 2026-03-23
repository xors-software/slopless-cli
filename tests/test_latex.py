"""Tests for the LaTeX export module."""

import json
import os
import tempfile
from pathlib import Path

import pytest

from slopless.latex import (
    LATEX_OUTPUT_FILENAME,
    LATEX_TEMPLATE_DIR,
    _editorial_qc,
    _generate_finding_detail,
    _generate_report_tex,
    _generate_reportgen_macros,
    _generate_summary_tex,
    _infer_type,
    _sort_vulns,
    escape_latex,
    escape_latex_code,
    export_findings_to_latex,
)
from slopless.notion import generate_finding_ids


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

SAMPLE_VULNS = [
    {
        "severity": "HIGH",
        "title": "SQL Injection in user_login()",
        "description": "User input is concatenated directly into SQL query string.",
        "recommendation": "Use parameterized queries instead of string concatenation.",
        "file": "src/auth.py",
        "line": 42,
        "category": "Security",
        "cwe_id": "CWE-89",
        "code_snippet": 'query = f"SELECT * FROM users WHERE name = \'{username}\'"',
        "confidence": "HIGH",
    },
    {
        "severity": "CRITICAL",
        "title": "Hardcoded API Key",
        "description": "AWS secret key is hardcoded in source code.",
        "recommendation": "Use environment variables or a secrets manager.",
        "file": "config.py",
        "line": 10,
        "category": "Security",
        "cwe_id": "CWE-798",
        "code_snippet": 'AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"',
        "confidence": "HIGH",
    },
    {
        "severity": "MEDIUM",
        "title": "Missing rate limiting on login endpoint",
        "description": "The /api/login endpoint has no rate limiting.",
        "recommendation": "Add rate limiting middleware.",
        "file": "src/routes/auth.py",
        "line": 88,
        "category": "Security",
        "cwe_id": "CWE-307",
        "code_snippet": "",
        "confidence": "MEDIUM",
    },
    {
        "severity": "LOW",
        "title": "Unused import in utils.py",
        "description": "The 'os' module is imported but never used.",
        "recommendation": "Remove the unused import.",
        "file": "src/utils.py",
        "line": 1,
        "category": "Code Quality",
        "cwe_id": "",
        "code_snippet": "import os",
        "confidence": "LOW",
    },
]


# ---------------------------------------------------------------------------
# escape_latex
# ---------------------------------------------------------------------------


class TestEscapeLatex:
    def test_special_chars(self):
        assert escape_latex("a & b") == r"a \& b"
        assert escape_latex("100%") == r"100\%"
        assert escape_latex("$var") == r"\$var"
        assert escape_latex("#tag") == r"\#tag"
        assert escape_latex("file_name") == r"file\_name"
        assert escape_latex("{brace}") == r"\{brace\}"

    def test_combined(self):
        result = escape_latex("cost: $100 & 50% off #deal")
        assert r"\$" in result
        assert r"\&" in result
        assert r"\%" in result
        assert r"\#" in result

    def test_empty_string(self):
        assert escape_latex("") == ""

    def test_no_special_chars(self):
        assert escape_latex("hello world") == "hello world"

    def test_tilde_and_caret(self):
        assert escape_latex("~") == r"\textasciitilde{}"
        assert escape_latex("^") == r"\textasciicircum{}"

    def test_backslash(self):
        assert escape_latex("\\") == r"\textbackslash{}"


class TestEscapeLatexCode:
    def test_strips_trailing_whitespace(self):
        result = escape_latex_code("  code  \n  more  ")
        assert result == "  code\n  more"

    def test_empty(self):
        assert escape_latex_code("") == ""


# ---------------------------------------------------------------------------
# Sorting & type inference
# ---------------------------------------------------------------------------


class TestSortVulns:
    def test_sorts_by_severity(self):
        sorted_v = _sort_vulns(SAMPLE_VULNS)
        severities = [v["severity"] for v in sorted_v]
        assert severities == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    def test_empty_list(self):
        assert _sort_vulns([]) == []


class TestInferType:
    def test_security(self):
        assert _infer_type({"title": "SQL Injection", "category": "Security"}) == "Security"

    def test_code_quality(self):
        assert _infer_type({"title": "Unused import", "category": "lint"}) == "Code Quality"

    def test_reliability(self):
        assert _infer_type({"title": "Race condition in scheduler", "category": ""}) == "Reliability"

    def test_performance(self):
        assert _infer_type({"title": "N+1 query in dashboard", "category": ""}) == "Performance"


# ---------------------------------------------------------------------------
# Finding ID generation (reuses notion.generate_finding_ids)
# ---------------------------------------------------------------------------


class TestFindingIds:
    def test_ids_match_severity(self):
        sorted_v = _sort_vulns(SAMPLE_VULNS)
        ids = generate_finding_ids(sorted_v)
        assert ids[0] == "XORS-C1"  # CRITICAL
        assert ids[1] == "XORS-H1"  # HIGH
        assert ids[2] == "XORS-M1"  # MEDIUM
        assert ids[3] == "XORS-L1"  # LOW

    def test_increments_within_severity(self):
        vulns = [
            {"severity": "HIGH", "title": "A"},
            {"severity": "HIGH", "title": "B"},
            {"severity": "LOW", "title": "C"},
        ]
        ids = generate_finding_ids(vulns)
        assert ids == ["XORS-H1", "XORS-H2", "XORS-L1"]


# ---------------------------------------------------------------------------
# LaTeX content generation
# ---------------------------------------------------------------------------


class TestReportgenMacros:
    def test_contains_severity_counts(self):
        sorted_v = _sort_vulns(SAMPLE_VULNS)
        macros = _generate_reportgen_macros(SAMPLE_VULNS, sorted_v)
        assert r"\newcommand{\criticalissues}{1}" in macros
        assert r"\newcommand{\highissues}{1}" in macros
        assert r"\newcommand{\mediumissues}{1}" in macros
        assert r"\newcommand{\lowissues}{1}" in macros

    def test_contains_category_breakdown(self):
        sorted_v = _sort_vulns(SAMPLE_VULNS)
        macros = _generate_reportgen_macros(SAMPLE_VULNS, sorted_v)
        assert "IssueCategoryTableCell" in macros
        assert "Security" in macros


class TestReportTex:
    def test_contains_summary_table(self):
        sorted_v = _sort_vulns(SAMPLE_VULNS)
        ids = generate_finding_ids(sorted_v)
        report = _generate_report_tex(sorted_v, ids)
        assert r"\begin{SummaryTable}" in report
        assert "XORS-C1" in report
        assert "XORS-H1" in report

    def test_contains_detailed_sections(self):
        sorted_v = _sort_vulns(SAMPLE_VULNS)
        ids = generate_finding_ids(sorted_v)
        report = _generate_report_tex(sorted_v, ids)
        assert r"\subsection{XORS-C1:" in report
        assert r"\paragraph{Description.}" in report
        assert r"\paragraph{Recommendation.}" in report

    def test_escapes_special_chars_in_titles(self):
        vulns = [{"severity": "HIGH", "title": "Use of eval() & exec()", "description": "Bad", "recommendation": "Fix"}]
        ids = generate_finding_ids(vulns)
        report = _generate_report_tex(vulns, ids)
        assert r"\&" in report


class TestFindingDetail:
    def test_basic_structure(self):
        vuln = SAMPLE_VULNS[0]
        detail = _generate_finding_detail("XORS-H1", vuln)
        assert r"\subsection{XORS-H1:" in detail
        assert r"\begin{IssueHeaderTable}" in detail
        assert r"\paragraph{Description.}" in detail
        assert r"\paragraph{Recommendation.}" in detail
        assert r"\paragraph{Code Reference.}" in detail
        assert r"\clearpage" in detail

    def test_no_code_snippet(self):
        vuln = {**SAMPLE_VULNS[2], "code_snippet": ""}
        detail = _generate_finding_detail("XORS-M1", vuln)
        assert r"\paragraph{Code Reference.}" not in detail


class TestSummaryTex:
    def test_contains_executive_summary(self):
        sorted_v = _sort_vulns(SAMPLE_VULNS)
        summary = _generate_summary_tex(sorted_v, "TestProject")
        assert r"\chapter{Executive Summary}" in summary
        assert "TestProject" in summary


# ---------------------------------------------------------------------------
# Editorial QC
# ---------------------------------------------------------------------------


class TestEditorialQC:
    def test_collapses_excessive_blank_lines(self):
        text = "line1\n\n\n\n\nline2"
        result = _editorial_qc(text)
        assert "\n\n\n\n" not in result
        assert "line1" in result and "line2" in result

    def test_strips_trailing_whitespace(self):
        text = "line1   \nline2  "
        result = _editorial_qc(text)
        for line in result.splitlines():
            assert line == line.rstrip()

    def test_standardizes_abbreviations(self):
        text = "this is eg a test"
        result = _editorial_qc(text)
        assert r"e.g.\ " in result

    def test_empty_input(self):
        assert _editorial_qc("") == ""

    def test_ends_with_newline(self):
        result = _editorial_qc("some text")
        assert result.endswith("\n")


# ---------------------------------------------------------------------------
# Full export integration test
# ---------------------------------------------------------------------------


class TestExportFindingsToLatex:
    def test_generates_output_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.tex")
            result = export_findings_to_latex(
                SAMPLE_VULNS,
                output_path=output_path,
                template_dir="/nonexistent-template",  # no template copy
                project_name="IntegrationTest",
            )

            assert Path(result).exists()
            assert result.endswith(".tex")

            # Check generated files exist
            output_dir = Path(result).parent
            assert (output_dir / "chapters" / "summary.tex").exists()
            assert (output_dir / "chapters" / "dashboard.tex").exists()
            assert (output_dir / "chapters" / "goals.tex").exists()
            assert (output_dir / "chapters" / "report.tex").exists()
            assert (output_dir / "chapters" / "reportgen" / "report.tex").exists()
            assert (output_dir / "chapters" / "reportgen" / "macros.tex").exists()

    def test_report_contains_all_findings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.tex")
            export_findings_to_latex(
                SAMPLE_VULNS,
                output_path=output_path,
                template_dir="/nonexistent-template",
                project_name="TestProject",
            )

            report = (Path(tmpdir) / "chapters" / "reportgen" / "report.tex").read_text()
            assert "XORS-C1" in report
            assert "XORS-H1" in report
            assert "XORS-M1" in report
            assert "XORS-L1" in report

    def test_empty_vulns(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.tex")
            result = export_findings_to_latex(
                [],
                output_path=output_path,
                template_dir="/nonexistent-template",
                project_name="EmptyTest",
            )
            assert Path(result).exists()

    def test_default_output_location(self):
        """When no output_path is given, writes to slopless-latex-report/ in cwd."""
        with tempfile.TemporaryDirectory() as tmpdir:
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                result = export_findings_to_latex(
                    SAMPLE_VULNS,
                    template_dir="/nonexistent-template",
                    project_name="DefaultTest",
                )
                assert "slopless-latex-report" in result
                assert Path(result).exists()
            finally:
                os.chdir(original_cwd)

    def test_with_real_template(self):
        """If VAR_BITMIND template exists, copies support files."""
        template_dir = Path(LATEX_TEMPLATE_DIR).resolve()
        if not template_dir.is_dir():
            pytest.skip("VAR_BITMIND template not found")

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.tex")
            result = export_findings_to_latex(
                SAMPLE_VULNS,
                output_path=output_path,
                template_dir=str(template_dir),
                project_name="TemplateTest",
            )
            output_dir = Path(result).parent

            # Should have copied cls/sty files
            assert any(f.suffix == ".cls" for f in output_dir.iterdir())


# ---------------------------------------------------------------------------
# Notion export compatibility (non-breaking)
# ---------------------------------------------------------------------------


class TestNotionCompatibility:
    """Verify that importing latex does not break notion exports."""

    def test_notion_imports_still_work(self):
        from slopless.notion import (
            NotionAuthError,
            NotionPageNotFoundError,
            export_findings_to_notion,
            generate_finding_ids,
        )
        assert callable(export_findings_to_notion)
        assert callable(generate_finding_ids)

    def test_shared_finding_ids(self):
        """LaTeX and Notion use the same ID generation."""
        from slopless.latex import _sort_vulns
        sorted_v = _sort_vulns(SAMPLE_VULNS)
        ids = generate_finding_ids(sorted_v)
        assert all(id.startswith("XORS-") for id in ids)
        assert len(ids) == len(SAMPLE_VULNS)
