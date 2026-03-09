"""Local diff-aware scanning for Slopless.

Detects git state, computes changed files against a base branch,
and runs Slopless scans scoped to the current branch's changes.
Designed for interactive use with Claude Code in VS Code.
"""

import io
import json
import os
import subprocess
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from slopless.config import get_api_url, get_auth_headers, get_license_key

console = Console()


@dataclass
class GitState:
    """Current git repository state."""

    is_repo: bool = False
    repo_root: str = ""
    current_branch: str = ""
    base_branch: str = "main"
    changed_files: list[str] = field(default_factory=list)
    has_staged: bool = False
    has_unstaged: bool = False
    diff_stat: str = ""
    error: str = ""


@dataclass
class Finding:
    """A single scan finding, normalized."""

    file: str
    line: int | str = "?"
    line_end: int | str | None = None
    severity: str = "MEDIUM"
    title: str = ""
    category: str = ""
    cwe_id: str = ""
    description: str = ""
    code_snippet: str = ""
    recommendation: str = ""
    confidence: str = ""


@dataclass
class ScanResult:
    """Result of a diff-aware scan."""

    success: bool = False
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    base_branch: str = ""
    current_branch: str = ""
    error: str = ""

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.upper() == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.upper() == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.upper() == "MEDIUM")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.upper() == "LOW")

    @property
    def total_count(self) -> int:
        return len(self.findings)

    @property
    def is_clean(self) -> bool:
        return self.success and self.critical_count == 0 and self.high_count == 0


def _run_git(args: list[str], cwd: str | None = None) -> tuple[bool, str]:
    """Run a git command and return (success, output)."""
    try:
        result = subprocess.run(
            ["git"] + args,
            capture_output=True,
            text=True,
            cwd=cwd,
            timeout=30,
        )
        return result.returncode == 0, result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False, ""


def detect_git_state(repo_path: str = ".", base_branch: str | None = None) -> GitState:
    """Detect the current git repository state.

    Args:
        repo_path: Path to check (defaults to cwd)
        base_branch: Explicit base branch. If None, auto-detected.

    Returns:
        GitState with all detected information
    """
    state = GitState()

    # Check if inside a git repo
    ok, root = _run_git(["rev-parse", "--show-toplevel"], cwd=repo_path)
    if not ok:
        state.error = "Not inside a git repository."
        return state

    state.is_repo = True
    state.repo_root = root

    # Current branch
    ok, branch = _run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=root)
    if ok:
        state.current_branch = branch

    # Determine base branch
    if base_branch:
        state.base_branch = base_branch
    else:
        state.base_branch = _detect_base_branch(root)

    # Verify base branch exists
    ok, _ = _run_git(["rev-parse", "--verify", state.base_branch], cwd=root)
    if not ok:
        # Try with origin/ prefix
        ok, _ = _run_git(["rev-parse", "--verify", f"origin/{state.base_branch}"], cwd=root)
        if ok:
            state.base_branch = f"origin/{state.base_branch}"
        else:
            state.error = f"Base branch '{state.base_branch}' not found locally. Try: git fetch origin"
            return state

    # Get changed files (committed on branch + staged + unstaged)
    changed = set()

    # Files changed in commits on this branch vs base
    merge_base_ok, merge_base = _run_git(
        ["merge-base", state.base_branch, "HEAD"], cwd=root
    )
    if merge_base_ok and merge_base:
        ok, diff_output = _run_git(
            ["diff", "--name-only", merge_base, "HEAD"], cwd=root
        )
        if ok and diff_output:
            changed.update(diff_output.splitlines())

    # Staged changes
    ok, staged = _run_git(["diff", "--name-only", "--cached"], cwd=root)
    if ok and staged:
        state.has_staged = True
        changed.update(staged.splitlines())

    # Unstaged changes
    ok, unstaged = _run_git(["diff", "--name-only"], cwd=root)
    if ok and unstaged:
        state.has_unstaged = True
        changed.update(unstaged.splitlines())

    # Untracked files (new files not yet committed)
    ok, untracked = _run_git(["ls-files", "--others", "--exclude-standard"], cwd=root)
    if ok and untracked:
        changed.update(untracked.splitlines())

    # Filter to files that actually exist on disk
    state.changed_files = sorted(
        f for f in changed
        if (Path(root) / f).is_file()
    )

    # Diff stat summary
    if merge_base_ok and merge_base:
        ok, stat = _run_git(["diff", "--stat", merge_base], cwd=root)
        if ok:
            state.diff_stat = stat

    return state


def _detect_base_branch(repo_root: str) -> str:
    """Auto-detect the default base branch for this repo."""
    # Try remote HEAD
    ok, output = _run_git(["symbolic-ref", "refs/remotes/origin/HEAD"], cwd=repo_root)
    if ok and output:
        # refs/remotes/origin/main -> main
        return output.split("/")[-1]

    # Check if common defaults exist
    for candidate in ["main", "master", "develop"]:
        ok, _ = _run_git(["rev-parse", "--verify", candidate], cwd=repo_root)
        if ok:
            return candidate
        ok, _ = _run_git(["rev-parse", "--verify", f"origin/{candidate}"], cwd=repo_root)
        if ok:
            return f"origin/{candidate}"

    return "main"


def _create_changed_files_zip(repo_root: str, changed_files: list[str]) -> io.BytesIO:
    """Create a ZIP of only the changed files."""
    zip_buffer = io.BytesIO()
    root = Path(repo_root)

    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel_path in changed_files:
            full_path = root / rel_path
            if full_path.is_file():
                zf.write(full_path, rel_path)

    zip_buffer.seek(0)
    return zip_buffer


async def run_diff_scan(
    git_state: GitState,
    scan_full_repo: bool = False,
) -> ScanResult:
    """Run a Slopless scan scoped to changed files.

    Args:
        git_state: Detected git state with changed files
        scan_full_repo: If True, scan entire repo instead of just changed files

    Returns:
        ScanResult with normalized findings
    """
    result = ScanResult(
        base_branch=git_state.base_branch,
        current_branch=git_state.current_branch,
    )

    if not git_state.changed_files and not scan_full_repo:
        result.success = True
        result.files_scanned = 0
        return result

    license_key = get_license_key()
    if not license_key:
        result.error = "Not logged in. Run 'slopless login' first."
        return result

    api_url = get_api_url()
    headers = get_auth_headers()

    # Create zip of changed files (or full repo)
    if scan_full_repo:
        from slopless.cli import _create_repo_zip

        zip_buffer = _create_repo_zip(Path(git_state.repo_root))
    else:
        zip_buffer = _create_changed_files_zip(git_state.repo_root, git_state.changed_files)

    zip_size = len(zip_buffer.getvalue())
    if zip_size > 50 * 1024 * 1024:
        result.error = "Changed files too large for upload (>50MB)."
        return result

    result.files_scanned = len(git_state.changed_files) if not scan_full_repo else -1

    try:
        async with httpx.AsyncClient(timeout=300.0) as client:
            response = await client.post(
                f"{api_url}/v1/proxy/scan/upload",
                files={"file": ("diff.zip", zip_buffer, "application/zip")},
                data={
                    "auto_fix": "false",
                    "cross_validate": "true",
                    "parallel_candidates": "1",
                    "polish": "false",
                },
                headers=headers,
            )

            if response.status_code == 401:
                result.error = "License key expired or invalid. Run 'slopless login'."
                return result

            response.raise_for_status()
            api_result = response.json()

    except httpx.TimeoutException:
        result.error = "Scan timed out."
        return result
    except httpx.HTTPError as e:
        result.error = f"API error: {e}"
        return result

    if not api_result.get("success"):
        result.error = api_result.get("error", "Scan failed.")
        return result

    # Normalize findings
    result.success = True
    for vuln in api_result.get("vulnerabilities", []):
        result.findings.append(
            Finding(
                file=vuln.get("file_path", vuln.get("file", "unknown")),
                line=vuln.get("line_number", vuln.get("line", "?")),
                severity=vuln.get("severity", "MEDIUM").upper(),
                title=vuln.get("title", "Untitled"),
                category=vuln.get("category", ""),
                cwe_id=vuln.get("cwe_id", ""),
                description=vuln.get("description", ""),
                code_snippet=vuln.get("code_snippet", ""),
                recommendation=vuln.get("recommendation", ""),
                confidence=vuln.get("confidence", ""),
            )
        )

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    result.findings.sort(key=lambda f: severity_order.get(f.severity, 2))

    return result


# =============================================================================
# Output Formatting
# =============================================================================


def format_text(result: ScanResult) -> str:
    """Format scan results as plain text optimized for Claude Code / terminal.

    This is the primary output format for the local workflow. It is designed
    to be concise, actionable, and easy for Claude Code to parse and act on.
    """
    lines: list[str] = []

    if not result.success:
        lines.append(f"SCAN FAILED: {result.error}")
        return "\n".join(lines)

    # Header
    lines.append(f"Slopless Diff Scan: {result.current_branch} vs {result.base_branch}")
    lines.append(f"Files scanned: {result.files_scanned}")
    lines.append("")

    # Severity summary
    lines.append("SEVERITY SUMMARY")
    lines.append(f"  CRITICAL: {result.critical_count}")
    lines.append(f"  HIGH:     {result.high_count}")
    lines.append(f"  MEDIUM:   {result.medium_count}")
    lines.append(f"  LOW:      {result.low_count}")
    lines.append(f"  TOTAL:    {result.total_count}")
    lines.append("")

    if result.is_clean and result.total_count == 0:
        lines.append("CLEAN — No findings. Ready for PR.")
        return "\n".join(lines)

    if result.is_clean:
        lines.append("PASS — No CRITICAL or HIGH findings.")
        lines.append("")

    # Group by file
    by_file: dict[str, list[Finding]] = {}
    for f in result.findings:
        by_file.setdefault(f.file, []).append(f)

    lines.append("FINDINGS BY FILE")
    lines.append("-" * 60)

    for filepath, findings in by_file.items():
        lines.append(f"\n  {filepath}")
        for f in findings:
            line_ref = f"{f.line}" if f.line != "?" else "?"
            lines.append(f"    [{f.severity}] {f.title} (line {line_ref})")
            if f.description:
                desc = f.description[:200].replace("\n", " ")
                lines.append(f"      {desc}")
            if f.recommendation:
                rec = f.recommendation[:200].replace("\n", " ")
                lines.append(f"      Fix: {rec}")
            if f.cwe_id:
                lines.append(f"      CWE: {f.cwe_id}")
            lines.append("")

    # Next actions
    lines.append("-" * 60)
    if result.critical_count > 0 or result.high_count > 0:
        lines.append("ACTION REQUIRED: Fix CRITICAL/HIGH findings before opening PR.")
        lines.append("Run 'slopless diff-scan' again after fixing to verify.")
    else:
        lines.append("Optional: Fix MEDIUM/LOW findings to improve security posture.")

    return "\n".join(lines)


def format_json(result: ScanResult) -> str:
    """Format scan results as stable JSON for machine consumption."""
    data = {
        "success": result.success,
        "error": result.error if result.error else None,
        "branch": result.current_branch,
        "base_branch": result.base_branch,
        "files_scanned": result.files_scanned,
        "summary": {
            "total": result.total_count,
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
            "is_clean": result.is_clean,
        },
        "findings": [
            {
                "file": f.file,
                "line": f.line,
                "severity": f.severity,
                "title": f.title,
                "category": f.category,
                "cwe_id": f.cwe_id,
                "description": f.description,
                "recommendation": f.recommendation,
                "confidence": f.confidence,
            }
            for f in result.findings
        ],
    }
    return json.dumps(data, indent=2)


def print_rich(result: ScanResult) -> None:
    """Print scan results with rich formatting for interactive terminal use."""
    if not result.success:
        console.print(f"[red]Scan failed:[/red] {result.error}")
        return

    # Header
    console.print(
        Panel(
            f"[bold]{result.current_branch}[/bold] vs [dim]{result.base_branch}[/dim]  |  "
            f"{result.files_scanned} files scanned",
            title="[bold]Slopless Diff Scan[/bold]",
            border_style="blue",
        )
    )

    # Severity summary
    summary_text = Text()
    summary_text.append(f"CRITICAL: {result.critical_count}", style="bold red" if result.critical_count else "dim")
    summary_text.append("  |  ")
    summary_text.append(f"HIGH: {result.high_count}", style="bold yellow" if result.high_count else "dim")
    summary_text.append("  |  ")
    summary_text.append(f"MEDIUM: {result.medium_count}", style="bold blue" if result.medium_count else "dim")
    summary_text.append("  |  ")
    summary_text.append(f"LOW: {result.low_count}", style="dim")
    console.print(summary_text)
    console.print()

    if result.total_count == 0:
        console.print("[green]No findings. Ready for PR.[/green]")
        return

    # Group by file
    by_file: dict[str, list[Finding]] = {}
    for f in result.findings:
        by_file.setdefault(f.file, []).append(f)

    sev_colors = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue", "LOW": "dim"}

    for filepath, findings in by_file.items():
        table = Table(title=f"[bold]{filepath}[/bold]", show_header=True, expand=True)
        table.add_column("Sev", width=10)
        table.add_column("Line", width=8)
        table.add_column("Finding", ratio=3)
        table.add_column("Fix", ratio=2)

        for f in findings:
            color = sev_colors.get(f.severity, "white")
            table.add_row(
                f"[{color}]{f.severity}[/{color}]",
                str(f.line),
                f"{f.title}\n[dim]{f.description[:150]}[/dim]" if f.description else f.title,
                f.recommendation[:150] if f.recommendation else "",
            )

        console.print(table)
        console.print()

    # Status
    if result.critical_count > 0 or result.high_count > 0:
        console.print("[bold red]Fix CRITICAL/HIGH findings before opening PR.[/bold red]")
    else:
        console.print("[green]No blocking findings. Consider fixing MEDIUM/LOW.[/green]")
