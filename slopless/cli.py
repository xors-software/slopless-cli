"""Slopless CLI - Security scanner and AI feature implementation for vibe-coded apps.

Usage:
    slopless login <license-key>   # Authenticate with your license
    slopless scan owner/repo       # Scan a GitHub repository
    slopless feature "Add X"       # Generate feature spec and implement
    slopless git branch|commit|push  # Git utilities
    slopless whoami                # Check authentication status
    slopless logout                # Remove stored credentials
"""

import asyncio
import io
import json
import os
import re
import subprocess
import zipfile
from pathlib import Path

import click
import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.markdown import Markdown
from rich.prompt import Confirm, Prompt

from slopless import __version__
from slopless.config import (
    Credentials,
    check_for_updates,
    clear_credentials,
    get_api_url,
    get_auth_headers,
    get_license_key,
    load_credentials,
    mask_license_key,
    save_credentials,
    validate_license,
)

console = Console()


def _check_version_on_startup() -> None:
    """Check for updates in the background and warn if outdated."""
    async def check() -> None:
        try:
            info = await check_for_updates(__version__)
            if info and info.update_available:
                console.print(
                    f"[yellow]⚠ Update available:[/yellow] {info.current_version} → {info.latest_version}"
                )
                console.print("[dim]Run 'slopless update' to upgrade[/dim]")
                console.print()
        except Exception:
            pass  # Silently fail
    
    try:
        asyncio.run(check())
    except Exception:
        pass


@click.group()
@click.version_option(version=__version__, prog_name="slopless")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """Slopless - Security scanner and AI feature implementation for vibe-coded apps.

    Scan your code for security vulnerabilities and implement features using AI.

    Get started:
        slopless login <your-license-key>
        slopless scan owner/repo
        slopless feature "Add user authentication"

    Get a license at https://slopless.work
    """
    # Check for updates on startup (except for version/help/update commands)
    if ctx.invoked_subcommand not in ("update", None):
        _check_version_on_startup()


# =============================================================================
# Authentication Commands
# =============================================================================


@cli.command()
@click.argument("license_key", required=False)
@click.option("--api-url", default=None, help="Override API URL (for development)")
def login(license_key: str | None, api_url: str | None) -> None:
    """Authenticate with your license key.

    Your license key grants access to the security scanning service.
    Purchase a license at https://slopless.work

    Examples:
        slopless login                           # Interactive prompt
        slopless login sk-slopless-abc123        # Provide key directly
    """
    if not license_key:
        license_key = console.input("[bold]Enter your license key:[/bold] ").strip()

    if not license_key:
        console.print("[red]✗[/red] License key is required")
        raise click.Abort()

    console.print("[dim]Validating license key...[/dim]")

    async def run() -> None:
        try:
            url = api_url or get_api_url()
            info = await validate_license(license_key, url)

            if not info.valid:
                console.print("[red]✗[/red] Invalid license key")
                console.print("[dim]Check your key and try again, or get one at https://slopless.work[/dim]")
                raise click.Abort()

            # Save credentials
            creds = Credentials(license_key=license_key, api_url=url)
            save_credentials(creds)

            console.print("[green]✓[/green] Logged in successfully!")
            console.print(f"   Email: {info.email or 'N/A'}")
            console.print(f"   Plan: {info.plan}")
            if info.organization:
                console.print(f"   Organization: {info.organization}")
            console.print()
            console.print("[dim]You can now run scans with 'slopless scan'[/dim]")

        except httpx.ConnectError:
            console.print("[red]✗[/red] Could not connect to licensing server")
            console.print("[dim]Check your internet connection and try again[/dim]")
            raise click.Abort()
        except Exception as e:
            console.print(f"[red]✗[/red] Login failed: {e}")
            raise click.Abort()

    asyncio.run(run())


@cli.command()
def logout() -> None:
    """Remove stored license credentials.

    This will remove your saved license key from this machine.
    """
    creds = load_credentials()

    if not creds:
        console.print("[yellow]Not logged in[/yellow]")
        return

    clear_credentials()
    console.print("[green]✓[/green] Logged out successfully")


@cli.command()
@click.option("--check", is_flag=True, help="Only check for updates, don't install")
def update(check: bool) -> None:
    """Update slopless to the latest version.
    
    Examples:
        slopless update           # Update to latest
        slopless update --check   # Just check for updates
    """
    async def run() -> None:
        console.print("[dim]Checking for updates...[/dim]")
        
        info = await check_for_updates(__version__, force=True)
        
        if not info:
            console.print("[yellow]Could not check for updates[/yellow]")
            console.print("[dim]Check your internet connection[/dim]")
            return
        
        console.print(f"[bold]Current version:[/bold] {info.current_version}")
        console.print(f"[bold]Latest version:[/bold]  {info.latest_version}")
        console.print()
        
        if not info.update_available:
            console.print("[green]✓[/green] You're already on the latest version!")
            return
        
        if check:
            console.print(f"[yellow]Update available![/yellow] Run 'slopless update' to upgrade.")
            return
        
        # Perform the update
        console.print("[bold blue]Updating...[/bold blue]")
        console.print()
        
        # Try pipx first, then pip
        update_commands = [
            ["pipx", "upgrade", "slopless"],
            ["pip", "install", "--upgrade", "slopless"],
        ]
        
        for cmd in update_commands:
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    console.print(f"[green]✓[/green] Updated to version {info.latest_version}!")
                    console.print()
                    console.print("[dim]Restart your terminal to use the new version.[/dim]")
                    return
            except FileNotFoundError:
                continue
        
        # If all methods fail, give manual instructions
        console.print("[red]✗[/red] Automatic update failed")
        console.print()
        console.print("[bold]Manual update options:[/bold]")
        console.print("  pipx upgrade slopless")
        console.print("  pip install --upgrade slopless")
        console.print()
        console.print("Or reinstall from source:")
        console.print("  git pull && pipx install . --force")
    
    asyncio.run(run())


@cli.command()
def whoami() -> None:
    """Show current authentication status."""
    license_key = get_license_key()

    if not license_key:
        console.print("[yellow]Not logged in[/yellow]")
        console.print("[dim]Run 'slopless login' to authenticate[/dim]")
        return

    console.print(f"[bold]License Key:[/bold] {mask_license_key(license_key)}")
    console.print(f"[bold]API URL:[/bold] {get_api_url()}")

    console.print()
    console.print("[dim]Checking license status...[/dim]")

    async def check() -> None:
        try:
            info = await validate_license(license_key)
            if info.valid:
                console.print("[green]✓[/green] License is valid")
                console.print(f"   Email: {info.email or 'N/A'}")
                console.print(f"   Plan: {info.plan}")
                if info.organization:
                    console.print(f"   Organization: {info.organization}")
                    if info.seats:
                        console.print(f"   Seats: {info.seats}")
                if info.usage_limit:
                    console.print(f"   Usage: {info.usage_count}/{info.usage_limit} scans this month")
            else:
                console.print("[red]✗[/red] License is invalid or expired")
        except Exception as e:
            console.print(f"[yellow]Could not validate license: {e}[/yellow]")

    asyncio.run(check())


# =============================================================================
# Scan Commands
# =============================================================================


@cli.command()
@click.argument("target", default=".")
@click.option("--auto-fix/--no-fix", default=True, help="Generate fixes for vulnerabilities")
@click.option("--cross-validate/--no-validate", default=True, help="Cross-validate HIGH/CRITICAL findings")
@click.option("--parallel", default=3, help="Number of parallel fix candidates")
@click.option("--polish", is_flag=True, help="Run polish agent after security scan")
@click.option("--output", "-o", type=click.Path(), help="Save report to JSON file")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["rich", "json", "markdown"]),
    default="rich",
    help="Output format",
)
def scan(
    target: str,
    auto_fix: bool,
    cross_validate: bool,
    parallel: int,
    polish: bool,
    output: str | None,
    output_format: str,
) -> None:
    """Scan a repository for security vulnerabilities.

    Uses unified agent architecture:
    - SecurityAgent: Combined STRIDE threat modeling + vulnerability detection (OPUS)
    - CodingAgent: Parallel fix generation with candidate selection (SONNET)
    - PolishAgent: Optional UX/code polish (SONNET)

    TARGET can be a local path or a GitHub repository.

    Examples:
        slopless scan                              # Scan current directory with fixes
        slopless scan /path/to/repo --no-fix      # Scan without generating fixes
        slopless scan owner/repo                   # Scan GitHub repo
        slopless scan . --output report.json       # Save report
        slopless scan . --polish                   # Run polish after security
    """
    # Check authentication
    license_key = get_license_key()
    if not license_key:
        console.print("[red]✗[/red] Not logged in")
        console.print("[dim]Run 'slopless login' to authenticate with your license key[/dim]")
        console.print("[dim]Get a license at https://slopless.work[/dim]")
        raise click.Abort()

    asyncio.run(
        _run_scan(
            target,
            auto_fix,
            cross_validate,
            parallel,
            polish,
            output,
            output_format,
        )
    )


# =============================================================================
# PR Review Commands
# =============================================================================


@cli.command("review-pr")
@click.argument("pr_url")
@click.option("--project-id", default=None, help="Project ID for architecture context (auto-detected if not provided)")
@click.option("--no-security", is_flag=True, help="Skip security checks")
@click.option("--no-architecture", is_flag=True, help="Skip architecture checks")
@click.option("--no-quality", is_flag=True, help="Skip code quality checks")
@click.option("--output", "-o", type=click.Path(), help="Save report to JSON file")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["rich", "json", "markdown"]),
    default="rich",
    help="Output format",
)
@click.option("--github-token", envvar="GITHUB_TOKEN", default=None, help="GitHub token (or set GITHUB_TOKEN env var)")
def review_pr(
    pr_url: str,
    project_id: str | None,
    no_security: bool,
    no_architecture: bool,
    no_quality: bool,
    output: str | None,
    output_format: str,
    github_token: str | None,
) -> None:
    """Review a pull request for security and code quality issues.

    Uses existing scan context from Slopless to provide intelligent,
    architecture-aware PR reviews. If no prior scan exists, performs
    differential analysis on the PR changes.

    PR_URL should be a GitHub pull request URL like:
        https://github.com/owner/repo/pull/123

    Examples:
        slopless review-pr https://github.com/owner/repo/pull/42
        slopless review-pr owner/repo#42
        slopless review-pr https://github.com/owner/repo/pull/42 --no-quality
        slopless review-pr owner/repo#42 -o review.json --format json
    """
    # Check authentication
    license_key = get_license_key()
    if not license_key:
        console.print("[red]✗[/red] Not logged in")
        console.print("[dim]Run 'slopless login' to authenticate with your license key[/dim]")
        raise click.Abort()

    asyncio.run(
        _run_pr_review(
            pr_url=pr_url,
            project_id=project_id,
            check_security=not no_security,
            check_architecture=not no_architecture,
            check_quality=not no_quality,
            output=output,
            output_format=output_format,
            github_token=github_token,
        )
    )


def _parse_pr_shorthand(pr_input: str) -> str:
    """Convert shorthand PR references to full URLs.
    
    Accepts:
        - Full URL: https://github.com/owner/repo/pull/123
        - Shorthand: owner/repo#123
    
    Returns full GitHub PR URL.
    """
    # Already a full URL
    if pr_input.startswith("http"):
        return pr_input
    
    # Shorthand format: owner/repo#123
    match = re.match(r"^([^/]+/[^#]+)#(\d+)$", pr_input)
    if match:
        repo_path = match.group(1)
        pr_number = match.group(2)
        return f"https://github.com/{repo_path}/pull/{pr_number}"
    
    console.print(f"[red]✗[/red] Invalid PR reference: {pr_input}")
    console.print("[dim]Use: https://github.com/owner/repo/pull/123 or owner/repo#123[/dim]")
    raise click.Abort()


async def _run_pr_review(
    pr_url: str,
    project_id: str | None,
    check_security: bool,
    check_architecture: bool,
    check_quality: bool,
    output: str | None,
    output_format: str,
    github_token: str | None,
) -> None:
    """Execute PR review via the hosted API."""
    # Normalize PR URL
    pr_url = _parse_pr_shorthand(pr_url)
    
    # Extract repo info for display
    pr_match = re.search(r"github\.com/([^/]+/[^/]+)/pull/(\d+)", pr_url)
    if not pr_match:
        console.print("[red]✗[/red] Could not parse PR URL")
        return
    
    repo_path = pr_match.group(1)
    pr_number = pr_match.group(2)
    
    console.print(f"[bold]🔍 Reviewing PR:[/bold] {repo_path}#{pr_number}")
    
    checks = []
    if check_security:
        checks.append("security")
    if check_architecture:
        checks.append("architecture")
    if check_quality:
        checks.append("quality")
    console.print(f"[dim]Checks: {', '.join(checks)}[/dim]")
    console.print()
    
    api_url = get_api_url()
    headers = get_auth_headers()
    
    # Build request
    request_data = {
        "pr_url": pr_url,
        "check_security": check_security,
        "check_architecture": check_architecture,
        "check_code_quality": check_quality,
    }
    
    if project_id:
        request_data["project_id"] = project_id
    
    if github_token:
        request_data["access_token"] = github_token
    
    try:
        async with httpx.AsyncClient(timeout=180.0) as client:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Analyzing PR diff...", total=None)
                
                response = await client.post(
                    f"{api_url}/pr-review/analyze",
                    json=request_data,
                    headers=headers,
                )
                
                progress.update(task, description="Processing review results...")
            
            if response.status_code == 401:
                console.print("[red]✗[/red] Authentication failed")
                if "GitHub" in response.text or "token" in response.text.lower():
                    console.print("[dim]GitHub token required. Use --github-token or set GITHUB_TOKEN env var[/dim]")
                else:
                    console.print("[dim]License key may be expired. Run 'slopless login' to re-authenticate[/dim]")
                return
            
            if response.status_code == 404:
                console.print("[red]✗[/red] PR not found or not accessible")
                console.print("[dim]Check the PR URL and ensure you have access to the repository[/dim]")
                return
            
            if response.status_code != 200:
                try:
                    error = response.json().get("detail", response.text)
                except Exception:
                    error = response.text
                console.print(f"[red]✗[/red] Review failed: {error}")
                return
            
            result = response.json()
            
    except httpx.TimeoutException:
        console.print("[red]✗[/red] Request timed out")
        console.print("[dim]The PR may be very large. Try again or review locally.[/dim]")
        return
    except httpx.ConnectError:
        console.print("[red]✗[/red] Could not connect to Slopless API")
        console.print("[dim]Check your internet connection[/dim]")
        return
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")
        return
    
    # Check for success
    if not result.get("success"):
        console.print(f"[red]✗[/red] Review failed: {result.get('error', 'Unknown error')}")
        return
    
    # Save to file if requested
    if output:
        output_path = Path(output)
        output_path.write_text(json.dumps(result, indent=2))
        console.print(f"[green]✓[/green] Report saved to: {output_path}")
        console.print()
    
    # Display based on format
    if output_format == "json":
        console.print(json.dumps(result, indent=2))
    elif output_format == "markdown":
        _print_pr_review_markdown(result)
    else:
        _print_pr_review_rich(result)


def _print_pr_review_rich(result: dict) -> None:
    """Print PR review results with rich formatting."""
    verdict = result.get("verdict", "comment")
    risk_level = result.get("risk_level", "medium")
    summary = result.get("summary", "Review complete")
    findings = result.get("findings", [])
    total = result.get("total_findings", len(findings))
    by_severity = result.get("by_severity", {})
    review_time = result.get("review_time", 0)
    context_used = result.get("architecture_context_used", False)
    known_vulns = result.get("known_vulns_checked", 0)
    
    # Verdict styling
    verdict_styles = {
        "approve": ("green", "✓ APPROVE"),
        "request_changes": ("red", "✗ REQUEST CHANGES"),
        "comment": ("yellow", "💬 COMMENT"),
    }
    verdict_color, verdict_text = verdict_styles.get(verdict, ("white", verdict.upper()))
    
    risk_styles = {
        "low": ("green", "Low"),
        "medium": ("yellow", "Medium"),
        "high": ("red", "High"),
        "critical": ("bold red", "Critical"),
    }
    risk_color, risk_text = risk_styles.get(risk_level, ("white", risk_level))
    
    # Header panel
    header_text = Text()
    header_text.append(f"Verdict: ", style="bold")
    header_text.append(verdict_text, style=f"bold {verdict_color}")
    header_text.append(f"  |  Risk: ", style="bold")
    header_text.append(risk_text, style=risk_color)
    header_text.append(f"  |  Findings: {total}")
    
    if context_used:
        header_text.append("\n")
        header_text.append("📚 Using architecture context from previous scan", style="dim")
        if known_vulns > 0:
            header_text.append(f" ({known_vulns} known vulns checked)", style="dim")
    
    console.print(Panel(header_text, title=f"[bold]PR Review[/bold]", border_style=verdict_color))
    console.print()
    
    # Summary
    if summary:
        console.print(Panel(summary, title="Summary", border_style="blue"))
        console.print()
    
    # Severity breakdown
    if by_severity:
        severity_text = Text()
        sev_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
        for sev in ["critical", "high", "medium", "low"]:
            count = by_severity.get(sev, 0)
            if count > 0:
                severity_text.append(f"{sev_icons.get(sev, '⚪')} {sev.capitalize()}: {count}  ")
        if severity_text:
            console.print(severity_text)
            console.print()
    
    if not findings:
        if total == 0:
            console.print("[green]✓ No issues found in this PR![/green]")
        else:
            console.print(f"[dim]{total} findings (details not loaded)[/dim]")
        console.print()
        console.print(f"[dim]Review completed in {review_time:.1f}s[/dim]")
        return
    
    # Sort findings by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "medium").lower(), 2))
    
    # Display each finding
    for i, finding in enumerate(sorted_findings, 1):
        severity = finding.get("severity", "medium").lower()
        title = finding.get("title", "Finding")
        file_path = finding.get("file_path", "Unknown")
        line_start = finding.get("line_start", "?")
        line_end = finding.get("line_end")
        finding_type = finding.get("type", "issue")
        description = finding.get("description", "")
        code_snippet = finding.get("code_snippet", "")
        suggestion = finding.get("suggestion", "")
        cwe_id = finding.get("cwe_id", "")
        confidence = finding.get("confidence", "medium")
        
        sev_colors = {"critical": "red", "high": "yellow", "medium": "blue", "low": "dim"}
        sev_color = sev_colors.get(severity, "white")
        
        content_parts = []
        
        # Location
        location = f"{file_path}:{line_start}"
        if line_end and line_end != line_start:
            location += f"-{line_end}"
        content_parts.append(f"[bold]Location:[/bold] {location}")
        content_parts.append(f"[bold]Type:[/bold] {finding_type}  |  [bold]Confidence:[/bold] {confidence}")
        if cwe_id:
            content_parts.append(f"[bold]CWE:[/bold] {cwe_id}")
        content_parts.append("")
        
        if description:
            content_parts.append("[bold]Description:[/bold]")
            content_parts.append(description[:500])
            content_parts.append("")
        
        if code_snippet:
            content_parts.append("[bold]Code:[/bold]")
            snippet = code_snippet[:300] + "..." if len(code_snippet) > 300 else code_snippet
            content_parts.append(f"[dim]{snippet}[/dim]")
            content_parts.append("")
        
        if suggestion:
            content_parts.append("[bold green]Suggestion:[/bold green]")
            content_parts.append(suggestion[:400])
        
        panel_title = f"[{sev_color}][{severity.upper()}][/{sev_color}] {i}. {title}"
        console.print(Panel("\n".join(content_parts), title=panel_title, border_style=sev_color))
        console.print()
    
    console.print(f"[dim]Review completed in {review_time:.1f}s[/dim]")


def _print_pr_review_markdown(result: dict) -> None:
    """Print PR review results in markdown format."""
    verdict = result.get("verdict", "comment")
    risk_level = result.get("risk_level", "medium")
    summary = result.get("summary", "Review complete")
    findings = result.get("findings", [])
    total = result.get("total_findings", len(findings))
    by_severity = result.get("by_severity", {})
    context_used = result.get("architecture_context_used", False)
    pr_number = result.get("pr_number", "?")
    repo = result.get("repo", "")
    
    verdict_emoji = {"approve": "✅", "request_changes": "❌", "comment": "💬"}.get(verdict, "📝")
    risk_emoji = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}.get(risk_level, "⚪")
    
    print(f"# PR Review: {repo}#{pr_number}\n")
    print(f"**Verdict:** {verdict_emoji} {verdict.upper()}\n")
    print(f"**Risk Level:** {risk_emoji} {risk_level.capitalize()}\n")
    
    if context_used:
        print("*📚 Using architecture context from previous Slopless scan*\n")
    
    print("## Summary\n")
    print(f"{summary}\n")
    
    if by_severity:
        print("## Findings by Severity\n")
        print("| Severity | Count |")
        print("|----------|-------|")
        sev_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
        for sev in ["critical", "high", "medium", "low"]:
            count = by_severity.get(sev, 0)
            print(f"| {sev_icons.get(sev, '⚪')} {sev.capitalize()} | {count} |")
        print(f"| **Total** | **{total}** |")
        print()
    
    if not findings:
        if total == 0:
            print("✅ **No issues found in this PR!**\n")
        return
    
    print("## Detailed Findings\n")
    
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "medium").lower(), 2))
    
    for i, finding in enumerate(sorted_findings, 1):
        severity = finding.get("severity", "medium").upper()
        title = finding.get("title", "Finding")
        file_path = finding.get("file_path", "Unknown")
        line_start = finding.get("line_start", "?")
        description = finding.get("description", "")
        suggestion = finding.get("suggestion", "")
        cwe_id = finding.get("cwe_id", "")
        
        sev_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        sev_icon = sev_icons.get(severity, "⚪")
        
        print(f"### {i}. {sev_icon} [{severity}] {title}\n")
        print(f"**Location:** `{file_path}:{line_start}`")
        if cwe_id:
            print(f"**CWE:** {cwe_id}")
        print()
        
        if description:
            print(f"**Description:**\n{description}\n")
        
        if suggestion:
            print(f"**Suggestion:**\n{suggestion}\n")
        
        print("---\n")
    
    print("*Reviewed by [Slopless](https://slopless.work)*\n")


# =============================================================================
# Feature Implementation Commands
# =============================================================================


@cli.command()
@click.argument("description")
@click.option("--dry-run", is_flag=True, help="Generate plan without implementing")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompts")
@click.option("--branch", "-b", default=None, help="Create a new branch for changes")
@click.option("--commit", "-c", is_flag=True, help="Auto-commit changes when done")
@click.option("--no-tests", is_flag=True, help="Skip test generation")
def feature(
    description: str,
    dry_run: bool,
    yes: bool,
    branch: str | None,
    commit: bool,
    no_tests: bool,
) -> None:
    """Implement a feature using AI.

    Analyzes your codebase, generates an implementation plan, and writes code.
    Works like Cursor - generates a todo list and implements each task.

    Examples:
        slopless feature "Add user authentication with JWT"
        slopless feature "Add dark mode toggle" --dry-run
        slopless feature "Add API rate limiting" -b feature/rate-limit -c
    """
    # Check authentication
    license_key = get_license_key()
    if not license_key:
        console.print("[red]✗[/red] Not logged in")
        console.print("[dim]Run 'slopless login' to authenticate[/dim]")
        raise click.Abort()

    # Check we're in a git repo
    if not Path(".git").exists():
        console.print("[red]✗[/red] Not in a git repository")
        console.print("[dim]Run this command from your project root[/dim]")
        raise click.Abort()

    asyncio.run(
        _run_feature(
            description=description,
            dry_run=dry_run,
            auto_confirm=yes,
            branch_name=branch,
            auto_commit=commit,
            create_tests=not no_tests,
        )
    )


async def _run_feature(
    description: str,
    dry_run: bool,
    auto_confirm: bool,
    branch_name: str | None,
    auto_commit: bool,
    create_tests: bool,
) -> None:
    """Execute the feature implementation workflow."""
    api_url = get_api_url()
    headers = get_auth_headers()
    
    console.print(Panel(
        f"[bold]{description}[/bold]",
        title="🚀 Feature Request",
        border_style="blue"
    ))
    console.print()
    
    # Create branch if requested
    if branch_name and not dry_run:
        _git_create_branch(branch_name)
    
    # Step 1: Analyze codebase and generate plan
    console.print("[bold blue]Step 1:[/bold blue] Analyzing codebase and generating implementation plan...")
    console.print()
    
    # Zip local directory for upload
    console.print("[dim]Preparing codebase...[/dim]")
    zip_buffer = _create_repo_zip(Path("."))
    
    try:
        async with httpx.AsyncClient(timeout=300.0) as client:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Generating implementation plan...", total=None)
                
                response = await client.post(
                    f"{api_url}/v1/proxy/feature/plan",
                    files={"file": ("repo.zip", zip_buffer, "application/zip")},
                    data={
                        "description": description,
                        "create_tests": str(create_tests).lower(),
                    },
                    headers=headers,
                )
                
                progress.update(task, completed=True)
            
            if response.status_code == 401:
                console.print("[red]✗[/red] License expired or invalid")
                return
            
            if response.status_code != 200:
                error = response.json().get("error", response.text)
                console.print(f"[red]✗[/red] Failed to generate plan: {error}")
                return
            
            result = response.json()
            
    except httpx.TimeoutException:
        console.print("[red]✗[/red] Request timed out")
        return
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")
        return
    
    # Display the plan
    plan = result.get("plan", {})
    tasks = plan.get("tasks", [])
    
    console.print(Panel(
        plan.get("summary", "Implementation plan generated"),
        title="📋 Implementation Plan",
        border_style="green"
    ))
    console.print()
    
    # Display tasks as a todo list
    if tasks:
        table = Table(title="Tasks", show_header=True, header_style="bold magenta")
        table.add_column("#", style="dim", width=3)
        table.add_column("Task", style="bold")
        table.add_column("Files", style="cyan")
        table.add_column("Effort", style="green", width=8)
        
        for i, task_item in enumerate(tasks, 1):
            files = ", ".join(task_item.get("files_to_modify", [])[:3])
            if len(task_item.get("files_to_modify", [])) > 3:
                files += f" (+{len(task_item['files_to_modify']) - 3} more)"
            table.add_row(
                str(i),
                task_item.get("title", "Untitled"),
                files or "N/A",
                task_item.get("estimated_effort", "medium"),
            )
        
        console.print(table)
        console.print()
    
    # Show files to be changed
    files_to_create = plan.get("files_to_create", [])
    files_to_modify = plan.get("files_to_modify", [])
    
    if files_to_create:
        console.print("[bold]Files to create:[/bold]")
        for f in files_to_create[:10]:
            path = f.get("path", f) if isinstance(f, dict) else f
            console.print(f"  [green]+[/green] {path}")
        if len(files_to_create) > 10:
            console.print(f"  [dim]... and {len(files_to_create) - 10} more[/dim]")
        console.print()
    
    if files_to_modify:
        console.print("[bold]Files to modify:[/bold]")
        for f in files_to_modify[:10]:
            path = f.get("path", f) if isinstance(f, dict) else f
            console.print(f"  [yellow]~[/yellow] {path}")
        if len(files_to_modify) > 10:
            console.print(f"  [dim]... and {len(files_to_modify) - 10} more[/dim]")
        console.print()
    
    if dry_run:
        console.print("[yellow]Dry run complete.[/yellow] Use without --dry-run to implement.")
        return
    
    # Confirm before implementing
    if not auto_confirm:
        if not Confirm.ask("Proceed with implementation?"):
            console.print("[yellow]Cancelled[/yellow]")
            return
    
    # Step 2: Implement the feature
    console.print()
    console.print("[bold blue]Step 2:[/bold blue] Implementing feature...")
    console.print()
    
    try:
        async with httpx.AsyncClient(timeout=600.0) as client:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                impl_task = progress.add_task("Implementing...", total=None)
                
                # Reset zip buffer
                zip_buffer.seek(0)
                
                response = await client.post(
                    f"{api_url}/v1/proxy/feature/implement",
                    files={"file": ("repo.zip", zip_buffer, "application/zip")},
                    data={
                        "description": description,
                        "create_tests": str(create_tests).lower(),
                    },
                    headers=headers,
                )
                
                progress.update(impl_task, completed=True)
            
            if response.status_code != 200:
                error = response.json().get("error", response.text)
                console.print(f"[red]✗[/red] Implementation failed: {error}")
                return
            
            impl_result = response.json()
            
    except httpx.TimeoutException:
        console.print("[red]✗[/red] Implementation timed out")
        return
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")
        return
    
    # Apply changes locally
    changes = impl_result.get("changes", [])
    files_written = 0
    
    for change in changes:
        file_path = Path(change.get("path", ""))
        content = change.get("content", "")
        
        if file_path and content:
            # Create parent directories if needed
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content)
            files_written += 1
            action = "[green]+[/green]" if change.get("action") == "create" else "[yellow]~[/yellow]"
            console.print(f"  {action} {file_path}")
    
    console.print()
    console.print(f"[green]✓[/green] Wrote {files_written} files")
    
    # Auto-commit if requested
    if auto_commit and files_written > 0:
        console.print()
        _git_commit_all(f"feat: {description[:50]}")
    
    # Summary
    console.print()
    console.print(Panel(
        f"[green]✓[/green] Feature implementation complete!\n\n"
        f"Files created: {len(files_to_create)}\n"
        f"Files modified: {len(files_to_modify)}\n\n"
        f"[dim]Review the changes and run your tests.[/dim]",
        title="🎉 Done",
        border_style="green"
    ))
    
    if not auto_commit:
        console.print()
        console.print("[dim]To commit your changes:[/dim]")
        console.print("  slopless git commit -m \"feat: your message\"")


# =============================================================================
# Command Center
# =============================================================================


COMMAND_CENTER_SKILLS_DIR = Path(__file__).parent.parent / "command-center" / "skills"


def _run_shell(cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command, returning the result."""
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)


def _command_exists(cmd: str) -> bool:
    """Check if a command is available on PATH."""
    return subprocess.run(
        f"command -v {cmd}", shell=True, capture_output=True
    ).returncode == 0


@cli.command("command-center")
@click.option("--license-key", default=None, help="Slopless license key (uses stored credentials if omitted)")
@click.option("--telegram-token", default=None, help="Telegram bot token (prompted if not provided)")
@click.option("--anthropic-key", default=None, help="Bring your own Anthropic API key (bypasses slopless LLM proxy)")
@click.option("--skip-deps", is_flag=True, help="Skip dependency installation")
@click.option("--no-start", is_flag=True, help="Configure only, don't start the daemon")
def command_center(
    license_key: str | None,
    telegram_token: str | None,
    anthropic_key: str | None,
    skip_deps: bool,
    no_start: bool,
) -> None:
    """Set up the Slopless Command Center — AI-powered PR orchestration via Telegram.

    One command to go from zero to a working Telegram bot that scans repos,
    reviews PRs, implements features, and iterates to perfection.

    \b
    Quick start:
        slopless command-center                          # Uses stored license key
        slopless command-center --license-key sl-xxx     # Provide key directly

    \b
    Prerequisites:
        - GitHub CLI authenticated (gh auth login)
        - That's it. Everything else is auto-installed.

    \b
    What it does:
        1. Validates your slopless license
        2. Installs ZeroClaw (if needed)
        3. Configures the Telegram bot
        4. Installs all orchestration skills
        5. Starts the daemon — you're live
    """
    console.print()
    console.print(Panel.fit(
        "[bold]Slopless Command Center[/bold]\n"
        "[dim]AI-powered PR orchestration via Telegram[/dim]",
        border_style="cyan",
    ))
    console.print()

    # ── Step 1: License Key ──────────────────────────────────────────────
    console.print("[bold]\\[1/5] License[/bold]")

    if not license_key:
        license_key = get_license_key()

    if not license_key:
        license_key = Prompt.ask("  Enter your slopless license key")

    if not license_key:
        console.print("  [red]✗[/red] License key is required")
        console.print("  [dim]Get one at https://slopless.work[/dim]")
        raise click.Abort()

    with Progress(SpinnerColumn(), TextColumn("[dim]Validating license...[/dim]"), console=console, transient=True) as progress:
        progress.add_task("validate", total=None)

        async def _validate():
            return await validate_license(license_key)

        try:
            info = asyncio.run(_validate())
        except Exception:
            console.print("  [red]✗[/red] Could not reach licensing server")
            console.print("  [dim]Check your connection and try again[/dim]")
            raise click.Abort()

    if not info.valid:
        console.print("  [red]✗[/red] Invalid license key")
        raise click.Abort()

    save_credentials(Credentials(license_key=license_key))
    org_name = info.organization or "personal"
    console.print(f"  [green]✓[/green] License valid — {info.plan} ({org_name})")
    console.print()

    # ── Step 2: Dependencies ─────────────────────────────────────────────
    console.print("[bold]\\[2/5] Dependencies[/bold]")

    if not skip_deps:
        # ZeroClaw
        if _command_exists("zeroclaw"):
            zc_ver = _run_shell("zeroclaw --version 2>/dev/null || echo unknown", check=False).stdout.strip()
            console.print(f"  [green]✓[/green] ZeroClaw ({zc_ver})")
        else:
            console.print("  [cyan]→[/cyan] Installing ZeroClaw...")
            if _command_exists("brew"):
                result = _run_shell("brew install zeroclaw", check=False)
                if result.returncode == 0:
                    console.print("  [green]✓[/green] ZeroClaw installed via Homebrew")
                else:
                    console.print("  [red]✗[/red] Failed to install ZeroClaw")
                    console.print("  [dim]Try manually: brew install zeroclaw[/dim]")
                    raise click.Abort()
            else:
                console.print("  [red]✗[/red] Homebrew not found — install ZeroClaw manually")
                console.print("  [dim]See: https://github.com/zeroclaw-labs/zeroclaw[/dim]")
                raise click.Abort()

        # GitHub CLI
        if _command_exists("gh"):
            gh_auth = _run_shell("gh auth status 2>&1", check=False)
            if "Logged in" in gh_auth.stdout or "Logged in" in gh_auth.stderr:
                console.print("  [green]✓[/green] GitHub CLI authenticated")
            else:
                console.print("  [yellow]![/yellow] GitHub CLI not authenticated")
                console.print("  [dim]Run: gh auth login[/dim]")
        else:
            console.print("  [yellow]![/yellow] GitHub CLI not found (optional but recommended)")
            console.print("  [dim]Install: brew install gh[/dim]")

        # Claude Code (optional)
        if _command_exists("claude"):
            console.print("  [green]✓[/green] Claude Code CLI")
        else:
            console.print("  [dim]  ○ Claude Code CLI not found (optional, for feature implementation)[/dim]")
    else:
        console.print("  [dim]Skipped[/dim]")

    console.print()

    # ── Step 3: Telegram Bot ─────────────────────────────────────────────
    console.print("[bold]\\[3/5] Telegram Bot[/bold]")

    if not telegram_token:
        # Check if already configured in ZeroClaw
        zc_config_path = Path.home() / ".zeroclaw" / "config.toml"
        existing_token = None
        if zc_config_path.exists():
            content = zc_config_path.read_text()
            import re as _re
            match = _re.search(r'bot_token\s*=\s*"([^"]+)"', content)
            if match:
                existing_token = match.group(1)

        if existing_token:
            console.print("  [green]✓[/green] Telegram bot already configured")
            telegram_token = existing_token
        else:
            console.print("  [cyan]→[/cyan] You need a Telegram bot token.")
            console.print()
            console.print("  [bold]Quick setup (takes 30 seconds):[/bold]")
            console.print("  1. Open Telegram → search @BotFather")
            console.print("  2. Send /newbot")
            console.print("  3. Name it (e.g., 'Slopless Command Center')")
            console.print("  4. Pick a username ending in 'bot'")
            console.print("  5. Copy the token BotFather gives you")
            console.print()
            telegram_token = Prompt.ask("  Paste your bot token here")

    if not telegram_token:
        console.print("  [red]✗[/red] Telegram bot token is required")
        raise click.Abort()

    console.print(f"  [green]✓[/green] Bot token set ({telegram_token[:8]}...)")
    console.print()

    # ── Step 4: Configure ZeroClaw ───────────────────────────────────────
    console.print("[bold]\\[4/5] Configuration[/bold]")

    zeroclaw_dir = Path.home() / ".zeroclaw"
    zeroclaw_dir.mkdir(parents=True, exist_ok=True)
    (zeroclaw_dir / "workspace" / "skills").mkdir(parents=True, exist_ok=True)
    (zeroclaw_dir / "workspace" / "state").mkdir(parents=True, exist_ok=True)

    api_url = get_api_url()

    if anthropic_key:
        provider_line = 'default_provider = "anthropic"'
        api_key_line = f'api_key = "{anthropic_key}"'
        console.print("  [green]✓[/green] Using your Anthropic key (BYOK mode)")
    else:
        provider_line = f'default_provider = "custom:{api_url}/v1/llm"'
        api_key_line = f'api_key = "{license_key}"'
        console.print("  [green]✓[/green] Using slopless LLM proxy (license-authenticated)")

    config_content = f'''{provider_line}
default_model = "claude-sonnet-4-20250514"
default_temperature = 0.7
{api_key_line}

[autonomy]
level = "supervised"
workspace_only = false
allowed_commands = [
    "git", "gh", "claude", "slopless", "unslop",
    "ls", "cat", "grep", "find", "echo", "pwd", "wc",
    "head", "tail", "date", "mkdir", "cp", "mv", "gpg",
]
forbidden_paths = ["/etc/shadow", "/proc", "/sys", "/boot", "/dev", "~/.ssh", "~/.aws"]
allowed_roots = ["~/work", "~/projects", "~/repos", "/tmp"]
max_actions_per_hour = 200
max_cost_per_day_cents = 5000

[agent]
compact_context = false
max_tool_iterations = 25
max_history_messages = 50
parallel_tools = true
tool_dispatcher = "auto"

[scheduler]
enabled = true
max_tasks = 64
max_concurrent = 8

[skills]
open_skills_enabled = false

[memory]
backend = "sqlite"
auto_save = true
embedding_provider = "none"

[channels_config]
cli = true
message_timeout_secs = 600

[channels_config.telegram]
bot_token = "{telegram_token}"
allowed_users = ["*"]

[gateway]
port = 42617
host = "127.0.0.1"
require_pairing = true

[runtime]
kind = "native"

[secrets]
encrypt = true

[heartbeat]
enabled = false
interval_minutes = 60

[cron]
enabled = true
max_run_history = 50

[tunnel]
provider = "none"

[reliability]
provider_retries = 3
provider_backoff_ms = 1000
'''

    config_path = zeroclaw_dir / "config.toml"
    config_path.write_text(config_content)
    console.print("  [green]✓[/green] ZeroClaw config written")

    # Install skills
    skills_dir = COMMAND_CENTER_SKILLS_DIR
    if skills_dir.exists():
        installed = 0
        for skill_dir in sorted(skills_dir.iterdir()):
            skill_md = skill_dir / "SKILL.md"
            if skill_md.exists():
                dest = zeroclaw_dir / "workspace" / "skills" / skill_dir.name
                if dest.exists():
                    import shutil
                    shutil.rmtree(dest)
                import shutil
                shutil.copytree(skill_dir, dest)
                installed += 1
        console.print(f"  [green]✓[/green] {installed} skills installed")
    else:
        console.print("  [yellow]![/yellow] Skills directory not found — skills will load from defaults")

    # Write identity
    identity_path = zeroclaw_dir / "workspace" / "IDENTITY.md"
    identity_path.write_text(
        "# Slopless Command Center\\n\\n"
        "I am the Slopless Command Center — an always-on AI assistant for code security "
        "and PR orchestration.\\n\\n"
        "I help teams:\\n"
        "- Scan repos for security vulnerabilities using `slopless scan`\\n"
        "- Review pull requests with `slopless review-pr`\\n"
        "- Implement features and raise PRs via Claude Code\\n"
        "- Iterate on scan findings until clean\\n"
        "- Track and adopt existing workstreams\\n\\n"
        f"Organization: {org_name}\\n"
        f"License: {info.plan}\\n"
    )
    console.print("  [green]✓[/green] Identity configured")
    console.print()

    # ── Step 5: Start ────────────────────────────────────────────────────
    console.print("[bold]\\[5/5] Launch[/bold]")

    if no_start:
        console.print("  [dim]Skipped (--no-start). Start manually:[/dim]")
        console.print(f"  [bold]ANTHROPIC_API_KEY={license_key} zeroclaw daemon[/bold]")
    else:
        console.print("  [green]✓[/green] Starting daemon...")
        console.print()
        console.print(Panel.fit(
            "[bold green]Command Center is live![/bold green]\\n\\n"
            "Open your Telegram bot and send a message.\\n\\n"
            "[bold]Try these commands:[/bold]\\n"
            "  • [cyan]list projects[/cyan] — discover your workspace\\n"
            "  • [cyan]scan <repo>[/cyan] — run a security scan\\n"
            "  • [cyan]review PR <url>[/cyan] — review a pull request\\n"
            "  • [cyan]status[/cyan] — see what's being tracked\\n\\n"
            "[dim]Press Ctrl+C to stop the daemon[/dim]",
            border_style="green",
        ))
        console.print()

        os.environ["ANTHROPIC_API_KEY"] = license_key
        os.execvp("zeroclaw", ["zeroclaw", "daemon"])


# =============================================================================
# Git Utility Commands
# =============================================================================


@cli.group()
def git() -> None:
    """Git utilities for feature development.
    
    Convenient wrappers around common git operations.
    """
    pass


@git.command("branch")
@click.argument("name")
@click.option("--from", "base", default=None, help="Base branch to create from")
def git_branch(name: str, base: str | None) -> None:
    """Create a new branch for feature development.
    
    Examples:
        slopless git branch feature/auth
        slopless git branch fix/bug-123 --from main
    """
    _git_create_branch(name, base)


@git.command("commit")
@click.option("-m", "--message", required=True, help="Commit message")
@click.option("-a", "--all", "add_all", is_flag=True, help="Stage all changes")
def git_commit(message: str, add_all: bool) -> None:
    """Commit staged changes.
    
    Examples:
        slopless git commit -m "feat: add authentication"
        slopless git commit -am "fix: resolve bug"
    """
    if add_all:
        _git_add_all()
    _git_commit(message)


@git.command("push")
@click.option("-u", "--set-upstream", is_flag=True, help="Set upstream for new branches")
def git_push(set_upstream: bool) -> None:
    """Push commits to remote.
    
    Examples:
        slopless git push
        slopless git push -u  # For new branches
    """
    _git_push(set_upstream)


@git.command("status")
def git_status() -> None:
    """Show git status."""
    _run_git(["status", "-sb"])


@git.command("diff")
@click.option("--staged", is_flag=True, help="Show staged changes")
def git_diff(staged: bool) -> None:
    """Show changes."""
    args = ["diff"]
    if staged:
        args.append("--staged")
    _run_git(args)


# =============================================================================
# Git Helper Functions
# =============================================================================


def _run_git(args: list[str], capture: bool = False) -> subprocess.CompletedProcess | None:
    """Run a git command."""
    try:
        result = subprocess.run(
            ["git"] + args,
            capture_output=capture,
            text=True,
            check=False,
        )
        if result.returncode != 0 and capture:
            console.print(f"[red]✗[/red] Git error: {result.stderr}")
            return None
        return result
    except FileNotFoundError:
        console.print("[red]✗[/red] Git not found. Please install git.")
        return None


def _git_create_branch(name: str, base: str | None = None) -> bool:
    """Create and switch to a new branch."""
    if base:
        result = _run_git(["checkout", "-b", name, base], capture=True)
    else:
        result = _run_git(["checkout", "-b", name], capture=True)
    
    if result and result.returncode == 0:
        console.print(f"[green]✓[/green] Created and switched to branch: {name}")
        return True
    return False


def _git_add_all() -> bool:
    """Stage all changes."""
    result = _run_git(["add", "-A"], capture=True)
    return result is not None and result.returncode == 0


def _git_commit(message: str) -> bool:
    """Create a commit."""
    result = _run_git(["commit", "-m", message], capture=True)
    if result and result.returncode == 0:
        console.print(f"[green]✓[/green] Committed: {message}")
        return True
    elif result:
        console.print(f"[yellow]![/yellow] {result.stdout or result.stderr}")
    return False


def _git_commit_all(message: str) -> bool:
    """Stage all and commit."""
    _git_add_all()
    return _git_commit(message)


def _git_push(set_upstream: bool = False) -> bool:
    """Push to remote."""
    args = ["push"]
    
    if set_upstream:
        # Get current branch name
        result = _run_git(["rev-parse", "--abbrev-ref", "HEAD"], capture=True)
        if result and result.returncode == 0:
            branch = result.stdout.strip()
            args.extend(["-u", "origin", branch])
    
    result = _run_git(args, capture=True)
    if result and result.returncode == 0:
        console.print("[green]✓[/green] Pushed to remote")
        return True
    return False


# =============================================================================
# Scan Implementation
# =============================================================================


async def _run_scan(
    target: str,
    auto_fix: bool,
    cross_validate: bool,
    parallel: int,
    polish: bool,
    output: str | None,
    output_format: str,
) -> None:
    """Execute the scan via the hosted API using unified agents."""
    # Determine if target is a GitHub repo
    github_patterns = [
        r"^https?://github\.com/([^/]+/[^/]+)",
        r"^github\.com/([^/]+/[^/]+)",
        r"^([^/\s]+/[^/\s]+)$",
    ]

    github_repo = None
    for pattern in github_patterns:
        match = re.match(pattern, target.strip())
        if match:
            repo_path_str = match.group(1).replace(".git", "").rstrip("/")
            if "/" in repo_path_str and not repo_path_str.startswith("."):
                github_repo = repo_path_str
                break

    api_url = get_api_url()
    headers = get_auth_headers()

    # Build unified scan options
    scan_options = {
        "auto_fix": auto_fix,
        "cross_validate": cross_validate,
        "parallel_candidates": parallel,
        "polish": polish,
    }

    if github_repo:
        # Scan GitHub repo via API
        console.print(f"[bold]🛡️ Scanning:[/bold] {github_repo}")
        console.print(f"[dim]Agents: SecurityAgent{' + CodingAgent' if auto_fix else ''}{' + PolishAgent' if polish else ''}[/dim]")
        result = await _scan_github_repo(api_url, headers, github_repo, scan_options)
    else:
        # Scan local path via upload
        local_path = Path(target)
        if not local_path.exists():
            console.print(f"[red]✗[/red] Path not found: {target}")
            return

        console.print(f"[bold]🛡️ Scanning:[/bold] {local_path.resolve()}")
        console.print(f"[dim]Agents: SecurityAgent{' + CodingAgent' if auto_fix else ''}{' + PolishAgent' if polish else ''}[/dim]")
        result = await _scan_local_path(api_url, headers, local_path, scan_options)

    if not result:
        return

    # Process result
    if not result.get("success"):
        console.print(f"[red]✗[/red] Scan failed: {result.get('error', 'Unknown error')}")
        return

    vulns = result.get("vulnerabilities", [])
    summary = result.get("summary", {})

    # Save to file if requested
    if output:
        output_path = Path(output)
        output_path.write_text(json.dumps({"vulnerabilities": vulns, "summary": summary}, indent=2))
        console.print(f"[green]✓[/green] Report saved to: {output_path}")
        console.print()

    # Display based on format
    if output_format == "json":
        console.print(json.dumps({"vulnerabilities": vulns, "summary": summary}, indent=2))
    elif output_format == "markdown":
        _print_markdown_report(vulns, summary)
    else:
        _print_rich_report(vulns, summary)


async def _scan_github_repo(
    api_url: str,
    headers: dict,
    github_repo: str,
    scan_options: dict,
) -> dict | None:
    """Scan a GitHub repository via the unified API."""
    try:
        async with httpx.AsyncClient(timeout=300.0) as client:
            with console.status("[bold blue]Running SecurityAgent...[/bold blue]"):
                response = await client.post(
                    f"{api_url}/v1/proxy/scan/github",
                    json={
                        "github_repo": github_repo,
                        **scan_options,
                    },
                    headers=headers,
                )

            if response.status_code == 401:
                console.print("[red]✗[/red] License key expired or invalid")
                console.print("[dim]Run 'slopless login' to re-authenticate[/dim]")
                return None

            response.raise_for_status()
            return response.json()

    except httpx.TimeoutException:
        console.print("[red]✗[/red] Scan timed out (repository may be too large)")
        return None
    except httpx.HTTPError as e:
        console.print(f"[red]✗[/red] API error: {e}")
        return None


async def _scan_local_path(
    api_url: str,
    headers: dict,
    local_path: Path,
    scan_options: dict,
) -> dict | None:
    """Scan a local directory by uploading it to the unified API."""
    console.print("[dim]Zipping directory...[/dim]")

    zip_buffer = _create_repo_zip(local_path)
    zip_size = len(zip_buffer.getvalue())
    console.print(f"[dim]ZIP size: {zip_size / 1024 / 1024:.1f} MB[/dim]")

    if zip_size > 50 * 1024 * 1024:
        console.print("[red]✗[/red] Repository too large for upload (>50MB)")
        console.print("[dim]For large repos, scan a GitHub URL instead[/dim]")
        return None

    try:
        async with httpx.AsyncClient(timeout=300.0) as client:
            with console.status("[bold blue]Running SecurityAgent...[/bold blue]"):
                response = await client.post(
                    f"{api_url}/v1/proxy/scan/upload",
                    files={"file": ("repo.zip", zip_buffer, "application/zip")},
                    data={
                        "auto_fix": str(scan_options.get("auto_fix", True)).lower(),
                        "cross_validate": str(scan_options.get("cross_validate", True)).lower(),
                        "parallel_candidates": str(scan_options.get("parallel_candidates", 3)),
                        "polish": str(scan_options.get("polish", False)).lower(),
                    },
                    headers=headers,
                )

            if response.status_code == 401:
                console.print("[red]✗[/red] License key expired or invalid")
                return None

            response.raise_for_status()
            return response.json()

    except httpx.TimeoutException:
        console.print("[red]✗[/red] Scan timed out")
        return None
    except httpx.HTTPError as e:
        console.print(f"[red]✗[/red] API error: {e}")
        return None


def _create_repo_zip(local_path: Path) -> io.BytesIO:
    """Create a ZIP file of a repository in memory."""
    zip_buffer = io.BytesIO()
    skip_dirs = {"node_modules", ".git", "__pycache__", "venv", ".venv", "dist", "build", ".next", ".unslop"}

    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in local_path.rglob("*"):
            if file_path.is_file():
                rel_path = file_path.relative_to(local_path)
                if any(part in skip_dirs for part in rel_path.parts):
                    continue
                zf.write(file_path, rel_path)

    zip_buffer.seek(0)
    return zip_buffer


# =============================================================================
# Output Formatting
# =============================================================================


def _print_rich_report(vulns: list, summary: dict) -> None:
    """Print vulnerability report with rich formatting."""
    # Count by severity
    critical = sum(1 for v in vulns if v.get("severity", "").lower() == "critical")
    high = sum(1 for v in vulns if v.get("severity", "").lower() == "high")
    medium = sum(1 for v in vulns if v.get("severity", "").lower() == "medium")
    low = sum(1 for v in vulns if v.get("severity", "").lower() == "low")
    total = len(vulns)

    # Use summary if provided
    if summary:
        by_sev = summary.get("by_severity", {})
        critical = by_sev.get("critical", critical)
        high = by_sev.get("high", high)
        medium = by_sev.get("medium", medium)
        low = by_sev.get("low", low)
        total = summary.get("total", total)

    # Summary panel
    summary_text = Text()
    summary_text.append(f"Total: {total}  |  ", style="bold")
    summary_text.append(f"Critical: {critical}", style="bold red" if critical else "dim")
    summary_text.append("  |  ")
    summary_text.append(f"High: {high}", style="bold yellow" if high else "dim")
    summary_text.append("  |  ")
    summary_text.append(f"Medium: {medium}", style="bold blue" if medium else "dim")
    summary_text.append("  |  ")
    summary_text.append(f"Low: {low}", style="dim")

    console.print(Panel(summary_text, title="[bold]Vulnerability Summary[/bold]", border_style="blue"))
    console.print()

    if not vulns:
        console.print("[green]✓ No vulnerabilities found![/green]")
        return

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_vulns = sorted(vulns, key=lambda v: severity_order.get(v.get("severity", "medium").lower(), 2))

    # Display each vulnerability
    for i, vuln in enumerate(sorted_vulns, 1):
        severity = vuln.get("severity", "medium").lower()
        title = vuln.get("title", "Untitled Vulnerability")
        file_path = vuln.get("file_path", "Unknown")
        line_number = vuln.get("line_number", "?")
        cwe_id = vuln.get("cwe_id", "")
        description = vuln.get("description", "")
        code_snippet = vuln.get("code_snippet", "")
        recommendation = vuln.get("recommendation", "")

        sev_colors = {"critical": "red", "high": "yellow", "medium": "blue", "low": "dim"}
        sev_color = sev_colors.get(severity, "white")

        content_parts = []
        content_parts.append(f"[bold]Location:[/bold] {file_path}:{line_number}")
        if cwe_id:
            content_parts.append(f"[bold]CWE:[/bold] {cwe_id}")
        content_parts.append("")

        if description:
            content_parts.append("[bold]Description:[/bold]")
            content_parts.append(description[:500])
            content_parts.append("")

        if code_snippet:
            content_parts.append("[bold]Vulnerable Code:[/bold]")
            snippet = code_snippet[:300] + "..." if len(code_snippet) > 300 else code_snippet
            content_parts.append(f"[dim]{snippet}[/dim]")
            content_parts.append("")

        if recommendation:
            content_parts.append("[bold]Recommendation:[/bold]")
            content_parts.append(recommendation[:300])

        panel_title = f"[{sev_color}][{severity.upper()}][/{sev_color}] {i}. {title}"
        console.print(Panel("\n".join(content_parts), title=panel_title, border_style=sev_color))
        console.print()


def _print_markdown_report(vulns: list, summary: dict) -> None:
    """Print vulnerability report in markdown format."""
    # Count by severity
    critical = sum(1 for v in vulns if v.get("severity", "").lower() == "critical")
    high = sum(1 for v in vulns if v.get("severity", "").lower() == "high")
    medium = sum(1 for v in vulns if v.get("severity", "").lower() == "medium")
    low = sum(1 for v in vulns if v.get("severity", "").lower() == "low")
    total = len(vulns)

    if summary:
        by_sev = summary.get("by_severity", {})
        critical = by_sev.get("critical", critical)
        high = by_sev.get("high", high)
        medium = by_sev.get("medium", medium)
        low = by_sev.get("low", low)
        total = summary.get("total", total)

    print("# Security Vulnerability Report\n")
    print("## Summary\n")
    print("| Severity | Count |")
    print("|----------|-------|")
    print(f"| 🔴 Critical | {critical} |")
    print(f"| 🟠 High | {high} |")
    print(f"| 🟡 Medium | {medium} |")
    print(f"| 🟢 Low | {low} |")
    print(f"| **Total** | **{total}** |")
    print()

    if not vulns:
        print("✅ No vulnerabilities found!\n")
        return

    print("## Vulnerabilities\n")

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_vulns = sorted(vulns, key=lambda v: severity_order.get(v.get("severity", "medium").lower(), 2))

    for i, vuln in enumerate(sorted_vulns, 1):
        severity = vuln.get("severity", "medium").upper()
        title = vuln.get("title", "Untitled Vulnerability")
        file_path = vuln.get("file_path", "Unknown")
        line_number = vuln.get("line_number", "?")
        cwe_id = vuln.get("cwe_id", "")
        description = vuln.get("description", "")
        code_snippet = vuln.get("code_snippet", "")
        recommendation = vuln.get("recommendation", "")

        sev_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        sev_icon = sev_icons.get(severity, "⚪")

        print(f"### {i}. {sev_icon} [{severity}] {title}\n")
        print(f"**Location:** `{file_path}:{line_number}`")
        if cwe_id:
            print(f"**CWE:** {cwe_id}")
        print()

        if description:
            print(f"**Description:**\n{description}\n")

        if code_snippet:
            print("**Vulnerable Code:**")
            print("```")
            print(code_snippet[:500])
            print("```\n")

        if recommendation:
            print(f"**Recommendation:**\n{recommendation}\n")

        print("---\n")


if __name__ == "__main__":
    cli()
