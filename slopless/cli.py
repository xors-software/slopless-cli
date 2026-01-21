"""Slopless CLI - Security scanner for vibe-coded apps.

Usage:
    slopless login <license-key>   # Authenticate with your license
    slopless scan owner/repo       # Scan a GitHub repository
    slopless scan ./path           # Scan a local directory
    slopless whoami                # Check authentication status
    slopless logout                # Remove stored credentials
"""

import asyncio
import io
import json
import re
import zipfile
from pathlib import Path

import click
import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from slopless import __version__
from slopless.config import (
    Credentials,
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


@click.group()
@click.version_option(version=__version__, prog_name="slopless")
def cli() -> None:
    """Slopless - Security scanner for vibe-coded apps.

    Scan your code for security vulnerabilities using AI-powered analysis.

    Get started:
        slopless login <your-license-key>
        slopless scan owner/repo

    Get a license at https://slopless.work
    """
    pass


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
@click.option("--skip-assessment", is_flag=True, help="Skip architecture assessment")
@click.option("--skip-threat-model", is_flag=True, help="Skip threat modeling")
@click.option("--skip-review", is_flag=True, help="Skip vulnerability review")
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
    skip_assessment: bool,
    skip_threat_model: bool,
    skip_review: bool,
    output: str | None,
    output_format: str,
) -> None:
    """Scan a repository for security vulnerabilities.

    TARGET can be a local path or a GitHub repository.

    Examples:
        slopless scan                              # Scan current directory
        slopless scan /path/to/repo                # Scan local path
        slopless scan owner/repo                   # Scan GitHub repo
        slopless scan github.com/owner/repo        # Full GitHub URL
        slopless scan . --output report.json       # Save report
        slopless scan . --format markdown          # Markdown output
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
            skip_assessment,
            skip_threat_model,
            skip_review,
            output,
            output_format,
        )
    )


async def _run_scan(
    target: str,
    skip_assessment: bool,
    skip_threat_model: bool,
    skip_review: bool,
    output: str | None,
    output_format: str,
) -> None:
    """Execute the scan via the hosted API."""
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

    if github_repo:
        # Scan GitHub repo via API
        console.print(f"[bold]🛡️ Scanning:[/bold] {github_repo}")
        result = await _scan_github_repo(
            api_url, headers, github_repo, skip_assessment, skip_threat_model, skip_review
        )
    else:
        # Scan local path via upload
        local_path = Path(target)
        if not local_path.exists():
            console.print(f"[red]✗[/red] Path not found: {target}")
            return

        console.print(f"[bold]🛡️ Scanning:[/bold] {local_path.resolve()}")
        result = await _scan_local_path(
            api_url, headers, local_path, skip_assessment, skip_threat_model, skip_review
        )

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
    skip_assessment: bool,
    skip_threat_model: bool,
    skip_review: bool,
) -> dict | None:
    """Scan a GitHub repository via the API."""
    try:
        async with httpx.AsyncClient(timeout=300.0) as client:
            with console.status("[bold blue]Scanning repository...[/bold blue]"):
                response = await client.post(
                    f"{api_url}/v1/proxy/scan/github",
                    json={
                        "github_repo": github_repo,
                        "skip_assessment": skip_assessment,
                        "skip_threat_model": skip_threat_model,
                        "skip_review": skip_review,
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
    skip_assessment: bool,
    skip_threat_model: bool,
    skip_review: bool,
) -> dict | None:
    """Scan a local directory by uploading it to the API."""
    console.print("[dim]Zipping directory...[/dim]")

    # Create ZIP in memory
    zip_buffer = io.BytesIO()
    skip_dirs = {"node_modules", ".git", "__pycache__", "venv", ".venv", "dist", "build", ".next"}

    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in local_path.rglob("*"):
            if file_path.is_file():
                rel_path = file_path.relative_to(local_path)
                if any(part in skip_dirs for part in rel_path.parts):
                    continue
                zf.write(file_path, rel_path)

    zip_buffer.seek(0)
    zip_size = len(zip_buffer.getvalue())
    console.print(f"[dim]ZIP size: {zip_size / 1024 / 1024:.1f} MB[/dim]")

    if zip_size > 50 * 1024 * 1024:
        console.print("[red]✗[/red] Repository too large for upload (>50MB)")
        console.print("[dim]For large repos, scan a GitHub URL instead[/dim]")
        return None

    try:
        async with httpx.AsyncClient(timeout=300.0) as client:
            with console.status("[bold blue]Uploading and scanning...[/bold blue]"):
                response = await client.post(
                    f"{api_url}/v1/proxy/scan/upload",
                    files={"file": ("repo.zip", zip_buffer, "application/zip")},
                    data={
                        "skip_assessment": str(skip_assessment).lower(),
                        "skip_threat_model": str(skip_threat_model).lower(),
                        "skip_review": str(skip_review).lower(),
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
