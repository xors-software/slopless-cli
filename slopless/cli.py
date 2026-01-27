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
