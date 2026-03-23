"""Notion integration for Slopless CLI.

Creates a Notion database (table) from scan findings, matching the
XORS audit report structure:
Severity, Description, Status, Type, Affected Files, Commit, Created Time, Created By, Unique ID.
"""

import asyncio
from datetime import datetime

import httpx
from rich.console import Console

from slopless.config import get_notion_page_id, get_notion_token

console = Console()

NOTION_API = "https://api.notion.com/v1"
NOTION_VERSION = "2022-06-28"

# Severity -> ID prefix, matching VAR_BITMIND convention (XORS-H1, XORS-M2, etc.)
SEVERITY_PREFIX = {
    "CRITICAL": "C",
    "HIGH": "H",
    "MEDIUM": "M",
    "LOW": "L",
}

# Notion select option colors per severity
SEVERITY_COLORS = {
    "CRITICAL": "red",
    "HIGH": "orange",
    "MEDIUM": "yellow",
    "LOW": "blue",
}

STATUS_OPTIONS = [
    {"name": "Open", "color": "red"},
    {"name": "In Progress", "color": "yellow"},
    {"name": "Resolved", "color": "green"},
    {"name": "Won't Fix", "color": "gray"},
]

TYPE_OPTIONS = [
    {"name": "Security", "color": "red"},
    {"name": "Code Quality", "color": "blue"},
    {"name": "Reliability", "color": "orange"},
    {"name": "Performance", "color": "yellow"},
    {"name": "Best Practice", "color": "green"},
]


def _notion_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Notion-Version": NOTION_VERSION,
    }


def _truncate(text: str, limit: int = 2000) -> str:
    """Truncate text to Notion's rich_text limit."""
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def generate_finding_ids(vulns: list[dict]) -> list[str]:
    """Generate XORS-style IDs (e.g. XORS-H1, XORS-M2) for a list of findings.

    Findings should already be sorted by severity (CRITICAL > HIGH > MEDIUM > LOW).
    """
    counters: dict[str, int] = {}
    ids: list[str] = []
    for vuln in vulns:
        sev = vuln.get("severity", "MEDIUM").upper()
        prefix = SEVERITY_PREFIX.get(sev, "U")
        counters[prefix] = counters.get(prefix, 0) + 1
        ids.append(f"XORS-{prefix}{counters[prefix]}")
    return ids


async def create_findings_database(
    token: str,
    parent_page_id: str,
    title: str,
) -> str:
    """Create a Notion database with the audit findings schema.

    Returns the database ID.
    """
    severity_options = [
        {"name": sev, "color": color}
        for sev, color in SEVERITY_COLORS.items()
    ]

    payload = {
        "parent": {"type": "page_id", "page_id": parent_page_id},
        "title": [{"type": "text", "text": {"content": title}}],
        "properties": {
            "Unique ID": {"title": {}},
            "Severity": {"select": {"options": severity_options}},
            "Description": {"rich_text": {}},
            "Type": {"select": {"options": TYPE_OPTIONS}},
            "Status": {"select": {"options": STATUS_OPTIONS}},
            "Affected Files": {"rich_text": {}},
            "Line Number": {"number": {"format": "number"}},
            "Developer Response": {"rich_text": {}},
            "Commit": {"rich_text": {}},
            "Created Time": {"rich_text": {}},
            "Created By": {"rich_text": {}},
        },
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            f"{NOTION_API}/databases",
            json=payload,
            headers=_notion_headers(token),
        )
        if resp.status_code == 401:
            raise NotionAuthError("Invalid Notion token. Run `slopless notion-setup` or set NOTION_TOKEN.")
        if resp.status_code == 404:
            raise NotionPageNotFoundError(
                "Parent page not found. Make sure you've shared it with your Notion integration."
            )
        resp.raise_for_status()
        data = resp.json()
        return data["id"]


def _infer_type(vuln: dict) -> str:
    """Infer finding type category from vuln data."""
    vuln_type = vuln.get("type", "vulnerability").lower()
    category = vuln.get("category", "").lower()
    title = vuln.get("title", "").lower()

    if vuln_type == "threat":
        return "Security"

    quality_keywords = ["naming", "style", "format", "lint", "unused", "dead code", "complexity"]
    if any(kw in title or kw in category for kw in quality_keywords):
        return "Code Quality"

    reliability_keywords = ["null", "race condition", "deadlock", "memory leak", "crash", "exception handling"]
    if any(kw in title or kw in category for kw in reliability_keywords):
        return "Reliability"

    perf_keywords = ["performance", "n+1", "slow", "timeout", "cache"]
    if any(kw in title or kw in category for kw in perf_keywords):
        return "Performance"

    return "Security"


def _extract_file_from_text(text: str) -> str:
    """Try to extract file path references from text."""
    import re

    file_patterns = [
        r'\b([a-zA-Z0-9_][a-zA-Z0-9_/.-]*\/[a-zA-Z0-9_.-]+\.(?:py|js|ts|jsx|tsx|go|rs|java|rb|php|sol|move|c|cpp|h))\b',
        r'\b([a-zA-Z0-9_-]+\.(?:py|js|ts|jsx|tsx|go|rs|java|rb|php|sol|move|c|cpp|h))\b',
    ]
    found_files: list[str] = []
    for pattern in file_patterns:
        matches = re.findall(pattern, text)
        for m in matches:
            if (
                m not in found_files
                and not m.startswith("e.g.")
                and not m.startswith("os.path")
                and not m.startswith("request.")
                and "." in m
                and len(m) > 4
            ):
                found_files.append(m)

    return ", ".join(found_files[:5]) if found_files else ""


def _build_affected_files(vuln: dict) -> str:
    """Build affected files string from vuln data."""
    file_path = vuln.get("file") or vuln.get("file_path") or ""

    if not file_path:
        snippet = vuln.get("code_snippet") or vuln.get("codeSnippet") or ""
        if snippet:
            file_path = _extract_file_from_text(snippet)
        if not file_path:
            desc = vuln.get("description", "") + " " + vuln.get("title", "")
            file_path = _extract_file_from_text(desc)

    if not file_path:
        return "N/A"

    line = vuln.get("line") or vuln.get("line_number")
    if line and int(line) > 0:
        return f"{file_path}:{line}"
    return file_path


async def add_finding_row(
    token: str,
    database_id: str,
    finding_id: str,
    vuln: dict,
    created_date: str,
) -> None:
    """Insert a single finding as a row in the Notion database."""
    severity = vuln.get("severity", "MEDIUM").upper()

    # Build description: title + description + recommendation + CWE
    desc_parts = []
    title = vuln.get("title", "Untitled")
    desc_parts.append(title)
    if vuln.get("description"):
        desc_parts.append(vuln["description"])
    if vuln.get("recommendation"):
        desc_parts.append(f"Recommendation: {vuln['recommendation']}")
    cwe = vuln.get("cwe") or vuln.get("cwe_id") or ""
    if cwe:
        desc_parts.append(f"[{cwe}]")
    full_description = "\n\n".join(desc_parts)

    # Get line number
    line_val = vuln.get("line") or vuln.get("line_number")
    if isinstance(line_val, str):
        try:
            line_val = int(line_val)
        except (ValueError, TypeError):
            line_val = None
    if line_val == 0:
        line_val = None

    properties: dict = {
        "Unique ID": {"title": [{"text": {"content": finding_id}}]},
        "Severity": {"select": {"name": severity}},
        "Description": {"rich_text": [{"text": {"content": _truncate(full_description)}}]},
        "Type": {"select": {"name": _infer_type(vuln)}},
        "Status": {"select": {"name": "Open"}},
        "Affected Files": {"rich_text": [{"text": {"content": _truncate(_build_affected_files(vuln))}}]},
        "Developer Response": {"rich_text": [{"text": {"content": ""}}]},
        "Commit": {"rich_text": [{"text": {"content": vuln.get("commit", "N/A")}}]},
        "Created Time": {"rich_text": [{"text": {"content": created_date}}]},
        "Created By": {"rich_text": [{"text": {"content": "XORS"}}]},
    }

    if line_val is not None:
        properties["Line Number"] = {"number": line_val}

    payload = {
        "parent": {"database_id": database_id},
        "properties": properties,
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            f"{NOTION_API}/pages",
            json=payload,
            headers=_notion_headers(token),
        )
        resp.raise_for_status()


async def export_findings_to_notion(
    vulns: list[dict],
    token: str | None = None,
    page_id: str | None = None,
    title: str | None = None,
) -> str:
    """Export scan findings to a Notion database.

    Args:
        vulns: List of vulnerability dicts from the scan API.
        token: Notion integration token (resolved from config if None).
        page_id: Parent page ID (resolved from config if None).
        title: Database title (auto-generated if None).

    Returns:
        URL to the created Notion database.
    """
    token = token or get_notion_token()
    page_id = page_id or get_notion_page_id()

    if not token:
        raise NotionAuthError(
            "No Notion token configured. Run `slopless notion-setup` or set NOTION_TOKEN env var."
        )
    if not page_id:
        raise NotionPageNotFoundError(
            "No Notion page ID configured. Run `slopless notion-setup` or set NOTION_PAGE_ID env var."
        )

    if not title:
        title = f"Slopless Audit Findings — {datetime.now().strftime('%Y-%m-%d %H:%M')}"

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_vulns = sorted(
        vulns,
        key=lambda v: severity_order.get(v.get("severity", "MEDIUM").upper(), 2),
    )

    # Generate XORS-style IDs
    finding_ids = generate_finding_ids(sorted_vulns)

    # Create database
    console.print("[dim]Creating Notion database...[/dim]")
    db_id = await create_findings_database(token, page_id, title)

    # Insert rows with rate-limit-friendly concurrency (Notion: 3 req/s)
    created_date = datetime.now().strftime("%Y-%m-%d")
    semaphore = asyncio.Semaphore(3)

    async def insert_with_limit(fid: str, vuln: dict) -> None:
        async with semaphore:
            await add_finding_row(token, db_id, fid, vuln, created_date)
            await asyncio.sleep(0.35)  # stay under 3 req/s

    console.print(f"[dim]Inserting {len(sorted_vulns)} findings...[/dim]")
    tasks = [
        insert_with_limit(fid, vuln)
        for fid, vuln in zip(finding_ids, sorted_vulns)
    ]
    await asyncio.gather(*tasks)

    # Build URL from database ID
    db_url = f"https://notion.so/{db_id.replace('-', '')}"
    return db_url


# =============================================================================
# Exceptions
# =============================================================================


class NotionAuthError(Exception):
    pass


class NotionPageNotFoundError(Exception):
    pass
