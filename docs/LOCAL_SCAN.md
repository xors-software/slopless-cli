# Slopless Local Diff Scan

## What is this?

A developer-local workflow for scanning your current branch changes with Slopless before opening a PR. Designed for interactive use with Claude Code in VS Code.

This is **not** a replacement for the Telegram / ZeroClaw remote orchestration flow. It extends the platform so that the same Slopless security review capabilities can be used interactively by a developer working locally.

## When to use this vs Telegram / remote workflow

| Use case | Tool |
|---|---|
| Quick pre-PR security check while coding | `slopless diff-scan` (local) |
| Iterative fix loop with Claude Code | `slopless diff-fix` (local) |
| CI/CD automated PR review | Slopless GitHub Action (remote) |
| Team-wide scan orchestration | Command Center / Telegram (remote) |
| Full repo baseline scan | `slopless scan` (remote API) |

## Prerequisites

1. **Slopless CLI installed**: `pip install -e .` from the `slopless-cli/` directory
2. **Authenticated**: Run `slopless login <your-license-key>`
3. **Inside a git repo**: Must be run from within a git working tree
4. **On a feature branch**: Works best when you have changes against a base branch

## Commands

### `slopless diff-scan`

Scans only the files changed on your current branch vs the base branch.

```bash
# Auto-detect base branch, text output (best for Claude Code)
slopless diff-scan

# Explicit base branch
slopless diff-scan --base main

# JSON output for scripting
slopless diff-scan --format json

# Rich terminal output with tables
slopless diff-scan --format rich

# Save report to file
slopless diff-scan -o report.json

# Scan entire repo instead of just changes
slopless diff-scan --full-repo
```

**Output formats:**
- `text` (default) — plain text optimized for Claude Code consumption. Severity summary, file-grouped findings, concise actionable wording.
- `json` — stable machine-friendly JSON with `success`, `summary`, `findings` fields.
- `rich` — colored terminal output with tables. Best for interactive terminal use.

**Exit codes:**
- `0` — scan passed (no CRITICAL/HIGH findings)
- `1` — CRITICAL or HIGH findings present
- `2` — scan failed (auth error, network error, etc.)

### `slopless diff-fix`

Runs a scan-fix loop. Each invocation scans once, reports findings, and exits so you (or Claude Code) can fix the issues. Re-run to re-scan.

```bash
# Single scan pass
slopless diff-fix --base main

# Limit iterations (for scripted use)
slopless diff-fix --max-rounds 1

# JSON output
slopless diff-fix --format json
```

## How Claude Code should use this

### Basic workflow

1. Developer asks Claude Code to check their branch for vulnerabilities
2. Claude Code runs: `slopless diff-scan --base main`
3. Claude Code reads the text output (severity summary + findings by file)
4. Claude Code fixes CRITICAL/HIGH findings using Edit/Write tools
5. Claude Code re-runs: `slopless diff-scan --base main`
6. Repeat until clean

### Example conversation

```
User: Check my branch for security issues before I open a PR

Claude Code: [runs] slopless diff-scan --base main
  -> Output shows 1 HIGH finding in src/auth.py:42 (SQL injection)

Claude Code: Found 1 HIGH severity issue. Let me fix it.
  -> Edits src/auth.py to use parameterized query

Claude Code: [runs] slopless diff-scan --base main
  -> Output shows 0 findings

Claude Code: Clean scan. Your branch is ready for PR.
```

### Using JSON format for programmatic fixes

```bash
slopless diff-scan --format json --base main
```

The JSON output has this structure:
```json
{
  "success": true,
  "branch": "feature/my-feature",
  "base_branch": "main",
  "files_scanned": 6,
  "summary": {
    "total": 2,
    "critical": 0,
    "high": 1,
    "medium": 1,
    "low": 0,
    "is_clean": false
  },
  "findings": [
    {
      "file": "src/auth.py",
      "line": 42,
      "severity": "HIGH",
      "title": "SQL Injection",
      "category": "injection",
      "cwe_id": "CWE-89",
      "description": "User input concatenated into SQL query...",
      "recommendation": "Use parameterized queries...",
      "confidence": "high"
    }
  ]
}
```

## What gets scanned

The diff-scan identifies changed files by combining:
- Files changed in commits on the current branch vs the base branch
- Staged changes (`git add`'d but not committed)
- Unstaged modifications
- Untracked files (new files not yet committed)

Only files that exist on disk are included. Deleted files are excluded.

The changed files are zipped and sent to the Slopless API for security analysis. The same scanning engine used for full-repo scans analyzes only your changed code.

## Base branch detection

If `--base` is not provided, the tool auto-detects by checking:
1. Remote HEAD (`origin/HEAD` → usually `main` or `master`)
2. Local `main` branch
3. Local `master` branch
4. Local `develop` branch
5. Fallback to `main` (will error if it doesn't exist)

## Limitations (MVP)

- Scanning goes through the hosted Slopless API — requires network access and valid license
- No inline VS Code decorations or extension integration (yet)
- Fix suggestions come from the scan engine; actual fixing is done by the developer or Claude Code
- The diff-fix loop runs one round per invocation — re-run to iterate
- Context around changed files is not included (only changed files themselves are scanned)
- Very large diffs (>50MB zipped) are rejected
