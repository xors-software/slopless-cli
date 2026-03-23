# Slopless CLI — Testing Guide

## 1. Installation

```bash
cd slopless-cli
pip install -e .
```

Verify installation:

```bash
slopless --version
slopless --help
```

## 2. Authentication

```bash
slopless login <YOUR_LICENSE_KEY>
```

Verify:

```bash
slopless whoami
```

## 3. Basic Scan

Scan a local directory:

```bash
slopless scan .
slopless scan /path/to/repo
```

Scan a GitHub repo:

```bash
slopless scan owner/repo
```

Scan without auto-fix:

```bash
slopless scan . --no-fix
```

Save report to file:

```bash
slopless scan . -o report.json --format json
```

## 4. Multi-Engine Scan (Claude + GPT)

Runs supplementary scan passes using multiple LLMs for better coverage. Findings corroborated by multiple engines get confidence boosts.

```bash
slopless scan . --multi-engine
slopless scan . --multi-engine --no-fix
slopless scan owner/repo --multi-engine
```

> **Note:** Multi-engine requires the server to have both `ANTHROPIC_API_KEY` and `OPENAI_API_KEY` configured.

## 5. Notion Integration

### Setup

First, configure your Notion credentials:

1. Create an integration at https://www.notion.so/my-integrations
2. Copy the integration token (starts with `ntn_` or `secret_`)
3. Share your target Notion page with the integration (click "..." on the page → "Add connections" → select your integration)
4. Copy the page ID from the page URL — it's the 32-character hex string after the page name

Then run:

```bash
slopless notion-setup
# (prompts for token and page ID interactively)
```

Or provide them directly:

```bash
slopless notion-setup --token ntn_YOUR_TOKEN --page-id YOUR_PAGE_ID
```

Or use environment variables (no setup needed):

```bash
export NOTION_TOKEN=ntn_YOUR_TOKEN
export NOTION_PAGE_ID=YOUR_PAGE_ID
```

### Scan + Export to Notion

```bash
slopless scan . --notion
slopless scan . --notion --notion-page OVERRIDE_PAGE_ID
slopless scan . --multi-engine --notion
```

This creates a new Notion database under the configured page with columns:
- Unique ID (XORS-H1, XORS-M2, etc.)
- Finding Name, Severity, Description, Type, Status
- Affected Files, Line Number
- Developer Response, Commit, Created Time, Created By

## 6. LaTeX / Overleaf Report

Generates a professional LaTeX audit report that can be compiled to PDF or uploaded to Overleaf.

### Basic Usage

```bash
slopless scan . --latex
```

### Custom Output Path

```bash
slopless scan . --latex --latex-output ./audit-report.tex
slopless scan . --latex --latex-output ./reports/
```

### Custom Template

If you have a custom kaobook template directory:

```bash
slopless scan . --latex --latex-template /path/to/template/dir
```

Or via environment variable:

```bash
export SLOPLESS_LATEX_TEMPLATE_DIR=/path/to/template/dir
slopless scan . --latex
```

### Combine with Other Flags

```bash
slopless scan . --multi-engine --latex --notion
slopless scan . --multi-engine --latex --latex-output ./report.tex --notion
```

### Compile to PDF (after generation)

```bash
cd <output-directory>
pdflatex main.tex
# or use latexmk:
latexmk -pdf main.tex
```

Or upload the generated `.tex` directory to Overleaf.

## 7. Combined Workflow (Full Pipeline)

The most complete scan uses all features together:

```bash
slopless scan /path/to/repo \
  --multi-engine \
  --notion \
  --latex \
  --latex-output ./audit-report/ \
  -o report.json
```

This will:
1. Upload and scan the repo with SecurityAgent + CodingAgent
2. Run supplementary engine passes (Claude + GPT) and merge findings
3. Display rich terminal report
4. Save JSON report to `report.json`
5. Export findings to Notion database
6. Generate LaTeX audit report in `./audit-report/`

## 8. Other Commands

### PR Review

```bash
slopless review-pr https://github.com/owner/repo/pull/42
slopless review-pr owner/repo#42
```

### Diff Scan (changed files only)

```bash
slopless diff-scan
slopless diff-scan --base main
slopless diff-scan --full-repo
```

### Diff Fix (scan-fix loop)

```bash
slopless diff-fix
slopless diff-fix --base main --max-rounds 3
```

## 9. Environment Variables Reference

| Variable | Purpose |
|----------|---------|
| `NOTION_TOKEN` | Notion integration token (alternative to `slopless notion-setup`) |
| `NOTION_PAGE_ID` | Notion parent page ID (alternative to `slopless notion-setup`) |
| `SLOPLESS_LATEX_TEMPLATE_DIR` | Path to custom LaTeX template directory |
| `GITHUB_TOKEN` | GitHub token for PR reviews |
| `SLOPLESS_API_URL` | Override API URL (for development) |

## 10. Troubleshooting

- **"Not logged in"** — Run `slopless login <LICENSE_KEY>`
- **"License key expired or invalid"** — Re-authenticate with `slopless login`
- **"Notion export failed"** — Check that your Notion integration has access to the parent page. Run `slopless notion-setup` to reconfigure.
- **"LaTeX export failed"** — Check that the output path is writable
- **Scan timeout** — Large repos may exceed the 5-minute timeout. Try scanning a subdirectory or use `--no-fix` to skip fix generation.
