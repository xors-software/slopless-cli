# Slopless

AI-powered security scanner and feature implementation for your code. Find vulnerabilities and build features with AI that understands your codebase.

## Installation

### Install from GitHub

```bash
# Clone the repo
git clone https://github.com/xors-software/slopless-cli.git
cd slopless-cli

# Install with pipx (recommended)
pipx install .

# Or with pip
pip install .
```

### Install from PyPI (coming soon)

```bash
pipx install slopless
```

### Verify Installation

```bash
slopless --version
```

## Quick Start

### 1. Get a License Key

Get your license key at [slopless.work](https://slopless.work)

### 2. Login

```bash
slopless login
# Enter your license key when prompted
```

### 3. Scan Your Code

```bash
# Scan a GitHub repository
slopless scan facebook/react

# Scan a local directory
slopless scan ./my-project

# Scan current directory
slopless scan .
```

### 4. Implement Features with AI

```bash
# Implement a feature (like Cursor, but for your terminal)
slopless feature "Add user authentication with JWT"

# Preview the plan first
slopless feature "Add dark mode toggle" --dry-run

# Auto-commit and create branch
slopless feature "Add API rate limiting" -b feature/rate-limit -c
```

## Commands

| Command | Description |
|---------|-------------|
| `slopless login` | Authenticate with your license key |
| `slopless scan <target>` | Scan a repository for vulnerabilities |
| `slopless review-pr <url>` | Review a pull request for issues |
| `slopless feature "description"` | Implement a feature using AI |
| `slopless git <command>` | Git utilities for feature development |
| `slopless update` | Update to the latest version |
| `slopless whoami` | Check your license status |
| `slopless logout` | Remove stored credentials |

## Automatic Updates

Slopless checks for updates once per day and will notify you if a newer version is available:

```
⚠ Update available: 0.1.0 → 0.2.0
Run 'slopless update' to upgrade
```

Update manually:
```bash
slopless update           # Update to latest
slopless update --check   # Just check for updates
```

## PR Review

The `review-pr` command analyzes pull requests for security issues, architecture violations, and code quality problems.

```bash
slopless review-pr <pr-url> [OPTIONS]

Options:
  --project-id ID        Use specific project for architecture context
  --no-security          Skip security checks
  --no-architecture      Skip architecture checks  
  --no-quality           Skip code quality checks
  -o, --output FILE      Save report to JSON file
  --format FORMAT        Output format: rich (default), json, markdown
  --github-token TOKEN   GitHub token (or use GITHUB_TOKEN env var)
```

### How It Works

1. **Fetch Diff**: Retrieves the PR diff from GitHub
2. **Load Context**: Uses architecture context from previous Slopless scans (if available)
3. **Analyze**: Reviews changed code for security issues, architecture violations, and quality problems
4. **Report**: Returns findings with verdict (approve/request_changes/comment)

### Examples

```bash
# Review a PR with full URL
slopless review-pr https://github.com/owner/repo/pull/42

# Shorthand format
slopless review-pr owner/repo#42

# Security-only review
slopless review-pr owner/repo#42 --no-architecture --no-quality

# Save as JSON for CI integration
slopless review-pr owner/repo#42 --format json -o review.json

# With explicit GitHub token
GITHUB_TOKEN=ghp_xxx slopless review-pr owner/repo#42
```

### Context from Previous Scans

If you've previously scanned the repository with `slopless scan`, the PR review will use that context to:
- Understand the codebase architecture
- Check for violations of existing patterns
- Avoid flagging known issues
- Provide more relevant suggestions

Without prior context, Slopless performs differential analysis on the PR changes alone.

## Feature Implementation

The `feature` command analyzes your codebase, generates an implementation plan, and writes the code - like having Cursor in your terminal.

```bash
slopless feature "Add user authentication with JWT" [OPTIONS]

Options:
  --dry-run           Generate plan without implementing
  -y, --yes           Skip confirmation prompts
  -b, --branch NAME   Create a new branch for changes
  -c, --commit        Auto-commit changes when done
  --no-tests          Skip test generation
```

### How It Works

1. **Analyze**: Uploads your codebase and analyzes the architecture
2. **Plan**: Generates a detailed implementation plan with tasks
3. **Review**: Shows you the plan and asks for confirmation
4. **Implement**: Writes code following existing patterns
5. **Apply**: Writes changes to your local files

### Examples

```bash
# Full workflow with branch and commit
slopless feature "Add user profile page" -b feature/profile -c

# Quick implementation (no confirmation)
slopless feature "Fix the login bug" -y

# Preview what will change
slopless feature "Add search functionality" --dry-run

# Skip test generation for quick prototypes
slopless feature "Add demo page" --no-tests
```

## Git Utilities

Convenient wrappers for common git operations during feature development.

```bash
# Create a feature branch
slopless git branch feature/my-feature

# Commit changes
slopless git commit -m "feat: add user authentication"

# Stage all and commit
slopless git commit -am "fix: resolve login bug"

# Push to remote
slopless git push
slopless git push -u  # For new branches

# Check status
slopless git status

# Show changes
slopless git diff
slopless git diff --staged
```

## Scan Options

```bash
slopless scan <target> [OPTIONS]

Options:
  --skip-assessment     Skip architecture assessment phase
  --skip-threat-model   Skip threat modeling phase  
  --skip-review         Skip vulnerability review phase
  -o, --output FILE     Save report to JSON file
  --format FORMAT       Output format: rich (default), json, markdown
```

### Scan Examples

```bash
# Scan and save report
slopless scan owner/repo --output report.json

# Markdown report (great for GitHub issues)
slopless scan . --format markdown > SECURITY.md

# Quick scan (skip some phases)
slopless scan . --skip-assessment --skip-threat-model

# JSON output for CI/CD pipelines
slopless scan . --format json | jq '.vulnerabilities | length'
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SLOPLESS_LICENSE_KEY` | License key (overrides stored credentials) |
| `SLOPLESS_API_URL` | API endpoint (default: https://api.slopless.work) |
| `SLOPLESS_CONFIG_DIR` | Config directory (default: ~/.slopless) |

## CI/CD Integration

Slopless works seamlessly in CI/CD pipelines. Add security scanning to every PR and push.

### Quick Start (GitHub Actions)

Add your `SLOPLESS_LICENSE_KEY` to repository secrets, then create `.github/workflows/slopless.yml`:

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Slopless
        run: pip install slopless

      - name: Security Scan
        env:
          SLOPLESS_LICENSE_KEY: ${{ secrets.SLOPLESS_LICENSE_KEY }}
        run: |
          slopless scan . --format json --output report.json

          # Fail on critical vulnerabilities
          CRITICAL=$(jq '[.vulnerabilities[] | select(.severity == "critical")] | length' report.json)
          if [ "$CRITICAL" -gt 0 ]; then
            echo "::error::Found $CRITICAL critical vulnerabilities!"
            exit 1
          fi

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-report
          path: report.json
```

### Using the Slopless Action (Recommended)

For a more feature-rich experience with PR comments and job summaries:

```yaml
name: Security Scan

on:
  pull_request:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - uses: actions/checkout@v4

      - uses: xors-software/slopless-action@v1
        with:
          license-key: ${{ secrets.SLOPLESS_LICENSE_KEY }}
          fail-on-critical: 'true'
          fail-on-high: 'false'
          comment-on-pr: 'true'
```

**Action Inputs:**

| Input | Description | Default |
|-------|-------------|---------|
| `license-key` | Your Slopless license key (required) | - |
| `path` | Path to scan | `.` |
| `fail-on-critical` | Fail if critical vulns found | `true` |
| `fail-on-high` | Fail if high vulns found | `false` |
| `auto-fix` | Generate fix suggestions | `true` |
| `cross-validate` | Cross-validate findings | `true` |
| `comment-on-pr` | Post results as PR comment | `true` |
| `output-format` | Output format (rich/json/markdown) | `markdown` |

**Action Outputs:**

| Output | Description |
|--------|-------------|
| `total-vulnerabilities` | Total count |
| `critical-count` | Critical vulnerabilities |
| `high-count` | High severity vulnerabilities |
| `medium-count` | Medium severity vulnerabilities |
| `low-count` | Low severity vulnerabilities |
| `scan-passed` | Whether thresholds passed |

### GitLab CI

```yaml
security_scan:
  image: python:3.12
  stage: test
  script:
    - pip install slopless
    - slopless scan . --format json --output security-report.json
    - |
      CRITICAL=$(jq '[.vulnerabilities[] | select(.severity == "critical")] | length' security-report.json)
      if [ "$CRITICAL" -gt 0 ]; then
        echo "Found $CRITICAL critical vulnerabilities!"
        exit 1
      fi
  variables:
    SLOPLESS_LICENSE_KEY: $SLOPLESS_LICENSE_KEY
  artifacts:
    paths:
      - security-report.json
    expire_in: 1 week
```

### CircleCI

```yaml
version: 2.1

jobs:
  security-scan:
    docker:
      - image: cimg/python:3.12
    steps:
      - checkout
      - run:
          name: Install Slopless
          command: pip install slopless
      - run:
          name: Run Security Scan
          command: slopless scan . --format json --output report.json
      - store_artifacts:
          path: report.json

workflows:
  security:
    jobs:
      - security-scan
```

### Bitbucket Pipelines

```yaml
pipelines:
  pull-requests:
    '**':
      - step:
          name: Security Scan
          image: python:3.12
          script:
            - pip install slopless
            - slopless scan . --format json --output report.json
          artifacts:
            - report.json
```

### Azure DevOps

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.12'

  - script: |
      pip install slopless
      slopless scan . --format json --output $(Build.ArtifactStagingDirectory)/report.json
    displayName: 'Security Scan'
    env:
      SLOPLESS_LICENSE_KEY: $(SLOPLESS_LICENSE_KEY)

  - publish: $(Build.ArtifactStagingDirectory)/report.json
    artifact: SecurityReport
```

### Docker

```dockerfile
FROM python:3.12-slim

RUN pip install slopless

WORKDIR /app
COPY . .

RUN slopless scan . --format json --output /report.json

# Use as build step, fail on criticals
RUN [ $(jq '[.vulnerabilities[] | select(.severity == "critical")] | length' /report.json) -eq 0 ]
```

## Requirements

- Python 3.11 or higher
- Git (for feature implementation)
- Internet connection (scans and AI run on our servers)

## Support

- **Website**: [slopless.work](https://slopless.work)
- **Issues**: [github.com/xors-software/slopless-cli/issues](https://github.com/xors-software/slopless-cli/issues)
- **Email**: support@xors.software

## License

MIT License - see [LICENSE](LICENSE) for details.
