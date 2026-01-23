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

### GitHub Actions

```yaml
- name: Security Scan
  env:
    SLOPLESS_LICENSE_KEY: ${{ secrets.SLOPLESS_LICENSE_KEY }}
  run: |
    pipx install slopless
    slopless scan . --format json --output security-report.json
```

### GitLab CI

```yaml
security_scan:
  script:
    - pipx install slopless
    - slopless scan . --format json --output security-report.json
  variables:
    SLOPLESS_LICENSE_KEY: $SLOPLESS_LICENSE_KEY
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
