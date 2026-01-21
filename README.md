# Slopless

AI-powered security scanner for your code. Find vulnerabilities before they find you.

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

Get your license key at [unslop.dev/pricing](https://unslop.dev/pricing)

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

## Commands

| Command | Description |
|---------|-------------|
| `slopless login` | Authenticate with your license key |
| `slopless scan <target>` | Scan a repository for vulnerabilities |
| `slopless whoami` | Check your license status |
| `slopless logout` | Remove stored credentials |

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

## Examples

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
| `SLOPLESS_API_URL` | API endpoint (default: https://api.unslop.dev) |
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
- Internet connection (scans run on our servers)

## Support

- **Docs**: [unslop.dev/docs](https://unslop.dev/docs)
- **Issues**: [github.com/xors-software/slopless-cli/issues](https://github.com/xors-software/slopless-cli/issues)
- **Email**: support@unslop.dev

## License

MIT License - see [LICENSE](LICENSE) for details.
