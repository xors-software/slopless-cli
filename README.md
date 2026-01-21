# Slopless CLI

Security scanner for vibe-coded apps. Find vulnerabilities in your code using AI-powered analysis.

## Installation

```bash
# Install via pipx (recommended)
pipx install slopless

# Or via pip
pip install slopless
```

## Quick Start

```bash
# 1. Login with your license key
slopless login sk-slopless-your-key

# 2. Scan a GitHub repository
slopless scan owner/repo

# 3. Or scan a local directory
slopless scan ./my-project
```

## Commands

### `slopless login`

Authenticate with your license key.

```bash
slopless login                      # Interactive prompt
slopless login sk-slopless-abc123   # Provide key directly
```

### `slopless scan`

Scan a repository for security vulnerabilities.

```bash
slopless scan owner/repo             # Scan GitHub repo
slopless scan ./path/to/project      # Scan local directory
slopless scan . --output report.json # Save report to file
slopless scan . --format markdown    # Output as markdown
slopless scan . --format json        # Output as JSON
```

Options:
- `--skip-assessment` - Skip architecture assessment phase
- `--skip-threat-model` - Skip threat modeling phase
- `--skip-review` - Skip vulnerability review phase
- `-o, --output FILE` - Save report to JSON file
- `--format [rich|json|markdown]` - Output format (default: rich)

### `slopless whoami`

Check your authentication status and license info.

```bash
slopless whoami
```

### `slopless logout`

Remove stored credentials from this machine.

```bash
slopless logout
```

## Configuration

Credentials are stored in `~/.slopless/credentials.json`.

Environment variables:
- `SLOPLESS_LICENSE_KEY` - License key (overrides stored credentials)
- `SLOPLESS_API_URL` - API endpoint (for development)
- `SLOPLESS_CONFIG_DIR` - Config directory location

## Get a License

Purchase a license at [https://unslop.dev/pricing](https://unslop.dev/pricing)

## Support

- Documentation: [https://unslop.dev/docs](https://unslop.dev/docs)
- Issues: [https://github.com/xors-software/slopless-cli/issues](https://github.com/xors-software/slopless-cli/issues)
