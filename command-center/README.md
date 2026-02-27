# Slopless Command Center

ZeroClaw-powered orchestration layer for running parallel slopless sessions across any repo. Command your bot from Telegram, get PRs raised, scanned, and iterated to perfection.

## Quick Start

```bash
cd command-center
./setup.sh
```

Then start the daemon:

```bash
ANTHROPIC_API_KEY="..." zeroclaw daemon
```

Open your Telegram bot and start commanding.

## What It Does

The command center gives you a "Jarvis" for code quality:

1. **Message your bot** on Telegram with a task
2. **It clones the repo**, creates a branch, implements changes using Claude Code
3. **Runs a slopless scan** for security vulnerabilities
4. **Iterates fixes** automatically (up to 3 rounds)
5. **Signs commits** with your GPG key
6. **Creates a PR** on GitHub with structured body
7. **Notifies you** with the PR URL, scan status, and open questions

## Available Commands (via Telegram)

| Command | Example |
|---------|---------|
| Scan a repo | "scan https://github.com/org/repo" |
| Review a PR | "review PR https://github.com/org/repo/pull/42" |
| Full PR workflow | "implement health check in slopless-cli and raise a PR" |
| Adopt existing PR | "adopt https://github.com/org/repo/pull/42" |
| List my PRs | "what PRs do I have open?" |
| Check status | "status" |

## Skills

| Skill | Description |
|-------|-------------|
| `slopless-scan` | Scan a repo for security vulnerabilities |
| `pr-review` | Review a GitHub PR for security/quality |
| `feature-branch` | Clone, branch, implement with Claude Code |
| `pr-create` | Push and create a GitHub PR |
| `scan-fix-loop` | Iteratively scan and fix (max 3 rounds) |
| `git-signing` | GPG commit signing with fallback prompts |
| `pr-workflow` | Full end-to-end PR lifecycle |
| `adopt-workstream` | Import existing PRs for tracking |

## Rules

Shared opinionated standards in `rules/`:

- `commit-standards.md` — Conventional commits, GPG signing, message format
- `pr-quality.md` — PR size limits, quality gates, branch naming
- `security-baseline.md` — Hard security rules enforced on all code

## Directory Structure

```
command-center/
  config.toml       # ZeroClaw config (committed, secrets in .env)
  setup.sh          # One-command setup for new team members
  .env.example      # Environment variable template
  .env              # Your secrets (gitignored)
  skills/           # ZeroClaw skills (SKILL.md files)
  rules/            # Shared coding standards
  workspace/        # Ephemeral working dirs (gitignored)
  state/            # ZeroClaw state (gitignored)
```

## Prerequisites

- [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) (`brew install zeroclaw`)
- [Claude Code](https://docs.anthropic.com/claude-code) (`npm install -g @anthropic-ai/claude-code`)
- [GitHub CLI](https://cli.github.com/) (`brew install gh`)
- [GPG](https://gnupg.org/) (`brew install gnupg`)
- [Slopless CLI](https://pypi.org/project/slopless/) (`pip install slopless`)
- Anthropic API key
- Telegram bot token (from @BotFather)

## Team Setup

1. Clone the slopless-cli repo
2. `cd command-center`
3. `./setup.sh` (guided, checks all prerequisites)
4. Set your Telegram username in the ZeroClaw config allowlist
5. `zeroclaw daemon`
