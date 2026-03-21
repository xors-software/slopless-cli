# Slopless Command Center

ZeroClaw-powered orchestration layer for running parallel slopless sessions across any repo. Command your bot from Telegram, get PRs raised, scanned, and iterated to perfection.

## Quick Start

```bash
cd command-center
./setup.sh
```

Then start the daemon:

```bash
./start.sh
```

This sources `.env`, seeds credentials into ZeroClaw memory, and starts the daemon.
Do **not** run `zeroclaw daemon` directly — your tokens won't be loaded.

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
| Send an image | Send a screenshot, diagram, or error as a photo with a message |

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
  start.sh          # Start daemon (sources .env, seeds credentials)
  setup.sh          # One-command setup for new team members
  .env.example      # Environment variable template
  .env              # Your secrets (gitignored)
  skills/           # ZeroClaw skills (SKILL.md files)
  rules/            # Shared coding standards
  deploy/           # Railway deployment (entrypoint, Dockerfile)
  workspace/        # Ephemeral working dirs (gitignored)
  state/            # ZeroClaw state (gitignored)
```

## Image Support

Send images directly to the bot via Telegram — screenshots, architecture diagrams, error messages, UI mockups, etc. The bot uses Claude's vision capabilities to analyze them.

- **Send as Photo** (preferred): Telegram compresses and routes it through the vision pipeline automatically
- **Send as Document**: Image-extension files (`.jpg`, `.png`, `.webp`, `.gif`) are also routed through vision
- **Limits**: Up to 4 images per message, 10 MB per image
- **Supported formats**: JPEG, PNG, WebP, GIF

Pair an image with a text message for best results, e.g. send a screenshot with "what's wrong with this error?" or an architecture diagram with "implement this".

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
5. `./start.sh` (not `zeroclaw daemon` — see note above)
