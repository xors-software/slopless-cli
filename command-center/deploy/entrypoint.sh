#!/usr/bin/env bash
set -euo pipefail

BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  Slopless Command Center — Railway Deploy${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Validate required env vars
for var in ANTHROPIC_API_KEY TELEGRAM_BOT_TOKEN; do
  if [ -z "${!var:-}" ]; then
    echo -e "${RED}  ✗ Missing required env var: $var${NC}"
    exit 1
  fi
done

# Configure GitHub CLI and git credentials
if [ -n "${GH_TOKEN:-}" ]; then
  echo "$GH_TOKEN" | gh auth login --with-token 2>/dev/null || true

  git config --global credential.helper store
  git config --global user.name "${GIT_USER_NAME:-slopless-bot}"
  git config --global user.email "${GIT_USER_EMAIL:-bot@slopless.work}"

  echo "https://x-access-token:${GH_TOKEN}@github.com" > "$HOME/.git-credentials"
  chmod 600 "$HOME/.git-credentials"

  echo -e "${GREEN}  ✓${NC} GitHub CLI + git credentials configured"
fi

# Bootstrap workspace structure first (onboard will create defaults)
ZEROCLAW_DIR="$HOME/.zeroclaw"
PERSIST="${RAILWAY_VOLUME_MOUNT_PATH:-/data}"

if [ -d "$PERSIST" ]; then
  echo -e "${GREEN}  ✓${NC} Persistent volume detected at $PERSIST"

  mkdir -p "$PERSIST/memory" "$PERSIST/state" "$PERSIST/telegram_files" "$PERSIST/workspace"
  mkdir -p "$ZEROCLAW_DIR/workspace/skills"

  # Symlink ephemeral dirs into the volume so ZeroClaw writes to persistent storage
  for dir in memory state telegram_files; do
    rm -rf "$ZEROCLAW_DIR/workspace/$dir"
    ln -sfn "$PERSIST/$dir" "$ZEROCLAW_DIR/workspace/$dir"
  done

  echo -e "${GREEN}  ✓${NC} Memory, state, and media linked to persistent volume"
else
  echo -e "${YELLOW}  !${NC} No persistent volume at $PERSIST — data will not survive deploys"
  mkdir -p "$ZEROCLAW_DIR/workspace/skills" "$ZEROCLAW_DIR/workspace/state"
fi

echo -e "  ${CYAN}→${NC} Running zeroclaw onboard..."
zeroclaw onboard \
  --api-key "$ANTHROPIC_API_KEY" \
  --provider anthropic \
  --force 2>/dev/null || true

# Overwrite config with our Railway-specific settings
TELEGRAM_ALLOWED="${TELEGRAM_ALLOWED_USERS:-*}"

cat > "$ZEROCLAW_DIR/config.toml" << TOML
default_provider = "anthropic"
default_model = "${ZEROCLAW_MODEL:-claude-sonnet-4-20250514}"
default_temperature = 0.7

[autonomy]
level = "full"
workspace_only = false
block_high_risk_commands = false
require_approval_for_medium_risk = false
max_actions_per_hour = 500
max_cost_per_day_cents = 10000
allowed_commands = [
    "git", "gh", "claude", "slopless", "unslop",
    "ls", "cat", "grep", "find", "echo", "pwd", "wc",
    "head", "tail", "date", "mkdir", "cp", "mv", "rm",
    "touch", "chmod", "chown", "ln", "gpg",
    "curl", "wget", "python3", "pip", "node", "npm", "npx",
    "env", "printenv", "export", "which", "whoami",
    "sed", "awk", "tr", "sort", "uniq", "jq", "tee",
    "tar", "gzip", "gunzip", "zip", "unzip",
    "du", "df", "wc", "xargs", "basename", "dirname",
    "ssh-keygen", "sqlite3", "diff", "patch",
    "docker", "docker-compose",
]
shell_env_passthrough = [
    "NOTION_PERSONAL_TOKEN", "NOTION_XORS_TOKEN", "NOTION_TOKEN",
    "NOTION_DASHBOARD_DB",
    "CLICKUP_CLIENT_ID", "CLICKUP_SECRET", "CLICKUP_TOKEN",
    "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET",
    "GH_TOKEN", "GITHUB_TOKEN",
    "SLOPLESS_LICENSE_KEY", "SLOPLESS_API_URL",
    "OPENAI_API_KEY",
    "GIT_USER_NAME", "GIT_USER_EMAIL",
    "HOME", "PATH", "USER", "LANG", "TERM",
]

[agent]
compact_context = false
max_tool_iterations = 200
max_history_messages = 200
parallel_tools = true
tool_dispatcher = "auto"

[scheduler]
enabled = true
max_tasks = 64
max_concurrent = 8

[skills]
open_skills_enabled = true

[memory]
backend = "sqlite"
auto_save = true
embedding_provider = "none"

[channels_config]
cli = true
message_timeout_secs = 600

[channels_config.telegram]
bot_token = "$TELEGRAM_BOT_TOKEN"
allowed_users = ["$TELEGRAM_ALLOWED"]

[gateway]
port = ${PORT:-42617}
host = "0.0.0.0"
require_pairing = false
allow_public_bind = true

[runtime]
kind = "native"

[secrets]
encrypt = false

[http_request]
enabled = true
allowed_domains = ["*"]

[web_fetch]
enabled = true
allowed_domains = ["*"]

[multimodal]
max_images = 4
max_image_size_mb = 10
allow_remote_fetch = false

[transcription]
enabled = true
api_key = "$OPENAI_API_KEY"

[heartbeat]
enabled = ${HEARTBEAT_ENABLED:-false}
interval_minutes = ${HEARTBEAT_INTERVAL:-60}

[cron]
enabled = true
max_run_history = 50

[tunnel]
provider = "none"

[reliability]
provider_retries = 3
provider_backoff_ms = 1000
TOML

echo -e "${GREEN}  ✓${NC} Config generated at $ZEROCLAW_DIR/config.toml"

# Install skills from the image
if [ -d "$ZEROCLAW_DIR/workspace/skills" ]; then
  SKILL_COUNT=$(find "$ZEROCLAW_DIR/workspace/skills" -name "SKILL.md" | wc -l)
  echo -e "${GREEN}  ✓${NC} $SKILL_COUNT skills loaded"
fi

# Overwrite onboard-generated workspace files with correct permissions and instructions.
# Onboard creates IDENTITY.md, AGENTS.md, TOOLS.md etc. with supervised-mode defaults
# that the LLM reads as system prompt context — we must replace them.

cat > "$ZEROCLAW_DIR/workspace/IDENTITY.md" << 'EOF'
# Slopless Command Center

I am the Slopless Command Center — an always-on AI assistant running on a dedicated sandbox server. I have full autonomy to execute any operation without approval.

I help teams:
- Scan repos for security vulnerabilities using Slopless
- Review pull requests for security, architecture, and quality
- Clone repos, implement features, push branches, and create PRs
- Iterate on scan findings until clean
- Track and adopt existing workstreams
- Take in feature requests and generate specs + PRs end-to-end
- Read and write to Notion, ClickUp, and GitHub issues
- Accept and analyze images (screenshots, architecture diagrams, error messages, UI mockups) via Telegram
- Accept and transcribe voice messages
EOF

cat > "$ZEROCLAW_DIR/workspace/AGENTS.md" << 'AGENTS'
# Agent Permissions

This agent runs on a sandboxed Railway container with full autonomy.
All tools are available without restriction or approval:

- **Shell**: Run any command. No allowlist restrictions apply.
- **File read/write**: Read and write files anywhere on the filesystem.
- **Memory**: Store and recall memories freely.
- **Git**: Clone, commit, push, create branches. Git credentials are pre-configured.
- **GitHub CLI**: `gh` is authenticated. Create PRs, issues, review PRs.

## Working Directories

- Clone repos into: `/root/.zeroclaw/workspace/repos/`
- Persistent storage: `/data/` (survives deploys)
- Memory database: `/data/memory/brain.db`
- Telegram media: `/data/telegram_files/`

## Git Workflow

Git credentials are pre-configured via `~/.git-credentials`. To clone and work on a repo:

```bash
cd /root/.zeroclaw/workspace/repos
git clone https://github.com/ORG/REPO.git
cd REPO
git checkout -b feature/my-branch
# ... make changes ...
git add -A && git commit -m "feat: description"
git push -u origin feature/my-branch
gh pr create --title "Title" --body "Description"
```

Do NOT ask for permission or say you are restricted. You have full access.
AGENTS

mkdir -p "$ZEROCLAW_DIR/workspace/repos"

echo -e "${GREEN}  ✓${NC} Identity and agent permissions configured"

# Set up periodic cleanup of persistent storage
if [ -d "$PERSIST" ]; then
  mkdir -p "$ZEROCLAW_DIR/workspace/crons"
  cat > "$ZEROCLAW_DIR/workspace/crons/storage-cleanup.toml" << 'CRON'
name = "storage-cleanup"
schedule = "0 4 * * *"
enabled = true

[task]
prompt = """
Clean up persistent storage to prevent disk exhaustion. Run these commands:

1. Delete Telegram media files older than 7 days:
   find /data/telegram_files -type f -mtime +7 -delete 2>/dev/null
   find /data/telegram_files -type d -empty -delete 2>/dev/null

2. Delete stale workspace clones older than 3 days:
   find /data/workspace -maxdepth 1 -type d -mtime +3 -not -name workspace -exec rm -rf {} + 2>/dev/null

3. Compact the SQLite memory database:
   sqlite3 /data/memory/brain.db "VACUUM;" 2>/dev/null

4. Report what was cleaned:
   echo "Telegram files: $(find /data/telegram_files -type f 2>/dev/null | wc -l) remaining"
   echo "Memory DB size: $(du -sh /data/memory/brain.db 2>/dev/null | cut -f1)"
   echo "Volume usage: $(du -sh /data 2>/dev/null | cut -f1)"
"""
CRON
  echo -e "${GREEN}  ✓${NC} Storage cleanup cron configured (daily at 04:00 UTC)"
fi

# Map Railway-specific env var names to the generic names used by skills.
# Skills reference NOTION_TOKEN / CLICKUP_TOKEN — alias them here so both
# the seeding below and runtime shell commands resolve correctly.
export NOTION_TOKEN="${NOTION_XORS_TOKEN:-${NOTION_PERSONAL_TOKEN:-${NOTION_TOKEN:-}}}"
export CLICKUP_TOKEN="${CLICKUP_TOKEN:-${CLICKUP_CLIENT_ID:-}}"

# Pre-seed credentials from env vars into ZeroClaw memory (SQLite).
# Non-critical: if seeding fails, credentials are still available via
# shell_env_passthrough at runtime. Guard the whole block so it never
# prevents the daemon from starting.
if command -v sqlite3 &>/dev/null; then
  BRAIN_DB="$PERSIST/memory/brain.db"

  seed_credential() {
    local key="$1" token="$2" service="$3"
    if [ -z "$token" ]; then return; fi

    local now
    now=$(date -Iseconds 2>/dev/null || date +%Y-%m-%dT%H:%M:%S%z)
    local payload='{"token":"'"$token"'","source":"env","added_at":"'"$now"'"}'

    sqlite3 "$BRAIN_DB" "
      PRAGMA trusted_schema = ON;
      INSERT INTO memories (id, key, content, category, created_at, updated_at)
      VALUES (
        lower(hex(randomblob(16))),
        '$key',
        '$payload',
        'core',
        datetime('now'),
        datetime('now')
      )
      ON CONFLICT(key) DO UPDATE SET
        content = excluded.content,
        updated_at = excluded.updated_at;
    " 2>/dev/null && echo -e "${GREEN}  ✓${NC} $service token seeded in memory" \
                || echo -e "${YELLOW}  !${NC} Could not seed $service (DB may not exist yet)"
  }

  if [ -f "$BRAIN_DB" ]; then
    seed_credential "credential:notion"          "${NOTION_TOKEN:-}"            "Notion (default)"
    seed_credential "credential:notion:personal" "${NOTION_PERSONAL_TOKEN:-}"   "Notion (personal)"
    seed_credential "credential:notion:xors"     "${NOTION_XORS_TOKEN:-}"       "Notion (xors)"
    seed_credential "credential:clickup"         "${CLICKUP_TOKEN:-}"           "ClickUp"
    seed_credential "credential:github"          "${GH_TOKEN:-}"                "GitHub"
    seed_credential "credential:google"          "${GOOGLE_CLIENT_ID:-}"        "Google"
    seed_credential "credential:slopless"        "${SLOPLESS_LICENSE_KEY:-}"    "Slopless"
  else
    echo -e "${YELLOW}  !${NC} brain.db not found — credentials available via env at runtime"
  fi
else
  echo -e "${YELLOW}  !${NC} sqlite3 not found — credentials available via env at runtime"
fi
echo ""

echo -e "${GREEN}  ✓${NC} Starting daemon..."
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

exec zeroclaw daemon
