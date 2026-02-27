#!/usr/bin/env bash
set -euo pipefail

BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
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

# Optional: configure GitHub CLI
if [ -n "${GH_TOKEN:-}" ]; then
  echo -e "${GREEN}  ✓${NC} GH_TOKEN set — GitHub CLI authenticated"
fi

# Bootstrap workspace structure first (onboard will create defaults)
ZEROCLAW_DIR="$HOME/.zeroclaw"
mkdir -p "$ZEROCLAW_DIR/workspace/skills" "$ZEROCLAW_DIR/workspace/state"

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
level = "supervised"
workspace_only = false
allowed_commands = [
    "git", "gh", "claude", "slopless", "unslop",
    "ls", "cat", "grep", "find", "echo", "pwd", "wc",
    "head", "tail", "date", "mkdir", "cp", "mv", "gpg",
]
forbidden_paths = ["/etc/shadow", "/proc", "/sys", "/boot", "/dev"]
allowed_roots = ["/app", "/tmp"]
max_actions_per_hour = 200
max_cost_per_day_cents = 5000

[agent]
compact_context = false
max_tool_iterations = 25
max_history_messages = 50
parallel_tools = true
tool_dispatcher = "auto"

[scheduler]
enabled = true
max_tasks = 64
max_concurrent = 8

[skills]
open_skills_enabled = false

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

# Create workspace identity files
cat > "$ZEROCLAW_DIR/workspace/IDENTITY.md" << 'EOF'
# Slopless Command Center

I am the Slopless Command Center — an always-on AI assistant for code security and PR orchestration.

I help teams:
- Scan repos for security vulnerabilities using Slopless
- Review pull requests for security, architecture, and quality
- Implement features and raise PRs via Claude Code
- Iterate on scan findings until clean
- Track and adopt existing workstreams
EOF

echo -e "${GREEN}  ✓${NC} Identity configured"
echo ""

echo -e "${GREEN}  ✓${NC} Starting daemon..."
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

exec zeroclaw daemon
