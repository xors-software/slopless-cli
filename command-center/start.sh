#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZEROCLAW_DIR="$HOME/.zeroclaw"
BRAIN_DB="$ZEROCLAW_DIR/workspace/memory/brain.db"

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
warn() { echo -e "  ${YELLOW}!${NC} $1"; }
info() { echo -e "  ${CYAN}→${NC} $1"; }

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  Slopless Command Center — Start${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Source .env so all tokens are in the daemon's environment
if [ -f "$SCRIPT_DIR/.env" ]; then
  set -a
  source "$SCRIPT_DIR/.env"
  set +a
  ok ".env loaded"
else
  warn "No .env file found at $SCRIPT_DIR/.env"
  info "Copy from template: cp .env.example .env"
fi

# Pre-seed ZeroClaw memory from env vars so skills can use recall
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
  " 2>/dev/null && ok "$service token seeded in memory" \
              || warn "Could not seed $service token (DB may be locked)"
}

export NOTION_TOKEN="${NOTION_XORS_TOKEN:-${NOTION_PERSONAL_TOKEN:-${NOTION_TOKEN:-}}}"
export CLICKUP_TOKEN="${CLICKUP_TOKEN:-${CLICKUP_CLIENT_ID:-}}"

if [ -f "$BRAIN_DB" ]; then
  seed_credential "credential:notion"          "${NOTION_TOKEN:-}"            "Notion (default)"
  seed_credential "credential:notion:personal" "${NOTION_PERSONAL_TOKEN:-}"   "Notion (personal)"
  seed_credential "credential:notion:xors"     "${NOTION_XORS_TOKEN:-}"       "Notion (xors)"
  seed_credential "credential:clickup"         "${CLICKUP_TOKEN:-}"           "ClickUp"
  seed_credential "credential:github"          "${GH_TOKEN:-}"                "GitHub"
  seed_credential "credential:google"          "${GOOGLE_CLIENT_ID:-}"        "Google"
  seed_credential "credential:slopless"        "${SLOPLESS_LICENSE_KEY:-}"    "Slopless"
else
  warn "brain.db not found — credentials will load from env vars at runtime"
fi

echo ""
echo -e "${GREEN}  ✓${NC} Starting daemon..."
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

exec zeroclaw daemon
