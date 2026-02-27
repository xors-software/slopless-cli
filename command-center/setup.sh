#!/usr/bin/env bash
set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

header() {
  echo ""
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BOLD}  Slopless Command Center Setup${NC}"
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""
}

ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; }
warn() { echo -e "  ${YELLOW}!${NC} $1"; }
info() { echo -e "  ${CYAN}→${NC} $1"; }

check_command() {
  local cmd="$1"
  local install_hint="$2"
  if command -v "$cmd" &>/dev/null; then
    ok "$cmd $(command -v "$cmd")"
  else
    fail "$cmd not found"
    info "Install: $install_hint"
    return 1
  fi
}

header

echo -e "${BOLD}[1/5] Checking prerequisites${NC}"
MISSING=0
check_command "brew"     "https://brew.sh" || MISSING=1
check_command "gh"       "brew install gh" || MISSING=1
check_command "gpg"      "brew install gnupg" || MISSING=1
check_command "claude"   "npm install -g @anthropic-ai/claude-code" || MISSING=1
check_command "slopless" "pip install slopless" || MISSING=1
check_command "node"     "https://nodejs.org" || MISSING=1

if [ "$MISSING" -eq 1 ]; then
  echo ""
  warn "Some prerequisites are missing. Install them and re-run this script."
  exit 1
fi
echo ""

echo -e "${BOLD}[2/5] Installing ZeroClaw${NC}"
if command -v zeroclaw &>/dev/null; then
  ok "ZeroClaw already installed ($(zeroclaw --version 2>/dev/null || echo 'unknown'))"
else
  info "Installing via Homebrew..."
  brew install zeroclaw
  ok "ZeroClaw installed"
fi
echo ""

echo -e "${BOLD}[3/5] Setting up environment${NC}"
if [ ! -f "$SCRIPT_DIR/.env" ]; then
  cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
  warn "Created .env from template — please edit with your keys:"
  info "$SCRIPT_DIR/.env"
  echo ""
  ${EDITOR:-nano} "$SCRIPT_DIR/.env"
else
  ok ".env already exists"
fi
source "$SCRIPT_DIR/.env"
echo ""

echo -e "${BOLD}[4/5] Onboarding ZeroClaw${NC}"
if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  fail "ANTHROPIC_API_KEY not set in .env"
  exit 1
fi

zeroclaw onboard \
  --api-key "$ANTHROPIC_API_KEY" \
  --provider anthropic \
  --force 2>/dev/null

for skill_dir in "$SCRIPT_DIR"/skills/*/; do
  if [ -f "$skill_dir/SKILL.md" ]; then
    zeroclaw skills install "$skill_dir" 2>/dev/null
    ok "Skill: $(basename "$skill_dir")"
  fi
done
echo ""

echo -e "${BOLD}[5/5] Verifying${NC}"
zeroclaw doctor 2>/dev/null && ok "zeroclaw doctor passed" || warn "zeroclaw doctor had warnings"
gh auth status 2>/dev/null | head -3 && ok "GitHub CLI authenticated" || warn "Run: gh auth login"
gpg --list-secret-keys --keyid-format long 2>/dev/null | head -5 && ok "GPG keys available" || warn "No GPG keys found"
echo ""

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}  Setup complete!${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  Start the daemon:  ${BOLD}zeroclaw daemon${NC}"
echo -e "  Check status:      ${BOLD}zeroclaw status${NC}"
echo -e "  Test via CLI:      ${BOLD}zeroclaw agent -m \"hello\"${NC}"
echo ""
