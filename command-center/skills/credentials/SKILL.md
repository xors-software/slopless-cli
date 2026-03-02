# Credentials Manager

## Description
Manage external service credentials (Notion, GitHub, Slack, custom APIs) that the command center can use on your behalf. Credentials are stored in ZeroClaw's encrypted memory and never logged or displayed in full.

## When to Use
- User says "connect notion", "add my notion key", "set up notion"
- User asks "what credentials do I have?", "list integrations"
- User says "remove notion", "disconnect slack"
- A skill needs a credential that isn't configured yet

## Instructions

### Resolving a Credential (used by all skills)

When any skill needs a credential, follow this **three-tier fallback** in order:

1. **Environment variable** (most reliable — survives daemon restarts):
   ```bash
   # Env var names: NOTION_TOKEN, CLICKUP_TOKEN, GH_TOKEN, LINEAR_TOKEN, SLACK_TOKEN
   if [ -n "${NOTION_TOKEN:-}" ]; then
     TOKEN="$NOTION_TOKEN"
     # Cache in memory so recall works for other skills
     memory save credential:notion '{"token":"'"$NOTION_TOKEN"'","source":"env","added_at":"'"$(date -Iseconds)"'"}'
   fi
   ```

2. **ZeroClaw memory** (persists across sessions, but can be lost on setup re-runs):
   ```bash
   CRED_JSON=$(recall credential:notion 2>/dev/null || echo "")
   if [ -n "$CRED_JSON" ]; then
     TOKEN=$(echo "$CRED_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")
   fi
   ```

3. **Ask the user** (last resort):
   > "I need your Notion integration token. Send it here or add NOTION_TOKEN to your .env file."

**Always try all three tiers before giving up.** Never tell the user credentials are missing if you haven't checked both env vars AND memory.

### Add a Credential
When user wants to add a service credential:

1. **Identify the service** from the user's message. Supported services:
   - `notion` — Notion API integration token (env: `NOTION_TOKEN`)
   - `github` — GitHub PAT (env: `GH_TOKEN`, may already be configured via gh CLI)
   - `clickup` — ClickUp API token (env: `CLICKUP_TOKEN`)
   - `slack` — Slack bot token (env: `SLACK_TOKEN`)
   - `linear` — Linear API key (env: `LINEAR_TOKEN`)
   - `jira` — Jira API token (env: `JIRA_TOKEN`)
   - `custom` — Any arbitrary key/value pair

2. **Check environment variable first** — the `.env` file is the canonical source:
   ```bash
   [ -n "${NOTION_TOKEN:-}" ] && memory save credential:notion '{"token":"'"$NOTION_TOKEN"'","source":"env","added_at":"'"$(date -Iseconds)"'"}'
   [ -n "${CLICKUP_TOKEN:-}" ] && memory save credential:clickup '{"token":"'"$CLICKUP_TOKEN"'","source":"env","added_at":"'"$(date -Iseconds)"'"}'
   ```
   If the env var is set, save to memory and report it as connected. Done.

3. **Ask for the credential value** if not in env:
   > "Please send me your Notion integration token. You can create one at https://www.notion.so/my-integrations
   >
   > I'll store it encrypted and only use it when you ask me to interact with Notion.
   >
   > Tip: For persistence across restarts, also add `NOTION_TOKEN=<value>` to your command center .env file."

4. **Store in ZeroClaw memory** with key `credential:{service}`:
   ```
   memory save credential:notion {"token": "<value>", "added_at": "<timestamp>", "added_by": "<telegram_user>"}
   ```

5. **Verify the credential works** (service-specific):
   - **Notion**: `curl -s -H "Authorization: Bearer <token>" -H "Notion-Version: 2022-06-28" https://api.notion.com/v1/users/me`
   - **GitHub**: `gh auth status` or `curl -H "Authorization: Bearer <token>" https://api.github.com/user`
   - **ClickUp**: `curl -s -H "Authorization: <token>" https://api.clickup.com/api/v2/user`
   - **Slack**: `curl -s -H "Authorization: Bearer <token>" https://slack.com/api/auth.test`
   - **Linear**: `curl -s -H "Authorization: <token>" https://api.linear.app/graphql -d '{"query":"{ viewer { id name } }"}'`

6. **Report result**:
   ```
   Credential Added
   ━━━━━━━━━━━━━━━━━━━━
   Service:  Notion
   Token:    ntn_...****
   Status:   Verified (connected as "Xiangan's Workspace")
   
   I can now:
   - Read and update Notion pages
   - Create tasks from scan findings
   - Sync PR status to Notion boards
   ```

### List Credentials
When user asks to see configured credentials:

1. **Recall from memory**:
   Look for all memory keys matching `credential:*`

2. **Format** (never show full tokens):
   ```
   Configured Integrations
   ━━━━━━━━━━━━━━━━━━━━━━━━

   Service     Status      Added
   notion      connected   2d ago
   github      connected   (via gh CLI)
   clickup     connected   1d ago
   slack       not set     —
   linear      not set     —

   "connect <service>" to add a new integration.
   "remove <service>" to disconnect.
   ```

### Remove a Credential
When user asks to remove/disconnect a service:

1. **Confirm**: "Are you sure you want to remove the Notion credential? Reply 'yes' to confirm."
2. **Delete from memory**: Remove `credential:notion`
3. **Report**: "Notion disconnected. I can no longer access your Notion workspace."

### Using Credentials in Other Skills
Other skills can check for credentials by recalling from memory:
```
recall credential:notion
```
If the credential is missing, prompt the user:
> "I need your Notion token to do this. Send it here or run 'connect notion'."

## Important Notes
- NEVER display full credential values in messages — always mask (show first 4 and last 4 chars)
- Credentials are stored in ZeroClaw's encrypted SQLite memory
- Each credential is scoped to the Telegram user who added it
- GitHub auth is often already available via `gh` CLI — check that first before asking for a token
- When a credential fails verification, report the error clearly and suggest how to fix it
- **Environment variables are the primary source of truth** — `.env` file persists across daemon restarts, memory does not always
- Always try env var before memory, and always try both before asking the user
- When saving a user-provided credential to memory, also suggest they add it to `.env` for persistence
- The `start.sh` wrapper script auto-seeds memory from `.env` on daemon startup — use it instead of `zeroclaw daemon` directly
