# Credentials Manager

## Description
Manage external service credentials (Notion, GitHub, Slack, custom APIs) that the command center can use on your behalf. Credentials are stored in ZeroClaw's encrypted memory and never logged or displayed in full.

## When to Use
- User says "connect notion", "add my notion key", "set up notion"
- User asks "what credentials do I have?", "list integrations"
- User says "remove notion", "disconnect slack"
- A skill needs a credential that isn't configured yet

## Instructions

### Add a Credential
When user wants to add a service credential:

1. **Identify the service** from the user's message. Supported services:
   - `notion` — Notion API integration token
   - `github` — GitHub PAT (may already be configured via gh CLI)
   - `slack` — Slack bot token
   - `linear` — Linear API key
   - `jira` — Jira API token
   - `custom` — Any arbitrary key/value pair

2. **Ask for the credential value** if not provided:
   > "Please send me your Notion integration token. You can create one at https://www.notion.so/my-integrations
   >
   > I'll store it encrypted and only use it when you ask me to interact with Notion."

3. **Store in ZeroClaw memory** with key `credential:{service}`:
   ```
   memory save credential:notion {"token": "<value>", "added_at": "<timestamp>", "added_by": "<telegram_user>"}
   ```

4. **Verify the credential works** (service-specific):
   - **Notion**: `curl -s -H "Authorization: Bearer <token>" -H "Notion-Version: 2022-06-28" https://api.notion.com/v1/users/me`
   - **GitHub**: `gh auth status` or `curl -H "Authorization: Bearer <token>" https://api.github.com/user`
   - **Slack**: `curl -s -H "Authorization: Bearer <token>" https://slack.com/api/auth.test`
   - **Linear**: `curl -s -H "Authorization: <token>" https://api.linear.app/graphql -d '{"query":"{ viewer { id name } }"}'`

5. **Report result**:
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
