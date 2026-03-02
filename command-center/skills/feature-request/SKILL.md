# Feature Request Pipeline

## Description
Take in engineering feature requests from any source (Telegram message, Notion ticket, ClickUp task, GitHub issue), generate a product spec using Slopless, and optionally kick off the full PR workflow to implement it. This is the end-to-end "idea to PR" skill.

## When to Use
- User describes a feature: "I want to add X", "we need Y", "build Z"
- User references an external ticket: "implement TICKET-123", "work on this Notion page"
- User asks to "generate a spec for X" or "plan feature X"
- User asks to "turn this into a PR" or "implement this feature end-to-end"
- User pastes a GitHub issue URL, Notion page URL, or ClickUp task URL

## Instructions

### Step 1: Parse the Feature Request

Identify the source and extract the feature description:

#### A) Direct Description (Telegram message)
The user typed the feature request directly:
```
Feature: <extract the core request>
Source:  Telegram (direct)
```

#### B) GitHub Issue URL
```bash
# Extract owner/repo and issue number
ISSUE_URL="<url>"
REPO=$(echo "$ISSUE_URL" | sed -E 's#https://github.com/([^/]+/[^/]+)/.*#\1#')
ISSUE_NUM=$(echo "$ISSUE_URL" | sed -E 's#.*/issues/([0-9]+).*#\1#')

gh issue view "$ISSUE_NUM" --repo "$REPO" --json title,body,labels,assignees,milestone
```

#### C) Notion Page URL
```bash
# Extract page ID from URL
PAGE_ID=$(echo "$NOTION_URL" | sed -E 's#.*-([a-f0-9]{32})$#\1#' | sed 's/./&-/8;s/./&-/13;s/./&-/18;s/./&-/23')

# Use notion-integration skill to read the page
recall credential:notion
NOTION_TOKEN=$(recall credential:notion | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")

curl -s "https://api.notion.com/v1/pages/$PAGE_ID" \
  -H "Authorization: Bearer $NOTION_TOKEN" \
  -H "Notion-Version: 2022-06-28" > /tmp/notion-feature.json

curl -s "https://api.notion.com/v1/blocks/$PAGE_ID/children?page_size=100" \
  -H "Authorization: Bearer $NOTION_TOKEN" \
  -H "Notion-Version: 2022-06-28" >> /tmp/notion-feature-blocks.json

python3 -c "
import json
with open('/tmp/notion-feature.json') as f:
    page = json.load(f)
with open('/tmp/notion-feature-blocks.json') as f:
    blocks = json.load(f)

props = page.get('properties', {})
title = ''
for p in props.values():
    if p.get('type') == 'title':
        title = ''.join(t.get('plain_text','') for t in p.get('title',[]))
        break

body_parts = []
for block in blocks.get('results', []):
    btype = block['type']
    content = block.get(btype, {})
    if 'rich_text' in content:
        text = ''.join(t.get('plain_text','') for t in content['rich_text'])
        body_parts.append(text)

print(f'Title: {title}')
print(f'Body: {chr(10).join(body_parts)}')
"
```

#### D) ClickUp Task URL
```bash
# ClickUp API — requires credential:clickup
recall credential:clickup
CLICKUP_TOKEN=$(recall credential:clickup | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")
TASK_ID=$(echo "$CLICKUP_URL" | sed -E 's#.*/t/([a-z0-9]+).*#\1#')

curl -s "https://api.clickup.com/api/v2/task/$TASK_ID" \
  -H "Authorization: $CLICKUP_TOKEN" \
  | python3 -c "
import json, sys
task = json.load(sys.stdin)
print(f'Title: {task.get(\"name\",\"\")}')
print(f'Description: {task.get(\"description\",\"\")}')
print(f'Status: {task.get(\"status\",{}).get(\"status\",\"\")}')
print(f'Priority: {task.get(\"priority\",{}).get(\"priority\",\"\")}')
print(f'Tags: {\", \".join(t[\"name\"] for t in task.get(\"tags\",[]))}')
"
```

---

### Step 2: Confirm and Enrich

Present the parsed feature request back to the user for confirmation:

```
Feature Request Received
━━━━━━━━━━━━━━━━━━━━━━━━━━

Title:   <feature title>
Source:  <Telegram / GitHub Issue #N / Notion / ClickUp>
Description:
  <parsed description, 3-5 lines max>

Target Repo: <detected or ask user>
Priority:    <from ticket, or ask>

What would you like me to do?
  1. Generate a product spec
  2. Generate spec + implement (full PR)
  3. Just create a GitHub issue
  4. Edit the request first
```

If the target repo is unclear, ask:
> "Which repo should this go into? Reply with a name or URL."

Resolve short names via the project-manager skill (recall `project-index` or `active-project:*`).

---

### Step 3: Generate Product Spec

Use the Slopless feature spec engine. Determine the best method:

#### Method A: Via Slopless CLI (if available)
```bash
cd "$PROJECT_DIR"
slopless feature "$FEATURE_DESCRIPTION" --output /tmp/spec-$TASK_ID.md --format markdown
```

#### Method B: Via Slopless API (if the CLI can't reach the project)
```bash
API_URL="${SLOPLESS_API_URL:-https://api.slopless.work}"
LICENSE_KEY=$(recall credential:slopless-license || echo "$SLOPLESS_LICENSE_KEY")

curl -s -X POST "$API_URL/v1/feature/spec/generate" \
  -H "Authorization: Bearer $LICENSE_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"description\": \"$FEATURE_DESCRIPTION\",
    \"repo_url\": \"$REPO_URL\",
    \"ticket_url\": \"$TICKET_URL\"
  }" > /tmp/spec-$TASK_ID.json
```

#### Method C: Via Claude Code (fallback — no API needed)
```bash
claude -p "Generate a detailed product/engineering spec for this feature request:

Title: $FEATURE_TITLE
Description: $FEATURE_DESCRIPTION
Target Repo: $REPO_URL

The spec should include:
1. Overview — what and why
2. User stories — who benefits and how
3. Technical approach — architecture, data model, API changes
4. Implementation tasks — ordered list with estimates
5. Acceptance criteria — how to verify it's done
6. Edge cases and risks
7. Dependencies

Format as clean Markdown." \
  --output-format text > /tmp/spec-$TASK_ID.md
```

Present the spec to the user:
```
Product Spec Generated
━━━━━━━━━━━━━━━━━━━━━━

$FEATURE_TITLE
──────────────

<first 20 lines of spec preview>
...

Full spec: /tmp/spec-$TASK_ID.md

Actions:
  "approve"        — proceed to implementation
  "edit"           — make changes first
  "save to notion" — push spec to Notion
  "create issue"   — create GitHub issue from spec
```

---

### Step 4: Save Spec to External Systems (optional)

#### Save to Notion
If user asks to save the spec to Notion, use the notion-integration skill:
```bash
NOTION_TOKEN=$(recall credential:notion | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")
DATABASE_ID=$(recall notion:databases | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('specs', d.get('features', '')))")

SPEC_CONTENT=$(cat /tmp/spec-$TASK_ID.md)

python3 << 'PYEOF'
import json, subprocess, os

token = os.environ.get("NOTION_TOKEN", "")
db_id = os.environ.get("DATABASE_ID", "")
title = os.environ.get("FEATURE_TITLE", "Untitled Spec")
spec = os.environ.get("SPEC_CONTENT", "")

# Split spec into blocks (Notion max 2000 chars per rich_text)
blocks = []
for line in spec.split('\n'):
    if line.startswith('# '):
        blocks.append({"object":"block","type":"heading_1","heading_1":{"rich_text":[{"type":"text","text":{"content":line[2:]}}]}})
    elif line.startswith('## '):
        blocks.append({"object":"block","type":"heading_2","heading_2":{"rich_text":[{"type":"text","text":{"content":line[3:]}}]}})
    elif line.startswith('### '):
        blocks.append({"object":"block","type":"heading_3","heading_3":{"rich_text":[{"type":"text","text":{"content":line[4:]}}]}})
    elif line.startswith('- '):
        blocks.append({"object":"block","type":"bulleted_list_item","bulleted_list_item":{"rich_text":[{"type":"text","text":{"content":line[2:]}}]}})
    elif line.strip():
        blocks.append({"object":"block","type":"paragraph","paragraph":{"rich_text":[{"type":"text","text":{"content":line}}]}})

payload = {
    "parent": {"database_id": db_id} if db_id else {"page_id": db_id},
    "properties": {
        "Name": {"title": [{"text": {"content": title}}]},
        "Status": {"select": {"name": "Draft"}}
    },
    "children": blocks[:100]
}

result = subprocess.run(
    ["curl", "-s", "-X", "POST", "https://api.notion.com/v1/pages",
     "-H", f"Authorization: Bearer {token}",
     "-H", "Notion-Version: 2022-06-28",
     "-H", "Content-Type: application/json",
     "-d", json.dumps(payload)],
    capture_output=True, text=True
)
resp = json.loads(result.stdout)
if "id" in resp:
    print(f"Saved to Notion: {resp.get('url', resp['id'])}")
else:
    print(f"Error: {resp}")
PYEOF
```

#### Create GitHub Issue from Spec
```bash
SPEC_BODY=$(cat /tmp/spec-$TASK_ID.md)
gh issue create --repo "$REPO" \
  --title "$FEATURE_TITLE" \
  --body "$SPEC_BODY" \
  --label "feature,slopless-generated"
```

#### Export to ClickUp
```bash
CLICKUP_TOKEN=$(recall credential:clickup | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")
LIST_ID="<target-list-id>"

curl -s -X POST "https://api.clickup.com/api/v2/list/$LIST_ID/task" \
  -H "Authorization: $CLICKUP_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"$FEATURE_TITLE\",
    \"description\": \"$(cat /tmp/spec-$TASK_ID.md)\",
    \"status\": \"to do\",
    \"tags\": [\"slopless-generated\"]
  }"
```

---

### Step 5: Implement (if user approves)

When user replies "approve" or chooses full implementation:

1. **Invoke the pr-workflow skill** with the spec as context:
   - Repo: `$REPO_URL`
   - Task: Full spec content from `/tmp/spec-$TASK_ID.md`
   - This triggers: feature-branch → scan → fix-loop → sign → create-pr

2. **Report progress** at each stage (pr-workflow handles this).

3. **Link back to source**: After PR is created, update the source ticket:

   **GitHub Issue**: Add a comment linking to the PR
   ```bash
   gh issue comment "$ISSUE_NUM" --repo "$REPO" \
     --body "PR created by Slopless: $PR_URL

   Spec and implementation auto-generated from this issue."
   ```

   **Notion**: Update status to "In Progress" and add PR link
   ```bash
   curl -s -X PATCH "https://api.notion.com/v1/pages/$PAGE_ID" \
     -H "Authorization: Bearer $NOTION_TOKEN" \
     -H "Notion-Version: 2022-06-28" \
     -H "Content-Type: application/json" \
     -d "{
       \"properties\": {
         \"Status\": { \"select\": { \"name\": \"In Progress\" } },
         \"PR\": { \"url\": \"$PR_URL\" }
       }
     }"
   ```

   **ClickUp**: Update task status
   ```bash
   curl -s -X PUT "https://api.clickup.com/api/v2/task/$TASK_ID" \
     -H "Authorization: $CLICKUP_TOKEN" \
     -H "Content-Type: application/json" \
     -d "{\"status\": \"in progress\"}"
   ```

---

### Step 6: Final Report

```
Feature Request Complete
━━━━━━━━━━━━━━━━━━━━━━━━━━

Feature:  $FEATURE_TITLE
Source:   <Telegram / GitHub #N / Notion / ClickUp>
Spec:     Generated ✓
PR:       #<number> — <pr-title>
URL:      <pr-url>
Scan:     <CLEAN / N findings>

Source updated:
  <GitHub issue #N commented with PR link>
  <Notion page status → In Progress>
  <ClickUp task status → in progress>

Next steps:
  "adopt <pr-url>"   — track for iteration
  "review PR #N"     — review the PR
  "status"           — check current workstreams
```

---

### Store in Memory

After each feature request flow:
- Key `feature-request:<task-id>`: title, source, spec path, PR URL, status, timestamp
- Key `active-project:<name>`: update with new PR if applicable

## Important Notes
- Always confirm the feature request with the user before generating a spec
- If the user just wants a spec (not a PR), stop after Step 3
- If the user just wants a GitHub issue, stop after Step 4
- The spec generation method (CLI vs API vs Claude) depends on what's available — try in order
- For Notion/ClickUp sources, the credential must be configured first
- Large feature requests may need to be broken into multiple PRs — ask the user
- If the target repo has no existing code (new project), adjust the spec to include setup
- Rate-limit external API calls (Notion: 3/sec, ClickUp: 100/min, GitHub: 5000/hr)
- Store the raw spec in /tmp for the session; it can be re-generated if lost
