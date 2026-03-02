# Notion Integration

## Description
Read and write to Notion workspaces — query databases, read pages, create/update content, and sync engineering context between Notion and the command center.

## When to Use
- User asks to "read my Notion", "check Notion", "get tasks from Notion"
- User asks to "create a Notion page", "add to Notion", "update Notion"
- User asks to "sync Notion", "pull from Notion", "push to Notion"
- Another skill needs to read/write Notion (e.g., feature-request pulling a ticket)
- User asks to "put the entry from X above Y" or any Notion page manipulation

## Instructions

### Prerequisites

1. **Resolve the Notion token** using the three-tier fallback (env > memory > ask):
   ```bash
   # Tier 1: Environment variable (most reliable)
   if [ -n "${NOTION_TOKEN:-}" ]; then
     export NOTION_TOKEN
     memory save credential:notion '{"token":"'"$NOTION_TOKEN"'","source":"env","added_at":"'"$(date -Iseconds)"'"}' 2>/dev/null || true

   # Tier 2: ZeroClaw memory
   elif CRED_JSON=$(recall credential:notion 2>/dev/null) && [ -n "$CRED_JSON" ]; then
     NOTION_TOKEN=$(echo "$CRED_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")
     export NOTION_TOKEN

   # Tier 3: Ask user
   else
     echo "I need your Notion integration token."
     echo "Create one at https://www.notion.so/my-integrations"
     echo "Send me the token and I'll store it securely."
     echo ""
     echo "Tip: Add NOTION_TOKEN=<value> to your command center .env file for persistence."
     exit 1
   fi
   ```

2. **Set the API version**:
   ```bash
   NOTION_VERSION="2022-06-28"
   ```

---

### Read Operations

#### Search for Pages or Databases
```bash
curl -s -X POST "https://api.notion.com/v1/search" \
  -H "Authorization: Bearer $NOTION_TOKEN" \
  -H "Notion-Version: $NOTION_VERSION" \
  -H "Content-Type: application/json" \
  -d "{\"query\": \"$SEARCH_TERM\", \"page_size\": 10}" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
for r in data.get('results', []):
    kind = r['object']
    title = ''
    if kind == 'page':
        props = r.get('properties', {})
        for p in props.values():
            if p.get('type') == 'title':
                title = ''.join(t.get('plain_text','') for t in p.get('title',[]))
                break
        if not title:
            title = ''.join(t.get('plain_text','') for t in r.get('title',[]))
    elif kind == 'database':
        title = ''.join(t.get('plain_text','') for t in r.get('title',[]))
    print(f'{kind}: {title} (id: {r[\"id\"]})')
"
```

#### Read a Page's Content (blocks)
```bash
PAGE_ID="<page-id>"
curl -s "https://api.notion.com/v1/blocks/$PAGE_ID/children?page_size=100" \
  -H "Authorization: Bearer $NOTION_TOKEN" \
  -H "Notion-Version: $NOTION_VERSION" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
for block in data.get('results', []):
    btype = block['type']
    content = block.get(btype, {})
    if 'rich_text' in content:
        text = ''.join(t.get('plain_text','') for t in content['rich_text'])
        print(f'[{btype}] {text}')
    elif btype == 'child_database':
        print(f'[database] {content.get(\"title\",\"untitled\")}')
    elif btype in ('divider',):
        print('---')
    else:
        print(f'[{btype}]')
"
```

#### Query a Database
```bash
DATABASE_ID="<database-id>"
curl -s -X POST "https://api.notion.com/v1/databases/$DATABASE_ID/query" \
  -H "Authorization: Bearer $NOTION_TOKEN" \
  -H "Notion-Version: $NOTION_VERSION" \
  -H "Content-Type: application/json" \
  -d '{"page_size": 20}' \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
for page in data.get('results', []):
    props = page.get('properties', {})
    row = {}
    for key, val in props.items():
        ptype = val.get('type','')
        if ptype == 'title':
            row[key] = ''.join(t.get('plain_text','') for t in val.get('title',[]))
        elif ptype == 'rich_text':
            row[key] = ''.join(t.get('plain_text','') for t in val.get('rich_text',[]))
        elif ptype == 'select':
            row[key] = (val.get('select') or {}).get('name','')
        elif ptype == 'multi_select':
            row[key] = ', '.join(s['name'] for s in val.get('multi_select',[]))
        elif ptype == 'date':
            d = val.get('date') or {}
            row[key] = d.get('start','')
        elif ptype == 'number':
            row[key] = str(val.get('number',''))
        elif ptype == 'checkbox':
            row[key] = 'Yes' if val.get('checkbox') else 'No'
        elif ptype == 'status':
            row[key] = (val.get('status') or {}).get('name','')
        elif ptype == 'url':
            row[key] = val.get('url','')
    print(f'  {row}  (id: {page[\"id\"]})')
"
```

#### Query with Filters (e.g., by date or status)
```bash
curl -s -X POST "https://api.notion.com/v1/databases/$DATABASE_ID/query" \
  -H "Authorization: Bearer $NOTION_TOKEN" \
  -H "Notion-Version: $NOTION_VERSION" \
  -H "Content-Type: application/json" \
  -d '{
    "filter": {
      "property": "Date",
      "date": { "equals": "2025-03-02" }
    },
    "sorts": [{ "property": "Date", "direction": "descending" }],
    "page_size": 10
  }'
```

---

### Write Operations

#### Create a Page in a Database
```bash
curl -s -X POST "https://api.notion.com/v1/pages" \
  -H "Authorization: Bearer $NOTION_TOKEN" \
  -H "Notion-Version: $NOTION_VERSION" \
  -H "Content-Type: application/json" \
  -d "{
    \"parent\": { \"database_id\": \"$DATABASE_ID\" },
    \"properties\": {
      \"Name\": { \"title\": [{ \"text\": { \"content\": \"$TITLE\" } }] },
      \"Status\": { \"select\": { \"name\": \"$STATUS\" } },
      \"Date\": { \"date\": { \"start\": \"$(date +%Y-%m-%d)\" } }
    }
  }"
```

#### Append Content to a Page
```bash
curl -s -X PATCH "https://api.notion.com/v1/blocks/$PAGE_ID/children" \
  -H "Authorization: Bearer $NOTION_TOKEN" \
  -H "Notion-Version: $NOTION_VERSION" \
  -H "Content-Type: application/json" \
  -d '{
    "children": [
      {
        "object": "block",
        "type": "heading_2",
        "heading_2": {
          "rich_text": [{ "type": "text", "text": { "content": "'"$HEADING"'" } }]
        }
      },
      {
        "object": "block",
        "type": "paragraph",
        "paragraph": {
          "rich_text": [{ "type": "text", "text": { "content": "'"$BODY_TEXT"'" } }]
        }
      }
    ]
  }'
```

#### Update a Page's Properties
```bash
curl -s -X PATCH "https://api.notion.com/v1/pages/$PAGE_ID" \
  -H "Authorization: Bearer $NOTION_TOKEN" \
  -H "Notion-Version: $NOTION_VERSION" \
  -H "Content-Type: application/json" \
  -d '{
    "properties": {
      "Status": { "select": { "name": "'"$NEW_STATUS"'" } }
    }
  }'
```

#### Duplicate a Page (read then create)
To duplicate a page (e.g., "copy the 2/27 entry and adjust for today"):

1. **Read the source page's properties**:
   ```bash
   SOURCE_PAGE_ID="<page-id>"
   curl -s "https://api.notion.com/v1/pages/$SOURCE_PAGE_ID" \
     -H "Authorization: Bearer $NOTION_TOKEN" \
     -H "Notion-Version: $NOTION_VERSION" > /tmp/source-page.json
   ```

2. **Read the source page's blocks (content)**:
   ```bash
   curl -s "https://api.notion.com/v1/blocks/$SOURCE_PAGE_ID/children?page_size=100" \
     -H "Authorization: Bearer $NOTION_TOKEN" \
     -H "Notion-Version: $NOTION_VERSION" > /tmp/source-blocks.json
   ```

3. **Create a new page with modified properties and re-add blocks**:
   ```bash
   python3 << 'PYEOF'
   import json, subprocess, sys
   from datetime import date

   with open("/tmp/source-page.json") as f:
       page = json.load(f)
   with open("/tmp/source-blocks.json") as f:
       blocks_data = json.load(f)

   parent = page.get("parent", {})
   props = page.get("properties", {})

   # Adjust date property if it exists
   for key, val in props.items():
       if val.get("type") == "date" and val.get("date"):
           val["date"]["start"] = str(date.today())
       # Strip read-only fields
       for ro in ("id", "type"):
           props[key].pop(ro, None)

   # Build clean children blocks (strip server-side fields)
   children = []
   for block in blocks_data.get("results", []):
       btype = block["type"]
       clean = {"object": "block", "type": btype, btype: block[btype]}
       children.append(clean)

   payload = {"parent": parent, "properties": props}
   if children:
       payload["children"] = children[:100]

   import os
   token = os.environ.get("NOTION_TOKEN", "")
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
       print(f"Created page: {resp['id']}")
       print(f"URL: {resp.get('url', 'n/a')}")
   else:
       print(f"Error: {resp}")
   PYEOF
   ```

---

### Presenting Results

Always format Notion data clearly for the user:

```
Notion Query Results
━━━━━━━━━━━━━━━━━━━━━━━

Database: Life Dashboard — Q1
Showing: 5 entries

  Date        Status      Summary
  2025-03-02  In Progress Today's plan — feature requests, PR pipeline...
  2025-03-01  Done        Shipped scan-fix loop, reviewed 3 PRs...
  2025-02-27  Done        Benchmark setup, EVMBench integration...

Actions:
  "read entry 2/27"     — show full content
  "duplicate 2/27"      — copy and adjust for today
  "add entry for today" — create a new daily entry
```

---

### Storing Notion Context

After a successful query, save useful references for quick access:
- Key `notion:dashboard`: database ID for the Life Dashboard
- Key `notion:last-query`: timestamp and result summary
- Key `notion:databases`: map of name → database_id for known databases

This lets future requests resolve "my dashboard" or "the Q1 page" without re-searching.

## Important Notes
- Always check for the credential before making API calls
- Notion API rate limit: 3 requests/second — add 400ms sleep between batch calls
- Page content is paginated (100 blocks max per call) — handle `has_more` / `next_cursor`
- The integration token must be shared with the specific pages/databases in Notion's UI
- Never log or display the full Notion token — always mask it
- For large databases, use filters to reduce response size
- If the Notion API returns 401, the token is invalid or the page isn't shared — report clearly
- If the Notion API returns 429, back off and retry after the `Retry-After` header value
- When duplicating or creating dated entries (e.g., daily logs), ALWAYS place the new entry at the TOP of the list (most recent first). In Notion databases, sort by date descending. For page blocks, prepend new content before existing blocks using the `after` parameter set to the first child block ID.
- The user may have multiple Notion workspaces — store credentials per workspace if needed (e.g., `credential:notion:personal`, `credential:notion:xors`)
