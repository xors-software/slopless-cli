# Context Migration

## Description
Import conversation context from Cursor IDE and Claude Code into ZeroClaw's memory. This lets the command center understand what you've been working on across all your tools without re-explaining.

## When to Use
- User asks "import my cursor context", "migrate my sessions", "sync from cursor"
- User asks "what have I been working on?" (and memory is empty)
- First time setup — after project discovery, offer to import context
- User asks "import context for slopless" (specific project)

## Instructions

### Step 1: Discover Available Context Sources

Check for Cursor IDE transcripts:
```bash
CURSOR_BASE="$HOME/.cursor/projects"
HOME_PREFIX=$(echo "$HOME" | sed 's#^/##' | tr '/' '-')

if [ -d "$CURSOR_BASE" ]; then
  for project_dir in "$CURSOR_BASE/${HOME_PREFIX}-"*/; do
    if [ -d "$project_dir/agent-transcripts" ]; then
      PROJECT_NAME=$(basename "$project_dir" | sed "s/^${HOME_PREFIX}-//" | tr '-' '/')
      COUNT=$(find "$project_dir/agent-transcripts" -name "*.txt" 2>/dev/null | wc -l | tr -d ' ')
      if [ "$COUNT" -gt 0 ]; then
        LATEST=$(find "$project_dir/agent-transcripts" -name "*.txt" -print0 | xargs -0 ls -t | head -1)
        MODIFIED=$(stat -f "%Sm" -t "%Y-%m-%d" "$LATEST" 2>/dev/null || stat -c "%y" "$LATEST" 2>/dev/null | cut -d' ' -f1)
        echo "$PROJECT_NAME | $COUNT sessions | last: $MODIFIED"
      fi
    fi
  done
fi
```

Check for Claude Code sessions:
```bash
CLAUDE_DIR="$HOME/.claude"
if [ -d "$CLAUDE_DIR" ]; then
  echo "Claude Code directory found"
  # Claude Code stores sessions in ~/.claude/projects/
  for proj_dir in "$CLAUDE_DIR/projects/"*/; do
    if [ -d "$proj_dir" ]; then
      PROJ_NAME=$(basename "$proj_dir")
      SESSION_COUNT=$(find "$proj_dir" -name "*.jsonl" -o -name "*.json" 2>/dev/null | wc -l | tr -d ' ')
      echo "claude-code: $PROJ_NAME | $SESSION_COUNT files"
    fi
  done
fi
```

### Step 2: Present and Ask for Consent

```
Context Sources Found
━━━━━━━━━━━━━━━━━━━━━━━━

Cursor IDE:
  work/xors/slopless-project          9 sessions   last: 2026-02-26
  work/xors/git-scout                 3 sessions   last: 2026-02-20
  work/xors/clients/byld/hike-mono    5 sessions   last: 2026-02-18

Claude Code:
  slopless-engine                     2 sessions
  
Total: 19 sessions across 4 projects

I'll extract a brief topic summary from each session (not full conversations).
Which projects should I import? Reply 'all' or list specific ones.
```

### Step 3: Extract Context (per project, per session)

For each approved project, extract topic summaries from transcripts:

**Cursor transcripts** (format: `<user_query>...</user_query>` XML tags):
```bash
for transcript in $(find "$TRANSCRIPT_DIR" -name "*.txt" -print0 | xargs -0 ls -t); do
  TOPIC=$(sed -n '/<user_query>/,/<\/user_query>/p' "$transcript" 2>/dev/null \
    | head -5 \
    | sed 's/<[^>]*>//g' \
    | tr -s ' \n' ' ' \
    | head -c 200)
  
  TIMESTAMP=$(stat -f "%Sm" -t "%Y-%m-%dT%H:%M" "$transcript" 2>/dev/null || \
    stat -c "%y" "$transcript" 2>/dev/null | cut -d'.' -f1)
  
  if [ -n "$TOPIC" ]; then
    echo "$TIMESTAMP | $TOPIC"
  fi
done
```

**Claude Code sessions** (format: JSONL with role/content):
```bash
for session in $(find "$CLAUDE_DIR/projects/$PROJECT" -name "*.jsonl" -print0 2>/dev/null | xargs -0 ls -t); do
  TOPIC=$(head -5 "$session" | grep -o '"content":"[^"]*"' | head -1 | sed 's/"content":"//;s/"$//' | head -c 200)
  if [ -n "$TOPIC" ]; then
    echo "claude-code | $TOPIC"
  fi
done
```

### Step 4: Store in ZeroClaw Memory

For each project, save a context summary:
- Key: `context:{project-name}`
- Value: structured summary of recent work

Format stored in memory:
```json
{
  "project": "slopless-project",
  "source": "cursor",
  "sessions": [
    {"date": "2026-02-26", "topic": "Run slopless on EVMBench benchmark — maximize accuracy"},
    {"date": "2026-02-24", "topic": "Fix digest output format for scan results"},
    {"date": "2026-02-22", "topic": "Add cross-validation for HIGH severity findings"}
  ],
  "imported_at": "2026-02-26T22:00:00",
  "session_count": 9
}
```

### Step 5: Report

```
Context Imported
━━━━━━━━━━━━━━━━━━━━━━━

slopless-project (9 sessions from Cursor):
  Latest: "Run slopless on EVMBench benchmark — maximize accuracy"
  Recent: "Fix digest output format for scan results"
  Recent: "Add cross-validation for HIGH severity findings"

git-scout (3 sessions from Cursor):
  Latest: "Build global navigation component with search"

Imported 12 session summaries across 2 projects.

I now have context on what you've been working on. Ask me:
  "what was I doing on slopless?" — recall recent work
  "continue where I left off on git-scout" — resume
```

## Important Notes
- Only extract the first user query per session — never store full conversation transcripts
- Truncate topics to 200 characters max
- Claude Code may store sessions differently across versions — handle missing/malformed files gracefully
- Context migration is one-directional (import only, no export back to Cursor/CC)
- Re-running migration for the same project updates existing context (doesn't duplicate)
- For Railway deployment: context migration is a local-only operation (runs on the user's machine)
