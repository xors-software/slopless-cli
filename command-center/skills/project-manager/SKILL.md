# Project Manager

## Description
Discover, index, and manage projects under the user's workspace using a consent-first, interactive flow. Prompts the user at each stage before accessing git history, GitHub PRs, or Cursor IDE context. Enables instant context-switching between projects.

## When to Use
- User asks "list projects", "what projects do I have?", "show my repos"
- User asks "status of X" or "what was I working on in X?"
- User asks to "load project X" or "switch to X"
- User asks "refresh projects" or "scan my workspace"

## Instructions

Follow the three-phase interactive flow below. Each phase requires user consent before proceeding.

---

### Phase 1: Lightweight Discovery

Detect the environment and discover projects accordingly.

1. **Check environment** — determine if running on Railway (deployed) or locally:
   ```bash
   if [ -n "${RAILWAY_ENVIRONMENT:-}" ]; then
     MODE="deployed"
   else
     MODE="local"
   fi
   ```

2. **If deployed (Railway)** — discover projects via GitHub API:
   ```bash
   gh repo list xors-software --json name,defaultBranchRef,primaryLanguage,url,pushedAt \
     --limit 30 --no-archived 2>/dev/null
   ```
   Parse the JSON output and present:
   ```
   Projects Found (GitHub — xors-software)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    #  Repo                   Default Branch    Language      Last Push
    1. slopless-engine        main              Python        2d ago
    2. slopless-cli           main              Python        1d ago
    3. slopless               main              TypeScript    3d ago
    4. git-scout              main              TypeScript    1w ago
    ...

   Found N repositories.
   ```
   If the GitHub org differs, ask the user or recall from memory.

3. **If local** — scan the workspace root for directories:
   ```bash
   for dir in ~/work/xors/*/; do
     name=$(basename "$dir")
     has_git="no"
     remote="—"
     branch="—"
     stack="—"

     if [ -d "$dir/.git" ] || [ -f "$dir/.git" ]; then
       has_git="yes"
       remote=$(git -C "$dir" remote get-url origin 2>/dev/null || echo "local-only")
       branch=$(git -C "$dir" branch --show-current 2>/dev/null || echo "detached")
     fi

     [ -f "$dir/pyproject.toml" ] && stack="python"
     [ -f "$dir/package.json" ] && stack="node"
     [ -f "$dir/Cargo.toml" ] && stack="rust"
     [ -f "$dir/go.mod" ] && stack="go"
     [ -f "$dir/Makefile" ] && [ "$stack" = "—" ] && stack="make"

     echo "$name | $has_git | $branch | $remote | $stack"
   done
   ```
   For multi-repo projects (directories containing sub-directories with `.git`), group them:
   ```bash
   for subdir in "$dir"/*/; do
     if [ -d "$subdir/.git" ]; then
       sub_name=$(basename "$subdir")
       sub_remote=$(git -C "$subdir" remote get-url origin 2>/dev/null || echo "local-only")
       sub_branch=$(git -C "$subdir" branch --show-current 2>/dev/null || echo "detached")
       echo "  sub: $sub_name | $sub_branch | $sub_remote"
     fi
   done
   ```

4. Present the list and **ask the user**:
   > "Want me to check GitHub for open PRs on these? I can check all, or just specific ones. Reply with 'all', project names/numbers, or 'skip'."

---

### Phase 2: GitHub Enrichment (user opts in)

Only run for projects the user approved. This makes GitHub API calls via `gh`.

1. **Check if `gh` is authenticated**:
   ```bash
   gh auth status 2>&1
   ```
   If not authenticated, report:
   > "GitHub CLI is not authenticated. Skipping PR checks. Run `gh auth login` to enable this."
   Then skip to Phase 3 prompt.

2. **For each approved project**, extract the GitHub owner/repo from the remote URL and query PRs:
   ```bash
   REMOTE=$(git -C "$PROJECT_DIR" remote get-url origin 2>/dev/null)
   # Extract owner/repo from GitHub URL
   REPO=$(echo "$REMOTE" | sed -E 's#.+github\.com[:/](.+)(\.git)?$#\1#' | sed 's/\.git$//')
   
   if [ -n "$REPO" ]; then
     gh pr list --repo "$REPO" --author @me --state open \
       --json number,title,headRefName,updatedAt,additions,deletions \
       --limit 5 2>/dev/null || echo "Could not fetch PRs for $REPO"
   fi
   ```

3. **Handle errors gracefully**:
   - If a remote is not GitHub: skip, note "non-GitHub remote"
   - If the repo is inaccessible (private, deleted): note "access denied", continue
   - If rate-limited: stop PR checks, report what was gathered so far

4. **Present enriched results**:
   ```
   GitHub PRs
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

   slopless-engine (xors-software/slopless-engine)
     #42 — Add cross-validation for HIGH findings
          branch: feat/cross-validate | +87 -12 | 2d ago

   slopless-cli (xors-software/slopless-cli)
     No open PRs

   git-scout (xors-software/git-scout)
     #5 — Global navigation frontend
          branch: feature/global-nav-frontend | +342 -89 | 1w ago

   Total: 2 open PRs across 3 repos checked.
   ```

5. **Ask the user**:
   > "I can also pull in context from your recent Cursor IDE sessions — this reads a one-line summary of your last chat per project (no full conversations are stored). Want me to check? Reply 'all', project names, or 'skip'."

---

### Phase 3: Cursor Context (explicit opt-in only)

Only run for projects the user specifically approved. This reads local files from the Cursor IDE data directory.

1. **Resolve the Cursor project directory dynamically** (works for any user/machine):
   ```bash
   CURSOR_BASE="$HOME/.cursor/projects"
   # Derive the prefix from the home directory path
   HOME_PREFIX=$(echo "$HOME" | sed 's#^/##' | tr '/' '-')
   # Derive the project path suffix
   PROJECT_SUFFIX=$(echo "$PROJECT_DIR" | sed "s#^$HOME/##" | tr '/' '-')
   CURSOR_DIR="$CURSOR_BASE/${HOME_PREFIX}-${PROJECT_SUFFIX}"
   ```

2. **Check if transcripts exist** (use `find` to avoid glob errors on empty dirs):
   ```bash
   if [ -d "$CURSOR_DIR/agent-transcripts" ]; then
     TRANSCRIPT_COUNT=$(find "$CURSOR_DIR/agent-transcripts" -name "*.txt" 2>/dev/null | wc -l | tr -d ' ')
     LATEST=$(find "$CURSOR_DIR/agent-transcripts" -name "*.txt" -print0 2>/dev/null | xargs -0 ls -t 2>/dev/null | head -1)
   fi
   ```
   If the directory doesn't exist or has no transcripts, skip silently.

3. **Extract only the first user query** from the most recent transcript (the topic/intent):
   ```bash
   if [ -n "$LATEST" ]; then
     # Transcripts use <user_query>...</user_query> XML tags
     sed -n '/<user_query>/,/<\/user_query>/p' "$LATEST" 2>/dev/null \
       | head -5 \
       | sed 's/<[^>]*>//g' \
       | tr -s ' \n' ' ' \
       | head -c 120
   fi
   ```
   NEVER store or transmit full transcript content. Only extract a brief topic summary.

4. **Present context**:
   ```
   Recent Cursor Context
   ━━━━━━━━━━━━━━━━━━━━━━━━━

   slopless-project (3 sessions found)
     Last: "Run slopless on EVMBench benchmark — pull it into the
           repo and maximize accuracy"

   git-scout (1 session found)
     Last: "Build the global navigation component with search"

   apis (no Cursor sessions found)
   ```

---

### Loading a Project

When user asks "load slopless" or "switch to slopless":

1. Run Phase 1 for that specific project (or use cached data if fresh).
2. Run Phase 2 for that project (auto-consent since user explicitly asked).
3. Optionally run Phase 3 if previous consent was given, or ask.
4. **Store in ZeroClaw memory** under key `active-project:<name>`:
   - Project name, local path, git remote URL, current branch
   - Tech stack (detected from manifests)
   - Open PR list (numbers, titles, URLs)
   - Last Cursor context summary (if approved)
   - Timestamp loaded
5. **Set as active context** so other skills can resolve short references:
   - "scan it" resolves to the active project path
   - "review the PR" resolves to the most recent open PR
   - "work on it" resolves to the active project repo
6. **Present**:
   ```
   Project Loaded: slopless-project
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

   Repos:
     slopless-engine   main   xors-software/slopless-engine
     slopless-cli      main   xors-software/slopless-cli
     slopless          main   xors-software/slopless

   Open PRs: 2
     #42 — Add cross-validation (slopless-engine)
     #18 — Fix review-pr format (slopless-cli)

   Context: "EVMBench benchmark integration"

   Stack: Python 3.11+, FastAPI, Anthropic SDK, Next.js
   URL:   https://github.com/xors-software/slopless-*

   Actions:
     "scan slopless-engine"    — security scan
     "review PR #42"           — review the open PR
     "adopt PR #18"            — iterate on it
     "work on: <task>"         — new feature/fix
   ```

---

### Store in Memory

After any completed discovery flow, save to ZeroClaw memory:
- Key `project-index`: full list of discovered projects with metadata
- Key `active-project:<name>`: currently loaded project context
- Key `project-index-timestamp`: when the index was last refreshed

### Refresh Policy
- On explicit request ("refresh projects")
- When user references a project not in the index
- If the index is older than 24 hours and user runs "list projects"
- Never auto-refresh without telling the user

## Important Notes
- Multi-repo projects (like slopless-project) should be grouped by parent directory
- Projects under `clients/` should be grouped by client name
- Cursor transcripts may contain sensitive data — only extract the first user query topic, never store raw content
- The project index enables all other skills to resolve short names (e.g., "slopless" -> repo paths)
- For Railway deployment: Phase 1 uses GitHub API (no local filesystem), Phase 2 works as-is, Phase 3 is skipped (Cursor transcripts are local-only)
- If a project has no `.git` directory, still list it as "non-git project"
- Rate-limit `gh pr list` calls to avoid GitHub API throttling (max 5 sequential, not concurrent)
