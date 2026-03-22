# Feature Branch

## Description
Clone a repo, create a feature branch, spawn a Claude Code session to implement changes, and commit the results.

## When to Use
- User requests a code change on a specific repo
- Part of the full PR workflow
- User says "implement", "add", "fix", "change", or "build" something in a repo

## Instructions

1. **Parse inputs**:
   - Target repo: GitHub URL or local path
   - Task description: what to implement
   - Branch name (optional): defaults to `slopless/<task-slug>`

2. **Set up workspace**:
   ```
   TASK_ID=$(date +%s)-$(echo "$TASK_DESC" | tr ' ' '-' | tr '[:upper:]' '[:lower:]' | head -c 20)
   WORK_DIR="/tmp/workspace/$TASK_ID"
   mkdir -p "$WORK_DIR"
   ```

3. **Clone or copy the repo**:
   - If GitHub URL: `git clone <url> "$WORK_DIR/repo" && cd "$WORK_DIR/repo"`
   - If local path: `cp -r <path> "$WORK_DIR/repo" && cd "$WORK_DIR/repo"`

4. **Create a feature branch**:
   ```
   BRANCH="slopless/$(echo "$TASK_DESC" | tr ' ' '-' | tr '[:upper:]' '[:lower:]' | head -c 40)"
   git checkout -b "$BRANCH"
   ```

5. **Read the project first** before writing any code:
   ```bash
   # Understand the existing patterns before implementing
   ls -la
   cat package.json 2>/dev/null | head -30
   find src -name "*.tsx" -o -name "*.ts" | head -20
   # Look at an existing feature for the pattern to follow
   ```

6. **Invoke Claude Code** to implement changes:
   ```
   claude -p "You are working in this repository. Implement the following: $TASK_DESC

   ARCHITECTURE RULES (non-negotiable):
   - Read existing code first and match its patterns exactly
   - NO magic values: every literal that controls behavior must be a named constant
   - NO monolith files: if a file would exceed 300 lines, decompose into components + lib/
   - Data-driven: entities with multiple instances (classes, items, levels) must be typed arrays, not copy-pasted JSX
   - Components accept props for anything that varies — hardcode nothing about parent context
   - Type everything with interfaces — no 'any'
   - Extract: game/business logic into lib/, UI into components/, config into constants
   - File structure for new features:
       page.tsx         — entry point, minimal, composes components
       components/      — UI components with typed props
       lib/             — logic, data, types, constants

   GENERAL RULES:
   - Follow existing code patterns and conventions
   - Write clean, production-ready code
   - Add tests if the project has a test suite
   - Do not modify unrelated files" \
     --allowedTools "Edit,Write,Bash(git diff:*),Bash(git status:*),Read" \
     --output-format json
   ```

7. **Stage and commit**:
   ```
   git add -A
   git commit -m "feat: <task-description-slug>"
   ```

8. **Report back**:
   ```
   Branch Ready: <branch-name>
   ━━━━━━━━━━━━━━━━━━━━━━━━━━
   Repo:    <repo-name>
   Branch:  <branch-name>
   Files:   <count> changed (+<added>, -<removed>)

   Changes:
   - <file1>: <brief description>
   - <file2>: <brief description>

   Next: scan | push | create-pr
   ```

## Important Notes
- Always work in an isolated workspace directory, never modify the original repo directly
- If Claude Code fails or times out, report the error and preserve the workspace for debugging
- The working directory path should be stored in memory for subsequent skills to use
- Limit Claude Code output to avoid token explosion on large repos
