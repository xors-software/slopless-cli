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
   WORK_DIR="$HOME/work/xors/slopless-project/slopless-cli/command-center/workspace/$TASK_ID"
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

5. **Invoke Claude Code** to implement changes:
   ```
   claude -p "You are working in this repository. Implement the following: $TASK_DESC

   Rules:
   - Follow existing code patterns and conventions
   - Write clean, production-ready code
   - Add tests if the project has a test suite
   - Do not modify unrelated files" \
     --allowedTools "Edit,Write,Bash(git diff:*),Bash(git status:*),Read" \
     --output-format json
   ```

6. **Stage and commit**:
   ```
   git add -A
   git commit -m "feat: <task-description-slug>"
   ```

7. **Report back**:
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
