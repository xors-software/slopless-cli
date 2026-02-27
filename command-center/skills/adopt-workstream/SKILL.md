# Adopt Workstream

## Description
Import existing PRs, branches, or repos into the command center's tracking. Enables the bot to pick up where you left off on any ongoing work, lowering switching cost.

## When to Use
- User says "adopt PR #42" or "track this PR"
- User asks "what PRs do I have open?"
- User wants the bot to start iterating on an existing PR
- User asks to "onboard" or "pick up" existing work

## Instructions

### List Open PRs
When user asks to see their open work:
```
gh pr list --author @me --state open --json number,title,url,headRefName,repository,updatedAt,additions,deletions --limit 20
```

Format output:
```
Your Open PRs
━━━━━━━━━━━━━━━━━━━━━━━
1. <repo>#<number> — <title>
   Branch: <branch>  |  +<added> -<removed>  |  Updated: <relative-time>

2. <repo>#<number> — <title>
   Branch: <branch>  |  +<added> -<removed>  |  Updated: <relative-time>
...

Reply "adopt <number>" to start tracking any PR.
```

### Adopt a Specific PR
When user provides a PR URL or number:

1. **Fetch PR details**:
   ```
   gh pr view <pr-url-or-number> --json title,body,headRefName,baseRefName,files,commits,reviews,comments,statusCheckRollup,url,repository
   ```

2. **Clone and checkout**:
   ```
   TASK_ID="adopted-$(date +%s)"
   WORK_DIR="$HOME/work/xors/slopless-project/slopless-cli/command-center/workspace/$TASK_ID"
   git clone <repo-url> "$WORK_DIR/repo"
   cd "$WORK_DIR/repo"
   git checkout <head-branch>
   ```

3. **Run initial scan**:
   Use the slopless-scan skill to assess current state.

4. **Gather context** from PR comments and reviews:
   ```
   gh pr view <number> --comments --json comments
   ```

5. **Store in memory**:
   - PR URL, number, title, branch, repo
   - Current scan status
   - Review comments and requested changes
   - Workspace directory path

6. **Report**:
   ```
   PR Adopted
   ━━━━━━━━━━━━━━━━━━━━━━
   PR:       <repo>#<number> — <title>
   Branch:   <branch> → <base>
   Files:    <count> changed
   Reviews:  <count> (<approved/changes-requested/pending>)
   Scan:     <running...>

   Review Comments:
   - <reviewer>: "<comment-summary>"
   ...

   What would you like me to do?
   - "fix review comments" — address reviewer feedback
   - "scan" — run security scan
   - "iterate" — scan and fix in a loop
   - "update" — pull latest and re-assess
   ```

### Adopt a Branch (no PR yet)
When user provides a repo + branch:
1. Clone and checkout the branch
2. Run scan
3. Store in memory
4. Ask if user wants to create a PR

## Important Notes
- Adopted PRs are tracked in ZeroClaw memory for persistence across sessions
- The bot can be asked "status" to see all tracked workstreams
- When adopting, never force-push or modify the branch without user confirmation
- Respect existing review comments — summarize them for context
