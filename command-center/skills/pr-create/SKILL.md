# PR Create

## Description
Push a feature branch to GitHub and create a Pull Request with a structured body. Notify the user with the PR URL.

## When to Use
- After feature-branch skill has created and committed changes
- After scan-fix-loop has iterated to a clean (or acceptable) state
- User explicitly asks to "create a PR" or "push and open a PR"

## Instructions

1. **Verify prerequisites**:
   - Confirm we're on a feature branch (not main/master)
   - Confirm there are commits to push: `git log main..HEAD --oneline`
   - Confirm GH_TOKEN or `gh auth status` is available

2. **Push the branch**:
   ```
   git push -u origin HEAD
   ```

3. **Generate PR body** from the commit history and scan results:
   ```
   COMMITS=$(git log main..HEAD --oneline)
   FILES=$(git diff main..HEAD --stat)
   ```

4. **Create the PR**:
   ```
   gh pr create \
     --title "<concise title from task description>" \
     --body "## Summary
   <1-3 sentence description of what this PR does and why>

   ## Changes
   $FILES

   ## Commits
   $COMMITS

   ## Slopless Scan
   <scan status: CLEAN / N findings remaining>

   ## Test Plan
   - [ ] <relevant test items>

   ---
   *Created by Slopless Command Center*" \
     --repo <owner/repo>
   ```

5. **Notify the user**:
   ```
   PR Created
   ━━━━━━━━━━━━━━━━━━━━━━━
   Repo:     <owner/repo>
   PR:       #<number> — <title>
   Branch:   <branch> → main
   Files:    <count> changed (+<added>, -<removed>)
   Scan:     <CLEAN | N findings>
   URL:      <pr-url>

   Awaiting review.
   ```

## Important Notes
- Never force-push
- If push fails due to auth, report clearly and suggest `gh auth login`
- If the repo has PR templates, try to detect and use them
- Store the PR URL in memory for tracking and future reference
