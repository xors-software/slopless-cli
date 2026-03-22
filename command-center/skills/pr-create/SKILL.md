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

3. **Preview (for UI/frontend changes)**:
   If the repo has a `package.json` with a dev server (Next.js, Vite, etc.), run the
   preview-build skill to start a dev server + Cloudflare tunnel before creating the PR.

   ```bash
   npm install --prefer-offline 2>/dev/null || npm install
   npx next dev -p 3000 &
   DEV_PID=$!
   sleep 10

   cloudflared tunnel --url http://localhost:3000 --no-autoupdate > /tmp/cloudflared.log 2>&1 &
   TUNNEL_PID=$!
   sleep 5

   PREVIEW_URL=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' /tmp/cloudflared.log | head -1)
   ```

   Send the preview URL to the user and wait for feedback before creating the PR.
   If the user says "looks good" or approves, proceed. If they request changes, iterate.
   Kill the dev server and tunnel after getting approval:
   ```bash
   kill $DEV_PID $TUNNEL_PID 2>/dev/null
   ```

   For backend-only repos (no package.json or no dev server), skip this step.

4. **Generate PR body** from the commit history, scan results, and preview:
   ```
   COMMITS=$(git log main..HEAD --oneline)
   FILES=$(git diff main..HEAD --stat)
   ```

5. **Create the PR**:
   ```
   gh pr create \
     --title "<concise title from task description>" \
     --body "## Summary
   <1-3 sentence description of what this PR does and why>

   ## Changes
   $FILES

   ## Commits
   $COMMITS

   ## Preview
   <PREVIEW_URL if available, otherwise 'N/A — backend-only changes'>
   Reviewed and approved by requester via Telegram.

   ## Slopless Scan
   <scan status: CLEAN / N findings remaining>

   ## Test Plan
   - [ ] <relevant test items>

   ---
   *Created by Slopless Command Center*" \
     --repo <owner/repo>
   ```

6. **Notify the user**:
   ```
   PR Created
   ━━━━━━━━━━━━━━━━━━━━━━━
   Repo:     <owner/repo>
   PR:       #<number> — <title>
   Branch:   <branch> → main
   Files:    <count> changed (+<added>, -<removed>)
   Preview:  <preview-url | skipped>
   Scan:     <CLEAN | N findings>
   URL:      <pr-url>

   Awaiting review.
   ```

## Important Notes
- Never force-push
- If push fails due to auth, report clearly and suggest `gh auth login`
- If the repo has PR templates, try to detect and use them
- Store the PR URL in memory for tracking and future reference
