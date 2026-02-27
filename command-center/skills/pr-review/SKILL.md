# PR Review

## Description
Review a GitHub Pull Request for security, architecture, and code quality issues using the Slopless CLI.

## When to Use
- User asks to "review" a PR
- User provides a PR URL (e.g., https://github.com/org/repo/pull/123)
- Part of the adopt-workstream flow when onboarding existing PRs

## Instructions

1. **Extract the PR URL** from the user's message. Accept formats:
   - `https://github.com/org/repo/pull/123`
   - `org/repo#123`
   - Just a number if the repo context is already known

2. **Run the review**:
   ```
   slopless review-pr <pr-url> \
     --github-token "$GH_TOKEN" \
     --output /tmp/slopless-review-$PR_NUM.json \
     --format json
   ```

3. **Parse and format the review**:
   ```
   PR Review: <repo>#<number>
   ━━━━━━━━━━━━━━━━━━━━━━━━━━
   Title:   <pr-title>
   Author:  <pr-author>
   Verdict: <APPROVE | REQUEST_CHANGES | COMMENT>

   Security:     <pass/fail> (<count> findings)
   Architecture: <pass/fail> (<count> findings)
   Quality:      <pass/fail> (<count> findings)

   Key Issues:
   1. [SEVERITY] <description>
   2. [SEVERITY] <description>
   ...

   Recommendation: <summary>
   ```

4. **Return the formatted review** to the user.

## Important Notes
- Requires GH_TOKEN to be set for private repos
- If the slopless CLI is not authenticated, report clearly and suggest running `slopless login`
- For large PRs (>500 lines changed), note this in the summary as it may affect review quality
