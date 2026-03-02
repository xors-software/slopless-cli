# Full PR Workflow

## Description
End-to-end workflow: clone a repo, implement changes, scan for security issues, iterate fixes, sign commits, create a PR, and notify the user. This is the primary "do everything" skill.

## When to Use
- User asks to "implement X on repo Y and raise a PR"
- User asks to "work on" or "build" something and wants a complete PR
- Any request that implies the full lifecycle: code -> scan -> fix -> PR
- Invoked by the feature-request skill after spec approval

## Instructions

### Step 1: Parse the Request
Extract from the user's message or from the feature-request pipeline context:
- **repo**: GitHub URL or known repo name (resolve from memory if needed)
- **task**: what to implement/fix/change
- **spec** (optional): path to a generated spec file (e.g., `/tmp/spec-*.md` from feature-request skill)
- **branch** (optional): custom branch name
- **source_ticket** (optional): Notion page ID, ClickUp task ID, or GitHub issue number to update after PR

If a spec file exists, pass it as context to Claude Code in Step 2.

### Step 2: Feature Branch (invoke feature-branch skill)
- Clone the repo to an isolated workspace
- Create a feature branch
- Spawn Claude Code to implement the changes
- Commit the implementation

Report progress:
```
[1/5] Implementation
━━━━━━━━━━━━━━━━━━━
Branch: <branch-name>
Files changed: <count>
Status: Complete — scanning...
```

### Step 3: Security Scan (invoke slopless-scan skill)
- Run slopless scan on the working directory
- Parse results

Report progress:
```
[2/5] Security Scan
━━━━━━━━━━━━━━━━━━━
CRITICAL: <n>  HIGH: <n>
MEDIUM:   <n>  LOW:  <n>
Status: <Clean | Findings detected — fixing...>
```

### Step 4: Iterate Fixes (invoke scan-fix-loop skill, if needed)
- Only if findings with severity >= MEDIUM exist
- Run fix-scan loop (max 3 rounds)

Report progress:
```
[3/5] Fix Iteration
━━━━━━━━━━━━━━━━━━━
Round <n>/<max>: <fixed-count> fixed, <remaining-count> remaining
Status: <Clean | Proceeding with N remaining>
```

### Step 5: Sign Commits (invoke git-signing skill)
- Configure GPG signing
- Sign all commits on the branch
- If passphrase needed, prompt user and wait for "retry"

Report progress:
```
[4/5] Signing
━━━━━━━━━━━━
Commits signed: <count>
Key: <key-id-last-8-chars>
Status: Verified
```

### Step 6: Create PR (invoke pr-create skill)
- Push branch to origin
- Create PR via gh with structured body
- Include scan results in PR body

### Step 7: Final Notification
```
PR Workflow Complete
━━━━━━━━━━━━━━━━━━━━━━━

Repo:      <owner/repo>
PR:        #<number> — <title>
Branch:    <branch> → main
Files:     <count> changed (+<added>, -<removed>)
Scan:      <CLEAN | N findings>
Signed:    <Yes | No (reason)>
URL:       <pr-url>

Open Questions:
- <any design decisions that need human input>
- <any ambiguities from the original request>

Reply "adopt <pr-url>" to track this PR for ongoing iteration.
```

### Step 8: Store in Memory
Save to ZeroClaw memory:
- Task ID, repo, branch, PR URL, scan status, timestamp
- Open questions for future reference

### Step 9: Update Source Ticket (if applicable)
If the workflow was triggered from a feature request with a source ticket:

- **GitHub Issue**: Comment with PR link
  ```bash
  gh issue comment "$ISSUE_NUM" --repo "$REPO" --body "PR created: $PR_URL"
  ```
- **Notion Page**: Update status and add PR URL (use notion-integration skill)
- **ClickUp Task**: Update status to "in progress" (use feature-request skill logic)

## Important Notes
- If any step fails, report clearly which step failed and why
- Preserve the workspace directory until the PR is merged or closed
- The user can resume from any step by referencing the task
- All progress updates go to the active channel (Telegram/CLI)
- When invoked from feature-request, the spec file should be passed as implementation context
