# Slopless Security Scan

## Description
Scan a repository or directory for security vulnerabilities using the Slopless CLI.

## When to Use
- User asks to "scan" a repo, directory, or codebase
- User provides a GitHub URL or local path and wants a security assessment
- Part of the PR workflow after code changes

## Instructions

1. **Parse the target**: Extract the repo URL or local path from the user's message.

2. **If GitHub URL**: Clone to a temporary workspace directory:
   ```
   TASK_ID=$(date +%s)
   WORK_DIR="/tmp/workspace/$TASK_ID"
   mkdir -p "$WORK_DIR"
   git clone <url> "$WORK_DIR/repo"
   cd "$WORK_DIR/repo"
   ```

3. **If local path**: Navigate directly to it.

4. **Run the scan**:
   ```
   slopless scan <path> --output /tmp/slopless-scan-$TASK_ID.json --format json
   ```
   If the CLI reports an authentication error, inform the user that `SLOPLESS_LICENSE_KEY` must be
   set as an environment variable and ask them to configure it.

5. **Parse and format results**: Read the JSON output and create a structured summary:
   ```
   Scan Complete: <repo-name>
   ━━━━━━━━━━━━━━━━━━━━━━━━
   CRITICAL: <count>  HIGH: <count>
   MEDIUM:   <count>  LOW:  <count>

   Top Findings:
   1. [SEVERITY] <title> — <file>:<line>
   2. [SEVERITY] <title> — <file>:<line>
   ...

   Full report: /tmp/slopless-scan-<id>.json
   ```

6. **Return the structured summary** to the user via the active channel.

## Important Notes
- Always include severity counts even if zero
- Limit displayed findings to top 10 by severity
- If scan fails, report the error clearly with the command that was run
- Clean up cloned repos from workspace/ after reporting (unless user wants to keep them)
