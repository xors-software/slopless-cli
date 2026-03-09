---
name: scan
description: Run a Slopless security scan on the current branch's changed files. Use when the user wants to scan for vulnerabilities before pushing or creating a PR.
---

# Slopless Diff Scan

Run a security scan on the current branch's changed files compared to the base branch.

## Steps

1. Run the following command in the repo root:

```bash
slopless diff-scan --base $ARGUMENTS --format text
```

If no arguments were provided, default to `main`:

```bash
slopless diff-scan --base main --format text
```

2. Present the full output to the user — it contains severity summary, findings grouped by file, and actionable recommendations.

3. If findings exist (exit code 1), ask the user if they want you to fix them. If yes:
   - Fix each finding following the recommendations in the report
   - Re-run `slopless diff-scan --base main --format text` to verify fixes
   - Repeat up to 3 rounds maximum

4. If the scan is clean (exit code 0), tell the user they're good to push/PR.
