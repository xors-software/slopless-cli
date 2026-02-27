# Scan-Fix-Iterate Loop

## Description
After code changes, run a slopless scan, fix any findings using Claude Code, and re-scan. Repeat up to 3 rounds until clean or user decides to proceed.

## When to Use
- After feature-branch skill has committed changes
- As part of the full PR workflow before creating a PR
- User asks to "fix scan findings" or "iterate until clean"

## Instructions

1. **Initialize loop state**:
   ```
   MAX_ROUNDS=3
   CURRENT_ROUND=1
   ```

2. **For each round**:

   a. **Run slopless scan** (use slopless-scan skill logic):
      ```
      slopless scan <working-dir> --output /tmp/slopless-iter-$ROUND.json --format json
      ```

   b. **Check results**:
      - If no findings with severity >= MEDIUM: **break** (clean)
      - If findings exist: continue to fix

   c. **Feed findings to Claude Code**:
      ```
      claude -p "Fix these security findings in the codebase:

      $(cat /tmp/slopless-iter-$ROUND.json | python3 -c '
      import json, sys
      data = json.load(sys.stdin)
      for v in data.get("vulnerabilities", [])[:10]:
          print(f"- [{v.get(\"severity\",\"?\")}] {v.get(\"title\",\"?\")} in {v.get(\"file\",\"?\")}:{v.get(\"line\",\"?\")}")
          print(f"  Description: {v.get(\"description\",\"?\")}")
      ')

      Rules:
      - Fix each finding without introducing new issues
      - Preserve existing functionality
      - Do not change unrelated code" \
        --allowedTools "Edit,Write,Read,Bash(git diff:*)" \
        --output-format json
      ```

   d. **Commit fixes**:
      ```
      git add -A
      git commit -m "fix: address slopless findings (round $CURRENT_ROUND)"
      ```

   e. **Report round progress**:
      ```
      Iteration Round $CURRENT_ROUND/$MAX_ROUNDS
      ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      Found:  <count> issues
      Fixed:  <attempted-count>
      Status: Scanning again...
      ```

3. **After all rounds**, report final state:
   ```
   Scan-Fix Complete
   ━━━━━━━━━━━━━━━━━━
   Rounds:     <rounds-used> / <max>
   Status:     <CLEAN | N remaining findings>
   Remaining:  <list if any>

   <if clean>  Ready for PR.
   <if not>    Should I proceed with PR anyway, or keep trying?
   ```

## Important Notes
- Never exceed MAX_ROUNDS to avoid infinite loops
- If a fix introduces new findings, count them in the next round
- Preserve the scan JSON files for audit trail
- If Claude Code fails to fix a finding after 2 attempts, mark it as "needs manual review"
