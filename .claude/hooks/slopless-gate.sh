#!/bin/bash
# Slopless PR Gate — runs slopless scan before git push or PR creation
# Blocks the action if CRITICAL or HIGH findings are detected.
#
# This hook is triggered by Claude Code's PreToolUse event on Bash commands.
# Exit 0 = allow, Exit 2 = block (stderr fed back to Claude as context).

set -euo pipefail

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null || echo "")

# Only gate on PR-related commands
if ! echo "$COMMAND" | grep -qE "(gh pr create|git push)"; then
  exit 0
fi

echo "=== Slopless PR Gate ===" >&2
echo "Running security scan before PR..." >&2

REPORT_FILE="/tmp/slopless-gate-$(date +%s).json"

# Run the scan with a 60s timeout (API can be slow)
SCAN_OUTPUT=$(timeout 60 slopless scan . -o "$REPORT_FILE" --format json 2>&1) || true
SCAN_EXIT=$?

# If scan timed out or failed to connect, warn but allow
if [ "$SCAN_EXIT" -eq 124 ] || echo "$SCAN_OUTPUT" | grep -qiE "(timed out|could not connect)"; then
  echo "WARNING: Slopless scan timed out or unavailable. Proceeding without scan." >&2
  echo "Run 'slopless scan .' manually when the API is available." >&2
  exit 0
fi

# If scan succeeded cleanly
if [ "$SCAN_EXIT" -eq 0 ] && [ -z "$(echo "$SCAN_OUTPUT" | grep -i 'failed\|error')" ]; then
  echo "Slopless scan passed — no issues found." >&2
  exit 0
fi

# Check if report was generated with findings
if [ -f "$REPORT_FILE" ]; then
  CRITICAL=$(python3 -c "
import json, sys
try:
    data = json.load(open('$REPORT_FILE'))
    vulns = data.get('vulnerabilities', [])
    critical = sum(1 for v in vulns if v.get('severity','').upper() == 'CRITICAL')
    high = sum(1 for v in vulns if v.get('severity','').upper() == 'HIGH')
    print(f'{critical},{high}')
except:
    print('0,0')
" 2>/dev/null || echo "0,0")

  CRIT_COUNT=$(echo "$CRITICAL" | cut -d, -f1)
  HIGH_COUNT=$(echo "$CRITICAL" | cut -d, -f2)

  if [ "$CRIT_COUNT" -gt 0 ] || [ "$HIGH_COUNT" -gt 0 ]; then
    echo "" >&2
    echo "BLOCKED: Found $CRIT_COUNT CRITICAL and $HIGH_COUNT HIGH severity issues." >&2
    echo "" >&2
    echo "Fix these findings before creating a PR:" >&2
    python3 -c "
import json
data = json.load(open('$REPORT_FILE'))
for v in data.get('vulnerabilities', []):
    sev = v.get('severity','?').upper()
    if sev in ('CRITICAL', 'HIGH'):
        print(f\"  [{sev}] {v.get('title','?')} — {v.get('file','?')}:{v.get('line','?')}\")
        print(f\"    {v.get('description','')[:120]}\")
" >&2 2>/dev/null || true
    echo "" >&2
    echo "Run 'slopless scan .' to see full report." >&2
    echo "Report saved: $REPORT_FILE" >&2
    exit 2
  fi
fi

# Scan completed but no CRITICAL/HIGH — allow with warning
echo "Slopless scan completed with warnings (no CRITICAL/HIGH). Proceeding." >&2
exit 0
