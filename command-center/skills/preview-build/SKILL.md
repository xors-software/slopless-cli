# Preview Build

## Description
Start a dev server for a project, expose it via a Cloudflare quick tunnel, and send the preview URL to the user. This gives the user a live, clickable link to verify what was built before the PR is created.

## When to Use
- After implementing a feature or building UI, before creating the PR
- User asks "show me what you built", "preview", "let me see it"
- User asks to "verify" or "demo" the changes
- Any time visual verification would help confirm correctness

## Critical: Shell Operator Workaround

The shell tool blocks `&`, `>`, `|`, `$()` operators. You MUST write commands
to a script file first, then execute the file. Never try to run background
processes or redirections inline — it will always fail.

## Instructions

### Step 1: Write the preview start script

Use the **file_write** tool to create `/tmp/preview.sh`:

```bash
#!/bin/bash
set -e

PROJECT_DIR="$1"
PORT="${2:-3000}"

cd "$PROJECT_DIR"

# Detect framework
if grep -q '"next"' package.json 2>/dev/null; then
  FRAMEWORK="next"
elif grep -q '"vite"' package.json 2>/dev/null; then
  FRAMEWORK="vite"
else
  FRAMEWORK="generic"
fi

# Install deps
npm install --prefer-offline 2>/dev/null || npm install

# Start dev server
case "$FRAMEWORK" in
  next)    npx next dev -p "$PORT" > /tmp/devserver.log 2>&1 &;;
  vite)    npx vite --port "$PORT" --host > /tmp/devserver.log 2>&1 &;;
  *)       npm run dev > /tmp/devserver.log 2>&1 &;;
esac
DEV_PID=$!
echo "$DEV_PID" > /tmp/preview-dev.pid

# Wait for server
echo "Waiting for dev server on port $PORT..."
for i in $(seq 1 30); do
  if curl -s "http://localhost:$PORT" > /dev/null 2>&1; then
    echo "Dev server ready"
    break
  fi
  sleep 2
done

# Start tunnel
cloudflared tunnel --url "http://localhost:$PORT" --no-autoupdate > /tmp/cloudflared.log 2>&1 &
TUNNEL_PID=$!
echo "$TUNNEL_PID" > /tmp/preview-tunnel.pid

# Wait for tunnel URL
echo "Waiting for tunnel URL..."
for i in $(seq 1 15); do
  PREVIEW_URL=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' /tmp/cloudflared.log 2>/dev/null | head -1)
  if [ -n "$PREVIEW_URL" ]; then
    echo "PREVIEW_URL=$PREVIEW_URL"
    break
  fi
  sleep 2
done

if [ -z "$PREVIEW_URL" ]; then
  echo "ERROR: Failed to get tunnel URL"
  cat /tmp/cloudflared.log
  exit 1
fi

echo "PREVIEW_READY=true"
echo "DEV_PID=$DEV_PID"
echo "TUNNEL_PID=$TUNNEL_PID"
```

### Step 2: Run the preview

Execute with the shell tool:

```
bash /tmp/preview.sh /root/.zeroclaw/workspace/repos/REPO_NAME
```

The script will output `PREVIEW_URL=https://xxx.trycloudflare.com`.

### Step 3: Send the URL to the user

```
🔗 Preview Ready
━━━━━━━━━━━━━━━━━━━

URL: $PREVIEW_URL

This is a live preview of your changes.
The link will stay active while the server is running.

When you're done reviewing, reply:
  "looks good" — I'll create the PR
  "fix X"      — I'll iterate and re-preview
  "stop"       — I'll tear down the preview
```

### Step 4: Cleanup (after user feedback)

Write `/tmp/preview-stop.sh`:

```bash
#!/bin/bash
kill $(cat /tmp/preview-dev.pid 2>/dev/null) 2>/dev/null
kill $(cat /tmp/preview-tunnel.pid 2>/dev/null) 2>/dev/null
pkill -f "next dev" 2>/dev/null
pkill -f cloudflared 2>/dev/null
rm -f /tmp/preview-dev.pid /tmp/preview-tunnel.pid /tmp/cloudflared.log /tmp/devserver.log
echo "Preview stopped"
```

Then run: `bash /tmp/preview-stop.sh`

## Important Notes
- ALWAYS use the script-file pattern. NEVER run `&` or `>` directly in the shell tool.
- Cloudflare quick tunnels are free and require no account or token
- Only one preview should be active at a time — run cleanup before starting a new one
- If port 3000 is in use, pass a different port: `bash /tmp/preview.sh /path/to/repo 3001`
- For large Next.js projects, the dev server may take 30-60s to start
- Always kill the dev server and tunnel when done to free resources
