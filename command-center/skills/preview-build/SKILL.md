# Preview Build

## Description
Start a dev server for a project, expose it via a Cloudflare quick tunnel, and send the preview URL to the user. This gives the user a live, clickable link to verify what was built before the PR is created.

## When to Use
- After implementing a feature or building UI, before creating the PR
- User asks "show me what you built", "preview", "let me see it"
- User asks to "verify" or "demo" the changes
- Any time visual verification would help confirm correctness

## Instructions

### Step 1: Detect the Project Type

```bash
cd "$PROJECT_DIR"

if [ -f "package.json" ]; then
  FRAMEWORK=$(python3 -c "import json; p=json.load(open('package.json')); deps={**p.get('dependencies',{}),**p.get('devDependencies',{})}; print('next' if 'next' in deps else 'vite' if 'vite' in deps else 'react-scripts' if 'react-scripts' in deps else 'unknown')")
  echo "Detected: $FRAMEWORK"
fi
```

### Step 2: Install Dependencies and Start Dev Server

```bash
cd "$PROJECT_DIR"
npm install --prefer-offline 2>/dev/null || npm install

# Start dev server in background based on framework
case "$FRAMEWORK" in
  next)     PORT=3000 npx next dev -p 3000 &;;
  vite)     npx vite --port 3000 --host &;;
  react-scripts) PORT=3000 npx react-scripts start &;;
  *)        npm run dev -- --port 3000 &;;
esac

DEV_PID=$!

# Wait for server to be ready
for i in $(seq 1 30); do
  if curl -s http://localhost:3000 > /dev/null 2>&1; then
    echo "Dev server ready on port 3000"
    break
  fi
  sleep 2
done
```

### Step 3: Start Cloudflare Quick Tunnel

```bash
# Start cloudflared in background — free, no account needed
cloudflared tunnel --url http://localhost:3000 --no-autoupdate > /tmp/cloudflared.log 2>&1 &
TUNNEL_PID=$!

# Extract the public URL (appears in stderr/stdout as https://xxx.trycloudflare.com)
PREVIEW_URL=""
for i in $(seq 1 15); do
  PREVIEW_URL=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' /tmp/cloudflared.log 2>/dev/null | head -1)
  if [ -n "$PREVIEW_URL" ]; then
    break
  fi
  sleep 2
done

if [ -z "$PREVIEW_URL" ]; then
  echo "Failed to create tunnel. Check /tmp/cloudflared.log"
  kill $DEV_PID $TUNNEL_PID 2>/dev/null
  exit 1
fi

echo "Preview URL: $PREVIEW_URL"
```

### Step 4: Report to User

Send the preview URL to the user:

```
🔗 Preview Ready
━━━━━━━━━━━━━━━━━━━

URL: $PREVIEW_URL

This is a live preview of your changes.
The link will stay active for ~15 minutes.

When you're done reviewing, reply:
  "looks good" — I'll create the PR
  "fix X"      — I'll iterate and re-preview
  "stop"       — I'll tear down the preview
```

Store the preview state in memory:
- Key `preview:active`: `{"url": "$PREVIEW_URL", "dev_pid": $DEV_PID, "tunnel_pid": $TUNNEL_PID, "project": "$PROJECT_DIR"}`

### Step 5: Handle User Feedback

- **"looks good" / "approve"** — Stop the preview, proceed to create the PR
- **"fix X" / feedback** — Stop the preview, make changes, then re-run the preview
- **"stop"** — Stop the preview without creating a PR

### Step 6: Cleanup

Always clean up when done:

```bash
kill $DEV_PID 2>/dev/null
kill $TUNNEL_PID 2>/dev/null
rm -f /tmp/cloudflared.log
```

## Important Notes
- Cloudflare quick tunnels are free and require no account or token
- Each tunnel gets a random `.trycloudflare.com` subdomain
- Tunnels auto-expire after ~15 minutes of inactivity
- Only one preview should be active at a time — kill previous before starting new
- If port 3000 is in use, try 3001, 3002, etc.
- The preview server runs in the Railway container so it uses the container's resources
- For large Next.js projects, `next dev` may take 30-60s to start — be patient
- Always kill the dev server and tunnel when done to free resources
