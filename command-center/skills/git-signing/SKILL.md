# GPG Commit Signing

## Description
Configure and perform GPG-signed commits. Handles key discovery, configuration, and graceful fallback when passphrase input is needed.

## When to Use
- Before pushing commits as part of the PR workflow
- User explicitly asks to sign commits
- When commit-standards rules require signed commits

## Instructions

1. **Discover available GPG keys**:
   ```
   gpg --list-secret-keys --keyid-format long 2>/dev/null
   ```

2. **Select the signing key**:
   - If `GPG_KEY_ID` environment variable is set, use that
   - Otherwise, extract the first available key ID from the output
   - If no keys found, notify the user:
     "No GPG keys found. To set up signing:
      1. Generate a key: `gpg --full-generate-key`
      2. Add it to GitHub: `gh gpg-key add <key-file>`
      3. Set GPG_KEY_ID in your command-center .env"

3. **Configure git for signing** (in the repo directory):
   ```
   git config user.signingkey <KEY_ID>
   git config commit.gpgsign true
   git config tag.gpgsign true
   ```

4. **Attempt a signed commit**:
   ```
   git commit -S -m "<message>"
   ```

5. **If signing fails** (passphrase not cached):
   Notify the user via the active channel:
   ```
   GPG Signing Required
   ━━━━━━━━━━━━━━━━━━━
   I need your GPG passphrase to sign commits.

   Run this in any terminal to cache it:
     gpg --sign --armor /dev/null

   Then reply "retry" and I'll try again.

   Alternatively, to cache for the session:
     export GPG_TTY=$(tty)
     gpg-connect-agent updatestartuptty /bye
   ```

6. **On retry**: Attempt the signed commit again.

## Important Notes
- Never ask for or store GPG passphrases directly
- The gpg-agent typically caches passphrases for a configurable TTL
- If the user has `pinentry-mac` installed, the macOS keychain may handle this transparently
- Always verify the signature after committing: `git log --show-signature -1`
