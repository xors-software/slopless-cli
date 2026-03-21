FROM debian:trixie-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates git gpg gnupg2 python3 python3-pip sqlite3 jq \
    && rm -rf /var/lib/apt/lists/*

# Install ZeroClaw — resolve latest release with binary assets via GitHub API,
# falling back to the install script if the API query fails.
RUN ASSET_URL=$(curl -sL "https://api.github.com/repos/zeroclaw-labs/zeroclaw/releases" \
      | python3 -c "import json,sys; releases=json.load(sys.stdin); \
        urls=[a['browser_download_url'] for r in releases for a in r.get('assets',[]) \
              if a['name']=='zeroclaw-x86_64-unknown-linux-gnu.tar.gz']; \
        print(urls[0] if urls else '')") \
    && if [ -n "$ASSET_URL" ]; then \
         curl -fsSL -o zeroclaw.tar.gz "$ASSET_URL" \
         && tar xzf zeroclaw.tar.gz \
         && install -m 0755 zeroclaw /usr/local/bin/zeroclaw \
         && rm -f zeroclaw.tar.gz zeroclaw; \
       else \
         curl -fsSL https://raw.githubusercontent.com/zeroclaw-labs/zeroclaw/main/install.sh | bash; \
       fi

# Install GitHub CLI
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
      -o /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
      > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update && apt-get install -y --no-install-recommends gh \
    && rm -rf /var/lib/apt/lists/*

# Install slopless CLI from GitHub (set GH_TOKEN as Railway build variable if repo is private)
ARG GH_TOKEN=""
RUN pip3 install --break-system-packages \
    "slopless @ git+https://${GH_TOKEN:+${GH_TOKEN}@}github.com/xors-software/slopless-cli.git"

WORKDIR /app

# Copy skills and rules
COPY skills/ /root/.zeroclaw/workspace/skills/
COPY rules/ /app/rules/

# Copy entrypoint
COPY deploy/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 42617

ENTRYPOINT ["/entrypoint.sh"]
