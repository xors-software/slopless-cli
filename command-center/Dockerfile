FROM debian:trixie-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates git gpg gnupg2 python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install ZeroClaw from pre-built release
RUN curl -fsSLO https://github.com/zeroclaw-labs/zeroclaw/releases/latest/download/zeroclaw-x86_64-unknown-linux-gnu.tar.gz \
    && tar xzf zeroclaw-x86_64-unknown-linux-gnu.tar.gz \
    && install -m 0755 zeroclaw /usr/local/bin/zeroclaw \
    && rm -f zeroclaw-x86_64-unknown-linux-gnu.tar.gz zeroclaw

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
