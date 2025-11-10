FROM python:3.12-slim-bookworm

# Pin version and digest for Bitwarden CLI
ARG BW_VERSION="2025.10.0"
ARG BW_SHA256="0544c64d3e9932bb5f2a70e819695ea78186a44ac87a0b1d753e9c55217041d9"

# Install minimal required packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    bash \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -g 231001 backvault \
 && useradd -m -u 231001 -g 231001 -s /bin/bash backvault

# Install Bitwarden CLI (verified)
RUN set -eux; \
    curl -Lo bw.zip "https://github.com/bitwarden/clients/releases/download/cli-v${BW_VERSION}/bw-linux-${BW_VERSION}.zip"; \
    echo "${BW_SHA256}  bw.zip" | sha256sum -c -; \
    unzip bw.zip -d /usr/local/bin; \
    chmod +x /usr/local/bin/bw; \
    rm bw.zip

# Install supercronic (cron replacement)
RUN curl -fsSL https://github.com/aptible/supercronic/releases/latest/download/supercronic-linux-amd64 \
    -o /usr/local/bin/supercronic && chmod +x /usr/local/bin/supercronic

RUN apt-get remove curl unzip -y

# Prepare working directories
RUN mkdir -p /app/backups /app/logs && \
    chmod 700 /app/backups && \
    chown -R 231001:231001 /app

# Copy project files
WORKDIR /app
COPY --chown=231001 ./src .
COPY --chown=231001 ./entrypoint.sh /app/entrypoint.sh
COPY --chown=231001 ./cleanup.sh /app/cleanup.sh

RUN chmod +x /app/entrypoint.sh /app/cleanup.sh

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install --no-input --no-cache-dir cryptography

USER 231001

ENTRYPOINT ["/app/entrypoint.sh"]
