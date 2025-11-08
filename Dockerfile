FROM python:3.12-slim-bookworm

# Install required system packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    unzip \
    bash \
    cron \
    && rm -rf /var/lib/apt/lists/*

# Install Bitwarden CLI
RUN set -eux; \
    curl -Lo bw.zip "https://bitwarden.com/download/?app=cli&platform=linux"; \
    unzip bw.zip -d /usr/local/bin; \
    chmod +x /usr/local/bin/bw; \
    rm bw.zip

RUN apt-get remove -y \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user and group
RUN groupadd -r backvault && \
    useradd -r -g backvault -u 1000 backvault && \
    mkdir -p /app/backups /var/log && \
    chown -R backvault:backvault /app /var/log

WORKDIR /app

# Copy application files
COPY --chown=backvault:backvault ./src /app/
COPY --chown=backvault:backvault ./entrypoint.sh /app/entrypoint.sh
COPY --chown=backvault:backvault ./cleanup.sh /app/cleanup.sh
COPY --chown=backvault:backvault requirements.txt /app/requirements.txt

# Set execute permissions on scripts
RUN chmod +x /app/entrypoint.sh /app/cleanup.sh

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install --no-input --no-cache-dir -r requirements.txt

# Switch to non-root user
USER backvault

ENTRYPOINT ["/app/entrypoint.sh"]
