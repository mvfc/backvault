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

# Create backup directory
RUN mkdir -p /app/backups && \
    mkdir -p /var/log/cron

# Copy application files
COPY ./src /app

# Set permissions for cron log
RUN touch /var/log/cron.log && \
    chmod 644 /var/log/cron.log

WORKDIR /app

COPY ./entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

# Start cron in the foreground
ENTRYPOINT ["/app/entrypoint.sh"]
