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

# Create backup directory
RUN mkdir -p /app/backups && \
    mkdir -p /var/log/cron

COPY ./src /app

RUN touch /var/log/cron.log && \
    chmod 644 /var/log/cron.log

WORKDIR /app

COPY ./entrypoint.sh /app/entrypoint.sh

COPY ./cleanup.sh /app/cleanup.sh

RUN chmod +x /app/entrypoint.sh

RUN chmod +x /app/cleanup.sh

RUN pip install --no-input --no-cache-dir cryptography

ENTRYPOINT ["/app/entrypoint.sh"]
