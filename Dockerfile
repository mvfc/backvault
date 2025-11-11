FROM python:3.12-slim-bookworm

# Pin version and digest for Bitwarden CLI
ARG BW_VERSION="2025.10.0"
ARG BW_SHA256="0544c64d3e9932bb5f2a70e819695ea78186a44ac87a0b1d753e9c55217041d9"
ARG SUPERCRONIC_URL=https://github.com/aptible/supercronic/releases/download/v0.2.39/supercronic-linux-amd64
ARG SUPERCRONIC_SHA1SUM=c98bbf82c5f648aaac8708c182cc83046fe48423
ARG SUPERCRONIC=supercronic-linux-amd64

# Install minimal required packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    bash \
    unzip \
    sqlcipher \
    age \
    libssl-dev \
    libsqlite3-dev \
    libsqlcipher-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -g 1000 backvault \
 && useradd -m -u 1000 -g 1000 -s /bin/bash backvault

# Install Bitwarden CLI (verified)
RUN set -eux; \
    curl -Lo bw.zip "https://github.com/bitwarden/clients/releases/download/cli-v${BW_VERSION}/bw-linux-${BW_VERSION}.zip"; \
    echo "${BW_SHA256}  bw.zip" | sha256sum -c -; \
    unzip bw.zip -d /usr/local/bin; \
    chmod +x /usr/local/bin/bw; \
    rm bw.zip

RUN curl -fsSLO "$SUPERCRONIC_URL" \
 && echo "${SUPERCRONIC_SHA1SUM}  ${SUPERCRONIC}" | sha1sum -c - \
 && chmod +x "$SUPERCRONIC" \
 && mv "$SUPERCRONIC" "/usr/local/bin/${SUPERCRONIC}" \
 && ln -s "/usr/local/bin/${SUPERCRONIC}" /usr/local/bin/supercronic

RUN apt-get remove curl unzip -y

# Prepare working directories
RUN mkdir -p /app/logs /app/backups /app/db && \
    chmod -R 700 /app && \
    chown -R 1000:1000 /app

# Copy project files
WORKDIR /app

COPY --chown=1000:1000 ./requirements.txt /app/requirements.txt
COPY --chown=1000:1000 ./src /app
COPY --chown=1000:1000 ./entrypoint.sh /app/entrypoint.sh
COPY --chown=1000:1000 ./cleanup.sh /app/cleanup.sh

RUN chmod +x /app/entrypoint.sh /app/cleanup.sh

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install --no-input --no-cache-dir -r requirements.txt

USER 1000:1000

ENTRYPOINT ["/app/entrypoint.sh"]
