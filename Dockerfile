FROM python:3.13-alpine

ARG BW_VERSION="2025.10.0"
ARG SUPERCRONIC_VERSION="v0.2.39"
ARG SUPERCRONIC_SHA1SUM_LINUX_AMD64=c98bbf82c5f648aaac8708c182cc83046fe48423
ARG SUPERCRONIC_SHA1SUM_LINUX_ARM64=5ef4ccc3d43f12d0f6c3763758bc37cc4e5af76e
ARG SUPERCRONIC_SHA1SUM_LINUX_ARMV7=8c3dbef8175e3f579baefe4e55978f2a27cb76b5
ARG SUPERCRONIC_SHA1SUM_LINUX_386=2f94144bc5b10ffca1f4020b3fab7cffca869e8e
ARG TARGETARCH

# Install minimal required packages
RUN apk update && apk add --no-cache \
    curl \
    bash \
    unzip \
    sqlcipher \
    libressl-dev \
    sqlite-dev \
    sqlcipher-dev \
    build-base \
    python3-dev \
    nodejs \
    npm \
    coreutils \
    lib6c-compat \
    && rm -rf /var/lib/apk/*

RUN apk upgrade -a

# Install Bitwarden CLI
RUN set -eux; \
    echo "Installing Bitwarden CLI version: ${BW_VERSION} with Node.js $(node --version)"; \
    npm install -g @bitwarden/cli@${BW_VERSION}; \
    bw --version

# Install supercronic
RUN set -eux; \
    echo "Installing supercronic for ${TARGETARCH}"; \
    \
    case "${TARGETARCH}" in \
        "amd64") SHA1SUM_VALUE="${SUPERCRONIC_SHA1SUM_LINUX_AMD64}" ;; \
        "arm64") SHA1SUM_VALUE="${SUPERCRONIC_SHA1SUM_LINUX_ARM64}" ;; \
        "armv7") SHA1SUM_VALUE="${SUPERCRONIC_SHA1SUM_LINUX_ARMV7}" ;; \
        "386") SHA1SUM_VALUE="${SUPERCRONIC_SHA1SUM_LINUX_386}" ;; \
        *) echo "Unsupported architecture for supercronic: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    \
    SUPERCRONIC_URL="https://github.com/aptible/supercronic/releases/download/${SUPERCRONIC_VERSION}/supercronic-linux-${TARGETARCH}"; \
    SUPERCRONIC_BINARY="supercronic-linux-${TARGETARCH}"; \
    \
    curl -fsSLO "$SUPERCRONIC_URL"; \
    echo "${SHA1SUM_VALUE}  ${SUPERCRONIC_BINARY}" | sha1sum -c -; \
    chmod +x "$SUPERCRONIC_BINARY"; \
    mv "$SUPERCRONIC_BINARY" /usr/local/bin/supercronic;

# Prepare working directories
RUN mkdir -p /app/logs /app/backups /app/db /app/src && \
    chmod -R 700 /app && \
    chown -R 1000:1000 /app

# Copy project files
WORKDIR /app

COPY --chown=1000:1000 ./requirements.txt /app/requirements.txt
COPY --chown=1000:1000 ./src /app/src
COPY --chown=1000:1000 ./entrypoint.sh /app/entrypoint.sh
COPY --chown=1000:1000 ./cleanup.sh /app/cleanup.sh

RUN chmod +x /app/entrypoint.sh /app/cleanup.sh

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install --no-input --no-cache-dir -r requirements.txt

RUN npm install koa@3.0.1 && npm install tmp@0.2.4

RUN apk del curl unzip binutils npm coreutils --no-cache && \
    rm -rf /var/lib/apk/*

ENV PYTHONPATH=/app

USER 1000:1000

ENTRYPOINT ["/app/entrypoint.sh"]
