FROM python:3.13-alpine

ARG BW_VERSION="2025.12.0"
ARG SUPERCRONIC_VERSION="v0.2.41"
ARG SUPERCRONIC_SHA1SUM_LINUX_AMD64=f70ad28d0d739a96dc9e2087ae370c257e79b8d7
ARG SUPERCRONIC_SHA1SUM_LINUX_ARM64=44e10e33e8d98b1d1522f6719f15fb9469786ff0
ARG SUPERCRONIC_SHA1SUM_LINUX_ARMV7=d1e9c90160c92201233daf164088bd861b4b39a4
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
    libffi-dev \
    cargo \
    su-exec \
    && rm -rf /var/lib/apk/*

RUN apk upgrade -a

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Install Bitwarden CLI
RUN set -eux; \
    echo "Installing Bitwarden CLI version: ${BW_VERSION} with Node.js $(node --version)"; \
    npm install -g @bitwarden/cli@${BW_VERSION}

# Install supercronic
RUN set -eux; \
    echo "Installing supercronic for ${TARGETARCH}"; \
    \
    case "${TARGETARCH}" in \
        "amd64") SHA1SUM_VALUE="${SUPERCRONIC_SHA1SUM_LINUX_AMD64}" ;; \
        "arm64") SHA1SUM_VALUE="${SUPERCRONIC_SHA1SUM_LINUX_ARM64}" ;; \
        "arm") SHA1SUM_VALUE="${SUPERCRONIC_SHA1SUM_LINUX_ARMV7}" ;; \
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
RUN mkdir -p /app/logs /app/backups /app/db /app/src /.config && \
    chmod -R 700 /app && \
    chmod -R 700 /.config

# Copy project files
WORKDIR /app

COPY ./requirements.txt /app/requirements.txt
COPY ./src /app/src
COPY ./entrypoint.sh /app/entrypoint.sh
COPY ./cleanup.sh /app/cleanup.sh
COPY ./run.sh /app/run.sh

RUN chmod +x /app/entrypoint.sh /app/cleanup.sh /app/run.sh

# Install Python dependencies
RUN pip install --upgrade pip --no-cache-dir && \
    pip install --no-input --no-cache-dir -r requirements.txt

RUN apk del curl unzip binutils npm coreutils build-base libffi-dev cargo python3-dev --no-cache && \
    rm -rf /var/lib/apk/*

ENV PYTHONPATH=/app

ENTRYPOINT ["/app/entrypoint.sh"]

CMD ["/app/run.sh"]
