# ========================================================
# Stage 1: Builder (Compiles wheels and downloads tools)
# ========================================================
FROM python:3.13-alpine AS builder

ARG BW_VERSION="2025.10.0"
ARG SUPERCRONIC_VERSION="v0.2.51"
ARG SUPERCRONIC_SHA1SUM_LINUX_AMD64=1692066e350a88ff4d7d6474fe3c7a6c41ec5e89
ARG SUPERCRONIC_SHA1SUM_LINUX_ARM64=9d4c2000493215a1898502b2fc2dada3e8ea8c7a
ARG SUPERCRONIC_SHA1SUM_LINUX_ARMV7=9224966499cd319ed85759e9b6442f885d920c4f
ARG TARGETARCH

# Install build dependencies
RUN apk update && apk add --no-cache \
    curl \
    build-base \
    cargo \
    libffi-dev \
    openssl-dev \
    sqlite-dev \
    sqlcipher-dev \
    python3-dev \
    nodejs \
    npm

# Download Supercronic
RUN set -eux; \
    ARCH="${TARGETARCH:-}"; \
    if [ -z "$ARCH" ]; then \
        case "$(apk --print-arch)" in \
            x86_64) ARCH="amd64" ;; \
            aarch64) ARCH="arm64" ;; \
            armv7|armhf) ARCH="arm" ;; \
            *) ARCH="$(apk --print-arch)" ;; \
        esac; \
    fi; \
    case "${ARCH}" in \
        "amd64") SHA1SUM_VALUE="${SUPERCRONIC_SHA1SUM_LINUX_AMD64}" ;; \
        "arm64") SHA1SUM_VALUE="${SUPERCRONIC_SHA1SUM_LINUX_ARM64}" ;; \
        "arm") SHA1SUM_VALUE="${SUPERCRONIC_SHA1SUM_LINUX_ARMV7}" ;; \
        *) echo "Unsupported architecture for supercronic: ${ARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/aptible/supercronic/releases/download/${SUPERCRONIC_VERSION}/supercronic-linux-${ARCH}" -o /usr/local/bin/supercronic; \
    echo "${SHA1SUM_VALUE}  /usr/local/bin/supercronic" | sha1sum -c -; \
    chmod +x /usr/local/bin/supercronic

# Install Bitwarden CLI globally into /usr/local
RUN npm install -g --prefix=/usr/local --omit=dev @bitwarden/cli@${BW_VERSION} && \
    npm cache clean --force

# Pre-compile Python wheels for dependencies
COPY ./requirements.txt /tmp/requirements.txt
RUN pip install --upgrade pip --no-cache-dir && \
    pip wheel --no-cache-dir -r /tmp/requirements.txt -w /wheels


# ========================================================
# Stage 2: Final Minimal Runtime Image
# ========================================================
FROM python:3.13-alpine

# Install ONLY runtime dependencies and apply security updates
RUN apk update && \
    apk upgrade --no-cache -a && \
    apk add --no-cache \
        bash \
        su-exec \
        sqlcipher \
        sqlcipher-libs \
        libffi \
        nodejs

# Copy Supercronic binary
COPY --from=builder /usr/local/bin/supercronic /usr/local/bin/supercronic

# Copy Bitwarden CLI node modules and create symlink
COPY --from=builder /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/@bitwarden/cli/build/bw.js /usr/local/bin/bw

# Copy and install pre-built Python wheels
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/* && \
    rm -rf /wheels

# Create appgroup and appuser idempotently (GID/UID 1000 to match default PGID/PUID)
RUN if ! getent group appgroup > /dev/null 2>&1; then \
        addgroup -S -g 1000 appgroup; \
    fi && \
    if ! getent passwd appuser > /dev/null 2>&1; then \
        adduser -S -u 1000 -G appgroup appuser; \
    fi

# Prepare working directories
RUN mkdir -p /app/logs /app/backups /app/db /app/src /.config && \
    chmod -R 700 /app && \
    chmod -R 700 /.config

WORKDIR /app

COPY ./src /app/src
COPY ./entrypoint.sh /app/entrypoint.sh
COPY ./cleanup.sh /app/cleanup.sh
COPY ./run.sh /app/run.sh

RUN chmod +x /app/entrypoint.sh /app/cleanup.sh /app/run.sh

ENV PYTHONPATH=/app

ENTRYPOINT ["/app/entrypoint.sh"]

CMD ["/app/run.sh"]


