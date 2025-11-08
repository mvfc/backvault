FROM python:3.12-slim-bookworm

# Docker automatically provides these build arguments for multi-platform builds
ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT

# Install required system packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    unzip \
    bash \
    cron \
    ca-certificates \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install Bitwarden CLI with proper architecture detection
# Downloads the correct binary for the TARGET platform, not the build host
RUN set -eux; \
    echo "Building for platform: ${TARGETPLATFORM:-linux/amd64}"; \
    echo "Target architecture: ${TARGETARCH}"; \
    \
    # Get latest version from GitHub API
    BW_VERSION=$(curl -s https://api.github.com/repos/bitwarden/clients/releases | \
                 jq -r '[.[] | select(.tag_name | startswith("cli-v"))] | .[0].tag_name' | \
                 sed 's/cli-v//') || BW_VERSION="2024.10.2"; \
    \
    echo "Installing Bitwarden CLI version: ${BW_VERSION}"; \
    \
    # Map Docker architecture names to Bitwarden binary names
    case "${TARGETARCH}" in \
        amd64) \
            ARCH_SUFFIX="x86_64" ;; \
        arm64) \
            ARCH_SUFFIX="aarch64" ;; \
        arm) \
            # arm with variant v7 (Raspberry Pi)
            ARCH_SUFFIX="armv7" ;; \
        *) \
            echo "Unsupported architecture: ${TARGETARCH}"; \
            exit 1 ;; \
    esac; \
    \
    echo "Downloading for architecture: ${ARCH_SUFFIX}"; \
    \
    # Download the architecture-specific binary from GitHub releases
    curl -fsSL "https://github.com/bitwarden/clients/releases/download/cli-v${BW_VERSION}/bw-linux-${BW_VERSION}.zip" -o bw.zip || \
    curl -fsSL "https://vault.bitwarden.com/download/?app=cli&platform=linux" -o bw.zip; \
    \
    unzip bw.zip -d /usr/local/bin; \
    chmod +x /usr/local/bin/bw; \
    rm bw.zip; \
    \
    # Test the binary (may fail due to seccomp, but that's okay)
    /usr/local/bin/bw --version || echo "Note: bw binary requires seccomp=unconfined at runtime"

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
