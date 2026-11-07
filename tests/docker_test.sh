#!/bin/bash
# Docker Image Test Script
# Validates the Docker image across all supported architectures

set -eo pipefail

REPO_NAME="${GITHUB_REPOSITORY:-$(git rev-parse --show-toplevel 2>/dev/null | xargs basename 2>/dev/null || echo backvault)}"
IMAGE_NAME="${IMAGE_NAME:-ghcr.io/$(echo "$REPO_NAME" | tr '[:upper:]' '[:lower:]')}"
if [ -z "${PLATFORMS[*]:-}" ]; then
    PLATFORMS=("linux/amd64" "linux/arm64" "linux/arm/v7")
fi

echo "=== Docker Image Tests ==="
echo "Image: $IMAGE_NAME"
echo "Platforms: ${PLATFORMS[*]}"
echo ""

if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not installed"
    exit 1
fi

if ! docker buildx version &> /dev/null; then
    echo "ERROR: Docker buildx is not available"
    exit 1
fi

CREATED_BUILDER=0
if ! docker buildx inspect &> /dev/null; then
    echo "Setting up docker buildx..."
    docker buildx create --name backvault-builder --use || true
    CREATED_BUILDER=1
fi

cleanup() {
    echo "Cleaning up..."
    if [ "$CREATED_BUILDER" = "1" ]; then
        docker buildx rm backvault-builder 2>/dev/null || true
    fi
    if [ -n "${restart_cid:-}" ]; then
        docker rm -f "$restart_cid" 2>/dev/null || true
        docker rmi "${restart_cid}-img" 2>/dev/null || true
    fi
}
trap cleanup EXIT

for platform in "${PLATFORMS[@]}"; do
    platform_tag=$(echo "$platform" | tr '/' '-')
    echo "=== Testing platform: $platform ==="

    echo "Building image for $platform..."
    docker buildx build \
        --platform "$platform" \
        --load \
        -t "${IMAGE_NAME}:${platform_tag}-test" \
        . || { echo "Build failed for $platform"; exit 1; }

    echo "Testing bw --version..."
    docker run --rm --platform "$platform" \
        "${IMAGE_NAME}:${platform_tag}-test" \
        bw --version

    echo "Testing supercronic --version..."
    docker run --rm --platform "$platform" \
        "${IMAGE_NAME}:${platform_tag}-test" \
        supercronic --version

    echo "Testing python3 --version..."
    docker run --rm --platform "$platform" \
        "${IMAGE_NAME}:${platform_tag}-test" \
        python3 --version

    echo "Testing sqlcipher availability..."
    docker run --rm --entrypoint sh --platform "$platform" \
        "${IMAGE_NAME}:${platform_tag}-test" \
        -c 'command -v sqlcipher'

    echo "Testing entrypoint.sh exists and is executable..."
    docker run --rm --platform "$platform" \
        "${IMAGE_NAME}:${platform_tag}-test" \
        test -x /app/entrypoint.sh

    echo "Testing run.sh exists and is executable..."
    docker run --rm --platform "$platform" \
        "${IMAGE_NAME}:${platform_tag}-test" \
        test -x /app/run.sh

    echo "Testing cleanup.sh exists and is executable..."
    docker run --rm --platform "$platform" \
        "${IMAGE_NAME}:${platform_tag}-test" \
        test -x /app/cleanup.sh

    echo "Testing required directories exist..."
    docker run --rm --platform "$platform" \
        "${IMAGE_NAME}:${platform_tag}-test" \
        sh -c 'test -d /app/backups && test -d /app/db && test -d /app/logs'

    echo "Testing environment variables..."
    docker run --rm --entrypoint sh --platform "$platform" \
        "${IMAGE_NAME}:${platform_tag}-test" \
        -c '[ "$PYTHONPATH" = "/app" ]'

    echo "Testing custom PGID=100 (existing group 'users')..."
    docker run --rm --platform "$platform" \
        -e PGID=100 \
        "${IMAGE_NAME}:${platform_tag}-test" \
        id | grep -q 'gid=100(users)'

    echo "Testing custom PUID and PGID (new group)..."
    docker run --rm --platform "$platform" \
        -e PUID=1001 -e PGID=2000 \
        "${IMAGE_NAME}:${platform_tag}-test" \
        id | grep -q 'uid=1001(appuser) gid=2000(appgroup)'

    echo "Testing recovery from missing appuser with PGID=100..."
    docker run --rm --platform "$platform" --entrypoint /bin/sh \
        -e PUID=1000 -e PGID=100 \
        "${IMAGE_NAME}:${platform_tag}-test" \
        -c 'deluser appuser >/dev/null 2>&1 || true; exec /app/entrypoint.sh id' | grep -q 'uid=1000(appuser) gid=100(users)'

    echo "Testing recovery from missing appuser with custom PUID and PGID..."
    docker run --rm --platform "$platform" --entrypoint /bin/sh \
        -e PUID=1001 -e PGID=2000 \
        "${IMAGE_NAME}:${platform_tag}-test" \
        -c 'deluser appuser >/dev/null 2>&1 || true; exec /app/entrypoint.sh id' | grep -q 'uid=1001(appuser) gid=2000(appgroup)'

    echo "Testing non-destructive behavior when group creation fails..."
    docker run --rm --platform "$platform" --entrypoint /bin/sh \
        -e PUID=1000 -e PGID=2000 \
        "${IMAGE_NAME}:${platform_tag}-test" \
        -c '
set -e
cat << "EOF" > /tmp/addgroup
#!/bin/sh
case "$*" in
    *appgrouptmp*)
        echo "addgroup: failed intentionally" >&2
        exit 1
        ;;
esac
exec /usr/sbin/addgroup "$@"
EOF
chmod +x /tmp/addgroup
export PATH=/tmp:$PATH
if /app/entrypoint.sh id >/dev/null 2>&1; then
    echo "Expected entrypoint to fail when group creation fails" >&2
    exit 1
fi
[ "$(id -u appuser 2>/dev/null)" = "1000" ]
[ "$(id -g appuser 2>/dev/null)" = "1000" ]
export PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin
/app/entrypoint.sh id | grep -q "uid=1000(appuser) gid=2000(appgroup)"
'

    echo "Testing non-destructive behavior across container restarts..."
    restart_cid="test-restart-${platform_tag//\//-}-$RANDOM-$$"
    docker create --name "$restart_cid" --platform "$platform" --entrypoint /bin/sh \
        -e PUID=1000 -e PGID=2000 \
        "${IMAGE_NAME}:${platform_tag}-test" \
        -c '
if [ ! -f /tmp/failed_once ]; then
    touch /tmp/failed_once
    cat << "EOF" > /tmp/addgroup
#!/bin/sh
case "$*" in
    *appgrouptmp*)
        echo "addgroup: intentional failure" >&2
        exit 1
        ;;
esac
exec /usr/sbin/addgroup "$@"
EOF
    chmod +x /tmp/addgroup
    export PATH=/tmp:$PATH
    exec /app/entrypoint.sh id
fi
exec /app/entrypoint.sh id
'
    if docker start -a "$restart_cid" 2>/dev/null; then
        echo "Expected container to exit with failure" >&2
        docker rm -f "$restart_cid" >/dev/null 2>&1 || true
        exit 1
    fi
    docker commit "$restart_cid" "${restart_cid}-img" >/dev/null
    docker run --rm --entrypoint /bin/sh "${restart_cid}-img" -c '
set -e
[ "$(id -u appuser 2>/dev/null)" = "1000" ]
[ "$(id -g appuser 2>/dev/null)" = "1000" ]
'
    docker rmi "${restart_cid}-img" >/dev/null
    docker start -a "$restart_cid" | grep -q 'uid=1000(appuser) gid=2000(appgroup)'
    docker rm -f "$restart_cid" >/dev/null


    echo "Testing zero-padded PUID and PGID normalization..."
    docker run --rm --platform "$platform" \
        -e PUID=01001 -e PGID=02000 \
        "${IMAGE_NAME}:${platform_tag}-test" \
        id | grep -q 'uid=1001(appuser) gid=2000(appgroup)'

    echo "Testing root execution with PUID=0 and PGID=0..."
    docker run --rm --platform "$platform" \
        -e PUID=0 -e PGID=0 \
        "${IMAGE_NAME}:${platform_tag}-test" \
        id | grep -q 'uid=0(root) gid=0(root)'

    echo "Testing bw execution under custom PUID/PGID..."
    docker run --rm --platform "$platform" \
        -e PUID=1001 -e PGID=2000 \
        "${IMAGE_NAME}:${platform_tag}-test" \
        bw --version

    echo "Testing bw execution under existing account PUID/PGID..."
    docker run --rm --platform "$platform" \
        -e PUID=2 -e PGID=2 \
        "${IMAGE_NAME}:${platform_tag}-test" \
        bw --version

    echo "=== $platform: All tests passed ==="
    echo ""
done

echo "=== All Docker tests passed! ==="
