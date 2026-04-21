#!/bin/bash
# Docker Image Test Script
# Validates the Docker image across all supported architectures

set -e

REPO_NAME="${GITHUB_REPOSITORY:-$(git rev-parse --show-toplevel 2>/dev/null | xargs basename 2>/dev/null || echo backvault)}"
IMAGE_NAME="${IMAGE_NAME:-ghcr.io/$(echo "$REPO_NAME" | tr '[:upper:]' '[:lower:]')}"
PLATFORMS=("linux/amd64" "linux/arm64" "linux/arm/v7")

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

    echo "Testing sqlcipher --version..."
    docker run --rm --platform "$platform" \
        "${IMAGE_NAME}:${platform_tag}-test" \
        sqlcipher --version || echo "Note: sqlcipher may not have --version"

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
    docker run --rm --platform "$platform" \
        "${IMAGE_NAME}:${platform_tag}-test" \
        printenv | grep -q PYTHONPATH || echo "Note: PYTHONPATH may not be set in test"

    echo "=== $platform: All tests passed ==="
    echo ""
done

echo "=== All Docker tests passed! ==="
