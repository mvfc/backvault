# Building BackVault Docker Images

This guide explains how to build BackVault Docker images correctly for different platforms.

## TL;DR - Quick Commands

### **Building on macOS (Intel or Apple Silicon)**

**For deployment on Linux servers (most common):**
```bash
docker build --platform linux/amd64 -t backvault:latest .
```

**For ARM servers (Raspberry Pi, AWS Graviton):**
```bash
docker build --platform linux/arm64 -t backvault:latest .
```

### **Building on Linux**

```bash
# Builds for your current architecture automatically
docker build -t backvault:latest .
```

### **Multi-Architecture Build (for publishing)**

```bash
# Set up buildx (one-time setup)
docker buildx create --use --name multiarch

# Build for multiple architectures
docker buildx build \
  --platform linux/amd64,linux/arm64,linux/arm/v7 \
  -t backvault:latest \
  --push \
  .
```

---

## Understanding Platform Detection

### The Problem

Docker on macOS runs in a Linux VM, but the Dockerfile needs to know which **target platform** to build for, not which platform you're building **from**.

**Example:**
- You're on: `macOS arm64` (Apple Silicon M1/M2)
- Docker container runs: `Linux`
- You want binary for: `Linux amd64` (Intel server)

### The Solution

The Dockerfile uses Docker's automatic build arguments:

```dockerfile
ARG TARGETPLATFORM  # e.g., "linux/amd64"
ARG TARGETARCH      # e.g., "amd64"
```

These tell the Dockerfile which architecture to download the Bitwarden CLI binary for.

---

## Build Scenarios

### Scenario 1: Building on Mac for Linux Server (Most Common)

**Problem:** Without --platform, Docker might build for arm64 but you need amd64

**Solution:**
```bash
# Always specify the target platform when building on Mac
docker build --platform linux/amd64 -t backvault:latest .
```

**Why this works:**
- Docker's TARGETARCH becomes "amd64"
- Dockerfile downloads x86_64 Bitwarden CLI binary
- Image works on Intel/AMD Linux servers

### Scenario 2: Building on Mac for ARM Server

If you're deploying to:
- Raspberry Pi 4/5
- AWS Graviton instances
- Other ARM64 servers

```bash
docker build --platform linux/arm64 -t backvault:latest .
```

### Scenario 3: Building on Linux

On a Linux machine, Docker detects the architecture automatically:

```bash
# No --platform needed on Linux
docker build -t backvault:latest .
```

### Scenario 4: Multi-Architecture Build (CI/CD)

For publishing to registries with multi-arch support:

```bash
# One-time: Create buildx builder
docker buildx create --use --name backvault-builder

# Build and push to registry
docker buildx build \
  --platform linux/amd64,linux/arm64,linux/arm/v7 \
  -t ghcr.io/yourusername/backvault:latest \
  --push \
  .
```

---

## Architecture Mapping

The Dockerfile maps Docker's architecture names to Bitwarden CLI binaries:

| Docker TARGETARCH | Bitwarden Binary | Use Case |
|-------------------|------------------|----------|
| `amd64` | `x86_64` | Intel/AMD servers (most common) |
| `arm64` | `aarch64` | Apple Silicon, AWS Graviton, Pi 4/5 |
| `arm/v7` | `armv7` | Raspberry Pi 2/3 |

---

## Verifying Your Build

### Check the Target Platform

During build, you'll see:
```
Building for platform: linux/amd64
Target architecture: amd64
Installing Bitwarden CLI version: 2024.10.2
Downloading for architecture: x86_64
```

### Test the Built Image

```bash
# Check the binary architecture
docker run --rm --entrypoint /bin/bash backvault:latest -c "file /usr/local/bin/bw"

# Should show:
# - "x86-64" for amd64
# - "aarch64" for arm64
# - "ARM" for arm/v7
```

### Run a Quick Test

```bash
docker run --rm \
  --security-opt seccomp=unconfined \
  --entrypoint /usr/local/bin/bw \
  backvault:latest \
  --version
```

---

## Common Issues

### Issue: "exec format error"

**Symptom:**
```
standard_init_linux.go:228: exec user process caused: exec format error
```

**Cause:** Binary architecture doesn't match the container's architecture

**Solution:**
- You built for wrong platform
- Rebuild with correct `--platform` flag

**Example:**
```bash
# Built for arm64 but running on amd64 server
docker build --platform linux/amd64 -t backvault:latest .
```

### Issue: Binary works in build but fails at runtime with SIGTRAP

**Cause:** Docker's seccomp security profile

**Solution:** Add to docker-compose.yml:
```yaml
security_opt:
  - seccomp=unconfined
```

### Issue: Build fails downloading Bitwarden CLI

**Symptom:**
```
ERROR: Unsupported architecture
```

**Cause:** Building for unsupported architecture

**Supported architectures:**
- ✅ linux/amd64
- ✅ linux/arm64
- ✅ linux/arm/v7
- ❌ linux/386 (not supported by Bitwarden)
- ❌ linux/arm/v6 (not supported by Bitwarden)

---

## Best Practices

### Local Development

```bash
# Always specify platform when building on Mac
docker build --platform linux/amd64 -t backvault:dev .

# Test it
docker-compose up
```

### Production Deployment

**Option 1: Use Pre-Built Images (Recommended)**
```yaml
# docker-compose.yml
services:
  backvault:
    image: ghcr.io/yourusername/backvault:latest
    # ...
```

**Option 2: Build on CI/CD**
- Let GitHub Actions build multi-arch images
- Images automatically match target platform
- No local build issues

**Option 3: Build on Target Server**
```bash
# Build directly on the server
ssh user@server
git clone https://github.com/yourusername/backvault.git
cd backvault
docker build -t backvault:latest .  # No --platform needed
```

---

## GitHub Actions Multi-Arch Builds

The repository includes GitHub Actions that automatically build for all architectures:

```yaml
# .github/workflows/docker-publish.yml
platforms: linux/amd64,linux/arm64,linux/arm/v7
```

**Advantages:**
- ✅ Builds happen on Linux runners (no Mac issues)
- ✅ Proper QEMU setup for cross-compilation
- ✅ Published images work on all platforms
- ✅ No need to build locally

**To use:**
1. Push to main branch
2. Wait for build (~10-15 minutes)
3. Pull and use: `docker pull ghcr.io/yourusername/backvault:latest`

---

## Advanced: Testing Multiple Architectures Locally

### Using QEMU

```bash
# Set up QEMU for cross-platform builds
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes

# Create buildx builder
docker buildx create --name multiarch --driver docker-container --use

# Build and load for specific platform
docker buildx build \
  --platform linux/arm64 \
  -t backvault:arm64 \
  --load \
  .

# Test the ARM image on your Mac
docker run --rm --security-opt seccomp=unconfined backvault:arm64 bw --version
```

---

## Troubleshooting Platform Issues

### Check Current Platform

```bash
# On build host
uname -m
# x86_64 = amd64
# aarch64 = arm64
# armv7l = arm/v7

# Docker's perspective
docker version --format '{{.Server.Arch}}'
```

### Check Image Platform

```bash
docker image inspect backvault:latest | grep Architecture
```

### Force Rebuild Without Cache

```bash
docker build --no-cache --platform linux/amd64 -t backvault:latest .
```

---

## Summary

**Building on macOS?**
→ Always use `--platform linux/amd64` (or your target platform)

**Building on Linux?**
→ No --platform flag needed

**Publishing multi-arch?**
→ Use GitHub Actions (already configured)

**Quick test?**
→ `docker run --rm --entrypoint /bin/bash backvault:latest -c "file /usr/local/bin/bw"`

---

**Need Help?**
- Check the build logs for "Building for platform:" message
- Verify the binary architecture matches your target
- Use GitHub Actions for production builds (easier and more reliable)
