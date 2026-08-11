# Testing Guide

This document describes how to run tests for Backvault.

## Prerequisites

- Python 3.13+
- [uv](https://github.com/astral-sh/uv) package manager
- Docker (for Docker/E2E tests)
- Bitwarden CLI (`bw`)

## Running Tests Locally

### Unit Tests

Run all unit tests with:

```bash
uv sync --dev
uv run pytest
```

### With Coverage Report

```bash
uv run pytest --cov=src --cov-report=html --cov-report=term
```

### Run Specific Test File

```bash
uv run pytest tests/test_bw_client.py -v
uv run pytest tests/test_run.py -v
uv run pytest tests/test_cli_integration.py -v
```

## Integration Tests (Requires Vaultwarden)

### Quick Start with Docker

1. Start a Vaultwarden instance:

```bash
docker run -d --name vaultwarden-test \
  -p 8080:80 \
  -e SIGNUPS_ALLOWED=true \
  vaultwarden/server:latest
```

2. Wait for it to be ready (~10 seconds)

```bash
sleep 10
```

3. Set environment variables:

```bash
export VAULTWARDEN_URL=http://localhost:8080
export BW_TEST_EMAIL=your-test-email@example.com
export BW_TEST_PASSWORD=your-test-password
export BW_TEST_MASTER_PASSWORD=your-master-password
```

4. Run E2E tests:

```bash
uv run pytest tests/test_e2e.py -v
```

### Manual CLI Testing

```bash
# Configure server
bw config server http://localhost:8080

# Login
bw login $BW_TEST_EMAIL --password $BW_TEST_PASSWORD

# Unlock
bw unlock $BW_TEST_MASTER_PASSWORD --raw

# Export vault
bw export --format json --password backup_password

# Check status
bw status
```

## Docker Image Testing

### Multi-Arch Build

```bash
# Build for all platforms
docker buildx build --platform=linux/amd64,linux/arm64,linux/arm/v7 --load .

# Test each platform
docker run --rm --platform linux/amd64 <image> bw --version
docker run --rm --platform linux/arm64 <image> bw --version
docker run --rm --platform linux/arm/v7 <image> bw --version
```

### Run Full Docker Test Suite

```bash
./tests/docker_test.sh
```

## CI/CD

Tests run automatically on GitHub Actions:

| Workflow | Trigger | Jobs |
|----------|---------|------|
| `ci.yml` | Push/PR to main | Lint, Unit Tests, Docker Build |
| `e2e.yml` | After CI success | E2E Tests with Vaultwarden |

### Manual CI Run

You can trigger E2E tests manually:

1. Go to Actions > E2E Tests
2. Click "Run workflow"
3. Select branch and run

## Test Organization

```
tests/
├── test_bw_client.py          # Bitwarden client unit tests (mocked)
├── test_db.py              # Database operations (mocked)
├── test_init.py           # FastAPI init endpoints (mocked)
├── test_run.py           # Main backup logic (mocked)
├── test_cli_integration.py  # CLI workflow tests (mocked)
├── test_e2e.py           # End-to-end tests (real Vaultwarden)
├── docker_test.sh          # Docker image validation script
└── README.md            # This file
```

## Troubleshooting

### "Vaultwarden failed to start"

Increase the wait time in the test fixture or check Docker logs:

```bash
docker logs vaultwarden-test
```

### "Failed to connect to Vaultwarden"

Ensure the container is running and port 8080 is available:

```bash
docker ps
curl http://localhost:8080/health
```

### SQLCipher errors

Ensure system dependencies are installed:

```bash
# Ubuntu/Debian
sudo apt-get install libsqlite3-dev libsqlcipher-dev libssl-dev

# Alpine
apk add sqlite-dev sqlcipher-dev libressl-dev
```

### "bw: command not found"

Install Bitwarden CLI:

```bash
# macOS
brew install bitwarden-cli

# Linux
npm install -g @bitwarden/cli
```

### Test timeout with Vaultwarden

If Vaultwarden takes too long to start, increase the timeout in tests/test_e2e.py:

```python
# Change this:
max_attempts = 30
# To this:
max_attempts = 60
```