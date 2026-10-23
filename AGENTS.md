# AGENTS.md

## Dev Commands

```bash
# Install dependencies (uses uv, not pip)
uv sync --dev

# Lint and format
uv run ruff check
uv run ruff format

# Run tests
uv run pytest
```

## Architecture

- **Python 3.12+** with `uv` for package management
- **SQLCipher** encrypted SQLite database for credential storage
- **FastAPI** serves setup UI on first run (src/init.py)
- **src/run.py** is the main backup execution logic
- **src/bw_client.py** wraps Bitwarden CLI for vault export

## Key Constraints

- Requires system libs: `libsqlite3-dev libsqlcipher-dev libssl-dev` (see CI workflow)
- Two encryption modes: `bitwarden` (default, requires CLI to decrypt) and `raw` (portable AES-256-GCM)
- Database path: `/app/db/backvault.db` with pragma key at `/app/db/backvault.db.pragma`
- Backup dir: `/app/backups` (or `/tmp` when `TEST_MODE` is set)

## Multi-Organization Export

- Configured via setup UI: organization IDs (comma-separated) and export mode (`single` or `multiple`)
- `single`: All orgs merged into one file (`backup_{timestamp}_orgs.enc`)
- `multiple`: Each org exported separately (`backup_{timestamp}_org-{org-id}.enc`)
- Personal vault always exported separately from organizations

## Docker

Multi-arch builds (amd64, arm64, arm/v7) use QEMU. Build with:
```bash
docker buildx build --platform=linux/amd64,linux/arm64,linux/arm/v7 --load .
```