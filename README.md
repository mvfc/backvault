# 🗄️ BackVault

**BackVault** is a lightweight Dockerized service that periodically backs up your **Bitwarden** or **Vaultwarden** vaults into password-protected encrypted files.  
It’s designed for hands-free, secure, and automated backups using the official Bitwarden CLI.

---

## 🚀 Features

- 🔒 Securely exports your vault using your Bitwarden credentials
- 🕐 **Interval-based backup scheduling** — configure backup frequency in hours
- 💾 Password-protected backup files using AES encryption
- 🧹 **Automated Cleanup**: Automatically deletes old backups daily at midnight based on configurable retention period
- ✨ **Two Encryption Modes**: Choose between Bitwarden's native encrypted format or a portable, standard AES-256-GCM encrypted format
- 🔐 **Security Hardened**: Non-root execution, log redaction, retry logic with exponential backoff
- 🌐 Works with both Bitwarden Cloud and self-hosted Bitwarden/Vaultwarden
- 🏗️ **Multi-Architecture Support**: Native images for amd64, arm64, and arm/v7 (Raspberry Pi)
- 🐳 Runs fully containerized — no setup or local dependencies required

---

## 📦 Quick Start (Docker)

You can run BackVault directly using the **published Docker image**, no build required.

**Available Images:**
- GitHub Container Registry: `ghcr.io/tgrecojr/backvault:latest`
- Multi-architecture support: amd64, arm64, arm/v7 (Raspberry Pi compatible)

```bash
docker run -d \
  --name backvault \
  -e BW_CLIENT_ID="your_client_id" \
  -e BW_CLIENT_SECRET="your_client_secret" \
  -e BW_PASSWORD="your_master_password" \
  -e BW_SERVER="https://vault.yourdomain.com" \
  -e BW_FILE_PASSWORD="backup_encryption_password" \
  -e BACKUP_ENCRYPTION_MODE="raw" \
  -e BACKUP_INTERVAL_HOURS=12 \
  -v /path/to/backup:/app/backups \
  --security-opt seccomp=unconfined \
  ghcr.io/tgrecojr/backvault:latest
```

> ⚠️ **Security Requirement**: The `--security-opt seccomp=unconfined` flag is **required** for the Bitwarden CLI to function properly inside the container.

> 🔑 **Important**: The container uses the official Bitwarden CLI internally.
> Your credentials are only used to generate the export — they are **never stored** persistently and **never sent** anywhere else.

---

## 🧩 Docker Compose Example

Here’s how to set it up with Docker Compose for easy management:

```yaml
services:
  backvault:
    image: ghcr.io/tgrecojr/backvault:latest
    container_name: backvault
    restart: unless-stopped

    # Run as current user to avoid permission issues with mounted volumes
    user: "${UID:-1000}:${GID:-1000}"

    # REQUIRED: Bitwarden CLI needs this to run
    security_opt:
      - seccomp=unconfined

    environment:
      BW_CLIENT_ID: "your_client_id"
      BW_CLIENT_SECRET: "your_client_secret"
      BW_PASSWORD: "your_master_password"
      BW_SERVER: "https://vault.yourdomain.com"
      BW_FILE_PASSWORD: "backup_encryption_password"
      BACKUP_ENCRYPTION_MODE: "raw" # Use 'bitwarden' for the default format
      BACKUP_INTERVAL_HOURS: 12
      RETAIN_DAYS: 7

      # Uncomment if using self-signed certificates
      # NODE_TLS_REJECT_UNAUTHORIZED: 0

    volumes:
      - ./backups:/app/backups
```

Then run:

```bash
docker compose up -d
```

BackVault will automatically:

1. Log in to your Bitwarden/Vaultwarden instance
2. Export your vault
3. Encrypt it using `BW_FILE_PASSWORD`
4. Store the backup in `/app/backups` (mounted to your host directory)
5. Logout after every backup

---

## ⚙️ Configuration

| Variable                       | Description                                    | Required | Default | Example                     |
| ------------------------------ | ---------------------------------------------- | -------- | ------- | --------------------------- |
| `BW_CLIENT_ID`                 | Bitwarden client ID for API authentication     | ✅        | -       | `xxxx-xxxx-xxxx-xxxx`       |
| `BW_CLIENT_SECRET`             | Bitwarden client secret                        | ✅        | -       | `your_client_secret`        |
| `BW_PASSWORD`                  | Master password for your vault                 | ✅        | -       | `supersecret`               |
| `BW_SERVER`                    | Bitwarden or Vaultwarden server URL            | ✅        | -       | `https://vault.example.com` |
| `BW_FILE_PASSWORD`             | Password to encrypt exported backup file       | ✅        | -       | `strong_backup_password`    |
| `BACKUP_INTERVAL_HOURS`        | Backup frequency in hours                      | ❌        | `12`    | `12`                        |
| `BACKUP_ENCRYPTION_MODE`       | `bitwarden` or `raw` (portable AES-256-GCM)    | ❌        | `bitwarden` | `raw`                   |
| `BACKUP_DIR`                   | Directory path for storing backups             | ❌        | `/app/backups` | `/app/backups`         |
| `RETAIN_DAYS`                  | Days to keep backups. Set to `0` to disable cleanup | ❌  | `7`     | `7`                         |
| `NODE_TLS_REJECT_UNAUTHORIZED` | Set to `0` **only** if using self-signed certificates | ❌ | `1` | `0`                         |

---

## 🔒 Security Considerations

### Master Password Storage

**Important**: BackVault requires your Bitwarden master password (`BW_PASSWORD`) to unlock and export your vault. This is a fundamental requirement of the Bitwarden CLI and cannot be avoided.

**Current Implementation:**
- Password is passed via environment variable
- Never logged or stored persistently
- Redacted from all log output
- Vault is locked immediately after each backup

**⚠️ Security Risks:**
- Environment variables are visible in `docker inspect <container>`
- May appear in container orchestration logs
- Stored in plain text in docker-compose.yml files

**Recommendations:**
1. **For production use**, consider using Docker Secrets or Kubernetes Secrets instead of environment variables
2. Store your `docker-compose.yml` and `.env` files securely with appropriate file permissions
3. Use a dedicated backup password (`BW_FILE_PASSWORD`) different from your master password
4. Regularly rotate your API keys and passwords
5. Limit access to the backup directory with proper file system permissions

> 📋 **Note**: There is an open issue to add support for file-based secrets (e.g., `BW_PASSWORD_FILE`) as a more secure alternative. See the GitHub issues for details.

### Additional Security Features

- **Non-root execution**: Container runs as UID 1000 by default (configurable via `user:` in docker-compose)
- **Automated logout**: Session is terminated immediately after each backup
- **Retry logic**: Implements exponential backoff to prevent account lockouts
- **Strong encryption**: AES-256-GCM with PBKDF2 (600,000 iterations) for raw mode backups
- **Security audited**: See [SECURITYASSESS.md](SECURITYASSESS.md) for detailed security assessment

---

## 🔐 Decrypting Backups

BackVault supports two encryption modes, set by the `BACKUP_ENCRYPTION_MODE` environment variable. The decryption method depends on which mode was used to create the backup.

### Mode 1: `bitwarden` (Default)

This mode uses Bitwarden's native encrypted JSON format. It's secure but proprietary, meaning you **must use the Bitwarden CLI** to decrypt it.

**How to Decrypt:**

1.  Install the official **Bitwarden CLI**: bitwarden.com/help/cli/
2.  Config the CLI to point to your server with `bw config server`.
3.  Log in using `bw login`.
4.  Run the `import` command. This will decrypt the file and import it into your vault.

    ```bash
    # This command decrypts the file and imports it into a vault.
    bw import bitwardenjson /path/to/backup.enc
    ```

    You will be prompted to enter your encryption password before the import can complete.

> This method can be used to restore your vault into the same or a different Bitwarden account. The encryption is self-contained.

### Mode 2: `raw` (Recommended for Portability)

This mode exports the vault as raw JSON and then encrypts it in-memory using a standard, portable format: **AES-256-GCM** with a key derived using **PBKDF2-SHA256**.

The main advantage is that you **do not need the Bitwarden CLI** to decrypt your data, making it ideal for disaster recovery. You can use standard tools like Python or OpenSSL.

**File Structure:**
The resulting `.enc` file contains: `[4-byte version][16-byte salt][12-byte nonce][encrypted data + 16-byte auth tag]`

**Version History:**
- **Version 1**: PBKDF2 iterations: 600,000 (OWASP 2023 recommendation)

**How to Decrypt (Python Script):**

Here is a simple Python script to decrypt the file. You only need the `cryptography` library.

1.  Save the code below as `decrypt.py`.
2.  Install the dependency: `pip install cryptography`.
3.  Run the script: `python decrypt.py /path/to/backup.enc "YOUR_FILE_PASSWORD"`

```python
# decrypt.py
import os
import sys
from getpass import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

SALT_SIZE = 16
KEY_SIZE = 32

# Version-specific parameters
VERSION_PARAMS = {
    1: {"iterations": 600000},  # Version 1: OWASP 2023 recommendation
}

def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
    # Read version header (4 bytes, big-endian)
    version = int.from_bytes(encrypted_data[:4], byteorder='big')

    if version not in VERSION_PARAMS:
        raise ValueError(f"Unsupported file version: {version}")

    # Get version-specific parameters
    iterations = VERSION_PARAMS[version]["iterations"]
    print(f"Decrypting version {version} file (PBKDF2 iterations: {iterations:,})", file=sys.stderr)

    # Extract components after version header
    offset = 4
    salt = encrypted_data[offset:offset+SALT_SIZE]
    nonce = encrypted_data[offset+SALT_SIZE:offset+SALT_SIZE+12]
    ciphertext_with_tag = encrypted_data[offset+SALT_SIZE+12:]

    # Derive key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations
    )
    key = kdf.derive(password.encode("utf-8"))

    # Decrypt
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, None)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <encrypted_file> [password]")
        sys.exit(1)

    file_path = sys.argv[1]
    password = sys.argv[2] if len(sys.argv) > 2 else getpass("Enter backup password: ")

    try:
        with open(file_path, "rb") as f:
            encrypted_contents = f.read()

        decrypted_json = decrypt_data(encrypted_contents, password)
        print(decrypted_json.decode("utf-8"))
        print("\nDecryption successful.", file=sys.stderr)
    except InvalidTag:
        print("Decryption failed: Invalid password or corrupted file.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)
        sys.exit(1)
```

---

## 🧠 Tips

* **Store `BW_FILE_PASSWORD` securely** — it's required for restoring backups and cannot be recovered if lost
* You can run this container alongside Vaultwarden on the same host or a separate machine
* Combine with tools like `restic` or `rclone` to push backups to cloud storage for offsite protection
* Test your backup restoration process periodically to ensure you can recover your data
* The container performs an initial backup immediately on startup, then follows the configured interval
* Cleanup runs automatically at midnight each day (container time), deleting backups older than `RETAIN_DAYS`

---

## 🐳 Updating

To update to the latest version:

```bash
docker pull ghcr.io/tgrecojr/backvault:latest
```

If using docker compose:
```bash
docker compose pull
docker compose up -d
```

---

## 🔄 CI/CD and Multi-Architecture Builds

BackVault uses GitHub Actions for automated building and publishing:

### Automated Workflows

- **Docker Publish**: Builds and publishes multi-arch images on merge to main
- **Security Scan**: Weekly vulnerability scanning with Trivy and Bandit
- **Test**: Runs linting and build tests on all PRs

### Supported Architectures

Images are automatically built for:
- `linux/amd64` - Standard x86_64 systems
- `linux/arm64` - ARM64 systems (Apple Silicon M1/M2, AWS Graviton)
- `linux/arm/v7` - 32-bit ARM (Raspberry Pi 2+)

### Using Specific Versions

```bash
# Use latest version
docker pull ghcr.io/tgrecojr/backvault:latest

# Use specific version (when tagged)
docker pull ghcr.io/tgrecojr/backvault:v1.0.0

# Use specific architecture
docker pull --platform linux/arm64 ghcr.io/tgrecojr/backvault:latest
```

### Building Locally

**Important**: If building on macOS, see [BUILD.md](BUILD.md) for detailed platform-specific instructions.

**On macOS (for Linux deployment):**
```bash
# Always specify target platform when building on Mac
docker build --platform linux/amd64 -t backvault:local .
```

**On Linux:**
```bash
# No --platform flag needed (auto-detects)
docker build -t backvault:local .
```

**Multi-architecture build (requires buildx):**
```bash
docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 -t backvault:local .
```

For comprehensive build documentation including troubleshooting, see **[BUILD.md](BUILD.md)**.

---

## 🪪 License

This project is licensed under the **AGPL-3.0 License**.
See LICENSE for details.

---

## 📚 Additional Documentation

- **[BUILD.md](BUILD.md)** - Platform-specific build instructions and troubleshooting
- **[SECURITYASSESS.md](SECURITYASSESS.md)** - Comprehensive security assessment and audit results
- **[CONTRIBUTING.md](.github/CONTRIBUTING.md)** - Guidelines for contributing to the project

---

## 🤝 Contributing

Pull requests and issue reports are welcome!
Feel free to open a PR or discussion on GitHub.

See [CONTRIBUTING.md](.github/CONTRIBUTING.md) for guidelines.

---

**BackVault** — secure, automated, encrypted vault backups.
