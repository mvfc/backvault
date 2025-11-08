# 🗄️ BackVault

**BackVault** is a lightweight Dockerized service that periodically backs up your **Bitwarden** or **Vaultwarden** vaults into password-protected encrypted files.  
It’s designed for hands-free, secure, and automated backups using the official Bitwarden CLI.

---

## 🚀 Features

- 🔒 Securely exports your vault using your Bitwarden credentials  
- 🕐 Supports both **interval-based** and **cron-based** backup scheduling  
- 💾 Password-protected backup files using AES encryption  
- 🧹 **Automated Cleanup**: Automatically deletes old backups based on a configurable retention period.
- ✨ **Two Encryption Modes**: Choose between Bitwarden's native encrypted format or a portable, standard AES-256-GCM encrypted format.
- 🌐 Works with both Bitwarden Cloud and self-hosted Bitwarden/Vaultwarden  
- 🐳 Runs fully containerized — no setup or local dependencies required

---

## 📦 Quick Start (Docker)

You can run BackVault directly using the **published Docker image**, no build required.
You can use either the github registry image (ghcr.io/mvfc/backvault) or the Docker Hub image (mvflc/backvault).

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
  ghcr.io/mvfc/backvault:latest
```

> 🔑 **Important**: The container uses the official Bitwarden CLI internally.
> Your credentials are only used to generate the export — they are **never stored** persistently and **never sent** anywhere else.

---

## 🧩 Docker Compose Example

Here’s how to set it up with Docker Compose for easy management:

```yaml
services:
  backvault:
    image: ghcr.io/mvfc/backvault:latest
    container_name: backvault
    restart: unless-stopped
    environment:
      BW_CLIENT_ID: "your_client_id"
      BW_CLIENT_SECRET: "your_client_secret"
      BW_PASSWORD: "your_master_password"
      BW_SERVER: "https://vault.yourdomain.com"
      BW_FILE_PASSWORD: "backup_encryption_password"
      BACKUP_ENCRYPTION_MODE: "raw" # Use 'bitwarden' for the default format
      BACKUP_INTERVAL_HOURS: 12
      NODE_TLS_REJECT_UNAUTHORIZED: 0
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

| Variable                       | Description                                    | Required | Example                     |
| ------------------------------ | ---------------------------------------------- | -------- | --------------------------- |
| `BW_CLIENT_ID`                 | Bitwarden client ID for API authentication     | ✅        | `xxxx-xxxx-xxxx-xxxx`       |
| `BW_CLIENT_SECRET`             | Bitwarden client secret                        | ✅        | `your_client_secret`        |
| `BW_PASSWORD`                  | Master password for your vault                 | ✅        | `supersecret`               |
| `BW_SERVER`                    | Bitwarden or Vaultwarden server URL            | ✅        | `https://vault.example.com` |
| `BW_FILE_PASSWORD`             | Password to encrypt exported backup file       | ✅        | `strong_backup_password`    |
| `BACKUP_INTERVAL_HOURS`        | Alternative to cron expression (integer hours) | ❌        | `12`                        |
| `BACKUP_ENCRYPTION_MODE`       | `bitwarden` (default) or `raw` for portable AES-256-GCM encryption. | ❌ | `raw` |
| `RETAIN_DAYS`                  | Days to keep backups. `7` by default. Set to `0` to disable cleanup. | ❌ | `7` |
| `CRON_EXPRESSION`              | Cron string to schedule backups                | ❌        | `0 */12 * * *`              |
| `NODE_TLS_REJECT_UNAUTHORIZED` | Set to `0` for self-signed certs               | ❌        | `0`                         |

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

* Store `BW_FILE_PASSWORD` securely — it’s required for restoring backups.
* You can run this container alongside Vaultwarden on the same host or a separate machine.
* Combine with tools like `restic` or `rclone` to push backups to cloud storage.

---

## 🐳 Updating

To update to the latest version:

```bash
docker pull ghcr.io/mvfc/backvault:latest
```

If using docker compose:
```bash
docker compose pull
docker compose up -d
```

---

## 🪪 License

This project is licensed under the **AGPL-3.0 License**.
See LICENSE for details.

---

## 🤝 Contributing

Pull requests and issue reports are welcome!
Feel free to open a PR or discussion on GitHub.

---

**BackVault** — secure, automated, encrypted vault backups.
