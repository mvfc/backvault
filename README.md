[![CI](https://github.com/mvfc/backvault/actions/workflows/ci.yml/badge.svg)](https://github.com/mvfc/backvault/actions/workflows/ci.yml) [![Release CI](https://github.com/mvfc/backvault/actions/workflows/release.yml/badge.svg)](https://github.com/mvfc/backvault/actions/workflows/release.yml) [![CodeQL](https://github.com/mvfc/backvault/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/mvfc/backvault/actions/workflows/github-code-scanning/codeql) [![GitHub version](https://badge.fury.io/gh/mvfc%2Fbackvault.svg?icon=si%3Agithub)](https://badge.fury.io/gh/mvfc%2Fbackvault) ![Docker Pulls](https://img.shields.io/docker/pulls/mvflc/backvault) ![Python Version from PEP 621 TOML](https://img.shields.io/python/required-version-toml?tomlFilePath=https%3A%2F%2Fraw.githubusercontent.com%2Fmvfc%2Fbackvault%2Fmain%2Fpyproject.toml) ![GitHub License](https://img.shields.io/github/license/mvfc/backvault?label=license&link=https%3A%2F%2Fgithub.com%2Fmvfc%2Fbackvault%2FLICENSE)

---

<p align=center><img width="500" height="500" alt="image" src="https://github.com/user-attachments/assets/3ca55b47-b1c7-4002-a167-f5752605fa1a" /></p>

**BackVault** is a lightweight Dockerized multi-architecture service that periodically backs up your **Bitwarden** or **Vaultwarden** vaults into password-protected encrypted files.
It’s designed for hands-free, secure, and automated backups using the official Bitwarden CLI.

---

## 🚀 Features

* 🔒 Securely exports your vault using your Bitwarden credentials
* 🕐 Supports both **interval-based** and **cron-based** backup scheduling
* 💾 Password-protected backup files using AES encryption
* 🧹 **Automated Cleanup**: Automatically deletes old backups based on a configurable retention period.
* ✨ **Two Encryption Modes**: Choose between Bitwarden's native encrypted format or a portable, standard AES-256-GCM encrypted format.
* 🌐 Works with both Bitwarden Cloud and self-hosted Bitwarden/Vaultwarden
* 🐳 Runs fully containerized — no setup or local dependencies required

---

## 📦 Quick Start (Docker)

You can run BackVault directly using the **published Docker image**, no build required.
You can use either the GitHub Registry image (`ghcr.io/mvfc/backvault`) or the Docker Hub image (`mvflc/backvault`).

All tags up from v2.0.0 are multi-architecture images and can be deployed to Linux/AMD64, Linux/ARM64 and Linux/ARM/v7 systems by just pointing to latest or the corresponding version tag.

Before running the Docker or Docker Compose commands, create the db and backup folders you will mount to on your host *WITHOUT* using sudo so they are owned by user 1000:1000 (which is unpriviledged). If you skip this step, you *MUST* do a `sudo chown -R 1000:1000 ./db` and a `sudo chown -R 1000:1000 ./backups`.

```bash
docker run -d \
  --name backvault \
  -e BW_SERVER="https://vault.yourdomain.com" \
  -e BACKUP_ENCRYPTION_MODE="raw" \
  -e BACKUP_INTERVAL_HOURS=12 \
  -v /path/to/backup:/app/backups \
  -v /path/to/db:/app/db \
  -p 8080:8080 \
  mvflc/backvault:latest
```

> 🔑 **Important**: The container uses the official Bitwarden CLI internally.
> Your credentials are only used to generate the export — they are **never stored** persistently and **never sent** anywhere else.

---

## 🧰 Initial Setup Flow

BackVault now includes a **secure one-time web-based setup UI** that replaces the need to pass sensitive credentials via environment variables.
When you start the container for the first time, it will:

1. Detect that no secure configuration exists yet.
2. Launch a **local-only setup UI** (FastAPI) on port `8080`.
3. Prompt you to enter your Bitwarden credentials and backup password.
4. Encrypt and store them in an **SQLCipher-encrypted SQLite database**, using a generated pragma key.
5. Securely store the encryption key and database inside the container volume, accessible only to the container’s internal user.

Once setup is complete:

* The UI **automatically shuts down**.
* The container transitions into normal mode and begins scheduled backups.
* All sensitive data is encrypted at rest — no plaintext secrets remain.

You can safely restart or update the container later without re-entering credentials, as long as the `/app/db` volume persists.

> 🧩 **Tip:** You can mount the `/app/db` directory to your host if you want to persist encrypted credentials across container updates.

---

## 🛡️ Security Architecture

The new version of BackVault is built around **principle of least privilege** and **container-isolated secrets**:

* 🧱 **Non-root container:** The service runs under an unprivileged user (`UID 1000`).
* 🔐 **Encrypted credential store:** All secrets (Bitwarden credentials, file encryption key and master password) are stored in an SQLCipher database using AES-256 encryption.
* 🔄 **No plaintext environment secrets:** You no longer need to define sensitive values like `BW_PASSWORD` or `BW_CLIENT_SECRET` as environment variables.
* 🕶️ **Ephemeral setup interface:** The setup UI is automatically destroyed after configuration to minimize attack surface and idle resource usage.

Together, these changes make BackVault one of the most secure self-hosted Bitwarden backup utilities available — suitable even for multi-user and shared-host environments.

---

## 🧩 Docker Compose Example

Here’s how to set it up with Docker Compose for easy management:

```yaml
services:
  backvault:
    image: mvflc/backvault:latest
    container_name: backvault
    restart: unless-stopped
    environment:
      BW_SERVER: "https://vault.yourdomain.com"
      BACKUP_ENCRYPTION_MODE: "raw" # Use 'bitwarden' for the default format
      BACKUP_INTERVAL_HOURS: 12
      NODE_TLS_REJECT_UNAUTHORIZED: 0
    volumes:
      - ./backups:/app/backups
      - ./db:/app/db
    ports:
      - "8080:8080"
```

Then run:

```bash
docker compose up -d
```

BackVault will automatically:

1. Log in to your Bitwarden/Vaultwarden instance
2. Export your vault
3. Encrypt it using the chosen file password
4. Store the backup in `/app/backups` (mounted to your host directory)
5. Logout after every backup

---

## ⚙️ Configuration

| Variable                       | Description                                    | Required | Example                     |
| ------------------------------ | ---------------------------------------------- | -------- | --------------------------- |
| `BW_SERVER`                    | Bitwarden or Vaultwarden server URL            | ✅        | `https://vault.example.com` |
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
The resulting `.enc` file contains: `[16-byte salt][12-byte nonce][encrypted data + 16-byte auth tag]`

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
PBKDF2_ITERATIONS = 600000

def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
    salt = encrypted_data[:SALT_SIZE]
    nonce = encrypted_data[SALT_SIZE:SALT_SIZE+12]
    ciphertext_with_tag = encrypted_data[SALT_SIZE+12:]
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS
    )
    key = kdf.derive(password.encode("utf-8"))
    
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, None)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <encrypted_file> [password]")
        sys.exit(1)
    
    file_path = sys.argv[1]
    password = sys.argv[2] if len(sys.argv) > 2 else getpass("Enter backup password: ")
    
    if file_path.endswith('.enc'):
        output_path = file_path[:-4] + '.json'
    else:
        output_path = file_path + '.json'
    
    try:
        with open(file_path, "rb") as f:
            encrypted_contents = f.read()
        
        decrypted_json = decrypt_data(encrypted_contents, password)
        
        with open(output_path, "wb") as f:
            f.write(decrypted_json)
        
        print(f"Decryption successful. Output saved to: {output_path}", file=sys.stderr)
    except InvalidTag:
        print("Decryption failed: Invalid password or corrupted file.", file=sys.stderr)
    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)
```

---

## 🧠 Tips

* Store your backup file password securely — it’s required for restoring backups.
* You can run this container alongside Vaultwarden on the same host or a separate machine.
* Combine with tools like `restic` or `rclone` to push backups to cloud storage.

---

## 🐳 Updating

To update to the latest version:

```bash
docker pull mvflc/backvault:latest
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

# ⚠️ Disclaimer

BackVault is provided "as is" and without any express or implied warranties, including, but not limited to, the implied warranties of merchantability and fitness for a particular purpose.

The maintainer and contributors assume no liability for any direct, indirect, incidental, special, exemplary, or consequential damages (including, but not limited to, procurement of substitute goods or services; loss of use, data, or profits; or business interruption) however caused and on any theory of liability, whether in contract, strict liability, or tort (including negligence or otherwise) arising in any way out of the use of this software, even if advised of the possibility of such damage.

You are solely responsible for verifying the integrity and restorability of your backups. Use of this software is entirely at your own risk.

---

## 🤝 Contributing

Pull requests and issue reports are welcome!
Feel free to open a PR or discussion on GitHub.

---

**BackVault** — secure, automated, encrypted vault backups.
