# 🗄️ BackVault

**BackVault** is a lightweight Dockerized service that periodically backs up your **Bitwarden** or **Vaultwarden** vaults into password-protected encrypted files.  
It’s designed for hands-free, secure, and automated backups using the official Bitwarden CLI.

---

## 🚀 Features

- 🔒 Securely exports your vault using your Bitwarden credentials  
- 🕐 Supports both **interval-based** and **cron-based** backup scheduling  
- 💾 Password-protected backup files using AES encryption  
- 🌐 Works with both Bitwarden Cloud and self-hosted Vaultwarden (supports self-signed certs)  
- 🐳 Runs fully containerized — no setup or local dependencies required

---

## 📦 Quick Start (Docker)

You can run BackVault directly using the **published Docker image**, no build required.

```bash
docker run -d \
  --name backvault \
  -e BW_CLIENT_ID="your_client_id" \
  -e BW_CLIENT_SECRET="your_client_secret" \
  -e BW_PASSWORD="your_master_password" \
  -e BW_SERVER="https://vault.yourdomain.com" \
  -e BW_FILE_PASSWORD="backup_encryption_password" \
  -e CRON_EXPRESSION="0 */12 * * *" \
  -v /path/to/backup:/app/backups \
  ghcr.io/mvfc/backvault:latest
````

> 🔑 **Important**: The container uses the official Bitwarden CLI internally.
> Your credentials are only used to generate the export — they are **never stored** persistently.

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
      CRON_EXPRESSION: "0 */12 * * *"
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
| `CRON_EXPRESSION`              | Cron string to schedule backups                | ❌        | `0 */12 * * *`              |
| `NODE_TLS_REJECT_UNAUTHORIZED` | Set to `0` for self-signed certs               | ❌        | `0`                         |

---

## 🔐 Backup Output

* Encrypted backup files are saved to `/app/backups`
* Files are timestamped, e.g.:

  ```
  backup_20251106_210613.enc
  ```
* To decrypt manually:

  ```bash
  openssl enc -d -aes-256-cbc -in file.enc -out vault.json -pass pass:your_backup_password
  ```

---

## 🧠 Tips

* Use a dedicated Bitwarden service account for backups.
* Store `BW_FILE_PASSWORD` securely — it’s required for restoring backups.
* You can run this container alongside Vaultwarden on the same host or a separate machine.
* Combine with tools like `restic` or `rclone` to push backups to cloud storage.

---

## 🐳 Updating

To update to the latest version:

```bash
docker pull ghcr.io/mvfc/backvault:latest
docker compose up -d
```

---

## 🪪 License

This project is licensed under the **AGPL-3.0 License**.
See [LICENSE](./LICENSE) for details.

---

## 🤝 Contributing

Pull requests and issue reports are welcome!
Feel free to open a PR or discussion on [GitHub](https://github.com/mvfc/backvault).

---

**BackVault** — secure, automated, encrypted vault backups.
