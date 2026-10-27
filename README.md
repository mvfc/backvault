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
* 📎 **Attachment Backups**: Packs all item attachments into an AES-256 encrypted 7-zip archive, with encrypted file names.
* 🌐 Works with both Bitwarden Cloud and self-hosted Bitwarden/Vaultwarden
* 🐳 Runs fully containerized — no setup or local dependencies required
* 🏢 **Multi-Organization Support**: Export multiple organizations with flexible output options

---

## 📦 Quick Start (Docker)

You can run BackVault directly using the **published Docker image**, no build required.
You can use either the GitHub Registry image (`ghcr.io/mvfc/backvault`) or the Docker Hub image (`mvflc/backvault`).

All tags up from v2.0.0 are multi-architecture images and can be deployed to Linux/AMD64, Linux/ARM64 and Linux/ARM/v7 systems by just pointing to latest or the corresponding version tag.

If you're mounting the db to a NFS mount, make sure your NFS server has the export configured with ```no_root_squash``` and your clients mounts with ```local_lock=all,sync,intr```.

```bash
docker run -d \
  --name backvault \
  -e BW_SERVER="https://vault.yourdomain.com" \
  -e BACKUP_ENCRYPTION_MODE="raw" \
  -e BACKUP_INTERVAL_HOURS=12 \
  -e TZ="Europe/Amsterdam" \
  -v /path/to/backup:/app/backups \
  -v /path/to/db:/app/db \
  -p 8080:8080 \
  mvflc/backvault:latest
```

> 🔑 **Important**: The container uses the official Bitwarden CLI internally.
> Your credentials are only used to generate the export — they are **never stored** persistently and **never sent** anywhere else.

---

## 🔒Credentials

The credentials used here are your master password (necessary to unlock the Vault), API Client and Secret (which can be found under Settings > Security > Keys on both Bitwarden and Vaultwarden web) and an encryption password for the backup.

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

* 🧱 **Non-root container:** The service runs under an unprivileged user (Default `UID 1000`).
* 🔐 **Encrypted credential store:** All secrets (Bitwarden credentials, file encryption key and master password) are stored in an SQLCipher database using AES-256 encryption.
* 🔄 **No plaintext environment secrets:** You no longer need to define sensitive values like `BW_PASSWORD` or `BW_CLIENT_SECRET` as environment variables.
* 🕶️ **Ephemeral setup interface:** The setup UI is automatically destroyed after configuration to minimize attack surface and idle resource usage.

Together, these changes make BackVault one of the most secure self-hosted Bitwarden backup utilities available — suitable even for multi-user and shared-host environments.

---

## 🏢 Multi-Organization Export

BackVault supports backing up **multiple organizations** from your Bitwarden account. During setup, you can configure:

1. **Organization IDs**: Comma-separated list of organization IDs to export. Leave empty to auto-discover all accessible organizations. **Note:** Auto-discovered organizations require export permission; users can configure only organizations they can export.
2. **Export Mode**: Choose how organizations are exported:
   - **No organization exports (personal vault only)**: Skip organization exports (`none`).
   - **Single combined file**: All orgs merged into one encrypted file (`backup_{timestamp}_orgs.enc`)
   - **Separate files per organization**: Each org exported to its own file (`backup_{timestamp}_org-{org-id}.enc`)

If `org_export_mode` is missing, it defaults to `none`. Upgraded installs must rerun setup to enable organization exports.

The personal vault is exported separately (as `backup_{timestamp}.enc` or `backup_{timestamp}_personal.enc`) when the backup succeeds.

### Encryption Mode Compatibility

**Important:** There is a compatibility requirement between encryption mode and organization export mode:

- **`raw` encryption mode**: Supports both Single and Separate files export options, as well as personal vault only.
- **`bitwarden` encryption mode**: Supports Separate files per organization or personal vault only. Bitwarden CLI cannot produce a single merged org export.

The UI offers **"Single combined file"** regardless of encryption mode. Selecting it with the default `bitwarden` mode when there are organizations to export causes `main()` to return `1` before the personal vault is exported, producing no backup. To export organizations with `bitwarden`, select **"Separate files per organization"**; for a combined file, set `BACKUP_ENCRYPTION_MODE=raw`.

### Getting Organization IDs

Run this command after logging in to find your organization IDs:

```bash
bw list organizations
```

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
      PUID: 1000
      PGID: 1000
      TZ: Europe/Amsterdam # Set to your timezone according to this list https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
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
| `BACKUP_ENCRYPTION_MODE`       | `bitwarden` (default) or `raw` for portable AES-256-GCM encryption. **Note:** `raw` is required for Single org export mode. | ❌ | `bitwarden` |
| `BACKUP_ATTACHMENTS`           | Set to `true` to also back up item attachments into an encrypted 7-zip archive. | ❌ | `true` |
| `RETAIN_DAYS`                  | Days to keep backups. `7` by default. Set to `0` to disable cleanup. | ❌ | `7` |
| `CRON_EXPRESSION`              | Cron string to schedule backups                | ❌        | `0 */12 * * *`              |
| `NODE_TLS_REJECT_UNAUTHORIZED` | Set to `0` for self-signed certs               | ❌        | `0`                         |
| `TZ` | Timezone for the container according to https://en.wikipedia.org/wiki/List_of_tz_database_time_zones | ❌ | `UTC` |
| `PUID` | UID of the user to run as (non-root container) | ❌ | `1000` |
| `PGID` | GID of the user to run as (non-root container) | ❌ | `1000` |

> **Note:** Organization IDs and export mode are configured via the web setup UI, not environment variables. Use "Separate files per organization" when `BACKUP_ENCRYPTION_MODE=bitwarden` (default). 

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

### Attachments archive (`*_attachments.7z`)

If `BACKUP_ATTACHMENTS` is enabled, attachments from vault items the backup account can access are stored in a separate AES-256 encrypted 7-zip archive (`*_attachments.7z`), regardless of the encryption mode used for the JSON export. This includes organization-owned items shared with the backup account, but not organization items the account cannot access. It uses the same password as the JSON backup, and file names are encrypted too, so the password is required even to list the contents.

Extract it with any 7-Zip compatible tool:

```bash
# 7-Zip (7zz / 7z) – prompts for the password
7z x backup_20250101_120000_attachments.7z

# or with py7zr (pip install py7zr); prompts for the password
python -m py7zr x -P backup_20250101_120000_attachments.7z ./attachments
```

The result contains one folder per vault item, named after the item id (matching the `id` field in the JSON export), with that item's attachments inside:

```
<item-id-1>/document.pdf
<item-id-2>/photo.jpg
```

#### How to Recover and Re-attach Files

Once extracted, each folder name corresponds to an item's unique `id` in your decrypted vault JSON file.

* **Restoring to Bitwarden / Vaultwarden**:
  * **Web UI**: Open the corresponding item in your Web Vault, click **Edit**, scroll to the **Attachments** section, and upload the recovered file(s).
  * **Bitwarden CLI**: Use the Bitwarden CLI to upload attachments directly to an item:

    ```bash
    bw create attachment --file ./attachments/<item-id>/document.pdf --itemid <item-id>
    ```

    > *Note:* If you imported your vault JSON into a new account or instance, items will receive new IDs. To find an item's original `id` (which matches the `attachments/<original-id>/` folder name), look up the item using identifying fields (such as `name`, `login.username`, `login.uris`, or `type`): check your decrypted personal vault JSON export (`backup_*_personal.json` or `backup_*.json`) for personal items (`organizationId: null`), or the matching decrypted organization JSON export (`backup_*_org-<id>.json` or `org_<id>.json`) for organization-owned items (`organizationId` set). In `bitwarden` encryption mode (where `.enc` backups are imported directly without first producing a plaintext JSON file), record an old-to-new item mapping before/during migration or import the backup into an empty temporary vault/organization and run `bw list items` (or `bw export --format json`) to inspect item details, then pass the target item's new ID to `bw create attachment`.

* **Restoring to KeePass / KeePassXC**:
  * Open KeePassXC, locate the imported entry, click **Edit Entry**, navigate to the **Advanced** section, and click **Add Attachment** to select the files from `./attachments/<item-id>/`.

---

## 🏢 Organization Recovery & Universal Export

This section describes how to restore organization backups to a Bitwarden or Vaultwarden instance, import supported Bitwarden JSON exports (personal or organization) into **KeePass / KeePassXC**, or convert decrypted personal vault JSON backups into standard Bitwarden CSV for generic CSV-compatible password managers.

### 🔄 Recovering Organizations to Bitwarden / Vaultwarden

Depending on your configured export mode and encryption mode, follow the corresponding steps:

#### 1. Separate Organization Files (`backup_*_org-<id>.enc`)

* **`bitwarden` encryption mode**:
  * **Bitwarden Web Vault**: Log into Web Vault -> Open **Admin Console** for your Organization -> Go to **Settings** > **Import Data** -> Choose format **Bitwarden (JSON)** (the importer automatically detects encrypted JSON files) -> Select file and enter backup password.
  * **Vaultwarden Web Vault**: Log into Vaultwarden Web Vault -> Select Organization -> Go to **Settings** > **Import Data** -> Choose format **Bitwarden (encrypted JSON)** or **Bitwarden (JSON)** -> Select file and enter password.
  * **Bitwarden CLI**:

    ```bash
    bw import bitwardenjson /path/to/backup_timestamp_org-id.enc --organizationid <target-org-id>
    ```

* **`raw` encryption mode**:
  1. Decrypt the file using `decrypt.py` (see above) to obtain `backup_*_org-<id>.json`.
  2. Import into Web UI (Select format: **Bitwarden (JSON)**) or via CLI:

     ```bash
     bw import bitwardenjson /path/to/backup_timestamp_org-id.json --organizationid <target-org-id>
     ```

#### 2. Single Combined Organization File (`backup_*_orgs.enc`)

The single combined file is exported in `raw` encryption mode as a JSON object containing all organization vaults keyed by Organization ID: `{ "org-id-1": { ... }, "org-id-2": { ... } }`.

To restore individual organizations:
1. Decrypt the `.enc` file using `decrypt.py` to produce `backup_*_orgs.json`.
2. Extract the individual organization JSON files using this Python script:

   ```python
   # extract_orgs.py
   import json, re, sys

   if len(sys.argv) < 2:
       print(f"Usage: python {sys.argv[0]} <decrypted_orgs.json>")
       sys.exit(1)

   with open(sys.argv[1], "r", encoding="utf-8") as f:
       orgs = json.load(f)

   for org_id, org_data in orgs.items():
       safe_id = re.sub(r"[^a-zA-Z0-9_-]", "_", str(org_id))
       filename = f"org_{safe_id}.json"
       with open(filename, "w", encoding="utf-8") as f_out:
           json.dump(org_data, f_out, indent=2)
       print(f"Extracted {filename}")
   ```

   Run: `python extract_orgs.py backup_20250101_120000_orgs.json`

3. Import each extracted `org_<org-id>.json` into your target organization via the Web Vault (format: **Bitwarden (JSON)**) or Bitwarden CLI (`bw import bitwardenjson org_<org-id>.json --organizationid <target-org-id>`).

---

### 🌐 Transforming Backups to Universal Export Formats (KeePass, 1Password, etc.)

If you need to migrate your backups to another password manager such as **KeePassXC**, **1Password**, or generic CSV-compatible applications:

#### Option A: Direct Import into KeePassXC (Recommended)

KeePassXC natively supports importing Bitwarden JSON exports:

1. Obtain unencrypted JSON depending on your backup encryption mode:
   - **`raw` mode**: Decrypt the `.enc` file using `decrypt.py` (or extract individual organization JSONs using `extract_orgs.py` for combined org backups).
   - **`bitwarden` mode**: Decrypt and export to unencrypted JSON using Bitwarden CLI (`bw import bitwardenjson /path/to/backup.enc` followed by `bw export --format json`), or import the encrypted JSON file directly into KeePassXC if supported by your KeePassXC version. Run the import in an empty Bitwarden account or isolated vault. `bw import` adds the backup items to the logged-in vault, and `bw export` then includes the existing items too.
2. Open KeePassXC and go to **Database** > **Import** > **Bitwarden (JSON)...**
3. Select the unencrypted `.json` file to import your items and folder structure. Note that attachments are not restored by the JSON import; extract `*_attachments.7z` separately and attach the files to entries in KeePassXC as needed.

#### Option B: Converting Personal Bitwarden JSON to Standard Bitwarden CSV

For password managers that require CSV format, use this script to convert a decrypted personal Bitwarden vault JSON into standard Bitwarden personal CSV.

> **Note:** Bitwarden's standard personal CSV format only supports `login` and `note` items. Credit cards, identities, and attachments cannot be fully represented in CSV format without losing sensitive fields. This script processes `login` and `note` items, preserves item `reprompt` settings, and skips/reports card or identity items so data is not silently omitted. For full preservation of all item types, use Bitwarden JSON import/export.

```python
# bitwarden_to_csv.py
import json, csv, io, sys

if len(sys.argv) < 2:
    print(f"Usage: python {sys.argv[0]} <decrypted_personal_vault.json> [output.csv]")
    sys.exit(1)

json_file = sys.argv[1]
csv_file = sys.argv[2] if len(sys.argv) > 2 else json_file.rsplit('.', 1)[0] + '.csv'

with open(json_file, 'r', encoding='utf-8') as f:
    data = json.load(f)

if data.get('encrypted'):
    print("Error: Input JSON is encrypted. Decrypt it before converting to CSV.", file=sys.stderr)
    sys.exit(1)

if 'collections' in data and 'folders' not in data:
    print("Error: Organization JSON export detected. This script only converts personal vault JSON exports.", file=sys.stderr)
    sys.exit(1)

items = data.get('items') or []
folders = {f['id']: f.get('name') or '' for f in (data.get('folders') or []) if f.get('id')}

headers = ['folder', 'favorite', 'type', 'name', 'notes', 'fields', 'reprompt', 'login_uri', 'login_username', 'login_password', 'login_totp']

type_labels = {3: 'card', 4: 'identity', 5: 'sshKey'}
skipped_items = []
converted_count = 0

with open(csv_file, 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(headers)

    for item in items:
        item_type = item.get('type', 1)
        name = item.get('name') or 'Unnamed Item'

        # 1: login, 2: note
        if item_type not in (1, 2):
            type_label = type_labels.get(item_type, f'unknown ({item_type})')
            skipped_items.append(f"'{name}' (type: {type_label})")
            continue

        type_str = 'login' if item_type == 1 else 'note'
        folder_name = folders.get(item.get('folderId'), '')
        favorite = '1' if item.get('favorite') else '0'
        notes = item.get('notes') or ''

        fields_list = [
            f"{field.get('name') or ''}: {field.get('value') or ''}"
            for field in (item.get('fields') or [])
            if field.get('name') or field.get('value')
        ]
        fields_str = '\n'.join(fields_list)

        reprompt_val = item.get('reprompt')
        reprompt_str = str(reprompt_val) if reprompt_val is not None else '0'

        login = item.get('login') or {}
        uris = [u.get('uri') for u in (login.get('uris') or []) if u.get('uri')]
        if uris:
            uri_buf = io.StringIO()
            csv.writer(uri_buf, lineterminator='').writerow(uris)
            login_uri = uri_buf.getvalue()
        else:
            login_uri = ''
        username = login.get('username') or ''
        password = login.get('password') or ''
        totp = login.get('totp') or ''

        writer.writerow([folder_name, favorite, type_str, name, notes, fields_str, reprompt_str, login_uri, username, password, totp])
        converted_count += 1

print(f"Successfully converted {converted_count} item(s) to {csv_file}")
if skipped_items:
    print(f"Warning: Skipped {len(skipped_items)} item(s) not supported by standard CSV format:\n  " + "\n  ".join(skipped_items), file=sys.stderr)
    print("Tip: Use standard Bitwarden JSON format to import/export credit cards and identity items without data loss.", file=sys.stderr)
```

Run:

```bash
python bitwarden_to_csv.py backup_20250101_120000.json output.csv
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

## Support the developer

Some people asked me if they could buy me a coffee or something so I set up a BuyMeACoffee. But please don't feel obligated to, I do this on my free time because I enjoy it, but any support is appreciated and help me get more free time to devote to the codebase.  

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/yellow_img.png)](https://www.buymeacoffee.com/mvfc)

---

**BackVault** — secure, automated, encrypted vault backups.
