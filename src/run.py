import os
import json
import logging
from src.bw_client import BitwardenClient
from datetime import datetime
from sys import stdout
from src.db import db_connect, get_key
from src.utils import validate_path
import re

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    handlers=[logging.StreamHandler(stdout)],
)
logger = logging.getLogger(__name__)


def require_env(name: str) -> str:
    val = os.getenv(name)
    if not val:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return val


def main():
    # Database setup
    DB_PATH = os.getenv("DB_PATH", "/app/db/backvault.db")
    DB_PATH = validate_path(DB_PATH, "/app")
    PRAGMA_KEY_FILE = os.getenv("PRAGMA_KEY_FILE", "/app/db/backvault.db.pragma")
    PRAGMA_KEY_FILE = validate_path(PRAGMA_KEY_FILE, "/app")
    db_conn, db_cursor = db_connect(DB_PATH, PRAGMA_KEY_FILE)
    if not db_conn or not db_cursor:
        return

    # Vault access information
    client_id = get_key(db_conn, "client_id")
    client_secret = get_key(db_conn, "client_secret")
    master_pw = get_key(db_conn, "master_password")
    file_pw = get_key(db_conn, "file_password")

    # Organization configuration
    org_ids_raw = get_key(db_conn, "organization_ids")
    org_export_mode_raw = get_key(db_conn, "org_export_mode")
    raw_value = org_export_mode_raw
    org_export_mode = raw_value if raw_value in ("single", "multiple", "none") else None
    if raw_value is not None and raw_value not in ("single", "multiple", "none"):
        logger.warning(f"Invalid org_export_mode '{raw_value}', ignoring")
    configured_org_ids = (
        [org.strip() for org in org_ids_raw.split(",") if org.strip()]
        if org_ids_raw
        else []
    )

    server = require_env("BW_SERVER")
    if (
        re.match(
            r"^(?:https?://)?(?:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3}|\w+)(:\d+)?(/[a-zA-Z0-9\-\._~/]*)?$",
            server,
        )
        is None
    ):
        logger.error(f"Invalid BW_SERVER URL: '{server}'")
        return

    # Configuration
    backup_dir = "/app/backups" if os.getenv("TEST_MODE") is None else "/tmp"  # nosec
    log_file = os.getenv("LOG_FILE")  # Optional log file
    log_file = validate_path(log_file, "/app")
    encryption_mode = os.getenv("BACKUP_ENCRYPTION_MODE", "bitwarden").lower()

    if encryption_mode not in ["bitwarden", "raw"]:
        logger.error(
            f"Invalid BACKUP_ENCRYPTION_MODE: '{encryption_mode}'. Must be 'bitwarden' or 'raw'."
        )
        return

    if log_file:
        logger.addHandler(logging.FileHandler(log_file))

    os.makedirs(backup_dir, exist_ok=True)

    # Create client
    logger.info("Connecting to vault...")
    source = BitwardenClient(
        bw_cmd="bw",
        server=server,
        client_id=client_id,
        client_secret=client_secret,
        use_api_key=True,
    )
    try:
        try:
            source.login()
        except Exception as e:
            logger.error(f"Login failed: {e}")
            return

        try:
            source.unlock(master_pw)
        except Exception as e:
            logger.error(f"Unlock failed: {e}")
            return

        # Determine org IDs to export (use configured or fetch all)
        if configured_org_ids:
            org_ids = configured_org_ids
            logger.info(f"Exporting configured organizations: {org_ids}")
        else:
            try:
                all_orgs = source.list_organizations()
                org_ids = [org.get("id") for org in all_orgs if org.get("id")]
                logger.info(f"Exporting all accessible organizations: {org_ids}")
            except Exception as e:
                logger.warning(
                    f"Failed to fetch organizations: {e}. No orgs will be exported."
                )
                org_ids = []

        # Validate org IDs to prevent path traversal in filenames
        # Keep original org_ids for export calls, create separate map for safe filenames
        safe_suffixes = {}
        seen_suffixes = {}
        for org_id in org_ids:
            if org_id is None:
                continue
            safe_id = re.sub(r"[^a-zA-Z0-9_-]", "_", org_id)
            if safe_id != org_id:
                logger.warning(
                    f"Org ID '{org_id}' contains unsafe characters, replaced with '{safe_id}'"
                )
            # Handle collisions by appending counter
            if safe_id in seen_suffixes:
                counter = seen_suffixes[safe_id] + 1
                seen_suffixes[safe_id] = counter
                safe_id = f"{safe_id}_{counter}"
            else:
                seen_suffixes[safe_id] = 0
            safe_suffixes[org_id] = safe_id

        # Generate timestamped filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        has_orgs = len(org_ids) > 0

        # Export personal vault
        if has_orgs:
            personal_file = os.path.join(backup_dir, f"backup_{timestamp}_personal.enc")
        else:
            personal_file = os.path.join(backup_dir, f"backup_{timestamp}.enc")

        logger.info(f"Starting export with mode: '{encryption_mode}'")

        if encryption_mode == "raw":
            source.export_raw_encrypted(personal_file, file_pw)
        elif encryption_mode == "bitwarden":
            source.export_bitwarden_encrypted(personal_file, file_pw)
        else:
            logger.error(
                f"Invalid BACKUP_ENCRYPTION_MODE: '{encryption_mode}'. Must be 'bitwarden' or 'raw'."
            )
            return

        logger.info(f"Personal vault export completed to {personal_file}.")

        # Export organizations
        # None means default to multiple (export all orgs)
        if org_export_mode is None:
            org_export_mode = "multiple"
            logger.info("org_export_mode not configured, defaulting to 'multiple'")

        if org_export_mode == "none":
            logger.info("Organization exports disabled by user configuration")
        elif org_export_mode == "single" and has_orgs:
            if encryption_mode == "raw":
                all_org_data = {}
                for org_id in org_ids:
                    try:
                        org_data = source.export_organization_raw(org_id)
                        all_org_data[org_id] = org_data
                    except Exception as e:
                        logger.warning(
                            f"Failed to export organization {org_id}: {e}. Skipping org."
                        )

                if not all_org_data:
                    logger.error(
                        f"No organizations exported successfully. "
                        f"Skipping combined org backup (backup_{timestamp}_orgs.enc)."
                    )
                else:
                    combined_data = json.dumps(all_org_data).encode("utf-8")
                    encrypted_data = source.encrypt_data(combined_data, file_pw)
                    org_file = os.path.join(backup_dir, f"backup_{timestamp}_orgs.enc")
                    with open(org_file, "wb") as f:
                        f.write(encrypted_data)
                    logger.info(f"Organization export completed to {org_file}.")

            elif encryption_mode == "bitwarden":
                logger.warning(
                    "org_export_mode='single' is not supported with encryption_mode='bitwarden'. "
                    "Skipping org export. Use org_export_mode='multiple' or switch to "
                    "encryption_mode='raw' to export organizations."
                )

        elif org_export_mode == "multiple" and has_orgs:
            for org_id in org_ids:
                safe_suffix = safe_suffixes.get(org_id, org_id)
                org_file = os.path.join(
                    backup_dir, f"backup_{timestamp}_org-{safe_suffix}.enc"
                )
                try:
                    if encryption_mode == "raw":
                        source.export_organization_raw_encrypted(
                            org_file, file_pw, org_id
                        )
                    elif encryption_mode == "bitwarden":
                        source.export_organization_bitwarden(org_file, file_pw, org_id)
                    logger.info(f"Organization export completed: {org_file}")
                except Exception as e:
                    logger.warning(
                        f"Failed to export organization {org_id}: {e}. Skipping org."
                    )
    finally:
        source.logout()
        logger.info("Successfully logged out.")


if __name__ == "__main__":
    main()
