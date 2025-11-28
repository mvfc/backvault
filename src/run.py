import os
import logging
from src.bw_client import BitwardenClient, BitwardenError
from datetime import datetime
from sys import stdout
from src.db import db_connect, get_key
from pathlib import Path
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

def _validate_backup_path(self, backup_file: str, allowed_base: str = "/app/backups") -> str:
    """
    Validate that the backup file path is within the allowed directory.
    Prevents path traversal attacks.
    """
    backup_path = Path(backup_file).resolve()
    allowed_path = Path(allowed_base).resolve()
    
    try:
        backup_path.relative_to(allowed_path)
    except ValueError:
        raise BitwardenError(f"Invalid backup path: must be within {allowed_base}")
    
    # Validate filename contains only safe characters
    if not re.match(r'^[a-zA-Z0-9._-]+$', backup_path.name):
        raise BitwardenError("Invalid filename: only alphanumeric, dots, dashes allowed")
    
    return str(backup_path)


def main():
    # Database setup
    DB_PATH = os.getenv("DB_PATH", "/app/db/backvault.db")
    _validate_backup_path(DB_PATH, "/app/db")
    PRAGMA_KEY_FILE = os.getenv("PRAGMA_KEY_FILE", "/app/db/backvault.db.pragma")
    _validate_backup_path(PRAGMA_KEY_FILE, "/app/db")
    db_conn, db_cursor = db_connect(DB_PATH, PRAGMA_KEY_FILE)
    if not db_conn or not db_cursor:
        return

    # Vault access information
    client_id = get_key(db_conn, "client_id")
    client_secret = get_key(db_conn, "client_secret")
    master_pw = get_key(db_conn, "master_password")
    file_pw = get_key(db_conn, "file_password")

    server = require_env("BW_SERVER")
    if re.match(r'^(?:https?://)?(?:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3}|localhost)(:\d+)?(/[a-zA-Z0-9\-\._~/]*)?$', server) is None:
        logger.error(f"Invalid BW_SERVER URL: '{server}'")
        return

    # Configuration
    backup_dir = os.getenv("BACKUP_DIR", "/app/backups")
    _validate_backup_path(backup_dir, "/app/backups")
    log_file = os.getenv("LOG_FILE")  # Optional log file
    _validate_backup_path(log_file, "/app/logs")
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

        # Generate timestamped filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(backup_dir, f"backup_{timestamp}.enc")

        logger.info(f"Starting export with mode: '{encryption_mode}'")

        if encryption_mode == "raw":
            source.export_raw_encrypted(backup_file, file_pw)
        elif encryption_mode == "bitwarden":
            source.export_bitwarden_encrypted(backup_file, file_pw)
        else:
            logger.error(
                f"Invalid BACKUP_ENCRYPTION_MODE: '{encryption_mode}'. Must be 'bitwarden' or 'raw'."
            )
            return

        logger.info(f"Export completed successfully to {backup_file}.")
    finally:
        source.logout()
        logger.info("Successfully logged out.")


if __name__ == "__main__":
    main()
