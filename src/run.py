import os
import logging
from bw_client import BitwardenClient
from datetime import datetime
from sys import stdout
import sqlcipher3
import hashlib
import base64
import uuid
from db import db_connect, get_key

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
    PRAGMA_KEY_FILE = os.getenv("PRAGMA_KEY_FILE", "/app/db/backvault.db.pragma")
    db_conn, db_cursor = db_connect(DB_PATH, PRAGMA_KEY_FILE)
    if not db_conn or not db_cursor:
        return
    
    # Vault access information
    client_id = get_key(db_conn, 'client_id')
    client_secret = get_key(db_conn, 'client_secret')
    master_pw = get_key(db_conn, 'master_password')
    file_pw = get_key(db_conn, 'file_password')

    server = require_env("BW_SERVER")

    # Configuration
    backup_dir = os.getenv("BACKUP_DIR", "/app/backups")
    log_file = os.getenv("LOG_FILE")  # Optional log file
    encryption_mode = os.getenv("BACKUP_ENCRYPTION_MODE", "bitwarden").lower()

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
