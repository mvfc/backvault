import os
import sys
import logging
from pathlib import Path
from bw_client import BitwardenClient
from datetime import datetime
from sys import stdout

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


def validate_backup_dir(backup_dir: str) -> str:
    """
    Validate and sanitize the backup directory path.
    Prevents path traversal attacks.
    """
    ALLOWED_BASE = "/app"

    # Convert to absolute path
    backup_path = Path(backup_dir).resolve()
    allowed_base = Path(ALLOWED_BASE).resolve()

    # Check if path is within allowed base
    try:
        backup_path.relative_to(allowed_base)
    except ValueError:
        logger.critical(f"BACKUP_DIR '{backup_dir}' is outside allowed path '{ALLOWED_BASE}'")
        sys.exit(1)

    return str(backup_path)

def main():
    # Vault access information
    client_id = require_env("BW_CLIENT_ID")
    client_secret = require_env("BW_CLIENT_SECRET")
    master_pw = require_env("BW_PASSWORD")
    server = require_env("BW_SERVER")
    file_pw = require_env("BW_FILE_PASSWORD")

    # Configuration
    backup_dir_raw = os.getenv("BACKUP_DIR", "/app/backups")
    log_file = os.getenv("LOG_FILE")  # Optional log file

    # Validate backup directory
    backup_dir = validate_backup_dir(backup_dir_raw)

    # Validate encryption mode with strict whitelist
    ALLOWED_MODES = {"raw", "bitwarden"}
    encryption_mode_raw = os.getenv("BACKUP_ENCRYPTION_MODE", "bitwarden")
    encryption_mode = encryption_mode_raw.lower().strip()

    if encryption_mode not in ALLOWED_MODES:
        logger.critical(
            f"Invalid BACKUP_ENCRYPTION_MODE: '{encryption_mode_raw}'. "
            f"Must be one of {ALLOWED_MODES}."
        )
        sys.exit(1)

    if log_file:
        logger.addHandler(logging.FileHandler(log_file))

    # Create backup directory with secure permissions
    os.makedirs(backup_dir, mode=0o700, exist_ok=True)

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
            sys.exit(1)

        try:
            source.unlock(master_pw)
        except Exception as e:
            logger.error(f"Unlock failed: {e}")
            sys.exit(1)

        # Generate timestamped filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(backup_dir, f"backup_{timestamp}.enc")

        logger.info(f"Starting export with mode: '{encryption_mode}'")

        try:
            if encryption_mode == "raw":
                source.export_raw_encrypted(backup_file, file_pw, backup_dir)
            elif encryption_mode == "bitwarden":
                source.export_bitwarden_encrypted(backup_file, file_pw, backup_dir)

            logger.info(f"Export completed successfully.")
        except Exception as e:
            logger.error(f"Export failed: {e}")
            sys.exit(1)

    finally:
        try:
            source.logout()
            logger.info("Successfully logged out.")
        except Exception as e:
            logger.warning(f"Logout encountered an error: {e}")


if __name__ == "__main__":
    main()
