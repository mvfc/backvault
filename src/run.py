import os
import logging
from bw_client import BitwardenClient
from datetime import datetime
from sys import stdout

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler("/var/log/cron.log"),
        logging.StreamHandler(stdout)
    ]
)
logger = logging.getLogger(__name__)


def require_env(name: str) -> str:
    val = os.getenv(name)
    if not val:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return val


def main():
    # Vault access information
    client_id = require_env("BW_CLIENT_ID")
    client_secret = require_env("BW_CLIENT_SECRET")
    master_pw = require_env("BW_PASSWORD")
    server = require_env("BW_SERVER")
    file_pw = require_env("BW_FILE_PASSWORD")

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
    backup_file = f"/app/backups/backup_{timestamp}.enc"

    # Run export command
    logger.info(f"Exporting backup to {backup_file}...")

    try:
        source._run(
            cmd=[
                "export",
                "--output",
                backup_file,
                "--format",
                "json",
                "--password",
                file_pw,
            ],
            capture_json=False,  # No need to parse JSON output for this command
        )
    except Exception as e:
        logger.error(f"Export failed: {e}")
        return

    logger.info("Export completed successfully.")

    source.logout()

    logger.info("Successfully logged out.")


if __name__ == "__main__":
    main()
