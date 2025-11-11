import sqlcipher3
import hashlib
import base64
import uuid
import logging
from sys import stdout
import os

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s: %(message)s",
    handlers=[logging.StreamHandler(stdout)],
)
logger = logging.getLogger(__name__)


def init_db(db_path: str, PRAGMA_KEY_FILE: str) -> None:
    logging.info(f"Initializing database, attempting to find or create pragma key at {PRAGMA_KEY_FILE}")
    try:
        with open(PRAGMA_KEY_FILE, "r") as f:
            PRAGMA_KEY = f.read().strip()
        logging.debug(f"Pragma key loaded from file.")
    except FileNotFoundError:
        t_sha = hashlib.sha512()
        t_sha.update(base64.urlsafe_b64encode(uuid.uuid4().bytes) + base64.urlsafe_b64encode(uuid.uuid4().bytes))
        hashed_pragma = base64.urlsafe_b64encode(t_sha.digest())
        PRAGMA_KEY = f"key='{hashed_pragma.__str__()[2:-1]}';"
        logging.debug(f"New Pragma key generated.")
        try:
            with open(PRAGMA_KEY_FILE, "w") as f:
                f.write(PRAGMA_KEY)
            logging.debug("Pragma saved to file.")
        except Exception as e:
            logging.error(f"Failed to save pragma to file: {e}")
            return
    try:
        conn = sqlcipher3.connect(db_path)
    except Exception as e:
        logging.error(f"Failed to create database file: {e}")
        return

    logging.info("Database file created.")
    cursor = conn.cursor()

    cursor.execute(f"PRAGMA {PRAGMA_KEY}")
    conn.commit()
    logging.info("Pragma set. Database encrypted.")

    logging.info("Creating table.")
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                name TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        logging.info("Table created.")
        conn.commit()
    except Exception as e:
        logging.error(f"Failed to create tables: {e}")
    finally:
        conn.close()

def db_connect(db_path: str, PRAGMA_KEY_FILE: str) -> tuple[sqlcipher3.Connection | None, sqlcipher3.Cursor | None]:
    logging.info(f"Connecting to database at {db_path}")
    if not os.path.exists(db_path):
        logging.error("Database file does not exist.")
        init_db(db_path, PRAGMA_KEY_FILE)
    try:
        with open(PRAGMA_KEY_FILE, "r") as f:
            PRAGMA_KEY = f.read().strip()
            logging.debug("Pragma loaded.")
    except Exception as e:
        logging.error(f"Failed to load pragma key from file: {e}")
        return None, None
    try:
        conn = sqlcipher3.connect(db_path)
    except Exception as e:
        logging.error(f"Failed to connect to database: {e}")
        return None, None
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA {PRAGMA_KEY}")
    conn.commit()
    return conn, cursor

def put_key(conn: sqlcipher3.Connection, name, value) -> None:
    conn.execute("INSERT OR REPLACE INTO keys (name, value) VALUES (?, ?)", (name, value))
    conn.commit()

def get_key(conn: sqlcipher3.Connection, name: str) -> str:
    value = conn.execute("SELECT value FROM keys WHERE name = ?", (name,)).fetchone()[0]
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    return value