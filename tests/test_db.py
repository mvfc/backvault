from unittest.mock import patch, MagicMock, mock_open, call
from src.db import init_db, db_connect, put_key, get_key
import sqlcipher3
import os


@patch("src.db.sqlcipher3.connect")
@patch("src.db.open", new_callable=mock_open)
@patch("src.db.hashlib.sha512")
@patch("src.db.uuid.uuid4")
@patch("src.db.base64.urlsafe_b64encode")
@patch.dict(
    os.environ,
    {
        "TEST_MODE": "1",
    },
)
def test_init_db_new_pragma_key(
    mock_b64encode, mock_uuid, mock_sha512, mock_file_open, mock_sql_connect
):
    """
    Tests that init_db creates a new pragma key when one doesn't exist.
    """
    mock_file_open.side_effect = [FileNotFoundError, MagicMock()]
    mock_uuid.return_value.bytes = b"test_uuid_bytes"
    mock_b64encode.return_value = b"test_b64_encoded_uuid"
    mock_sha512.return_value.digest.return_value = b"test_digest"

    init_db("/tmp/test.db", "/tmp/test.key")

    mock_file_open.assert_any_call("/tmp/test.key", "r")
    mock_file_open.assert_any_call("/tmp/test.key", "w")
    mock_sql_connect.assert_called_once_with("/tmp/test.db")
    conn = mock_sql_connect.return_value
    cursor = conn.cursor.return_value
    cursor.execute.assert_any_call("PRAGMA key='test_b64_encoded_uuid';")
    cursor.execute.assert_any_call("""
            CREATE TABLE IF NOT EXISTS keys (
                name TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
    conn.close.assert_called()


@patch("src.db.sqlcipher3.connect")
@patch.dict(
    os.environ,
    {
        "TEST_MODE": "1",
    },
)
@patch("src.db.open", new_callable=mock_open, read_data="key='test_pragma_key';")
def test_init_db_existing_pragma_key(mock_file_open, mock_sql_connect):
    """
    Tests that init_db uses an existing pragma key.
    """
    init_db("/tmp/test.db", "/tmp/test.key")

    mock_file_open.assert_called_once_with("/tmp/test.key", "r")
    mock_sql_connect.assert_called_once_with("/tmp/test.db")
    conn = mock_sql_connect.return_value
    cursor = conn.cursor.return_value
    cursor.execute.assert_any_call("PRAGMA key='test_pragma_key';")
    cursor.execute.assert_any_call("""
            CREATE TABLE IF NOT EXISTS keys (
                name TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
    conn.commit.assert_called()
    conn.close.assert_called()


@patch("src.db.os.path.exists", return_value=True)
@patch("src.db.sqlcipher3.connect")
@patch.dict(
    os.environ,
    {
        "TEST_MODE": "1",
    },
)
@patch("src.db.open", new_callable=mock_open, read_data="key='test_pragma_key';")
def test_db_connect(mock_file_open, mock_sql_connect, mock_path_exists):
    """
    Tests that db_connect connects to an existing database.
    """
    conn, cursor = db_connect("/tmp/test.db", "/tmp/test.key")

    mock_path_exists.assert_called_once_with("/tmp/test.db")
    mock_file_open.assert_called_once_with("/tmp/test.key", "r")
    mock_sql_connect.assert_called_once_with("/tmp/test.db")
    assert conn == mock_sql_connect.return_value
    assert cursor == conn.cursor.return_value
    calls = [
        call("PRAGMA key='test_pragma_key';"),
        call("PRAGMA journal_mode = WAL"),
        call("PRAGMA synchronous = FULL"),
    ]
    cursor.execute.assert_has_calls(calls)
    assert cursor.execute.call_count == 3


@patch("src.db.os.path.exists", return_value=False)
@patch("src.db.init_db")
@patch.dict(
    os.environ,
    {
        "TEST_MODE": "1",
    },
)
def test_db_connect_no_db_file(mock_init_db, mock_path_exists):
    """
    Tests that db_connect calls init_db if the database file does not exist.
    """
    db_connect("/tmp/test.db", "/tmp/test.key")
    mock_init_db.assert_called_once_with("/tmp/test.db", "/tmp/test.key")


def test_put_key():
    """
    Tests that put_key inserts or replaces a key-value pair.
    """
    conn = MagicMock(spec=sqlcipher3.Connection)
    put_key(conn, "test_name", "test_value")
    conn.execute.assert_called_once_with(
        "INSERT OR REPLACE INTO keys (name, value) VALUES (?, ?)",
        ("test_name", "test_value"),
    )

def test_get_key():
    """
    Tests that get_key retrieves a value by its name.
    """
    conn = MagicMock(spec=sqlcipher3.Connection)
    conn.execute.return_value.fetchone.return_value = ("test_value",)
    value = get_key(conn, "test_name")
    conn.execute.assert_called_once_with(
        "SELECT value FROM keys WHERE name = ?", ("test_name",)
    )
    assert value == "test_value"


def test_get_key_bytes_value():
    """
    Tests that get_key retrieves a bytes value and decodes it.
    """
    conn = MagicMock(spec=sqlcipher3.Connection)
    conn.execute.return_value.fetchone.return_value = (b"test_value",)
    value = get_key(conn, "test_name")
    assert value == "test_value"
