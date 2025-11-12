from fastapi.testclient import TestClient
from src.init import app, DB_PATH, PRAGMA_KEY_FILE
from unittest.mock import patch, MagicMock

client = TestClient(app)


def test_health_check():
    """
    Tests the /health endpoint.
    """
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_index():
    """
    Tests the / endpoint.
    """
    response = client.get("/")
    assert response.status_code == 200
    assert "<h3>Setup complete.</h3>" not in response.text


@patch("src.init.db_connect")
@patch("src.init.put_key")
def test_init(mock_put_key, mock_db_connect):
    """
    Tests the /init endpoint.
    """
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_db_connect.return_value = (mock_conn, mock_cursor)

    response = client.post(
        "/init",
        data={
            "master_password": "test_master_password",
            "client_id": "test_client_id",
            "client_secret": "test_client_secret",
            "file_password": "test_file_password",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["location"] == "/done"
    mock_db_connect.assert_called_once_with(DB_PATH, PRAGMA_KEY_FILE)
    mock_put_key.assert_any_call(mock_conn, "master_password", b"test_master_password")
    mock_put_key.assert_any_call(mock_conn, "client_id", b"test_client_id")
    mock_put_key.assert_any_call(mock_conn, "client_secret", b"test_client_secret")
    mock_put_key.assert_any_call(mock_conn, "file_password", b"test_file_password")
    mock_conn.close.assert_called_once()


@patch("src.init.db_connect", return_value=(None, None))
def test_init_db_connection_fails(mock_db_connect):
    """
    Tests that the /init endpoint handles a database connection failure.
    """
    response = client.post(
        "/init",
        data={
            "master_password": "test_master_password",
            "client_id": "test_client_id",
            "client_secret": "test_client_secret",
            "file_password": "test_file_password",
        },
    )
    assert response.status_code == 500
    assert response.text == "Database connection failed"


@patch("src.init.os.kill")
@patch("src.init.time.sleep")
def test_done_endpoint(mock_sleep, mock_kill):
    """
    Tests the /done endpoint.
    """
    response = client.get("/done")
    assert response.status_code == 200
    assert "<h3>Setup complete.</h3>" in response.text
    mock_sleep.assert_called_once_with(0.5)
    mock_kill.assert_called_once()
