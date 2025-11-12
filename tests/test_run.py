import pytest
from unittest.mock import patch, MagicMock
from src.run import main, require_env
import os
from subprocess import CompletedProcess


@patch("src.run.db_connect")
@patch("src.run.get_key")
@patch("src.bw_client.sprun")
@patch("src.run.BitwardenClient")
@patch.dict(
    os.environ,
    {
        "BW_SERVER": "https://test.server",
        "BACKUP_DIR": "/tmp",
        "DB_PATH": "/tmp/db.db",
        "PRAGMA_KEY_FILE": "/tmp/db.key",
    },
)
def test_main_bitwarden_encryption(
    mock_bw_client, mock_sprun, mock_get_key, mock_db_connect
):
    """
    Tests the main function with 'bitwarden' encryption mode.
    """
    mock_db_connect.return_value = (MagicMock(), MagicMock())
    mock_get_key.side_effect = [
        "test_client_id",
        "test_client_secret",
        "test_master_pw",
        "test_file_pw",
    ]
    mock_client_instance = mock_bw_client.return_value
    mock_sprun.return_value = CompletedProcess(
        args=[], returncode=0, stdout="", stderr=""
    )

    main()

    mock_db_connect.assert_called_once()
    mock_get_key.assert_any_call(mock_db_connect.return_value[0], "client_id")
    mock_bw_client.assert_called_once_with(
        bw_cmd="bw",
        server="https://test.server",
        client_id="test_client_id",
        client_secret="test_client_secret",
        use_api_key=True,
    )
    mock_client_instance.login.assert_called_once()
    mock_client_instance.unlock.assert_called_once_with("test_master_pw")
    mock_client_instance.export_bitwarden_encrypted.assert_called_once()
    mock_client_instance.logout.assert_called_once()


@patch("src.run.db_connect")
@patch("src.run.get_key")
@patch("src.bw_client.sprun")
@patch("src.run.BitwardenClient")
@patch.dict(
    os.environ,
    {
        "BW_SERVER": "https://test.server",
        "BACKUP_ENCRYPTION_MODE": "raw",
        "BACKUP_DIR": "/tmp",
        "DB_PATH": "/tmp/db.db",
        "PRAGMA_KEY_FILE": "/tmp/db.key",
    },
)
def test_main_raw_encryption(mock_bw_client, mock_sprun, mock_get_key, mock_db_connect):
    """
    Tests the main function with 'raw' encryption mode.
    """
    mock_db_connect.return_value = (MagicMock(), MagicMock())
    mock_get_key.side_effect = [
        "test_client_id",
        "test_client_secret",
        "test_master_pw",
        "test_file_pw",
    ]
    mock_client_instance = mock_bw_client.return_value
    mock_sprun.return_value = CompletedProcess(
        args=[], returncode=0, stdout="", stderr=""
    )

    main()

    mock_db_connect.assert_called_once()
    mock_get_key.assert_any_call(mock_db_connect.return_value[0], "client_id")
    mock_bw_client.assert_called_once_with(
        bw_cmd="bw",
        server="https://test.server",
        client_id="test_client_id",
        client_secret="test_client_secret",
        use_api_key=True,
    )
    mock_client_instance.login.assert_called_once()
    mock_client_instance.unlock.assert_called_once_with("test_master_pw")
    mock_client_instance.export_raw_encrypted.assert_called_once()
    mock_client_instance.logout.assert_called_once()


@patch("src.run.db_connect")
@patch("src.run.get_key")
@patch("src.run.BitwardenClient")
@patch.dict(
    os.environ,
    {
        "BW_SERVER": "https://test.server",
        "BACKUP_ENCRYPTION_MODE": "invalid",
        "BACKUP_DIR": "/tmp",
        "DB_PATH": "/tmp/db.db",
        "PRAGMA_KEY_FILE": "/tmp/db.key",
    },
)
def test_main_invalid_encryption_mode(mock_bw_client, mock_get_key, mock_db_connect):
    """
    Tests that the main function handles an invalid encryption mode.
    """
    mock_db_connect.return_value = (MagicMock(), MagicMock())
    mock_get_key.side_effect = [
        "test_client_id",
        "test_client_secret",
        "test_master_pw",
        "test_file_pw",
    ]
    mock_client_instance = mock_bw_client.return_value

    main()

    mock_client_instance.export_bitwarden_encrypted.assert_not_called()
    mock_client_instance.export_raw_encrypted.assert_not_called()


@patch("src.run.db_connect")
@patch("src.run.get_key")
@patch("src.run.BitwardenClient")
@patch.dict(
    os.environ,
    {
        "BW_SERVER": "https://test.server",
        "BACKUP_DIR": "/tmp",
        "DB_PATH": "/tmp/db.db",
        "PRAGMA_KEY_FILE": "/tmp/db.key",
    },
)
def test_main_login_fails(mock_bw_client, mock_get_key, mock_db_connect):
    """
    Tests that the main function handles a login failure.
    """
    mock_db_connect.return_value = (MagicMock(), MagicMock())
    mock_get_key.side_effect = [
        "test_client_id",
        "test_client_secret",
        "test_master_pw",
        "test_file_pw",
    ]
    mock_client_instance = mock_bw_client.return_value
    mock_client_instance.login.side_effect = Exception("Login failed")

    main()

    mock_client_instance.unlock.assert_not_called()
    mock_client_instance.logout.assert_called_once()


@patch("src.run.db_connect")
@patch("src.run.get_key")
@patch("src.run.BitwardenClient")
@patch.dict(
    os.environ,
    {
        "BW_SERVER": "https://test.server",
        "BACKUP_DIR": "/tmp",
        "DB_PATH": "/tmp/db.db",
        "PRAGMA_KEY_FILE": "/tmp/db.key",
    },
)
def test_main_unlock_fails(mock_bw_client, mock_get_key, mock_db_connect):
    """
    Tests that the main function handles an unlock failure.
    """
    mock_db_connect.return_value = (MagicMock(), MagicMock())
    mock_get_key.side_effect = [
        "test_client_id",
        "test_client_secret",
        "test_master_pw",
        "test_file_pw",
    ]
    mock_client_instance = mock_bw_client.return_value
    mock_client_instance.unlock.side_effect = Exception("Unlock failed")

    main()

    mock_client_instance.export_bitwarden_encrypted.assert_not_called()
    mock_client_instance.logout.assert_called_once()


def test_require_env_missing():
    """
    Tests that require_env raises a RuntimeError for a missing environment variable.
    """
    with pytest.raises(
        RuntimeError, match="Missing required environment variable: MISSING_VAR"
    ):
        require_env("MISSING_VAR")


@patch.dict(os.environ, {"EXISTING_VAR": "test_value"})
def test_require_env_exists():
    """
    Tests that require_env returns the value of an existing environment variable.
    """
    assert require_env("EXISTING_VAR") == "test_value"
