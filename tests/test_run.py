import pytest
from unittest.mock import patch, MagicMock
from src.run import main, require_env
import os
from pathlib import Path
from shutil import copy2
from subprocess import CompletedProcess


@patch("src.run.db_connect")
@patch("src.run.get_key")
@patch("src.bw_client.sprun")
@patch("src.run.BitwardenClient")
@patch.dict(
    os.environ,
    {
        "BW_SERVER": "https://test.server",
        "BACKUP_DIR": "/tmp/backups",
        "DB_PATH": "/tmp/db.db",
        "PRAGMA_KEY_FILE": "/tmp/db.key",
        "TEST_MODE": "1",
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
        "BACKUP_DIR": "/tmp/backups",
        "DB_PATH": "/tmp/db.db",
        "PRAGMA_KEY_FILE": "/tmp/db.key",
        "TEST_MODE": "1",
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
        "BACKUP_DIR": "/tmp/backups",
        "DB_PATH": "/tmp/db.db",
        "PRAGMA_KEY_FILE": "/tmp/db.key",
        "TEST_MODE": "1",
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
        "BACKUP_DIR": "/tmp/backups",
        "DB_PATH": "/tmp/db.db",
        "PRAGMA_KEY_FILE": "/tmp/db.key",
        "TEST_MODE": "1",
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
        "BACKUP_DIR": "/tmp/backups",
        "DB_PATH": "/tmp/db.db",
        "PRAGMA_KEY_FILE": "/tmp/db.key",
        "TEST_MODE": "1",
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


@patch("src.run.os.replace")
@patch("src.run.shutil.rmtree")
@patch("src.run.shutil.copy2")
@patch("src.run.db_connect")
@patch("src.run.get_key")
@patch("src.run.BitwardenClient")
@patch.dict(
    os.environ,
    {
        "BW_SERVER": "https://test.server",
        "DB_PATH": "/tmp/db.db",
        "PRAGMA_KEY_FILE": "/tmp/db.key",
        "TEST_MODE": "1",
        "BACKUP_ATTACHMENTS": "true",
    },
)
def test_main_attachments_archive_and_cleanup(
    mock_bw_client, mock_get_key, mock_db_connect, mock_copy, mock_rmtree,
    mock_replace
):
    """
    Tests that enabled attachment backup creates an archive with downloaded attachments and cleans up temporary files.
    """
    mock_db_connect.return_value = (MagicMock(), MagicMock())
    mock_get_key.side_effect = [
        "id",
        "secret",
        "master",
        "file_pw"
    ]
    mock_client_instance = mock_bw_client.return_value
    mock_client_instance.download_attachments.return_value = 2

    main()

    mock_client_instance.create_encrypted_archive.assert_called_once()
    args = mock_client_instance.create_encrypted_archive.call_args[0]
    archive_filename = Path(args[1]).name
    assert archive_filename.endswith("_attachments.7z") and args[2] == "file_pw"
    mock_rmtree.assert_called()
    assert mock_rmtree.call_args_list[0].args[0].startswith("/tmp/backvault_archive")
    assert mock_rmtree.call_args_list[1].args[0].startswith("/tmp/backvault_attachments")
    mock_copy.assert_called_once()
    staged_archive = mock_copy.call_args.args[1]
    assert Path(staged_archive).name.startswith(".backvault_archive_")
    assert Path(staged_archive).name != archive_filename
    mock_replace.assert_called_once()
    assert mock_replace.call_args.args[0] == staged_archive
    assert mock_replace.call_args.args[1].endswith(archive_filename)
    assert not Path(staged_archive).exists()


@pytest.mark.parametrize("existing_archive", [False, True])
@patch("src.run.shutil.copy2")
@patch("src.run.datetime")
@patch("src.run.BitwardenClient")
@patch("src.run.get_key")
@patch("src.run.db_connect")
@patch.dict(
    os.environ,
    {
        "BW_SERVER": "https://test.server",
        "DB_PATH": "/tmp/db.db",
        "PRAGMA_KEY_FILE": "/tmp/db.key",
        "TEST_MODE": "1",
        "BACKUP_ATTACHMENTS": "true",
    },
)
def test_main_attachment_copy_failure_preserves_final_path(
    mock_db_connect, mock_get_key, mock_bw_client, mock_datetime, mock_copy,
    tmp_path, existing_archive
):
    """
    Tests that a failure during the copy of the final archive preserves the existing archive if it exists, and cleans up temporary files.
    """
    mock_db_connect.return_value = (MagicMock(), MagicMock())
    mock_get_key.side_effect = [
        "id",
        "secret",
        "master",
        "file_pw"
    ]
    final_archive = Path("/tmp") / f"backup_{tmp_path.name}_attachments.7z"
    staged_files = []

    def create_archive(src_dir, archive_file, password):
        Path(archive_file).write_bytes(b"complete archive")

    def fail_copy(src, dst):
        staged_files.append(Path(dst))
        assert Path(dst).parent == final_archive.parent
        assert Path(dst) != final_archive
        Path(dst).write_bytes(b"partial")
        raise OSError("Copy failed")

    mock_copy.side_effect = fail_copy
    mock_datetime.now.return_value.strftime.return_value = tmp_path.name
    mock_client_instance = mock_bw_client.return_value
    mock_client_instance.download_attachments.return_value = 1
    mock_client_instance.create_encrypted_archive.side_effect = create_archive
    try:
        if existing_archive:
            final_archive.write_bytes(b"existing valid archive")

        with pytest.raises(OSError, match="Copy failed"):
            main()

        if existing_archive:
            assert final_archive.read_bytes() == b"existing valid archive"
        else:
            assert not final_archive.exists()
        assert len(staged_files) == 1
        assert not staged_files[0].exists()
        assert not Path(mock_client_instance.download_attachments.call_args.args[0]).exists()
        assert not Path(
            mock_client_instance.create_encrypted_archive.call_args.args[1]
        ).parent.exists()
        mock_client_instance.logout.assert_called_once()
    finally:
        final_archive.unlink(missing_ok=True)


@patch("src.run.shutil.copy2", wraps=copy2)
@patch("src.run.datetime")
@patch("src.run.BitwardenClient")
@patch("src.run.get_key")
@patch("src.run.db_connect")
@patch.dict(
    os.environ,
    {
        "BW_SERVER": "https://test.server",
        "DB_PATH": "/tmp/db.db",
        "PRAGMA_KEY_FILE": "/tmp/db.key",
        "TEST_MODE": "1",
        "BACKUP_ATTACHMENTS": "true",
    },
)
def test_main_attachment_copy_success_publishes_archive(
    mock_db_connect, mock_get_key, mock_bw_client, mock_datetime, mock_copy,
    tmp_path
):
    """
    Tests that a successful copy of the final archive publishes the archive and cleans up temporary files.
    """
    mock_db_connect.return_value = (MagicMock(), MagicMock())
    mock_get_key.side_effect = [
        "id",
        "secret",
        "master",
        "file_pw"
    ]
    mock_datetime.now.return_value.strftime.return_value = tmp_path.name
    final_archive = Path("/tmp") / f"backup_{tmp_path.name}_attachments.7z"
    mock_client_instance = mock_bw_client.return_value
    mock_client_instance.download_attachments.return_value = 1

    def create_archive(src_dir, archive_file, password):
        Path(archive_file).write_bytes(b"complete archive")

    mock_client_instance.create_encrypted_archive.side_effect = create_archive
    try:
        main()

        assert final_archive.read_bytes() == b"complete archive"
        mock_copy.assert_called_once()
        source_archive, staged_archive = map(Path, mock_copy.call_args.args)
        assert staged_archive.parent == final_archive.parent
        assert staged_archive != final_archive
        assert not staged_archive.exists()
        assert not source_archive.parent.exists()
        assert not Path(
            mock_client_instance.download_attachments.call_args.args[0]
        ).exists()
        mock_client_instance.logout.assert_called_once()
    finally:
        final_archive.unlink(missing_ok=True)


@pytest.mark.parametrize("failure_stage", ["download", "archive"])
@patch("src.run.shutil.rmtree")
@patch("src.run.db_connect")
@patch("src.run.get_key")
@patch("src.run.BitwardenClient")
@patch.dict(
    os.environ,
    {
        "BW_SERVER": "https://test.server",
        "DB_PATH": "/tmp/db.db",
        "PRAGMA_KEY_FILE": "/tmp/db.key",
        "TEST_MODE": "1",
        "BACKUP_ATTACHMENTS": "true",
    },
)
def test_main_attachment_failure_raises_exception(
    mock_bw_client, mock_get_key, mock_db_connect, mock_rmtree, failure_stage
):
    """
    Tests that a failure during attachment download or archive creation raises an exception and cleans up temporary files.
    """
    mock_db_connect.return_value = (MagicMock(), MagicMock())
    mock_get_key.side_effect = [
        "id",
        "secret",
        "master",
        "file_pw"
    ]
    mock_client_instance = mock_bw_client.return_value
    mock_client_instance.download_attachments.return_value = 2

    def fail_download(src_dir):
        raise RuntimeError("Download failed")

    def fail_archive(src_dir, archive_file, password):
        raise RuntimeError("Archive failed")

    if failure_stage == "download":
        mock_client_instance.download_attachments.side_effect = fail_download
    else:
        mock_client_instance.create_encrypted_archive.side_effect = fail_archive

    with pytest.raises(RuntimeError, match="failed"):
        main()

    mock_rmtree.assert_called()
    attachment_dir = mock_client_instance.download_attachments.call_args[0][0]
    assert mock_rmtree.call_args_list[-1].args[0] == attachment_dir
    if failure_stage == "archive":
        archive_file = mock_client_instance.create_encrypted_archive.call_args[0][1]
        assert mock_rmtree.call_args_list[0].args[0] == os.path.dirname(archive_file)
    mock_client_instance.logout.assert_called_once()


@patch("src.run.db_connect")
@patch("src.run.get_key")
@patch("src.run.BitwardenClient")
@patch.dict(
    os.environ,
    {
        "BW_SERVER": "https://test.server",
        "BACKUP_ENCRYPTION_MODE": "bitwarden",
        "DB_PATH": "/tmp/db.db",
        "PRAGMA_KEY_FILE": "/tmp/db.key",
        "TEST_MODE": "1",
        "BACKUP_ATTACHMENTS": "false",
    },
)
def test_main_attachments_disabled(mock_bw_client, mock_get_key, mock_db_connect):
    """
    Tests that disabled attachment backup skips attachment downloads and archive creation.
    """
    mock_db_connect.return_value = (MagicMock(), MagicMock())
    mock_get_key.side_effect = ["id", "secret", "master", "file_pw"]
    mock_client_instance = mock_bw_client.return_value

    main()

    mock_client_instance.export_bitwarden_encrypted.assert_called_once()
    mock_client_instance.download_attachments.assert_not_called()
    mock_client_instance.create_encrypted_archive.assert_not_called()
