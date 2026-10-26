import pytest
from unittest.mock import patch, MagicMock
import unittest
from src.run import main, require_env
import os
from pathlib import Path
from shutil import copy2
from subprocess import CompletedProcess


@patch("src.run.db_connect")
@patch("src.run.get_key")
@patch.dict(
    os.environ,
    {
        "BW_SERVER": "https://test.server",
        "DB_PATH": "/tmp/db.db",
        "PRAGMA_KEY_FILE": "/tmp/db.key",
        "TEST_MODE": "1",
    },
)
def test_main_missing_database_settings(mock_get_key, mock_db_connect, caplog):
    """
    Tests that main logs missing settings and returns 1 when required DB keys are missing.
    """
    mock_db_connect.return_value = (MagicMock(), MagicMock())
    mock_get_key.side_effect = ["test_client_id", None, None, "test_file_pw"]

    with caplog.at_level("ERROR"):
        result = main()

    assert result == 1
    assert "client_secret" in caplog.text
    assert "master_password" in caplog.text
    assert "Please rerun setup" in caplog.text


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
        "",  # organization_ids (empty)
        "multiple",  # org_export_mode
    ]
    mock_client_instance = mock_bw_client.return_value
    mock_sprun.return_value = CompletedProcess(
        args=[], returncode=0, stdout="", stderr=""
    )
    mock_client_instance.list_organizations = MagicMock(
        return_value=[{"id": "org-1"}, {"id": "org-2"}]
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
    mock_client_instance.list_organizations.assert_called_once()


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
        "",  # organization_ids (empty)
        "multiple",  # org_export_mode
    ]
    mock_client_instance = mock_bw_client.return_value
    mock_sprun.return_value = CompletedProcess(
        args=[], returncode=0, stdout="", stderr=""
    )
    mock_client_instance.list_organizations = MagicMock(
        return_value=[{"id": "org-1"}, {"id": "org-2"}]
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
    mock_client_instance.list_organizations.assert_called_once()


@patch("src.run.db_connect")
@patch("src.run.get_key")
@patch("src.run.BitwardenClient")
@patch.dict(
    os.environ,
    {
        "BW_SERVER": "https://test.server",
        "BACKUP_ENCRYPTION_MODE": "raw",
        "DB_PATH": "/tmp/db.db",
        "PRAGMA_KEY_FILE": "/tmp/db.key",
        "TEST_MODE": "1",
    },
)
def test_main_deduplicates_configured_org_ids(
    mock_bw_client, mock_get_key, mock_db_connect
):
    """
    Tests that duplicate organization IDs in configured_org_ids are deduplicated
    while preserving order.
    """
    mock_db_connect.return_value = (MagicMock(), MagicMock())
    mock_get_key.side_effect = [
        "test_client_id",
        "test_client_secret",
        "test_master_pw",
        "test_file_pw",
        " org-1, org-2, org-1, org-3 , org-2 ",  # organization_ids with duplicates and extra spaces
        "multiple",  # org_export_mode
    ]
    mock_client_instance = mock_bw_client.return_value

    main()

    assert mock_client_instance.export_organization_raw_encrypted.call_count == 3
    calls = mock_client_instance.export_organization_raw_encrypted.call_args_list
    exported_org_ids = [call.args[2] for call in calls]
    assert exported_org_ids == ["org-1", "org-2", "org-3"]


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
        "",  # organization_ids (empty)
        "multiple",  # org_export_mode
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
        "",  # organization_ids (empty)
        "multiple",  # org_export_mode
    ]
    mock_client_instance = mock_bw_client.return_value
    mock_client_instance.login.side_effect = Exception("Login failed")
    mock_client_instance.list_organizations = MagicMock(return_value=[{"id": "org-1"}])

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
        "",  # organization_ids (empty)
        "multiple",  # org_export_mode
    ]
    mock_client_instance = mock_bw_client.return_value
    mock_client_instance.unlock.side_effect = Exception("Unlock failed")
    mock_client_instance.list_organizations = MagicMock(return_value=[{"id": "org-1"}])

    main()

    mock_client_instance.export_bitwarden_encrypted.assert_not_called()
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
def test_main_org_discovery_failure_returns_nonzero(
    mock_bw_client, mock_get_key, mock_db_connect
):
    """
    Tests that when organization discovery fails, personal vault export proceeds,
    cleanup is performed, and main returns status 1.
    """
    mock_db_connect.return_value = (MagicMock(), MagicMock())
    mock_get_key.side_effect = [
        "test_client_id",
        "test_client_secret",
        "test_master_pw",
        "test_file_pw",
        "",  # organization_ids (empty, auto-discovery)
        "multiple",  # org_export_mode
    ]
    mock_client_instance = mock_bw_client.return_value
    mock_client_instance.list_organizations.side_effect = Exception("Fetch orgs failed")

    result = main()

    assert result == 1
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
        "BACKUP_DIR": "/tmp/backups",
        "DB_PATH": "/tmp/db.db",
        "PRAGMA_KEY_FILE": "/tmp/db.key",
        "TEST_MODE": "1",
    },
)
def test_main_single_bitwarden_aborts_before_personal_export(
    mock_bw_client, mock_sprun, mock_get_key, mock_db_connect
):
    """
    Tests that main fails fast when org_export_mode='single' with
    encryption_mode='bitwarden' and does not export the personal vault.
    """
    mock_db_connect.return_value = (MagicMock(), MagicMock())
    mock_get_key.side_effect = [
        "test_client_id",
        "test_client_secret",
        "test_master_pw",
        "test_file_pw",
        "org-1,org-2",  # organization_ids
        "single",  # org_export_mode
    ]
    mock_client_instance = mock_bw_client.return_value
    mock_sprun.return_value = CompletedProcess(
        args=[], returncode=0, stdout="", stderr=""
    )

    result = main()

    assert result == 1
    mock_client_instance.export_bitwarden_encrypted.assert_not_called()
    mock_client_instance.export_raw_encrypted.assert_not_called()
    mock_client_instance.logout.assert_called_once()


@patch("src.run.db_connect")
@patch("src.run.get_key")
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
def test_main_single_raw_all_orgs_fail_returns_nonzero(
    mock_bw_client, mock_get_key, mock_db_connect
):
    """
    Tests that main returns a non-zero code when all single-mode org exports fail.
    """
    mock_db_connect.return_value = (MagicMock(), MagicMock())
    mock_get_key.side_effect = [
        "test_client_id",
        "test_client_secret",
        "test_master_pw",
        "test_file_pw",
        "org-1,org-2",  # organization_ids
        "single",  # org_export_mode
    ]
    mock_client_instance = mock_bw_client.return_value
    mock_client_instance.export_organization_raw.side_effect = Exception("org failed")
    mock_client_instance.encrypt_data = MagicMock()

    result = main()

    assert result == 1
    assert mock_client_instance.export_organization_raw.call_count == 2
    mock_client_instance.encrypt_data.assert_not_called()
    mock_client_instance.logout.assert_called_once()


@patch("src.run.db_connect")
@patch("src.run.get_key")
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
def test_main_single_raw_partial_org_failure_returns_nonzero(
    mock_bw_client, mock_get_key, mock_db_connect
):
    """
    Tests that main returns status 1 when single-mode raw org export is incomplete
    (e.g., 1 org succeeds and 1 fails), while preserving combined-file output.
    """
    mock_db_connect.return_value = (MagicMock(), MagicMock())
    mock_get_key.side_effect = [
        "test_client_id",
        "test_client_secret",
        "test_master_pw",
        "test_file_pw",
        "org-1,org-2",  # organization_ids
        "single",  # org_export_mode
    ]
    mock_client_instance = mock_bw_client.return_value

    def mock_export_org_raw(org_id):
        if org_id == "org-1":
            return {"items": [{"id": "item-1"}]}
        raise Exception("org-2 failed")

    mock_client_instance.export_organization_raw.side_effect = mock_export_org_raw
    mock_client_instance.encrypt_data.return_value = b"encrypted_combined_data"

    result = main()

    assert result == 1
    assert mock_client_instance.export_organization_raw.call_count == 2
    mock_client_instance.encrypt_data.assert_called_once()
    mock_client_instance.logout.assert_called_once()


@patch("src.run.db_connect")
@patch("src.run.get_key")
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
def test_main_multiple_partial_org_failure_returns_nonzero(
    mock_bw_client, mock_get_key, mock_db_connect
):
    """
    Tests that main returns a non-zero code when a multiple-mode org export fails,
    so scheduled automation can detect an incomplete backup.
    """
    mock_db_connect.return_value = (MagicMock(), MagicMock())
    mock_get_key.side_effect = [
        "test_client_id",
        "test_client_secret",
        "test_master_pw",
        "test_file_pw",
        "org-1,org-2",  # organization_ids
        "multiple",  # org_export_mode
    ]
    mock_client_instance = mock_bw_client.return_value
    mock_client_instance.export_organization_raw_encrypted.side_effect = [
        None,
        Exception("org failed"),
    ]

    result = main()

    assert result == 1
    mock_client_instance.export_organization_raw_encrypted.assert_any_call(
        unittest.mock.ANY, "test_file_pw", "org-1"
    )
    mock_client_instance.logout.assert_called_once()


@patch("src.run.db_connect")
@patch("src.run.get_key")
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
def test_main_multiple_all_orgs_succeed_returns_zero(
    mock_bw_client, mock_get_key, mock_db_connect
):
    """
    Tests that main returns zero when all multiple-mode org exports succeed.
    """
    mock_db_connect.return_value = (MagicMock(), MagicMock())
    mock_get_key.side_effect = [
        "test_client_id",
        "test_client_secret",
        "test_master_pw",
        "test_file_pw",
        "org-1,org-2",  # organization_ids
        "multiple",  # org_export_mode
    ]
    mock_client_instance = mock_bw_client.return_value

    result = main()

    assert result == 0
    mock_client_instance.export_organization_raw_encrypted.assert_any_call(
        unittest.mock.ANY, "test_file_pw", "org-1"
    )
    mock_client_instance.export_organization_raw_encrypted.assert_any_call(
        unittest.mock.ANY, "test_file_pw", "org-2"
    )
    mock_client_instance.logout.assert_called_once()


@pytest.mark.parametrize("failure_stage", ["open", "write", "close"])
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
    },
    clear=True,
)
def test_main_success_marker_failure_returns_nonzero(
    mock_bw_client, mock_get_key, mock_db_connect, failure_stage, caplog
):
    mock_db_connect.return_value = (MagicMock(), MagicMock())
    mock_get_key.side_effect = [
        "test_client_id",
        "test_client_secret",
        "test_master_pw",
        "test_file_pw",
        "",
        "none",
    ]
    with patch("src.run.open") as mock_open:
        marker = mock_open.return_value
        failure = OSError("marker unavailable")
        if failure_stage == "open":
            mock_open.side_effect = failure
        elif failure_stage == "write":
            marker.__enter__.return_value.write.side_effect = failure
        else:
            marker.__exit__.side_effect = failure

        with caplog.at_level("INFO"):
            result = main()

    assert result == 1
    mock_open.assert_called_once_with("/tmp/.complete", "w")
    assert (
        "Failed to create backup success marker file: marker unavailable" in caplog.text
    )
    assert "Export completed successfully" not in caplog.text
    mock_bw_client.return_value.logout.assert_called_once()


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
    mock_bw_client, mock_get_key, mock_db_connect, mock_copy, mock_rmtree, mock_replace
):
    """
    Tests that enabled attachment backup creates an archive with downloaded attachments and cleans up temporary files.
    """
    mock_db_connect.return_value = (MagicMock(), MagicMock())
    mock_get_key.side_effect = [
        "id",
        "secret",
        "master",
        "file_pw",
        None,
        None,
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
    assert (
        mock_rmtree.call_args_list[1].args[0].startswith("/tmp/backvault_attachments")
    )
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
    mock_db_connect,
    mock_get_key,
    mock_bw_client,
    mock_datetime,
    mock_copy,
    tmp_path,
    existing_archive,
):
    """
    Tests that a failure during the copy of the final archive preserves the existing archive if it exists, and cleans up temporary files.
    """
    mock_db_connect.return_value = (MagicMock(), MagicMock())
    mock_get_key.side_effect = [
        "id",
        "secret",
        "master",
        "file_pw",
        None,
        None,
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
        assert not Path(
            mock_client_instance.download_attachments.call_args.args[0]
        ).exists()
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
    mock_db_connect, mock_get_key, mock_bw_client, mock_datetime, mock_copy, tmp_path
):
    """
    Tests that a successful copy of the final archive publishes the archive and cleans up temporary files.
    """
    mock_db_connect.return_value = (MagicMock(), MagicMock())
    mock_get_key.side_effect = [
        "id",
        "secret",
        "master",
        "file_pw",
        None,
        None,
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
        "file_pw",
        None,
        None,
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
    mock_get_key.side_effect = ["id", "secret", "master", "file_pw", None, None]
    mock_client_instance = mock_bw_client.return_value

    main()

    mock_client_instance.export_bitwarden_encrypted.assert_called_once()
    mock_client_instance.download_attachments.assert_not_called()
    mock_client_instance.create_encrypted_archive.assert_not_called()


def test_run_sh_skips_initial_backup_when_complete_marker_exists(tmp_path):
    """
    Tests that run.sh initial backup logic skips backup when .complete marker exists,
    even if no .enc files are present. Executes run.sh directly.
    """
    import subprocess

    app_dir = tmp_path / "app"
    app_dir.mkdir()
    backup_dir = app_dir / "backups"
    backup_dir.mkdir()
    (backup_dir / ".complete").write_text("20250101_000000")
    db_dir = app_dir / "db"
    db_dir.mkdir()
    (db_dir / "backvault.db").write_text("dummy db")
    (app_dir / "logs").mkdir()
    (app_dir / "src").mkdir()
    (app_dir / "src" / "run.py").write_text("# dummy")

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    supercronic_mock = bin_dir / "supercronic"
    supercronic_mock.write_text("#!/bin/bash\necho 'SUPERCRONIC_STARTED'\n")
    supercronic_mock.chmod(0o755)

    python_mock = bin_dir / "python"
    python_mock.write_text("#!/bin/bash\necho 'PYTHON_CALLED'\nexit 0\n")
    python_mock.chmod(0o755)

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"
    env["DB_PATH"] = str(db_dir)

    real_run_sh_path = Path(__file__).parents[1] / "run.sh"
    run_sh_content = real_run_sh_path.read_text()
    run_sh_adapted = (
        run_sh_content.replace("/app", str(app_dir))
        .replace("/usr/local/bin/python", str(python_mock))
        .replace("/usr/local/bin/supercronic", str(supercronic_mock))
    )

    test_script = tmp_path / "test_run.sh"
    test_script.write_text(run_sh_adapted)
    test_script.chmod(0o755)

    res = subprocess.run(
        [str(test_script)],
        cwd=str(app_dir),
        env=env,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )

    assert "Found successful backup marker" in res.stdout
    assert "Running initial backup..." not in res.stdout
    assert "PYTHON_CALLED" not in res.stdout


def test_run_sh_runs_initial_backup_when_complete_marker_missing(tmp_path):
    """
    Tests that run.sh initial backup logic runs backup when .complete marker is missing,
    even if existing .enc files created by previous runs exist. Executes run.sh directly.
    """
    import subprocess

    app_dir = tmp_path / "app"
    app_dir.mkdir()
    backup_dir = app_dir / "backups"
    backup_dir.mkdir()
    (backup_dir / "backup_20250101_000000_personal.enc").write_bytes(b"enc data")
    db_dir = app_dir / "db"
    db_dir.mkdir()
    (db_dir / "backvault.db").write_text("dummy db")
    (app_dir / "logs").mkdir()
    (app_dir / "src").mkdir()
    (app_dir / "src" / "run.py").write_text("# dummy")

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    supercronic_mock = bin_dir / "supercronic"
    supercronic_mock.write_text("#!/bin/bash\necho 'SUPERCRONIC_STARTED'\n")
    supercronic_mock.chmod(0o755)

    python_mock = bin_dir / "python"
    python_mock.write_text("#!/bin/bash\necho 'PYTHON_CALLED'\nexit 0\n")
    python_mock.chmod(0o755)

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"
    env["DB_PATH"] = str(db_dir)

    real_run_sh_path = Path(__file__).parents[1] / "run.sh"
    run_sh_content = real_run_sh_path.read_text()
    run_sh_adapted = (
        run_sh_content.replace("/app", str(app_dir))
        .replace("/usr/local/bin/python", str(python_mock))
        .replace("/usr/local/bin/supercronic", str(supercronic_mock))
    )

    test_script = tmp_path / "test_run.sh"
    test_script.write_text(run_sh_adapted)
    test_script.chmod(0o755)

    res = subprocess.run(
        [str(test_script)],
        cwd=str(app_dir),
        env=env,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )

    assert "Running initial backup..." in res.stdout
    assert "PYTHON_CALLED" in res.stdout
