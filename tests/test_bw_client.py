import json
import logging
import os
import pytest
from unittest.mock import patch, ANY, MagicMock
from src.bw_client import BitwardenClient, BitwardenError


@patch("src.bw_client.sprun")
def test_bitwarden_client_init_defaults(mock_sprun):
    """
    Tests that the BitwardenClient is initialized with default values.
    """
    client = BitwardenClient()
    assert client.bw_cmd == "bw"
    assert client.session is None
    assert client.client_id is None
    assert client.client_secret is None
    assert not client.use_api_key
    mock_sprun.assert_not_called()


@patch("src.bw_client.sprun")
def test_bitwarden_client_init_with_params(mock_sprun):
    """
    Tests that the BitwardenClient is initialized with provided parameters.
    """
    client = BitwardenClient(
        bw_cmd="/usr/local/bin/bw",
        session="test_session",
        server="https://my.bitwarden.server",
        client_id="test_client_id",
        client_secret="test_client_secret",
        use_api_key=True,
    )
    assert client.bw_cmd == "/usr/local/bin/bw"
    assert client.session == "test_session"
    assert client.client_id == "test_client_id"
    assert client.client_secret == "test_client_secret"
    assert client.use_api_key
    mock_sprun.assert_called_once_with(
        ["/usr/local/bin/bw", "config", "server", "https://my.bitwarden.server"],
        text=True,
        capture_output=True,
        check=True,
        env=ANY,
        preexec_fn=None,
    )


@patch("src.bw_client.sprun")
def test_bitwarden_client_init_server_config_fails(mock_sprun):
    """
    Tests that BitwardenError is raised when server configuration fails.
    """
    mock_sprun.side_effect = Exception("Failed to configure server")
    with pytest.raises(
        BitwardenError,
        match="Failed to configure BW server to https://my.bitwarden.server",
    ):
        BitwardenClient(server="https://my.bitwarden.server")


@patch("src.bw_client.sprun")
def test_login_with_api_key(mock_sprun):
    """
    Tests that the login method works correctly with an API key.
    """
    mock_sprun.return_value.stdout = "test_session_key"
    mock_sprun.return_value.stderr = ""
    mock_sprun.return_value.returncode = 0
    client = BitwardenClient(
        client_id="test_client_id",
        client_secret="test_client_secret",
        use_api_key=True,
    )
    session_key = client.login()
    assert session_key == "test_session_key"
    assert client.session == "test_session_key"
    mock_sprun.assert_called_once_with(
        ["bw", "login", "--apikey"],
        capture_output=True,
        text=True,
        check=True,
        env=ANY,
    )


@patch("src.bw_client.sprun")
def test_login_with_email_and_password(mock_sprun):
    """
    Tests that the login method works correctly with an email and password.
    The password must be passed via the BW_PASSWORD env var, never as a
    positional argument (which would leak it into logs and ps).
    """
    mock_sprun.return_value.stdout = "test_session_key"
    mock_sprun.return_value.stderr = ""
    mock_sprun.return_value.returncode = 0
    client = BitwardenClient()
    session_key = client.login(email="test_email", password="test_password")
    assert session_key == "test_session_key"
    assert client.session == "test_session_key"
    mock_sprun.assert_called_once_with(
        ["bw", "login", "test_email", "--passwordenv", "BW_PASSWORD", "--raw"],
        text=True,
        capture_output=True,
        check=True,
        env=ANY,
    )
    call = mock_sprun.call_args
    assert call.kwargs["env"]["BW_PASSWORD"] == "test_password"


@patch("src.bw_client.sprun")
def test_login_error_message_does_not_contain_password(mock_sprun):
    """
    Tests that when login fails, the returned error message does not
    contain the master password anywhere (regression test for the
    CalledProcessError argv leak).
    """
    from subprocess import CalledProcessError

    mock_sprun.side_effect = CalledProcessError(
        1,
        ["bw", "login", "test_email", "test_password", "--raw"],
        stderr="Authentication failed",
    )
    client = BitwardenClient()
    with pytest.raises(BitwardenError) as excinfo:
        client.login(email="test_email", password="test_password")
    assert "test_password" not in str(excinfo.value)


@patch("src.bw_client.sprun")
def test_redact_text_overlapping_secrets_longer_redacted_first(mock_sprun):
    """
    Tests that when one secret is a prefix/substring of another, the
    longer secret is fully redacted without leaving a suffix.
    """
    client = BitwardenClient(
        client_secret="supersecret123", client_id=None, session=None
    )
    env = {"BW_PASSWORD": "supersecret", "BW_SESSION": "sess"}
    text = "Command 'bw unlock' stderr: supersecret supersecret123 sess"
    result = client._redact_text(text, env)
    assert "supersecret" not in result
    assert "123" not in result
    assert "[REDACTED]" in result


@patch("src.bw_client.sprun")
def test_logout_cleanup_error_redacts_secrets(mock_sprun, caplog):
    """
    Tests that a failed cleanup logout after a command failure does not
    leak secrets into the logged error (regression).
    """
    from subprocess import CalledProcessError

    mock_sprun.side_effect = [
        CalledProcessError(1, ["bw", "unlock", "--raw"], stderr="wrong password"),
        CalledProcessError(
            1,
            ["bw", "logout"],
            stderr="unable to reach server for user supersecret",
        ),
    ]
    client = BitwardenClient(client_secret="supersecret", client_id=None, session=None)
    with caplog.at_level(logging.ERROR, logger="src.bw_client"):
        with pytest.raises(BitwardenError):
            client._run(["unlock", "--raw"])
    assert any("supersecret" in r.message for r in caplog.records) is False


@patch("src.bw_client.sprun")
def test_logout(mock_sprun):
    """
    Tests that the logout method works correctly.
    """
    mock_sprun.return_value.stdout = ""
    mock_sprun.return_value.stderr = ""
    mock_sprun.return_value.returncode = 0
    client = BitwardenClient(session="test_session")
    client.logout()
    assert client.session is None
    mock_sprun.assert_called_once_with(
        ["bw", "logout"], text=True, capture_output=True, check=True, env=ANY
    )


@patch("src.bw_client.sprun")
def test_logout_without_session_is_noop(mock_sprun):
    """
    Tests that calling logout when no session exists does not attempt to run
    `bw logout` and therefore does not raise (regression for the restart loop
    where login failed and the finally block still invoked logout).
    """
    client = BitwardenClient()
    client.logout()
    assert client.session is None
    mock_sprun.assert_not_called()


@patch("src.bw_client.sprun")
def test_login_with_api_key_retries_on_transient_failure(mock_sprun):
    """
    Tests that login retries a transient command failure (e.g. the Bitwarden
    server still starting up after a host reboot) and eventually succeeds.
    """
    from subprocess import CalledProcessError

    successful = MagicMock()
    successful.returncode = 0
    successful.stdout = "test_session_key"
    successful.stderr = ""

    mock_sprun.side_effect = [
        CalledProcessError(1, ["bw", "login", "--apikey"]),
        CalledProcessError(1, ["bw", "login", "--apikey"]),
        successful,
    ]
    client = BitwardenClient(
        client_id="test_client_id",
        client_secret="test_client_secret",
        use_api_key=True,
        login_retries=3,
        login_retry_delay=0,
    )
    session_key = client.login()
    assert session_key == "test_session_key"
    assert client.session == "test_session_key"
    assert mock_sprun.call_count == 3


def test_bitwarden_client_use_api_key_logic():
    """
    Tests that the use_api_key attribute is set correctly.
    """
    client_with_api_key = BitwardenClient(
        client_id="test_client_id",
        client_secret="test_client_secret",
    )
    assert client_with_api_key.use_api_key

    client_without_api_key = BitwardenClient()
    assert not client_without_api_key.use_api_key


@patch("src.bw_client.sprun")
def test_run_method_json_output(mock_sprun):
    """
    Tests that the _run method correctly parses JSON output.
    """
    mock_sprun.return_value.stdout = '{"success": true}'
    mock_sprun.return_value.stderr = ""
    mock_sprun.return_value.returncode = 0
    client = BitwardenClient()
    result = client._run(["status"], capture_json=True)
    assert result == {"success": True}


@patch("src.bw_client.sprun")
def test_run_method_json_parse_rejects_json_embedded_in_warning_line(mock_sprun):
    """
    Tests that _run with capture_json=True rejects candidate JSON embedded within a warning line.
    """
    mock_sprun.return_value.stdout = (
        '(node:1234) [DEP0040] DeprecationWarning: punycode {"success": true}'
    )
    mock_sprun.return_value.stderr = ""
    mock_sprun.return_value.returncode = 0
    client = BitwardenClient()
    with pytest.raises(BitwardenError, match="Failed to parse JSON output"):
        client._run(["status"], capture_json=True)


@patch("src.bw_client.sprun")
def test_run_method_json_parse_rejects_truncated_outer_json(mock_sprun):
    """
    Tests that _run with capture_json=True rejects candidate nested JSON arrays/objects
    when prefix contains malformed/truncated outer JSON.
    """
    mock_sprun.return_value.stdout = '{"truncated": [1, 2, 3]'
    mock_sprun.return_value.stderr = ""
    mock_sprun.return_value.returncode = 0
    client = BitwardenClient()
    with pytest.raises(BitwardenError, match="Failed to parse JSON output"):
        client._run(["status"], capture_json=True)


@patch("src.bw_client.sprun")
def test_run_method_json_parse_rejects_concatenated_json_objects(mock_sprun):
    """
    Tests that _run with capture_json=True rejects stdout containing
    concatenated JSON objects (e.g. {} followed by {}).
    """
    mock_sprun.return_value.stdout = "{}\n{}"
    mock_sprun.return_value.stderr = ""
    mock_sprun.return_value.returncode = 0
    client = BitwardenClient()
    with pytest.raises(BitwardenError, match="Failed to parse JSON output"):
        client._run(["status"], capture_json=True)


@patch("src.bw_client.sprun")
def test_run_method_json_parse_rejects_multiple_top_level_json_values(mock_sprun):
    """
    Tests that _run with capture_json=True rejects stdout containing
    multiple top-level JSON values (e.g. [] followed by [1, 2, 3]).
    """
    mock_sprun.return_value.stdout = "[]\n[1, 2, 3]"
    mock_sprun.return_value.stderr = ""
    mock_sprun.return_value.returncode = 0
    client = BitwardenClient()
    with pytest.raises(BitwardenError, match="Failed to parse JSON output"):
        client._run(["status"], capture_json=True)


@patch("src.bw_client.sprun")
def test_list_organizations_with_trailing_warning(mock_sprun):
    """
    Tests that list_organizations returns valid parsed array even when
    stdout is followed by a deprecation warning line.
    """
    mock_sprun.return_value.stdout = "[]\n(node:1234) DeprecationWarning: punycode"
    mock_sprun.return_value.stderr = ""
    mock_sprun.return_value.returncode = 0
    client = BitwardenClient()
    result = client.list_organizations()
    assert result == []
    mock_sprun.assert_called_once_with(
        ["bw", "list", "organizations"],
        text=True,
        capture_output=True,
        check=True,
        env=ANY,
    )


@patch("src.bw_client.sprun")
def test_run_method_non_json_output(mock_sprun):
    """
    Tests that the _run method correctly handles non-JSON output.
    """
    mock_sprun.return_value.stdout = "OK"
    mock_sprun.return_value.stderr = ""
    mock_sprun.return_value.returncode = 0
    client = BitwardenClient()
    result = client._run(["status"], capture_json=False)
    assert result == "OK"
    mock_sprun.assert_called_once_with(
        ["bw", "status"],
        text=True,
        capture_output=True,
        check=True,
        env=ANY,
    )


@patch("src.bw_client.sprun")
def test_run_method_error_handling(mock_sprun):
    """
    Tests that the _run method correctly handles errors.
    """
    from subprocess import CalledProcessError

    mock_sprun.side_effect = CalledProcessError(1, "cmd", stderr="error")
    client = BitwardenClient()
    with pytest.raises(BitwardenError):
        client._run(["status"])


@patch("src.bw_client.sprun")
def test_export_organization_and_list_organization_methods_pass_logout_on_error_false(
    mock_sprun, monkeypatch
):
    """
    Tests that list_organizations, export_organization_raw and export_organization_bitwarden
    pass logout_on_error=False to _run so failures do not trigger logout.
    """
    from subprocess import CalledProcessError

    monkeypatch.delenv("TEST_MODE", raising=False)

    mock_sprun.side_effect = CalledProcessError(
        1, ["bw", "list"], stderr="List orgs failed"
    )
    client = BitwardenClient(session="test_session")

    with pytest.raises(BitwardenError):
        client.list_organizations()

    list_calls = [
        call for call in mock_sprun.call_args_list if call.args[0][:2] == ["bw", "list"]
    ]
    assert len(list_calls) == 1
    logout_calls = [
        call for call in mock_sprun.call_args_list if call.args[0] == ["bw", "logout"]
    ]
    assert len(logout_calls) == 0

    mock_sprun.reset_mock()

    mock_sprun.side_effect = CalledProcessError(
        1, ["bw", "export"], stderr="Org export failed"
    )

    with pytest.raises(BitwardenError):
        client.export_organization_raw("org-123")

    export_calls = [
        call
        for call in mock_sprun.call_args_list
        if call.args[0][:2] == ["bw", "export"]
    ]
    assert len(export_calls) == 1
    logout_calls = [
        call for call in mock_sprun.call_args_list if call.args[0] == ["bw", "logout"]
    ]
    assert len(logout_calls) == 0

    mock_sprun.reset_mock()
    mock_sprun.side_effect = CalledProcessError(
        1, ["bw", "export"], stderr="Org export failed"
    )

    with pytest.raises(BitwardenError):
        client.export_organization_bitwarden(
            "/app/backups/backup.enc", "file_pw", "org-123"
        )

    export_calls = [
        call
        for call in mock_sprun.call_args_list
        if call.args[0][:2] == ["bw", "export"]
    ]
    assert len(export_calls) == 1
    logout_calls = [
        call for call in mock_sprun.call_args_list if call.args[0] == ["bw", "logout"]
    ]
    assert len(logout_calls) == 0


@patch("src.bw_client.sprun")
def test_run_method_json_parse_with_prefix_warning(mock_sprun):
    """
    Tests that the _run method handles JSON output prefixed with deprecation warnings containing brackets.
    """
    mock_sprun.return_value.stdout = (
        '(node:1234) [DEP0040] DeprecationWarning: punycode\n{"success": true}'
    )
    mock_sprun.return_value.stderr = ""
    mock_sprun.return_value.returncode = 0
    client = BitwardenClient()
    result = client._run(["status"], capture_json=True)
    assert result == {"success": True}


@patch("src.bw_client.sprun")
def test_run_method_json_parse_error_does_not_log_raw_output(mock_sprun, caplog):
    """
    Tests that a JSON parse failure does not log the raw command output
    (which may contain sensitive vault data).
    """
    mock_sprun.return_value.stdout = "not-json-sensitive-data-abc123"
    mock_sprun.return_value.stderr = ""
    mock_sprun.return_value.returncode = 0
    client = BitwardenClient()
    with caplog.at_level(logging.ERROR, logger="src.bw_client"):
        with pytest.raises(BitwardenError):
            client._run(["export"], capture_json=True)
    assert all(
        "not-json-sensitive-data-abc123" not in r.message for r in caplog.records
    )


@patch("src.bw_client.sprun")
def test_unlock_uses_passwordenv_not_positional_arg(mock_sprun):
    """
    Tests that the unlock method passes the master password via the
    BW_PASSWORD environment variable, never as a positional argument
    (which would leak it into logs and the process table via ps).
    """
    mock_sprun.return_value.stdout = "test_session_key"
    mock_sprun.return_value.stderr = ""
    mock_sprun.return_value.returncode = 0
    client = BitwardenClient(session="existing_session")
    session_key = client.unlock("supersecretmasterpw")
    assert session_key == "test_session_key"
    assert client.session == "test_session_key"
    mock_sprun.assert_called_once()
    call = mock_sprun.call_args
    args = call.args[0]
    assert "supersecretmasterpw" not in args
    assert args == ["bw", "unlock", "--passwordenv", "BW_PASSWORD", "--raw"]
    assert call.kwargs["env"]["BW_PASSWORD"] == "supersecretmasterpw"
    assert call.kwargs["env"]["BW_SESSION"] == "existing_session"


@patch("src.bw_client.sprun")
def test_unlock_error_message_does_not_contain_password(mock_sprun):
    """
    Tests that when unlock fails, the returned error message does not
    contain the master password anywhere (regression test for the
    CalledProcessError argv leak).
    """
    from subprocess import CalledProcessError

    mock_sprun.side_effect = CalledProcessError(
        1,
        ["bw", "unlock", "supersecretmasterpw", "--raw"],
        stderr="Authentication failed",
    )
    client = BitwardenClient(session="existing_session")
    with pytest.raises(BitwardenError) as excinfo:
        client.unlock("supersecretmasterpw")
    assert "supersecretmasterpw" not in str(excinfo.value)


def test_encrypt_data():
    """
    Tests that the encrypt_data method correctly encrypts data.
    """
    client = BitwardenClient()
    data = b"test_data"
    password = "test_password"
    encrypted_data = client.encrypt_data(data, password)
    assert encrypted_data != data


@patch("src.bw_client.sprun")
def test_download_and_archive_attachments(mock_sprun, tmp_path):
    """
    Tests that attachments are downloaded into per-item folders and packed
    into a password-protected 7z archive.
    """
    import py7zr
    from subprocess import CompletedProcess

    items = [
        {"id": "item-1", "attachments": [{"id": "a1", "fileName": "x.txt"}]},
        {"id": "item-2", "attachments": []},
    ]

    def fake_bw(cmd, **kwargs):
        if cmd[1:3] == ["list", "items"]:
            return CompletedProcess(cmd, 0, stdout=json.dumps(items), stderr="")
        if cmd[1:3] == ["get", "attachment"]:
            out = cmd[cmd.index("--output") + 1]
            with open(out, "w") as f:
                f.write("data")
            return CompletedProcess(cmd, 0, stdout="", stderr="")
        raise AssertionError(f"Unexpected command: {cmd}")

    mock_sprun.side_effect = fake_bw
    client = BitwardenClient(session="existing_session")

    src = tmp_path / "src"
    src.mkdir()
    assert client.download_attachments(str(src)) == 1
    assert (src / "item-1" / "x.txt").read_text() == "data"
    assert not (src / "item-2").exists()

    get_call = mock_sprun.call_args_list[1]
    assert get_call.args[0] == [
        "bw",
        "get",
        "attachment",
        "a1",
        "--itemid",
        "item-1",
        "--output",
        str(src / "item-1" / "x.txt"),
    ]
    assert get_call.kwargs["env"]["BW_SESSION"] == "existing_session"

    archive = tmp_path / "a.7z"
    client.create_encrypted_archive(str(src), str(archive), "pw")
    with py7zr.SevenZipFile(archive, "r", password="pw") as z:
        names = z.getnames()
        assert any(n.endswith("item-1/x.txt") for n in names)
        # The temporary source directory itself must not be an archive entry
        assert all(n == "item-1" or n.startswith("item-1/") for n in names)
        # The archive must be extractable and the file contents must match
        restored = tmp_path / "restored"
        z.extractall(path=restored)
        assert (restored / "item-1" / "x.txt").read_text() == "data"
    # The archive contents cannot be listed without the password
    with pytest.raises(Exception):
        with py7zr.SevenZipFile(archive, "r") as z:
            z.getnames()


@patch("src.bw_client.sprun")
def test_download_attachments_duplicate_names(mock_sprun, tmp_path):
    """
    Tests that attachment ids select downloads and duplicate names get unique suffixes.
    """
    from subprocess import CompletedProcess

    attachments = [
        {"id": "a1", "fileName": "x.txt"},
        {"id": "a2", "fileName": "x_1.txt"},
        {"id": "a3", "fileName": "x.txt"},
        {"id": "a4", "fileName": "x.txt"},
        {"id": "a5", "fileName": "notes"},
        {"id": "a6", "fileName": "notes"},
    ]
    items = [
        {"id": "item-1", "attachments": attachments},
        {"id": "item-2", "attachments": [{"id": "a7", "fileName": "x.txt"}]},
    ]
    mock_sprun.side_effect = [
        CompletedProcess(
            ["bw", "list", "items"], 0, stdout=json.dumps(items), stderr=""
        ),
        *[CompletedProcess([], 0, stdout="", stderr="") for _ in range(7)],
    ]
    client = BitwardenClient(session="existing_session")

    assert client.download_attachments(str(tmp_path)) == 7

    commands = [call.args[0] for call in mock_sprun.call_args_list[1:]]
    assert [cmd[3] for cmd in commands] == ["a1", "a2", "a3", "a4", "a5", "a6", "a7"]
    expected_paths = [
        "item-1/x.txt",
        "item-1/x_1.txt",
        "item-1/x_2.txt",
        "item-1/x_3.txt",
        "item-1/notes",
        "item-1/notes_1",
        "item-2/x.txt",
    ]
    assert [cmd[-1] for cmd in commands] == [
        str(tmp_path / path) for path in expected_paths
    ]


@pytest.mark.parametrize(
    "method_name, extra_args",
    [
        ("export_bitwarden_encrypted", ("pw",)),
        ("export_raw_encrypted", ("pw",)),
        ("export_organization_bitwarden", ("pw", "org-1")),
        ("export_organization_raw_encrypted", ("pw", "org-1")),
    ],
)
def test_export_methods_invalid_path_raises_bitwarden_error(method_name, extra_args):
    """
    Tests that invalid backup paths (e.g., path traversal outside /app) raise BitwardenError
    across all export methods.
    """
    client = BitwardenClient()
    method = getattr(client, method_name)
    invalid_path = "/etc/passwd"
    with pytest.raises(BitwardenError, match="Invalid path: must be within"):
        method(invalid_path, *extra_args)


def _decrypt_test_backup(filepath: str, password: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from src.bw_client import SALT_SIZE, KEY_SIZE, PBKDF2_ITERATIONS

    with open(filepath, "rb") as f:
        data = f.read()
    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE : SALT_SIZE + 12]
    ciphertext = data[SALT_SIZE + 12 :]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key = kdf.derive(password.encode("utf-8"))
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


@pytest.mark.parametrize(
    "method_name, extra_args",
    [
        ("export_raw_encrypted", ()),
        ("export_organization_raw_encrypted", ("org-123",)),
    ],
)
@patch.dict(os.environ, {"TEST_MODE": "1"})
@patch("src.bw_client.sprun")
def test_raw_export_methods_strip_warnings(
    mock_sprun, method_name, extra_args, tmp_path
):
    """
    Tests that export_raw_encrypted and export_organization_raw_encrypted strip warning
    lines from CLI stdout before encrypting.
    """
    mock_sprun.return_value.stdout = (
        '(node:1234) DeprecationWarning: punycode\n{"encrypted": false, "items": []}\n'
    )
    mock_sprun.return_value.stderr = ""
    mock_sprun.return_value.returncode = 0

    client = BitwardenClient()
    backup_file = str(tmp_path / "backup.enc")

    method = getattr(client, method_name)
    method(backup_file, "file_password", *extra_args)

    decrypted = _decrypt_test_backup(backup_file, "file_password")
    assert decrypted == b'{"encrypted": false, "items": []}'


@pytest.mark.parametrize(
    "method_name, extra_args",
    [
        ("export_raw_encrypted", ()),
        ("export_organization_raw_encrypted", ("org-123",)),
    ],
)
@patch.dict(os.environ, {"TEST_MODE": "1"})
@patch("src.bw_client.sprun")
def test_raw_export_methods_reject_invalid_json(
    mock_sprun, method_name, extra_args, tmp_path
):
    """
    Tests that export_raw_encrypted and export_organization_raw_encrypted raise
    BitwardenError when CLI stdout does not contain valid JSON.
    """
    mock_sprun.return_value.stdout = "An unhandled error occurred in Bitwarden CLI"
    mock_sprun.return_value.stderr = ""
    mock_sprun.return_value.returncode = 0

    client = BitwardenClient()
    backup_file = str(tmp_path / "backup.enc")

    method = getattr(client, method_name)
    with pytest.raises(BitwardenError, match="Failed to parse JSON output"):
        method(backup_file, "file_password", *extra_args)
