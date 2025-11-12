import pytest
from unittest.mock import patch, ANY
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
    """
    mock_sprun.return_value.stdout = "test_session_key"
    mock_sprun.return_value.stderr = ""
    mock_sprun.return_value.returncode = 0
    client = BitwardenClient()
    session_key = client.login(email="test_email", password="test_password")
    assert session_key == "test_session_key"
    assert client.session == "test_session_key"
    mock_sprun.assert_called_once_with(
        ["bw", "login", "test_email", "--password", "test_password", "--raw"],
        text=True,
        capture_output=True,
        check=True,
        env=ANY,
    )


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
    mock_sprun.assert_called_once_with(
        ["bw", "status"],
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


def test_encrypt_data():
    """
    Tests that the encrypt_data method correctly encrypts data.
    """
    client = BitwardenClient()
    data = b"test_data"
    password = "test_password"
    encrypted_data = client.encrypt_data(data, password)
    assert encrypted_data != data
