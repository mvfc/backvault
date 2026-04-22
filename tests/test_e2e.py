"""
End-to-End Tests with Real Vaultwarden

These tests require:
- Vaultwarden running (see fixtures)
- Test user credentials configured via environment variables

Marked with @pytest.mark.e2e - excluded from default pytest run.

Run with:
    VAULTWARDEN_URL=http://localhost:8888 \
    BW_TEST_EMAIL=test@example.com \
    BW_TEST_PASSWORD=testpassword123 \
    BW_TEST_MASTER_PASSWORD=masterpassword123 \
    uv run pytest tests/test_e2e.py -v -m e2e
"""

import json
import os
import subprocess
import time
from urllib.parse import urlparse

import pytest

pytestmark = pytest.mark.e2e

VAULTWARDEN_URL = os.getenv("VAULTWARDEN_URL", "http://localhost:8888")
VAULTWARDEN_PORT = str(urlparse(VAULTWARDEN_URL).port or 80)
IMAGE_NAME = os.getenv("IMAGE_NAME", "backvault:latest")
TEST_EMAIL = os.getenv("BW_TEST_EMAIL", "e2e@test.com")
TEST_PASSWORD = os.getenv("BW_TEST_PASSWORD", "Test123!")
TEST_MASTER_PASSWORD = os.getenv("BW_TEST_MASTER_PASSWORD", "Master123!")


@pytest.fixture(scope="module")
def vaultwarden_container():
    """Start Vaultwarden container for testing, clean up after."""
    container_name = "backvault-test-vaultwarden"

    result = subprocess.run(
        [
            "docker",
            "ps",
            "--filter",
            f"name={container_name}",
            "--format",
            "{{.Names}}",
        ],
        capture_output=True,
        text=True,
    )

    if container_name in result.stdout:
        print(f"Using existing container: {container_name}")
        yield container_name
        return

    result = subprocess.run(
        [
            "docker",
            "ps",
            "--filter",
            f"publish={VAULTWARDEN_PORT}",
            "--filter",
            "ancestor=vaultwarden/server",
            "--format",
            "{{.Names}}",
        ],
        capture_output=True,
        text=True,
    )
    if result.stdout.strip():
        container_names = result.stdout.strip().splitlines()
        container_name = container_names[0] if container_names else ""
        print(f"Using existing container on port {VAULTWARDEN_PORT}: {container_name}")
        yield container_name
        return

    print(f"Starting Vaultwarden container: {container_name}")
    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            container_name,
            "-p",
            f"{VAULTWARDEN_PORT}:80",
            "-e",
            "SIGNUPS_ALLOWED=true",
            "-e",
            "ADMIN_TOKEN=admin_secret_token_for_testing",
            "vaultwarden/server:latest",
        ],
        check=True,
    )

    max_attempts = 30
    for attempt in range(max_attempts):
        try:
            result = subprocess.run(
                ["curl", "-sf", f"{VAULTWARDEN_URL}/health"],
                capture_output=True,
                timeout=2,
            )
            if result.returncode == 0:
                print(f"Vaultwarden ready after {attempt + 1} attempts")
                break
        except Exception:
            pass
        time.sleep(2)
    else:
        pytest.fail("Vaultwarden failed to start")

    yield container_name

    print(f"Stopping Vaultwarden container: {container_name}")
    subprocess.run(["docker", "stop", container_name], capture_output=True)
    subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)


@pytest.fixture(scope="function")
def bw_env(tmp_path_factory):
    """Create isolated Bitwarden CLI environment."""
    appdata = tmp_path_factory.mktemp("bw_data")
    return {**os.environ, "BITWARDENCLI_APPDATA_DIR": str(appdata)}


@pytest.fixture(scope="function")
def test_user(vaultwarden_container, bw_env):
    """Create test user in Vaultwarden via admin API."""
    import urllib.request
    import urllib.error

    admin_url = VAULTWARDEN_URL.replace("http://", "http://admin:")
    req = urllib.request.Request(
        f"{admin_url}/admin/users",
        data=urllib.parse.urlencode(
            {
                "email": TEST_EMAIL,
                "password": TEST_PASSWORD,
                "masterPassword": TEST_MASTER_PASSWORD,
            }
        ).encode(),
        headers={
            "Authorization": f"Bearer {os.getenv('VAULTWARDEN_ADMIN_TOKEN', 'admin_secret_token_for_testing')}"
        },
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10)
    except urllib.error.HTTPError as e:
        if e.code == 400 and "exists" in e.read().decode().lower():
            pass
        else:
            pytest.fail(f"Registration failed: {e}")
    except Exception as e:
        pytest.fail(f"Registration failed: {e}")

    yield {"email": TEST_EMAIL, "password": TEST_PASSWORD, "bw_env": bw_env}


@pytest.fixture(scope="function")
def bw_session(test_user):
    """Create Bitwarden CLI session by logging in."""
    bw_env = test_user["bw_env"]
    subprocess.run(["bw", "config", "server", VAULTWARDEN_URL], check=True, env=bw_env)

    subprocess.run(["bw", "logout"], capture_output=True, env=bw_env)

    result = subprocess.run(
        [
            "bw",
            "login",
            TEST_EMAIL,
            "--password",
            TEST_PASSWORD,
            "--raw",
        ],
        capture_output=True,
        text=True,
        env={**bw_env, "BW_SESSION": ""},
    )

    if result.returncode != 0:
        pytest.fail(f"Login failed: {result.stderr}")

    session = result.stdout.strip()

    result = subprocess.run(
        [
            "bw",
            "unlock",
            TEST_MASTER_PASSWORD,
            "--raw",
        ],
        capture_output=True,
        text=True,
        env={**bw_env, "BW_SESSION": session},
    )

    if result.returncode != 0:
        pytest.fail(f"Unlock failed: {result.stderr}")

    session = result.stdout.strip()
    bw_env["BW_SESSION"] = session

    yield {"session": session, "bw_env": bw_env}

    subprocess.run(["bw", "lock"], capture_output=True, env=bw_env)
    subprocess.run(["bw", "logout"], capture_output=True, env=bw_env)
    if "BW_SESSION" in bw_env:
        del bw_env["BW_SESSION"]


class TestE2EBackup:
    """End-to-end backup tests with real Vaultwarden."""

    def test_cli_can_login_and_unlock(self, bw_session):
        """Verify CLI can login and unlock vault."""
        assert bw_session["session"]
        assert len(bw_session["session"]) > 0

        result = subprocess.run(
            ["bw", "status"],
            capture_output=True,
            text=True,
            env={**bw_session["bw_env"], "BW_SESSION": bw_session["session"]},
        )
        assert result.returncode == 0

        status = json.loads(result.stdout)
        assert status["status"] == "unlocked"

    def test_list_items(self, bw_session):
        """Test listing items in vault."""
        result = subprocess.run(
            ["bw", "list", "items"],
            capture_output=True,
            text=True,
            env={**bw_session["bw_env"], "BW_SESSION": bw_session["session"]},
        )

        assert result.returncode == 0
        items = json.loads(result.stdout)
        assert isinstance(items, list)

    def test_backup_personal_vault_raw_mode(self, bw_session, tmp_path, monkeypatch):
        """Test backing up personal vault with raw (AES-256-GCM) encryption."""
        from src.bw_client import BitwardenClient

        monkeypatch.setenv("TEST_MODE", "1")
        monkeypatch.setenv(
            "BITWARDENCLI_APPDATA_DIR",
            bw_session["bw_env"]["BITWARDENCLI_APPDATA_DIR"],
        )

        client = BitwardenClient(session=bw_session["session"], server=VAULTWARDEN_URL)

        backup_file = tmp_path / "personal_raw.enc"
        client.export_raw_encrypted(str(backup_file), "backup_password")

        assert backup_file.exists()
        assert backup_file.stat().st_size > 0

        content = backup_file.read_bytes()
        assert len(content) > 44

    def test_list_organizations(self, bw_session):
        """Test listing organizations (may be empty for personal account)."""
        result = subprocess.run(
            ["bw", "list", "organizations"],
            capture_output=True,
            text=True,
            env={**bw_session["bw_env"], "BW_SESSION": bw_session["session"]},
        )

        assert result.returncode == 0
        orgs = json.loads(result.stdout)
        assert isinstance(orgs, list)

    def test_status_returns_user_info(self, bw_session):
        """Test status returns user information."""
        result = subprocess.run(
            ["bw", "status"],
            capture_output=True,
            text=True,
            env={**bw_session["bw_env"], "BW_SESSION": bw_session["session"]},
        )

        assert result.returncode == 0
        status = json.loads(result.stdout)
        assert "status" in status
        assert status["status"] == "unlocked"


class TestE2EDocker:
    """Test Docker image functionality."""

    def test_docker_image_has_required_binaries(self):
        """Verify Docker image has all required binaries."""
        result = subprocess.run(
            ["docker", "image", "inspect", IMAGE_NAME],
            capture_output=True,
        )
        if result.returncode != 0:
            pytest.skip(f"Image not built yet: {IMAGE_NAME}")

        required_binaries = ["bw", "supercronic", "python3", "sqlcipher"]

        for binary in required_binaries:
            result = subprocess.run(
                ["docker", "run", "--rm", IMAGE_NAME, "which", binary],
                capture_output=True,
            )
            assert result.returncode == 0, f"Binary {binary} not found in image"

    def test_entrypoint_exists(self):
        """Verify entrypoint script is executable."""
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                IMAGE_NAME,
                "ls",
                "-la",
                "/app/entrypoint.sh",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            err = (result.stderr or "").lower()
            if (
                "unable to find image" in err
                or "pull access denied" in err
                or "not found" in err
            ):
                pytest.skip("Image not built yet")
            pytest.fail(f"Docker image check failed: {result.stderr}")

        assert "-rwxr-xr-x" in result.stdout


class TestE2EErrorHandling:
    """Test error handling with real Vaultwarden."""

    def test_invalid_session_handling(self, bw_session):
        """Test that invalid session is handled gracefully."""
        invalid_env = {**bw_session["bw_env"], "BW_SESSION": "invalid_session_key"}
        result = subprocess.run(
            ["bw", "status"],
            capture_output=True,
            text=True,
            env=invalid_env,
        )

        assert result.returncode != 0

    def test_unlock_with_wrong_password(self, bw_session):
        """Test unlock with wrong password fails properly."""
        session = bw_session["session"]
        locked_env = {**bw_session["bw_env"], "BW_SESSION": session}

        result = subprocess.run(["bw", "lock"], capture_output=True, env=locked_env)
        assert result.returncode == 0, f"Lock failed: {result.stderr}"

        result = subprocess.run(
            ["bw", "unlock", "wrong_password", "--raw"],
            capture_output=True,
            text=True,
            env={**locked_env, "BW_SESSION": session},
        )

        assert result.returncode != 0
