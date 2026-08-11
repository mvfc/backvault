"""
End-to-End Tests with Real Vaultwarden

These tests require:
- Vaultwarden running (see fixtures)
- Test user credentials configured via environment variables

Run with:
    VAULTWARDEN_URL=http://localhost:8080 \
    BW_TEST_EMAIL=test@example.com \
    BW_TEST_PASSWORD=testpassword123 \
    BW_TEST_MASTER_PASSWORD=masterpassword123 \
    uv run pytest tests/test_e2e.py -v
"""
import json
import os
import subprocess
import time

import pytest

VAULTWARDEN_URL = os.getenv("VAULTWARDEN_URL", "http://localhost:8080")
TEST_EMAIL = os.getenv("BW_TEST_EMAIL", "e2e@test.com")
TEST_PASSWORD = os.getenv("BW_TEST_PASSWORD", "Test123!")
TEST_MASTER_PASSWORD = os.getenv("BW_TEST_MASTER_PASSWORD", "Master123!")


@pytest.fixture(scope="module")
def vaultwarden_container():
    """Start Vaultwarden container for testing, clean up after."""
    container_name = "backvault-test-vaultwarden"

    result = subprocess.run(
        ["docker", "ps", "--filter", f"name={container_name}", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
    )

    if container_name in result.stdout:
        print(f"Using existing container: {container_name}")
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
            "8080:80",
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

    time.sleep(5)

    yield container_name

    print(f"Stopping Vaultwarden container: {container_name}")
    subprocess.run(["docker", "stop", container_name], capture_output=True)
    subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)


@pytest.fixture(scope="module")
def test_user(vaultwarden_container):
    """Create test user in Vaultwarden."""
    subprocess.run(["bw", "config", "server", VAULTWARDEN_URL], check=True)

    subprocess.run(["bw", "logout"], capture_output=True)

    result = subprocess.run(
        [
            "bw",
            "register",
            TEST_EMAIL,
            "--password",
            TEST_PASSWORD,
            "--master-password",
            TEST_MASTER_PASSWORD,
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0 and "already exists" not in result.stderr.lower():
        if "can only be" in result.stderr.lower():
            pass
        else:
            print(f"Register output: {result.stdout}")
            print(f"Register error: {result.stderr}")

    yield {"email": TEST_EMAIL, "password": TEST_PASSWORD}


@pytest.fixture(scope="module")
def bw_session(test_user):
    """Create Bitwarden CLI session by logging in."""
    subprocess.run(["bw", "config", "server", VAULTWARDEN_URL], check=True)

    subprocess.run(["bw", "logout"], capture_output=True)

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
        env={**os.environ, "BW_SESSION": ""},
    )

    if result.returncode != 0:
        if "not found" in result.stderr.lower() or "invalid" in result.stderr.lower():
            pytest.skip(f"Cannot login to test Vaultwarden: {result.stderr}")
        else:
            pytest.fail(f"Failed to login: {result.stderr}")

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
        env={**os.environ, "BW_SESSION": session},
    )

    if result.returncode != 0:
        pytest.skip(f"Cannot unlock vault: {result.stderr}")

    session = result.stdout.strip()
    os.environ["BW_SESSION"] = session

    yield session

    subprocess.run(["bw", "lock"], capture_output=True)
    subprocess.run(["bw", "logout"], capture_output=True)
    if "BW_SESSION" in os.environ:
        del os.environ["BW_SESSION"]


class TestE2EBackup:
    """End-to-end backup tests with real Vaultwarden."""

    def test_cli_can_login_and_unlock(self, bw_session):
        """Verify CLI can login and unlock vault."""
        assert bw_session
        assert len(bw_session) > 0

        result = subprocess.run(
            ["bw", "status"],
            capture_output=True,
            text=True,
            env={**os.environ, "BW_SESSION": bw_session},
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
            env={**os.environ, "BW_SESSION": bw_session},
        )

        assert result.returncode == 0
        items = json.loads(result.stdout)
        assert isinstance(items, list)

    def test_backup_personal_vault_raw_mode(self, bw_session, tmp_path):
        """Test backing up personal vault with raw (AES-256-GCM) encryption."""
        from src.bw_client import BitwardenClient

        client = BitwardenClient(session=bw_session, server=VAULTWARDEN_URL)

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
            env={**os.environ, "BW_SESSION": bw_session},
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
            env={**os.environ, "BW_SESSION": bw_session},
        )

        assert result.returncode == 0
        status = json.loads(result.stdout)
        assert "status" in status
        assert status["status"] == "unlocked"


class TestE2EDocker:
    """Test Docker image functionality."""

    def test_docker_image_has_required_binaries(self):
        """Verify Docker image has all required binaries."""
        required_binaries = ["bw", "supercronic", "python3"]

        for binary in required_binaries:
            result = subprocess.run(
                ["docker", "run", "--rm", "vaultwarden/server:latest", "which", binary],
                capture_output=True,
            )
            if result.returncode == 0 and binary == "bw":
                print(f"Found {binary} in vaultwarden image")
                continue
            try:
                subprocess.run(
                    ["docker", "run", "--rm", "backvault:latest", "which", binary],
                    capture_output=True,
                    check=True,
                )
            except subprocess.CalledProcessError:
                pytest.skip(f"Image not built yet: {binary}")

    def test_entrypoint_exists(self):
        """Verify entrypoint script is executable."""
        try:
            result = subprocess.run(
                ["docker", "run", "--rm", "backvault:latest", "ls", "-la", "/app/entrypoint.sh"],
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError:
            pytest.skip("Image not built yet")

        assert "-rwxr-xr-x" in result.stdout


class TestE2EErrorHandling:
    """Test error handling with real Vaultwarden."""

    def test_invalid_session_handling(self):
        """Test that invalid session is handled gracefully."""
        result = subprocess.run(
            ["bw", "status"],
            capture_output=True,
            text=True,
            env={**os.environ, "BW_SESSION": "invalid_session_key"},
        )

        assert result.returncode != 0

    def test_unlock_with_wrong_password(self):
        """Test unlock with wrong password fails properly."""
        subprocess.run(["bw", "lock"], capture_output=True)

        result = subprocess.run(
            [
                "bw",
                "unlock",
                "wrong_password",
                "--raw",
            ],
            capture_output=True,
            text=True,
            env={**os.environ, "BW_SESSION": ""},
        )

        assert result.returncode != 0