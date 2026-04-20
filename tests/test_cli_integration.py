"""
Unit tests for CLI integration workflow (mock-based).

These tests verify that the CLI commands are called correctly
when orchestrating a backup workflow. They use mocks to avoid
requiring a real Vaultwarden instance.

Run with: uv run pytest tests/test_cli_integration.py -v
"""
import json
import os
from unittest.mock import patch, MagicMock
from src.bw_client import BitwardenClient


class TestCLIWorkflow:
    """Tests for complete CLI workflows."""

    @patch("src.bw_client.sprun")
    def test_full_backup_workflow_bitwarden_mode(self, mock_sprun):
        """
        Test complete backup workflow: login -> unlock -> export personal ->
        export orgs (single) -> logout.

        Uses bitwarden encryption mode.
        """
        os.environ["TEST_MODE"] = "1"
        try:
            mock_sprun.side_effect = [
                MagicMock(returncode=0, stdout="", stderr=""),
                MagicMock(returncode=0, stdout="session_key_123", stderr=""),
                MagicMock(returncode=0, stdout="unlocked_session", stderr=""),
                MagicMock(returncode=0, stdout="", stderr=""),
                MagicMock(
                    returncode=0,
                    stdout=json.dumps([{"id": "org1", "name": "Test Org"}]),
                    stderr="",
                ),
                MagicMock(returncode=0, stdout="", stderr=""),
                MagicMock(returncode=0, stdout="", stderr=""),
            ]

            client = BitwardenClient(
                client_id="test_client_id",
                client_secret="test_client_secret",
                use_api_key=True,
                server="https://vault.example.com",
            )

            client.login()
            client.unlock("master_password")

            client.export_bitwarden_encrypted("/tmp/backups/personal.enc", "file_pw")

            orgs = client.list_organizations()
            for org in orgs:
                client.export_organization_bitwarden(
                    f"/tmp/backups/org-{org['id']}.enc", "file_pw", org["id"]
                )

            client.logout()

            assert mock_sprun.call_count == 7
            calls = [str(c) for c in mock_sprun.call_args_list]

            assert any("login" in c and "--apikey" in c for c in calls)
            assert any("unlock" in c for c in calls)
            assert any("export" in c and "personal" in c for c in calls)
            assert any("export" in c and "--organizationid" in c for c in calls)
        finally:
            del os.environ["TEST_MODE"]


class TestCLIEncryption:
    """Tests for encryption functionality."""

    def test_encrypt_data_produces_different_output(self):
        """
        Test that encrypt_data produces encrypted output different from input.
        """
        client = BitwardenClient()
        data = b"secret data here"
        password = "strong_password"

        encrypted = client.encrypt_data(data, password)

        assert encrypted != data
        assert len(encrypted) > len(data)

    def test_encrypt_data_produces_consistent_encryption(self):
        """
        Test that encrypt_data produces different output each time (due to random salt/nonce).
        """
        client = BitwardenClient()
        data = b"same data"
        password = "same_password"

        encrypted1 = client.encrypt_data(data, password)
        encrypted2 = client.encrypt_data(data, password)

        assert encrypted1 != encrypted2
        assert encrypted1[:16] != encrypted2[:16]

    def test_encrypt_data_format(self):
        """
        Test encrypted data has correct format: salt(16) + nonce(12) + ciphertext + tag(16).
        """
        client = BitwardenClient()
        data = b"test data"
        password = "test_password"

        encrypted = client.encrypt_data(data, password)

        salt = encrypted[:16]
        nonce = encrypted[16:28]
        ciphertext_with_tag = encrypted[28:]

        assert len(salt) == 16
        assert len(nonce) == 12
        assert len(ciphertext_with_tag) > 0

    def test_encrypt_data_decryptable(self):
        """
        Test that encrypted data can be decrypted with the same password.
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes

        client = BitwardenClient()
        original_data = b"secret data"
        password = "test_password"

        encrypted = client.encrypt_data(original_data, password)

        salt = encrypted[:16]
        nonce = encrypted[16:28]
        ciphertext_tag = encrypted[28:]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,
        )
        key = kdf.derive(password.encode("utf-8"))

        aesgcm = AESGCM(key)
        decrypted = aesgcm.decrypt(nonce, ciphertext_tag, None)

        assert decrypted == original_data
