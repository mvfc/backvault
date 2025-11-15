"""Tests for encryption/decryption functionality."""

import os
import sys
from pathlib import Path

import pytest
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Add src to path for imports (must be before importing from src)
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from decrypt import (  # noqa: E402
    ARGON2_MEMORY_COST as DEC_MEM,
    ARGON2_PARALLELISM as DEC_PAR,
    ARGON2_TIME_COST as DEC_TIME,
    PBKDF2_ITERATIONS as DEC_PBKDF2,
    decrypt_data,
)

# Constants for encryption (mirroring bw_client.py)
# We define these directly to avoid importing BitwardenClient which requires logging setup
SALT_SIZE = 16
KEY_SIZE = 32
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4
PBKDF2_ITERATIONS = 600000
ENCRYPTION_VERSION = 2


def encrypt_data_simple(data: bytes, password: str) -> bytes:
    """
    Simplified encryption function for testing (mirrors BitwardenClient.encrypt_data).
    This avoids needing to instantiate the full client with its logging setup.
    """
    # Add version header
    version = ENCRYPTION_VERSION.to_bytes(4, byteorder="big")
    salt = os.urandom(SALT_SIZE)

    # Derive key using Argon2id
    key = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )

    # Encrypt using AES-GCM
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    return version + salt + nonce + ciphertext


class TestEncryptionConstants:
    """Test that encryption/decryption constants are consistent."""

    def test_argon2_time_cost_matches(self):
        """Verify Argon2 time_cost matches between encrypt and decrypt."""
        assert ARGON2_TIME_COST == DEC_TIME
        assert ARGON2_TIME_COST == 3

    def test_argon2_memory_cost_matches(self):
        """Verify Argon2 memory_cost matches between encrypt and decrypt."""
        assert ARGON2_MEMORY_COST == DEC_MEM
        assert ARGON2_MEMORY_COST == 65536  # 64 MB in KiB

    def test_argon2_parallelism_matches(self):
        """Verify Argon2 parallelism matches between encrypt and decrypt."""
        assert ARGON2_PARALLELISM == DEC_PAR
        assert ARGON2_PARALLELISM == 4

    def test_pbkdf2_iterations_matches(self):
        """Verify PBKDF2 iterations match between encrypt and decrypt."""
        assert PBKDF2_ITERATIONS == DEC_PBKDF2
        assert PBKDF2_ITERATIONS == 600000  # OWASP 2023 recommendation

    def test_encryption_version(self):
        """Verify current encryption version is 2 (Argon2id)."""
        assert ENCRYPTION_VERSION == 2


class TestArgon2Encryption:
    """Test Version 2 (Argon2id) encryption and decryption."""

    def test_encrypt_decrypt_roundtrip(self, test_data, test_password):
        """Test that data can be encrypted and then decrypted successfully."""
        # Encrypt
        encrypted = encrypt_data_simple(test_data, test_password)

        # Decrypt
        decrypted = decrypt_data(encrypted, test_password)

        # Verify
        assert decrypted == test_data

    def test_version_header(self, test_data, test_password):
        """Test that encrypted data has correct version header."""
        encrypted = encrypt_data_simple(test_data, test_password)

        # Check version header (first 4 bytes)
        version = int.from_bytes(encrypted[:4], byteorder="big")
        assert version == 2

    def test_encrypted_data_structure(self, test_data, test_password):
        """Test that encrypted data has expected structure."""
        encrypted = encrypt_data_simple(test_data, test_password)

        # Expected minimum size:
        # 4 bytes (version) + 16 bytes (salt) + 12 bytes (nonce) + data + 16 bytes (tag)
        min_size = 4 + 16 + 12 + len(test_data) + 16
        assert len(encrypted) >= min_size

    def test_wrong_password_fails(self, test_data, test_password):
        """Test that decryption fails with wrong password."""
        encrypted = encrypt_data_simple(test_data, test_password)

        # Try to decrypt with wrong password
        with pytest.raises(InvalidTag):
            decrypt_data(encrypted, "WrongPassword123!")

    def test_different_password_different_output(self, test_data):
        """Test that same data with different passwords produces different ciphertext."""
        encrypted1 = encrypt_data_simple(test_data, "Password1")
        encrypted2 = encrypt_data_simple(test_data, "Password2")

        # Ciphertexts should be different (different salts, different keys)
        assert encrypted1 != encrypted2

    def test_same_password_different_output(self, test_data, test_password):
        """Test that encrypting twice with same password produces different output (different salt/nonce)."""
        encrypted1 = encrypt_data_simple(test_data, test_password)
        encrypted2 = encrypt_data_simple(test_data, test_password)

        # Should be different due to random salt and nonce
        assert encrypted1 != encrypted2

        # But both should decrypt to same data
        assert decrypt_data(encrypted1, test_password) == test_data
        assert decrypt_data(encrypted2, test_password) == test_data

    def test_empty_data(self, test_password):
        """Test encryption of empty data."""
        empty_data = b""

        encrypted = encrypt_data_simple(empty_data, test_password)
        decrypted = decrypt_data(encrypted, test_password)

        assert decrypted == empty_data

    def test_large_data(self, test_password):
        """Test encryption of larger data (simulating real vault backup)."""
        # Simulate a 1MB vault backup
        large_data = b"x" * (1024 * 1024)

        encrypted = encrypt_data_simple(large_data, test_password)
        decrypted = decrypt_data(encrypted, test_password)

        assert decrypted == large_data


class TestBackwardCompatibility:
    """Test backward compatibility with Version 1 (PBKDF2) format."""

    def test_version_1_encrypt_decrypt(self, test_data, test_password):
        """Test Version 1 (PBKDF2) encryption and decryption."""
        # Create Version 1 encrypted data
        encrypted_v1 = self._encrypt_data_v1(test_data, test_password)

        # Verify version header
        version = int.from_bytes(encrypted_v1[:4], byteorder="big")
        assert version == 1

        # Decrypt with decrypt_data (should handle V1)
        decrypted = decrypt_data(encrypted_v1, test_password)
        assert decrypted == test_data

    def test_version_1_wrong_password(self, test_data, test_password):
        """Test Version 1 fails with wrong password."""
        encrypted_v1 = self._encrypt_data_v1(test_data, test_password)

        with pytest.raises(InvalidTag):
            decrypt_data(encrypted_v1, "WrongPassword")

    @staticmethod
    def _encrypt_data_v1(data: bytes, password: str) -> bytes:
        """Helper to create Version 1 (PBKDF2) encrypted data for testing."""
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes

        version = (1).to_bytes(4, byteorder="big")
        salt = os.urandom(SALT_SIZE)

        # PBKDF2 key derivation
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        key = kdf.derive(password.encode("utf-8"))

        # Encrypt using AES-GCM
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)

        return version + salt + nonce + ciphertext


class TestErrorHandling:
    """Test error handling for invalid/corrupted data."""

    def test_invalid_version_number(self, test_data, test_password):
        """Test that invalid version numbers raise ValueError."""
        # Create data with invalid version (999)
        encrypted = encrypt_data_simple(test_data, test_password)
        corrupted = (999).to_bytes(4, byteorder="big") + encrypted[4:]

        with pytest.raises(ValueError, match="Unsupported encryption version"):
            decrypt_data(corrupted, test_password)

    def test_version_zero(self, test_data, test_password):
        """Test that version 0 is rejected."""
        encrypted = encrypt_data_simple(test_data, test_password)
        corrupted = (0).to_bytes(4, byteorder="big") + encrypted[4:]

        with pytest.raises(ValueError, match="Unsupported encryption version"):
            decrypt_data(corrupted, test_password)

    def test_data_too_short_no_version(self):
        """Test that data shorter than version header fails."""
        truncated = b"abc"  # Only 3 bytes
        with pytest.raises(Exception):  # Will fail reading version or elsewhere
            decrypt_data(truncated, "password")

    def test_data_too_short_no_salt(self, test_password):
        """Test that data with version but no salt fails."""
        # Version header only (4 bytes)
        truncated = (2).to_bytes(4, byteorder="big")
        # Argon2 will raise HashingError for too-short salt
        with pytest.raises(
            Exception
        ):  # Could be HashingError, ValueError, or InvalidTag
            decrypt_data(truncated, test_password)

    def test_data_too_short_no_nonce(self, test_password):
        """Test that data with version and salt but no nonce fails."""
        # Version (4) + partial salt (8 bytes)
        truncated = (2).to_bytes(4, byteorder="big") + os.urandom(8)
        # Will raise ValueError for invalid nonce size or HashingError for salt
        with pytest.raises(Exception):  # Could be ValueError or HashingError
            decrypt_data(truncated, test_password)

    def test_corrupted_ciphertext(self, test_data, test_password):
        """Test that corrupted ciphertext fails authentication."""
        encrypted = encrypt_data_simple(test_data, test_password)

        # Corrupt a byte in the ciphertext (after version+salt+nonce)
        corrupted = bytearray(encrypted)
        corrupted[-10] ^= 0xFF  # Flip bits in ciphertext
        corrupted = bytes(corrupted)

        with pytest.raises(InvalidTag):
            decrypt_data(corrupted, test_password)

    def test_corrupted_salt(self, test_data, test_password):
        """Test that corrupted salt produces wrong key and fails."""
        encrypted = encrypt_data_simple(test_data, test_password)

        # Corrupt a byte in the salt
        corrupted = bytearray(encrypted)
        corrupted[5] ^= 0xFF  # Flip bits in salt
        corrupted = bytes(corrupted)

        with pytest.raises(InvalidTag):
            decrypt_data(corrupted, test_password)

    def test_corrupted_nonce(self, test_data, test_password):
        """Test that corrupted nonce fails decryption."""
        encrypted = encrypt_data_simple(test_data, test_password)

        # Corrupt a byte in the nonce (after version+salt)
        corrupted = bytearray(encrypted)
        corrupted[20] ^= 0xFF  # Flip bits in nonce
        corrupted = bytes(corrupted)

        with pytest.raises(InvalidTag):
            decrypt_data(corrupted, test_password)

    def test_empty_password(self, test_data):
        """Test encryption/decryption with empty password."""
        empty_password = ""

        encrypted = encrypt_data_simple(test_data, empty_password)
        decrypted = decrypt_data(encrypted, empty_password)

        assert decrypted == test_data

        # Wrong password should still fail
        with pytest.raises(InvalidTag):
            decrypt_data(encrypted, "not-empty")

    def test_very_long_password(self, test_data):
        """Test encryption with very long password (10000 chars)."""
        long_password = "a" * 10000

        encrypted = encrypt_data_simple(test_data, long_password)
        decrypted = decrypt_data(encrypted, long_password)

        assert decrypted == test_data

    def test_password_with_null_bytes(self, test_data):
        """Test password containing null bytes."""
        null_password = "pass\x00word\x00test"

        encrypted = encrypt_data_simple(test_data, null_password)
        decrypted = decrypt_data(encrypted, null_password)

        assert decrypted == test_data


class TestSecurityProperties:
    """Test security properties of the encryption."""

    def test_salt_is_random(self, test_data, test_password):
        """Verify that salt is different for each encryption."""
        encrypted1 = encrypt_data_simple(test_data, test_password)
        encrypted2 = encrypt_data_simple(test_data, test_password)

        # Extract salts (bytes 4-20 after version header)
        salt1 = encrypted1[4:20]
        salt2 = encrypted2[4:20]

        assert salt1 != salt2

    def test_nonce_is_random(self, test_data, test_password):
        """Verify that nonce is different for each encryption."""
        encrypted1 = encrypt_data_simple(test_data, test_password)
        encrypted2 = encrypt_data_simple(test_data, test_password)

        # Extract nonces (bytes 20-32 after version header)
        nonce1 = encrypted1[20:32]
        nonce2 = encrypted2[20:32]

        assert nonce1 != nonce2

    def test_unicode_password(self, test_data):
        """Test that unicode passwords work correctly."""
        unicode_password = "Pāšş🔐wørd"

        encrypted = encrypt_data_simple(test_data, unicode_password)
        decrypted = decrypt_data(encrypted, unicode_password)

        assert decrypted == test_data

    def test_special_characters_in_data(self, test_password):
        """Test that data with special characters encrypts/decrypts correctly."""
        special_data = b"\x00\x01\xff\xfe Special chars: \xe2\x9c\x93\xe2\x9c\x97"

        encrypted = encrypt_data_simple(special_data, test_password)
        decrypted = decrypt_data(encrypted, test_password)

        assert decrypted == special_data
