import os
import subprocess
import json
import logging
import re
import time
from typing import Any, Callable
from sys import stdout
from pathlib import Path
from functools import wraps
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Constants for encryption
SALT_SIZE = 16
KEY_SIZE = 32  # For AES-256
PBKDF2_ITERATIONS = 600000  # OWASP 2023 recommendation
ENCRYPTION_VERSION = 1  # File format version for future compatibility

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler("/var/log/cron.log"),
        logging.StreamHandler(stdout)
    ]
)

logger = logging.getLogger(__name__)

class BitwardenError(Exception):
    """Base exception for Bitwarden wrapper."""

    pass


def retry_with_backoff(max_attempts: int = 3, base_delay: float = 2.0, max_delay: float = 30.0):
    """
    Decorator to retry a function with exponential backoff on BitwardenError.

    :param max_attempts: Maximum number of retry attempts
    :param base_delay: Initial delay in seconds (doubles with each retry)
    :param max_delay: Maximum delay between retries in seconds
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except BitwardenError as e:
                    last_exception = e
                    if attempt == max_attempts - 1:
                        # Last attempt failed, re-raise
                        logger.error(f"{func.__name__} failed after {max_attempts} attempts")
                        raise
                    # Calculate delay with exponential backoff
                    delay = min(base_delay * (2 ** attempt), max_delay)
                    logger.warning(
                        f"{func.__name__} attempt {attempt + 1}/{max_attempts} failed: {e}. "
                        f"Retrying in {delay:.1f} seconds..."
                    )
                    time.sleep(delay)
            # Should not reach here, but just in case
            raise last_exception
        return wrapper
    return decorator


class BitwardenClient:
    def __init__(
        self,
        bw_cmd: str = "bw",
        session: str | None = None,
        server: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        use_api_key: bool = True,
    ):
        """
        Initialize Bitwarden client wrapper.

        :param bw_cmd: Path to bw CLI command (default "bw")
        :param session: Existing BW_SESSION token (optional)
        :param server: Bitwarden server URL (optional, Vaultwarden compatible)
        :param client_id: Client ID for API key login (optional)
        :param client_secret: Client Secret for API key login (optional)
        :param use_api_key: Whether to use API key login if client_id and client_secret are provided (Default to True)
        """
        self.bw_cmd = bw_cmd
        self.session = session
        self.client_id = client_id
        self.client_secret = client_secret
        self.use_api_key = (
            use_api_key and client_id is not None and client_secret is not None
        )
        if server:
            logger.info(f"Configuring BW server: {server}")
            env = os.environ.copy()  # do not add BW_SESSION
            try:
                subprocess.run(
                    [self.bw_cmd, "config", "server", server],
                    text=True,
                    capture_output=True,
                    check=True,
                    env=env,
                    preexec_fn=None,  # Disable process group creation
                )
            except subprocess.CalledProcessError as e:
                if e.returncode == 1:
                    pass
                else:
                    logger.error("Bitwarden CLI error configuring server")
                    logger.error(f"Return code: {e.returncode}")
                    logger.error(f"stdout: {e.stdout}")
                    logger.error(f"stderr: {e.stderr}")
                    raise BitwardenError("Failed to configure BW server") from e
            except Exception as e:
                try:
                    self.logout()
                except Exception:
                    pass
                raise BitwardenError("Failed to configure BW server") from e

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logout()

    def _run(self, cmd: list[str], capture_json: bool = True) -> Any:
        """
        Run a bw CLI command safely.
        :param cmd: list of arguments, e.g., ["list", "items"]
        :param capture_json: parse stdout as JSON if True
        """
        env = os.environ.copy()
        if self.session:
            env["BW_SESSION"] = self.session
        full_cmd = [self.bw_cmd] + cmd

        # Log command but redact sensitive arguments
        safe_cmd = self._redact_sensitive_args(full_cmd)
        logger.info(f"Running command: {' '.join(safe_cmd)}")

        try:
            result = subprocess.run(
                full_cmd,
                text=True,
                capture_output=True,
                check=True,
                env=env,
                preexec_fn=None,  # Disable process group creation
            )
        except subprocess.CalledProcessError as e:
            logger.error(f"Bitwarden CLI command failed with exit code {e.returncode}")
            logger.error(f"stdout: {e.stdout}")
            logger.error(f"stderr: {e.stderr}")
            logger.error(f"Command: {' '.join(safe_cmd)}")
            raise BitwardenError("Bitwarden CLI command failed") from e

        output = result.stdout.strip()
        if capture_json:
            try:
                return json.loads(output)
            except json.JSONDecodeError as e:
                logger.error("Failed to parse JSON output from Bitwarden CLI")
                raise BitwardenError("Failed to parse JSON output") from e
        else:
            return output

    def _redact_sensitive_args(self, cmd: list[str]) -> list[str]:
        """
        Redact sensitive arguments from command list for safe logging.
        """
        redacted = []
        skip_next = False
        sensitive_flags = {"--password", "--raw"}
        sensitive_commands = {"unlock"}

        for i, arg in enumerate(cmd):
            if skip_next:
                redacted.append("***REDACTED***")
                skip_next = False
            elif arg in sensitive_flags:
                redacted.append(arg)
                skip_next = True
            elif arg in sensitive_commands and i + 1 < len(cmd):
                redacted.append(arg)
                skip_next = True
            else:
                redacted.append(arg)

        return redacted

    # -------------------------------
    # Core API methods
    # -------------------------------
    def logout(self) -> None:
        """Logout and clear session"""
        self._run(["logout"], capture_json=False)
        self.session = None
        logger.info("Logged out successfully")

    def status(self) -> dict[str, Any]:
        """Return current session status"""
        return self._run(["status"])

    @retry_with_backoff(max_attempts=3, base_delay=2.0)
    def login(
        self, email: str | None = None, password: str | None = None, raw: bool = True
    ) -> str:
        """
        Login with email/password or API key.
        Returns session key if raw=True.
        Retries up to 3 times with exponential backoff on failure.
        """
        if self.use_api_key:
            logger.info("Logging in via API key")

            # Ensure env vars are set so bw login --apikey is non-interactive
            env = os.environ.copy()
            env["BW_CLIENTID"] = self.client_id
            env["BW_CLIENTSECRET"] = self.client_secret

            cmd = [self.bw_cmd, "login", "--apikey"]

            # Run CLI
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, check=True, env=env
                )
            except subprocess.CalledProcessError as e:
                logger.error("Bitwarden CLI login failed")
                logger.error(f"Return code: {e.returncode}")
                logger.error(f"stdout: {e.stdout}")
                logger.error(f"stderr: {e.stderr}")
                logger.error(f"Command: {' '.join(cmd)}")
                try:
                    self.logout()
                except Exception:
                    pass
                raise BitwardenError("Bitwarden CLI login failed") from e

            # API key login doesn't return a session token - that comes from unlock
            logger.info("Logged in successfully via API key")
            logger.debug(f"Login output: {result.stdout.strip()}")
            # Don't set self.session here - it will be set by unlock()

        else:
            logger.info("Logging in via email/password")
            cmd = ["login", email]
            if password:
                cmd += ["--password", password]
            if raw:
                cmd.append("--raw")
            self.session = self._run(cmd, capture_json=False)
            logger.info("Logged in successfully")

        # Note: For API key login, session will be None until unlock() is called
        return self.session

    @retry_with_backoff(max_attempts=3, base_delay=2.0)
    def unlock(self, password: str) -> str:
        """
        Unlock vault with master password or API key secret.
        Returns session token.
        Retries up to 3 times with exponential backoff on failure.
        """
        env = os.environ.copy()
        # Only set BW_SESSION if we have a valid session (not the case after API key login)
        if self.session:
            env["BW_SESSION"] = self.session

        cmd = [self.bw_cmd, "unlock", password, "--raw"]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=True, env=env
            )
        except subprocess.CalledProcessError as e:
            logger.error("Bitwarden CLI unlock failed. Logging out.")
            logger.error(f"Return code: {e.returncode}")
            logger.error(f"stdout: {e.stdout}")
            logger.error(f"stderr: {e.stderr}")
            # Don't log the password in the command
            safe_cmd = [self.bw_cmd, "unlock", "***REDACTED***", "--raw"]
            logger.error(f"Command: {' '.join(safe_cmd)}")
            try:
                self.logout()
            except Exception:
                pass
            raise BitwardenError("Bitwarden CLI unlock failed") from e

        self.session = result.stdout.strip()
        logger.info("Vault unlocked successfully")
        return self.session
    
    def encrypt_data(self, data: bytes, password: str) -> bytes:
        """
        Encrypts data using AES-256-GCM with a key derived from the password.
        Format: version (4 bytes) + salt (16 bytes) + nonce (12 bytes) + ciphertext + tag (16 bytes)

        Version 1 format:
        - PBKDF2 iterations: 600,000
        - Key derivation: PBKDF2-HMAC-SHA256
        - Encryption: AES-256-GCM
        """
        logger.info("Encrypting data in-memory...")

        # Add version header for future compatibility
        version = ENCRYPTION_VERSION.to_bytes(4, byteorder='big')

        salt = os.urandom(SALT_SIZE)

        # Derive a key from the password and salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        key = kdf.derive(password.encode("utf-8"))

        # Encrypt using AES-GCM
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # GCM recommended nonce size
        ciphertext = aesgcm.encrypt(nonce, data, None)

        logger.info("Encryption successful.")
        return version + salt + nonce + ciphertext


    def _validate_backup_path(self, backup_file: str, allowed_base: str = "/app/backups") -> str:
        """
        Validate that the backup file path is within the allowed directory.
        Prevents path traversal attacks.
        Returns the validated absolute path.
        """
        # Convert to absolute paths
        backup_path = Path(backup_file).resolve()
        allowed_path = Path(allowed_base).resolve()

        # Check if backup path is within allowed directory
        try:
            backup_path.relative_to(allowed_path)
        except ValueError:
            logger.error(f"Invalid backup path: {backup_file} is outside allowed directory {allowed_base}")
            raise BitwardenError(f"Invalid backup path: must be within {allowed_base}")

        # Validate filename contains only safe characters
        filename = backup_path.name
        if not re.match(r'^[a-zA-Z0-9._-]+$', filename):
            logger.error(f"Invalid backup filename: {filename} contains unsafe characters")
            raise BitwardenError("Invalid backup filename: only alphanumeric, dots, dashes, and underscores allowed")

        # Validate file extension
        if not filename.endswith('.enc'):
            logger.error(f"Invalid backup filename: {filename} must end with .enc")
            raise BitwardenError("Invalid backup filename: must end with .enc")

        return str(backup_path)

    def export_bitwarden_encrypted(self, backup_file: str, file_pw: str, allowed_dir: str = "/app/backups"):
        """Exports using Bitwarden's built-in encryption."""
        # Validate backup path
        validated_path = self._validate_backup_path(backup_file, allowed_dir)

        logger.info("Exporting with Bitwarden encryption...")
        self._run(
            cmd=["export", "--output", validated_path, "--format", "json", "--password", file_pw],
            capture_json=False,
        )

    def export_raw_encrypted(self, backup_file: str, file_pw: str, allowed_dir: str = "/app/backups"):
        """Exports raw data and encrypts it in-memory."""
        # Validate backup path
        validated_path = self._validate_backup_path(backup_file, allowed_dir)

        logger.info("Exporting raw data from Bitwarden...")
        # Get raw JSON string (not parsed)
        raw_json_str = self._run(cmd=["export", "--format", "json", "--raw"], capture_json=False)
        encrypted_data = self.encrypt_data(raw_json_str.encode("utf-8"), file_pw)

        with open(validated_path, "wb") as f:
            f.write(encrypted_data)
