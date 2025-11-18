import os
from subprocess import CalledProcessError, run as sprun
import json
import logging
import re
from typing import Any
from sys import stdout
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Constants for encryption
SALT_SIZE = 16
KEY_SIZE = 32  # For AES-256
PBKDF2_ITERATIONS = 600000

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    handlers=[logging.StreamHandler(stdout)],
)

logger = logging.getLogger(__name__)

password_regex = re.compile(r"('--password',\s*)('[^']*')(\s*]')", re.IGNORECASE)
unlock_regex = re.compile(r"('unlock',\s*)('[^']*\s*-)", re.IGNORECASE)


class BitwardenError(Exception):
    """Base exception for Bitwarden wrapper."""

    pass


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
            logger.debug(f"Configuring BW server: {server}")
            env = os.environ.copy()  # do not add BW_SESSION
            try:
                sprun(
                    [self.bw_cmd, "config", "server", server],
                    text=True,
                    capture_output=True,
                    check=True,
                    env=env,
                    preexec_fn=None,  # Disable process group creation
                )
            except CalledProcessError as e:
                if e.returncode == 1:
                    pass
                else:
                    logger.error(f"Bitwarden CLI error: {e.stderr.strip()}")
                    raise BitwardenError(e.stderr.strip())
            except Exception:
                try:
                    self.logout()
                except Exception:
                    pass
                raise BitwardenError(f"Failed to configure BW server to {server}")

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logout()

    def _run(
        self,
        cmd: list[str],
        capture_json: bool = True,
        text: bool = True,
        capture_output: bool = True,
        check: bool = True,
        env=os.environ.copy(),
    ) -> Any:
        """
        Run a bw CLI command safely.
        :param cmd: list of arguments, e.g., ["list", "items"]
        :param capture_json: parse stdout as JSON if True
        """
        if self.session:
            env["BW_SESSION"] = self.session
        full_cmd = [self.bw_cmd] + cmd
        # Redact sensitive values before logging
        def _redact_cmd(cmd):
            redacted = []
            sensitive_flags = {"--password", "--apikey", "--clientsecret", "password"}
            skip_next = False
            for i, arg in enumerate(cmd):
                if skip_next:
                    redacted.append("[REDACTED]")
                    skip_next = False
                elif arg in sensitive_flags:
                    redacted.append(arg)
                    skip_next = True
                else:
                    # For direct password (e.g. `bw unlock <password>`) redact if flag is not used
                    if i > 0 and cmd[i-1] == "unlock":
                        redacted.append("[REDACTED]")
                    else:
                        redacted.append(arg)
            return redacted
        logger.debug(f"Running command: {' '.join(_redact_cmd(full_cmd))}")
        try:
            result = sprun(
                full_cmd,
                text=text,
                capture_output=capture_output,
                check=check,
                env=env,
            )
        except Exception as e:
            masked_e = password_regex.sub("('--password', '****')]", e.__str__())
            masked_e = unlock_regex.sub("('unlock', '****', '-)", masked_e)
            logger.error(f"Failed to run command: {masked_e}")
            try:
                sprun(
                    [self.bw_cmd, "logout"],
                    text=text,
                    capture_output=capture_output,
                    check=True,
                    env=env,
                )
            except Exception as inner_e:
                masked_inner_e = password_regex.sub(
                    "('--password', '****')]", inner_e.__str__()
                )
                masked_inner_e = unlock_regex.sub(
                    "'unlock', '**** --raw'", masked_inner_e
                )
                logger.error(
                    f"Failed to log out after error. Failure: {masked_inner_e}"
                )
            raise BitwardenError(f"Failed to run command: {masked_e}") from None

        if result.returncode != 0:
            logger.error(
                f"Bitwarden CLI error: {
                    unlock_regex.sub(
                        password_regex.sub(
                            "('--password', '****')]", result.stderr.strip()
                        ),
                        "'unlock', '**** --raw'",
                    )
                }"
            )
            raise BitwardenError(
                unlock_regex.sub(
                    password_regex.sub(
                        "('--password', '****')]", result.stderr.strip()
                    ),
                    "'unlock', '**** --raw'",
                )
            )

        output = result.stdout.strip()
        if capture_json:
            try:
                return json.loads(output)
            except json.JSONDecodeError:
                logger.error(f"Failed to parse JSON output: {output}")
                raise BitwardenError("Failed to parse JSON output")
        else:
            return output

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

    def login(
        self, email: str | None = None, password: str | None = None, raw: bool = True
    ) -> str:
        """
        Login with email/password or API key.
        Returns session key if raw=True.
        """
        if self.use_api_key:
            logger.info("Logging in via API key")

            # Ensure env vars are set so bw login --apikey is non-interactive
            env = os.environ.copy()
            env["BW_CLIENTID"] = self.client_id
            env["BW_CLIENTSECRET"] = self.client_secret

            cmd = ["login", "--apikey"]

            # Run CLI
            result = self._run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                env=env,
                capture_json=False,
            )
            self.session = result
            logger.info("Logged in successfully")

        else:
            logger.info("Logging in via email/password")
            cmd = ["login", email]
            if password:
                cmd += ["--password", password]
            if raw:
                cmd.append("--raw")
            self.session = self._run(cmd, capture_json=False)
            logger.info("Logged in successfully")

        return self.session

    def unlock(self, password: str) -> str:
        """
        Unlock vault with master password or API key secret.
        Returns session token.
        """
        env = os.environ.copy()
        env["BW_SESSION"] = self.session

        cmd = ["unlock", password, "--raw"]
        result = self._run(
            cmd, capture_output=True, text=True, check=True, env=env, capture_json=False
        )

        self.session = result
        logger.info("Vault unlocked successfully")
        return self.session

    def encrypt_data(self, data: bytes, password: str) -> bytes:
        """
        Encrypts data using AES-256-GCM with a key derived from the password.
        Format: salt (16 bytes) + nonce (12 bytes) + ciphertext + tag (16 bytes)
        """
        logger.info("Encrypting data in-memory...")
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
        return salt + nonce + ciphertext

    def export_bitwarden_encrypted(self, backup_file: str, file_pw: str):
        """Exports using Bitwarden's built-in encryption."""
        logger.info(f"Exporting with Bitwarden encryption to {backup_file}...")
        self._run(
            cmd=[
                "export",
                "--output",
                backup_file,
                "--format",
                "json",
                "--password",
                file_pw,
            ],
            capture_json=False,
        )

    def export_raw_encrypted(self, backup_file: str, file_pw: str):
        """Exports raw data and encrypts it in-memory."""
        logger.info("Exporting raw data from Bitwarden...")
        raw_json = self._run(
            cmd=["export", "--format", "json", "--raw"], capture_json=True
        )
        encrypted_data = self.encrypt_data(
            json.dumps(raw_json).encode("utf-8"), file_pw
        )
        with open(backup_file, "wb") as f:
            f.write(encrypted_data)
