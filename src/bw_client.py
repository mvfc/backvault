import os
import time
from subprocess import CalledProcessError, run as sprun
import json
import logging
from typing import Any
from sys import stdout
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from src.utils import validate_path, BitwardenError

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


def _safe_error(e: Exception) -> str:
    """
    Build a safe error message from an exception without interpolating
    its string representation wholesale. CalledProcessError.__str__()
    includes the full argv, which can leak secrets passed as arguments.
    """
    if isinstance(e, CalledProcessError):
        from shlex import quote

        cmd = " ".join(quote(str(a)) for a in e.cmd) if e.cmd else "(unknown)"
        msg = f"Command '{cmd}' returned non-zero exit status {e.returncode}."
        if e.stderr:
            msg += f" stderr: {e.stderr.strip()}"
        return msg
    return str(e)


class BitwardenClient:
    def __init__(
        self,
        bw_cmd: str = "bw",
        session: str | None = None,
        server: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        use_api_key: bool = True,
        login_retries: int = 5,
        login_retry_delay: float = 2.0,
    ):
        """
        Initialize Bitwarden client wrapper.

        :param bw_cmd: Path to bw CLI command (default "bw")
        :param session: Existing BW_SESSION token (optional)
        :param server: Bitwarden server URL (optional, Vaultwarden compatible)
        :param client_id: Client ID for API key login (optional)
        :param client_secret: Client Secret for API key login (optional)
        :param use_api_key: Whether to use API key login if client_id and client_secret are provided (Default to True)
        :param login_retries: Number of times to retry login on transient failure (e.g. server starting up)
        :param login_retry_delay: Seconds to wait between login retries
        """
        self.bw_cmd = bw_cmd
        self.session = session
        self.client_id = client_id
        self.client_secret = client_secret
        self.login_retries = login_retries
        self.login_retry_delay = login_retry_delay
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

    def _redact_text(self, text: str, env: dict | None = None) -> str:
        """
        Redact all known secret values from an arbitrary string.
        Used as a defense-in-depth redaction layer for any outgoing
        message, regardless of where the secret originated.
        """
        secrets = set()
        for value in (self.session, self.client_id, self.client_secret):
            if value:
                secrets.add(value)
        if env:
            for key in ("BW_PASSWORD", "BW_CLIENTSECRET", "BW_CLIENTID", "BW_SESSION"):
                if env.get(key):
                    secrets.add(env[key])
        redacted = text
        for secret in sorted(
            (s for s in secrets if s), key=len, reverse=True
        ):
            if secret in redacted:
                redacted = redacted.replace(secret, "[REDACTED]")
        return redacted

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
                    if i > 0 and cmd[i - 1] == "unlock":
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
            returncode = e.returncode if isinstance(e, CalledProcessError) else None
            masked_e = f"Command '{self.bw_cmd} {' '.join(_redact_cmd(cmd))}'"
            if returncode is not None:
                masked_e += f" returned non-zero exit status {returncode}."
            if isinstance(e, CalledProcessError) and e.stderr:
                masked_e += f" stderr: {self._redact_text(str(e.stderr), env)}"
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
                logger.error(
                    f"Failed to log out after error. Failure: "
                    f"{self._redact_text(_safe_error(inner_e), env)}"
                )
            raise BitwardenError(f"Failed to run command: {masked_e}") from None

        if result.returncode != 0:
            masked_stderr = self._redact_text(result.stderr.strip(), env)
            logger.error(f"Bitwarden CLI error: {masked_stderr}")
            raise BitwardenError(masked_stderr)

        output = result.stdout.strip()
        if capture_json:
            try:
                return json.loads(output)
            except json.JSONDecodeError:
                logger.error("Failed to parse JSON output")
                raise BitwardenError("Failed to parse JSON output")
        else:
            return output

    # -------------------------------
    # Core API methods
    # -------------------------------
    def logout(self) -> None:
        """Logout and clear session. No-op if no session is active."""
        if self.session is None:
            logger.info("No active session; skipping logout")
            return
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

            # Retry so transient failures (e.g. the server still starting up
            # after a host reboot) do not abort the whole run.
            attempts = self.login_retries + 1
            for attempt in range(1, attempts + 1):
                try:
                    result = self._run(
                        cmd,
                        capture_output=True,
                        text=True,
                        check=True,
                        env=env,
                        capture_json=False,
                    )
                    break
                except BitwardenError:
                    if attempt >= attempts:
                        raise
                    logger.warning(
                        f"Login attempt {attempt}/{attempts} failed; retrying "
                        f"in {self.login_retry_delay}s"
                    )
                    time.sleep(self.login_retry_delay)
            self.session = result
            logger.info("Logged in successfully")

        else:
            logger.info("Logging in via email/password")
            env = os.environ.copy()
            cmd = ["login", email]
            if password:
                env["BW_PASSWORD"] = password
                cmd += ["--passwordenv", "BW_PASSWORD"]
            if raw:
                cmd.append("--raw")
            self.session = self._run(
                cmd, capture_json=False, env=env
            )
            logger.info("Logged in successfully")

        return self.session

    def unlock(self, password: str) -> str:
        """
        Unlock vault with master password or API key secret.
        Returns session token.
        """
        env = os.environ.copy()
        env["BW_SESSION"] = self.session
        env["BW_PASSWORD"] = password

        cmd = ["unlock", "--passwordenv", "BW_PASSWORD", "--raw"]
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
        try:
            backup_file = validate_path(backup_file, "/app")
        except BitwardenError as e:
            logger.error(f"Invalid backup file path: {e}")
            raise
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
        try:
            backup_file = validate_path(backup_file, "/app")
        except BitwardenError as e:
            logger.error(f"Invalid backup file path: {e}")
            raise
        logger.info("Exporting raw data from Bitwarden...")
        raw_json = self._run(
            cmd=["export", "--format", "json", "--raw"], capture_json=True
        )
        encrypted_data = self.encrypt_data(
            json.dumps(raw_json).encode("utf-8"), file_pw
        )
        with open(backup_file, "wb") as f:
            f.write(encrypted_data)

    def list_organizations(self) -> list[dict[str, Any]]:
        """List all organizations the user has access to."""
        logger.info("Fetching organization list...")
        return self._run(["list", "organizations"])

    def export_organization_raw(self, org_id: str) -> dict[str, Any]:
        """Export organization vault as raw JSON."""
        logger.info(f"Exporting organization vault: {org_id}")
        return self._run(
            cmd=["export", "--organizationid", org_id, "--format", "json", "--raw"],
            capture_json=True,
        )

    def export_organization_bitwarden(
        self, backup_file: str, file_pw: str, org_id: str
    ):
        """Export organization vault using Bitwarden's built-in encryption."""
        try:
            backup_file = validate_path(backup_file, "/app")
        except BitwardenError as e:
            logger.error(f"Invalid backup file path: {e}")
            raise
        logger.info(f"Exporting organization {org_id} with Bitwarden encryption...")
        self._run(
            cmd=[
                "export",
                "--organizationid",
                org_id,
                "--output",
                backup_file,
                "--format",
                "encrypted_json",
                "--password",
                file_pw,
            ],
            capture_json=False,
        )

    def export_organization_raw_encrypted(
        self, backup_file: str, file_pw: str, org_id: str
    ):
        """Export organization vault and encrypt it in-memory."""
        try:
            backup_file = validate_path(backup_file, "/app")
        except BitwardenError as e:
            logger.error(f"Invalid backup file path: {e}")
            raise
        logger.info(f"Exporting organization {org_id} with raw encryption...")
        raw_json = self.export_organization_raw(org_id)
        encrypted_data = self.encrypt_data(
            json.dumps(raw_json).encode("utf-8"), file_pw
        )
        with open(backup_file, "wb") as f:
            f.write(encrypted_data)
